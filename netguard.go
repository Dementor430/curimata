package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Addresses that the proxies listen on inside the container.
const (
	socksAddr = "127.0.0.1:1080"
	httpAddr  = "127.0.0.1:3128"
)

// dialTimeout bounds one outbound connection attempt.
const dialTimeout = 30 * time.Second

// rawTerminal tells the log helper to end its lines with CR LF. The host
// terminal is in raw mode while a container runs, so a bare LF would leave
// the next line indented.
var rawTerminal atomic.Bool

// The network log file receives every log line. The terminal belongs to the
// container, so only lines that you must see go there too: a line in the
// middle of a full-screen program breaks its display.
var (
	netlogMutex sync.Mutex
	netlogFile  *os.File
)

// openNetlog opens the network log of the container name, and returns its
// path. Each run appends to the file.
func openNetlog(name string) (string, error) {
	baseDir, err := dataDir()
	if err != nil {
		return "", err
	}
	logDir := filepath.Join(baseDir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return "", fmt.Errorf("create log directory: %w", err)
	}
	path := filepath.Join(logDir, name+".net.log")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return "", fmt.Errorf("open network log: %w", err)
	}
	netlogMutex.Lock()
	netlogFile = file
	netlogMutex.Unlock()
	return path, nil
}

func closeNetlog() {
	netlogMutex.Lock()
	defer netlogMutex.Unlock()
	if netlogFile != nil {
		netlogFile.Close() //nolint:errcheck // log lines are best effort
		netlogFile = nil
	}
}

// netlogf writes a line to the terminal and to the network log.
func netlogf(format string, args ...any) {
	end := "\n"
	if rawTerminal.Load() {
		end = "\r\n"
	}
	fmt.Fprintf(os.Stderr, "curimata: "+format+end, args...)
	netfilef(format, args...)
}

// netfilef writes a line to the network log only.
func netfilef(format string, args ...any) {
	netlogMutex.Lock()
	defer netlogMutex.Unlock()
	if netlogFile != nil {
		fmt.Fprintf(netlogFile, time.Now().Format(time.RFC3339)+" "+format+"\n", args...)
	}
}

// rule allows one host, or one family of hosts, on one port.
type rule struct {
	host     string // lower case, no trailing dot; "" after a leading "*."
	wildcard bool
	port     int // 0 allows every port
}

// allowlist decides which outbound connections the container may open.
// It holds no default rule: whatever does not match is refused.
type allowlist struct {
	rules []rule
}

// parseAllowlist reads rules in the form "host:port".
//
//	deb.debian.org:443   one host, one port
//	*.pypi.org:443       that domain and every name below it
//	10.0.0.5:5432        a literal address
//	example.com:*        every port on one host
func parseAllowlist(specs []string) (*allowlist, error) {
	list := &allowlist{}
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" || strings.HasPrefix(spec, "#") {
			continue
		}

		host, portText, ok := splitHostPort(spec)
		if !ok {
			return nil, fmt.Errorf("allow rule %q: expected host:port", spec)
		}

		r := rule{host: canonicalHost(host)}
		if after, found := strings.CutPrefix(r.host, "*."); found {
			r.wildcard = true
			r.host = after
		}
		if r.host == "" {
			return nil, fmt.Errorf("allow rule %q: empty host", spec)
		}

		if portText != "*" {
			port, err := strconv.Atoi(portText)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("allow rule %q: bad port %q", spec, portText)
			}
			r.port = port
		}
		list.rules = append(list.rules, r)
	}
	if len(list.rules) == 0 {
		return nil, errors.New("no allow rules")
	}
	return list, nil
}

// splitHostPort splits on the last colon, but keeps a bare IPv6 address whole.
func splitHostPort(spec string) (host, port string, ok bool) {
	if strings.HasPrefix(spec, "[") {
		end := strings.Index(spec, "]")
		if end < 0 || end+2 > len(spec) || spec[end+1] != ':' {
			return "", "", false
		}
		return spec[1:end], spec[end+2:], true
	}
	i := strings.LastIndex(spec, ":")
	if i <= 0 || i == len(spec)-1 {
		return "", "", false
	}
	return spec[:i], spec[i+1:], true
}

func canonicalHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

// permits reports whether the container may reach host on port.
//
// The test runs on the name the client asked for, never on the address it
// resolves to. So a moving CDN address stays allowed, and an allowed name
// cannot be reached by writing down its address instead.
func (a *allowlist) permits(host string, port int) bool {
	host = canonicalHost(host)
	for _, r := range a.rules {
		if r.port != 0 && r.port != port {
			continue
		}
		if r.host == host {
			return true
		}
		if r.wildcard && strings.HasSuffix(host, "."+r.host) {
			return true
		}
	}
	return false
}

func (a *allowlist) String() string {
	parts := make([]string, 0, len(a.rules))
	for _, r := range a.rules {
		host := r.host
		if r.wildcard {
			host = "*." + host
		}
		port := "*"
		if r.port != 0 {
			port = strconv.Itoa(r.port)
		}
		parts = append(parts, host+":"+port)
	}
	return strings.Join(parts, " ")
}

// netguard holds the proxies that serve one container.
type netguard struct {
	allow     *allowlist
	listeners []net.Listener
	wg        sync.WaitGroup
	closed    atomic.Bool
}

// proxyEnv is the environment that points the container's tools at us.
func proxyEnv() []string {
	return []string{
		"http_proxy=http://" + httpAddr,
		"https_proxy=http://" + httpAddr,
		"HTTP_PROXY=http://" + httpAddr,
		"HTTPS_PROXY=http://" + httpAddr,
		// socks5h keeps name resolution on our side. The container has no
		// resolver of its own, so plain socks5 would fail.
		"ALL_PROXY=socks5h://" + socksAddr,
		"all_proxy=socks5h://" + socksAddr,
		"no_proxy=localhost,127.0.0.1",
		"NO_PROXY=localhost,127.0.0.1",
	}
}

// startNetguard serves the proxies on listeners that already live inside the
// container's network namespace.
//
// The container has loopback and nothing else: no route, no address, no
// resolver. These two ports are its whole view of the network, so a program
// cannot avoid the allowlist by opening a socket of its own.
func startNetguard(listeners []net.Listener, allow *allowlist) *netguard {
	g := &netguard{allow: allow, listeners: listeners}
	g.wg.Add(len(listeners))
	go g.serve(listeners[0], g.handleSocks)
	go g.serve(listeners[1], g.handleHTTP)
	return g
}

func (g *netguard) close() {
	g.closed.Store(true)
	for _, l := range g.listeners {
		_ = l.Close()
	}
	g.wg.Wait()
}

func (g *netguard) serve(l net.Listener, handle func(net.Conn)) {
	defer g.wg.Done()
	for {
		conn, err := l.Accept()
		if err != nil {
			if g.closed.Load() {
				return
			}
			netlogf("proxy accept failed: %v", err)
			return
		}
		go handle(conn)
	}
}

// deniedError tells the client that the allowlist refused a target. The
// client is often an agent, which can only read what we send back. So the
// message says what the sandbox allows and how the user adds a target.
type deniedError struct {
	target  string // host:port
	allowed string
}

func (e *deniedError) Error() string {
	return fmt.Sprintf("curimata sandbox: %s is not on the network allowlist. Allowed: %s. "+
		"To reach it, the user must start curimata again with: -allow %s", e.target, e.allowed, e.target)
}

// dial opens the outbound connection, after the allowlist agrees.
//
// This runs on an ordinary thread, which is still in our own network
// namespace. So the connection leaves through the host's network.
func (g *netguard) dial(host string, port int) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	if !g.allow.permits(host, port) {
		netlogf("DENY  %s", target)
		return nil, &deniedError{target: target, allowed: g.allow.String()}
	}
	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		netfilef("FAIL  %s: %v", target, err)
		return nil, err
	}
	netfilef("ALLOW %s", target)
	return conn, nil
}

// splice copies in both directions until either side closes.
func splice(a, b net.Conn) {
	defer a.Close() //nolint:errcheck // closing after the copy
	defer b.Close() //nolint:errcheck // closing after the copy

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); closeWrite(a) }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a); closeWrite(b) }()
	wg.Wait()
}

// closeWrite ends one direction, so the peer sees the end of the stream.
func closeWrite(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

// --- SOCKS5 (RFC 1928) ---------------------------------------------------

const (
	socksVersion   = 0x05
	socksNoAuth    = 0x00
	socksConnect   = 0x01
	socksIPv4      = 0x01
	socksDomain    = 0x03
	socksIPv6      = 0x04
	socksOK        = 0x00
	socksDenied    = 0x02
	socksUnreached = 0x04
	socksBadCmd    = 0x07
)

func (g *netguard) handleSocks(client net.Conn) {
	defer client.Close() //nolint:errcheck // the reply is already written

	_ = client.SetDeadline(time.Now().Add(dialTimeout))
	r := bufio.NewReader(client)

	// Greeting: version, number of methods, methods.
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil || head[0] != socksVersion {
		return
	}
	if _, err := io.ReadFull(r, make([]byte, int(head[1]))); err != nil {
		return
	}
	if _, err := client.Write([]byte{socksVersion, socksNoAuth}); err != nil {
		return
	}

	// Request: version, command, reserved, address type.
	req := make([]byte, 4)
	if _, err := io.ReadFull(r, req); err != nil || req[0] != socksVersion {
		return
	}
	if req[1] != socksConnect {
		socksReply(client, socksBadCmd)
		return
	}

	var host string
	switch req[3] {
	case socksIPv4, socksIPv6:
		size := net.IPv4len
		if req[3] == socksIPv6 {
			size = net.IPv6len
		}
		raw := make([]byte, size)
		if _, err := io.ReadFull(r, raw); err != nil {
			return
		}
		host = net.IP(raw).String()
	case socksDomain:
		size := make([]byte, 1)
		if _, err := io.ReadFull(r, size); err != nil {
			return
		}
		raw := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, raw); err != nil {
			return
		}
		host = string(raw)
	default:
		socksReply(client, socksBadCmd)
		return
	}

	portRaw := make([]byte, 2)
	if _, err := io.ReadFull(r, portRaw); err != nil {
		return
	}
	port := int(portRaw[0])<<8 | int(portRaw[1])

	upstream, err := g.dial(host, port)
	if err != nil {
		// SOCKS has no room for a message, only for a code.
		code := byte(socksUnreached)
		var denied *deniedError
		if errors.As(err, &denied) {
			code = socksDenied
		}
		socksReply(client, code)
		return
	}

	if err := socksReply(client, socksOK); err != nil {
		upstream.Close() //nolint:errcheck // giving up anyway
		return
	}
	_ = client.SetDeadline(time.Time{})

	// Bytes may already sit in the buffer, so drain it before splicing.
	if n := r.Buffered(); n > 0 {
		if _, err := io.CopyN(upstream, r, int64(n)); err != nil {
			upstream.Close() //nolint:errcheck // giving up anyway
			return
		}
	}
	splice(client, upstream)
}

func socksReply(w io.Writer, code byte) error {
	// The bound address is not useful to a CONNECT client, so report 0.0.0.0:0.
	_, err := w.Write([]byte{socksVersion, code, 0x00, socksIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// --- HTTP proxy ----------------------------------------------------------

func (g *netguard) handleHTTP(client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(dialTimeout))
	r := bufio.NewReader(client)

	req, err := http.ReadRequest(r)
	if err != nil {
		client.Close() //nolint:errcheck // nothing to say to a broken client
		return
	}

	if req.Method == http.MethodConnect {
		g.handleConnect(client, r, req)
		return
	}
	g.handlePlainHTTP(client, r, req)
}

// handleConnect serves "CONNECT host:port", which is how a client reaches an
// HTTPS site. We only move bytes, so TLS stays end to end and we never see
// inside it.
func (g *netguard) handleConnect(client net.Conn, r *bufio.Reader, req *http.Request) {
	host, port, err := targetOf(req.Host, 443)
	if err != nil {
		httpError(client, http.StatusBadRequest, err.Error())
		return
	}

	upstream, err := g.dial(host, port)
	if err != nil {
		dialError(client, err)
		return
	}

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		upstream.Close() //nolint:errcheck // giving up anyway
		client.Close()   //nolint:errcheck // giving up anyway
		return
	}
	_ = client.SetDeadline(time.Time{})

	if n := r.Buffered(); n > 0 {
		if _, err := io.CopyN(upstream, r, int64(n)); err != nil {
			upstream.Close() //nolint:errcheck // giving up anyway
			client.Close()   //nolint:errcheck // giving up anyway
			return
		}
	}
	splice(client, upstream)
}

// handlePlainHTTP serves ordinary proxied requests, the form that apt and
// curl use for an http:// address.
//
// A client may send many requests over one connection (keep-alive). We read
// them one at a time, and we check each one against the allowlist, because
// each request names its own host. The connection to the server stays open
// while the requests go to the same host and port.
func (g *netguard) handlePlainHTTP(client net.Conn, clientReader *bufio.Reader, request *http.Request) {
	defer client.Close() //nolint:errcheck // the exchange is over

	var server *serverConn
	defer func() {
		server.close()
	}()

	for {
		keepOpen := g.forwardRequest(client, clientReader, request, &server)
		if !keepOpen {
			return
		}

		// Wait for the next request on the same connection. A client that
		// stays silent too long loses the connection.
		_ = client.SetReadDeadline(time.Now().Add(keepAliveIdleTimeout))
		nextRequest, err := http.ReadRequest(clientReader)
		if err != nil {
			return
		}
		_ = client.SetReadDeadline(time.Time{})

		if nextRequest.Method == http.MethodConnect {
			server.close()
			server = nil
			g.handleConnect(client, clientReader, nextRequest)
			return
		}
		request = nextRequest
	}
}

// keepAliveIdleTimeout is how long a proxy connection may wait between two
// requests.
const keepAliveIdleTimeout = 90 * time.Second

// serverConn is the open connection from the HTTP proxy to one server.
type serverConn struct {
	// target is "host:port", so that the next request can tell whether it
	// may use this connection.
	target string
	conn   net.Conn
	reader *bufio.Reader
}

func (server *serverConn) close() {
	if server != nil {
		_ = server.conn.Close()
	}
}

// forwardRequest sends one request to its server and copies the response
// back to the client. It reports whether the client connection may carry
// another request.
//
// server holds the connection of the previous request. forwardRequest uses
// it again when the target is the same, and replaces it otherwise.
func (g *netguard) forwardRequest(client net.Conn, clientReader *bufio.Reader, request *http.Request, server **serverConn) bool {
	target := request.Host
	scheme := ""
	if request.URL != nil {
		scheme = strings.ToLower(request.URL.Scheme)
		if request.URL.Host != "" {
			target = request.URL.Host
		}
	}

	// A client that wants TLS must ask for CONNECT. If we served an
	// "https://" address here we would have to guess the port, and a rule
	// that allows port 80 would then also open port 443.
	if scheme == "https" {
		netlogf("DENY  %s: https needs CONNECT, not a proxied request", target)
		httpError(client, http.StatusBadRequest,
			"this proxy serves https only through CONNECT; the client sent an absolute https URL")
		return false
	}

	host, port, err := targetOf(target, 80)
	if err != nil {
		httpError(client, http.StatusBadRequest, err.Error())
		return false
	}

	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	if *server == nil || (*server).target != hostPort {
		(*server).close()
		*server = nil
		conn, err := g.dial(host, port)
		if err != nil {
			dialError(client, err)
			return false
		}
		*server = &serverConn{target: hostPort, conn: conn, reader: bufio.NewReader(conn)}
	}
	_ = client.SetDeadline(time.Time{})

	// We answer "Expect: 100-continue" ourselves. Otherwise the client
	// holds the body back until the server agrees, while we wait for the
	// body before we send anything to the server.
	if strings.EqualFold(request.Header.Get("Expect"), "100-continue") {
		request.Header.Del("Expect")
		if _, err := io.WriteString(client, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return false
		}
	}

	// Forward the request as an origin-form request, without the proxy hop.
	request.RequestURI = ""
	if request.URL != nil {
		request.URL.Scheme = ""
		request.URL.Host = ""
	}
	request.Header.Del("Proxy-Connection")
	request.Header.Del("Proxy-Authorization")

	serverWriter := bufio.NewWriter((*server).conn)
	if err := request.Write(serverWriter); err != nil {
		return false
	}
	if err := serverWriter.Flush(); err != nil {
		return false
	}

	response, err := http.ReadResponse((*server).reader, request)
	if err != nil {
		httpError(client, http.StatusBadGateway, "read response: "+err.Error())
		return false
	}

	// Pass on interim responses such as "103 Early Hints" and wait for the
	// final one.
	for response.StatusCode >= 100 && response.StatusCode < 200 &&
		response.StatusCode != http.StatusSwitchingProtocols {
		if err := response.Write(client); err != nil {
			return false
		}
		response, err = http.ReadResponse((*server).reader, request)
		if err != nil {
			return false
		}
	}
	defer response.Body.Close() //nolint:errcheck // Write has read it to the end

	clientWriter := bufio.NewWriter(client)
	if err := response.Write(clientWriter); err != nil {
		return false
	}
	if err := clientWriter.Flush(); err != nil {
		return false
	}

	// After "101 Switching Protocols" the connection is no longer HTTP, for
	// example a WebSocket. Move the bytes as they are, in both directions.
	if response.StatusCode == http.StatusSwitchingProtocols {
		if !copyBuffered(client, (*server).reader) || !copyBuffered((*server).conn, clientReader) {
			return false
		}
		splice(client, (*server).conn)
		*server = nil
		return false
	}

	return !request.Close && !response.Close
}

// copyBuffered writes the bytes that already sit in reader to destination.
func copyBuffered(destination io.Writer, reader *bufio.Reader) bool {
	bufferedBytes := reader.Buffered()
	if bufferedBytes == 0 {
		return true
	}
	_, err := io.CopyN(destination, reader, int64(bufferedBytes))
	return err == nil
}

// targetOf splits "host" or "host:port" and applies a default port.
func targetOf(target string, fallback int) (string, int, error) {
	if target == "" {
		return "", 0, errors.New("no target host")
	}
	host, portText, ok := splitHostPort(target)
	if !ok {
		return canonicalHost(target), fallback, nil
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("bad port in %q", target)
	}
	return canonicalHost(host), port, nil
}

func httpError(w io.WriteCloser, code int, message string) {
	writeHTTPError(w, code, http.StatusText(code), "", message)
}

// dialError answers a request whose target we could not reach.
//
// Many clients never show the body of a failed CONNECT; curl, for one,
// reports only the status code. Python and Go show the reason phrase, so a
// refusal names the target there as well. The Proxy-Status header (RFC 9209)
// carries the full message for clients that read headers.
func dialError(w io.WriteCloser, err error) {
	var denied *deniedError
	if !errors.As(err, &denied) {
		writeHTTPError(w, http.StatusBadGateway, http.StatusText(http.StatusBadGateway), "", err.Error())
		return
	}
	proxyStatus := "curimata; error=http_request_denied; details=" + strconv.Quote(denied.Error())
	writeHTTPError(w, http.StatusForbidden, "Blocked by curimata allowlist: "+denied.target, proxyStatus, denied.Error())
}

func writeHTTPError(w io.WriteCloser, code int, reason, proxyStatus, message string) {
	header := ""
	if proxyStatus != "" {
		header = "Proxy-Status: " + proxyStatus + "\r\n"
	}
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n%sContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s\n",
		code, reason, header, len(message)+1, message)
	w.Close() //nolint:errcheck // the message is already out
}
