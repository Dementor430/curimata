package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startTestProxy starts a netguard whose allowlist permits only the given
// test server. It returns a function that opens a client connection to the
// HTTP proxy, and the number of TCP connections the server has accepted.
func startTestProxy(t *testing.T, handler http.HandlerFunc) (dialProxy func() net.Conn, serverHost string, serverConnections *atomic.Int32) {
	t.Helper()

	serverConnections = &atomic.Int32{}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			serverConnections.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)
	serverHost = strings.TrimPrefix(server.URL, "http://")

	allow, err := parseAllowlist([]string{serverHost})
	if err != nil {
		t.Fatal(err)
	}

	var listeners []net.Listener
	for range 2 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
	}
	guard := startNetguard(listeners, allow)
	t.Cleanup(guard.close)

	dialProxy = func() net.Conn {
		conn, err := net.Dial("tcp", listeners[1].Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = conn.Close()
		})
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		return conn
	}
	return dialProxy, serverHost, serverConnections
}

// sendRequest writes one proxied request and reads the response.
func sendRequest(t *testing.T, conn net.Conn, reader *bufio.Reader, rawRequest string) (*http.Response, string) {
	t.Helper()
	if _, err := io.WriteString(conn, rawRequest); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return response, string(body)
}

func TestPlainHTTPKeepAlive(t *testing.T) {
	dialProxy, serverHost, serverConnections := startTestProxy(t, func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "path="+request.URL.Path)
	})
	conn := dialProxy()
	reader := bufio.NewReader(conn)

	for _, path := range []string{"/first", "/second", "/third"} {
		rawRequest := "GET http://" + serverHost + path + " HTTP/1.1\r\nHost: " + serverHost + "\r\n\r\n"
		response, body := sendRequest(t, conn, reader, rawRequest)
		if response.StatusCode != http.StatusOK || body != "path="+path {
			t.Fatalf("%s: got %d %q", path, response.StatusCode, body)
		}
	}
	if count := serverConnections.Load(); count != 1 {
		t.Errorf("server saw %d connections, want 1", count)
	}
}

func TestPlainHTTPChecksEveryRequest(t *testing.T) {
	dialProxy, serverHost, _ := startTestProxy(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	})
	conn := dialProxy()
	reader := bufio.NewReader(conn)

	allowed := "GET http://" + serverHost + "/ HTTP/1.1\r\nHost: " + serverHost + "\r\n\r\n"
	if response, _ := sendRequest(t, conn, reader, allowed); response.StatusCode != http.StatusOK {
		t.Fatalf("allowed request: got %d", response.StatusCode)
	}

	// The second request on the same connection names a host that the
	// allowlist does not hold.
	_, port, _ := net.SplitHostPort(serverHost)
	deniedHost := "denied.example:" + port
	denied := "GET http://" + deniedHost + "/ HTTP/1.1\r\nHost: " + deniedHost + "\r\n\r\n"
	if response, _ := sendRequest(t, conn, reader, denied); response.StatusCode != http.StatusForbidden {
		t.Fatalf("denied request: got %d, want 403", response.StatusCode)
	}
}

func TestPlainHTTPConnectionClose(t *testing.T) {
	dialProxy, serverHost, _ := startTestProxy(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	})
	conn := dialProxy()
	reader := bufio.NewReader(conn)

	rawRequest := "GET http://" + serverHost + "/ HTTP/1.1\r\nHost: " + serverHost + "\r\nConnection: close\r\n\r\n"
	if response, body := sendRequest(t, conn, reader, rawRequest); body != "ok" {
		t.Fatalf("got %d %q", response.StatusCode, body)
	}

	// The proxy must close the connection now. Before the fix it waited
	// for the client to close first, and both sides hung.
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("connection still open after Connection: close (err=%v)", err)
	}
}

func TestPlainHTTPExpectContinue(t *testing.T) {
	dialProxy, serverHost, _ := startTestProxy(t, func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		_, _ = io.WriteString(writer, "got="+string(body))
	})
	conn := dialProxy()
	reader := bufio.NewReader(conn)

	head := "POST http://" + serverHost + "/ HTTP/1.1\r\nHost: " + serverHost +
		"\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatal(err)
	}
	// A real client holds the body back until it sees "100 Continue".
	interim, err := http.ReadResponse(reader, nil)
	if err != nil || interim.StatusCode != http.StatusContinue {
		t.Fatalf("want 100 Continue, got %v %v", interim, err)
	}
	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if string(body) != "got=hello" {
		t.Fatalf("got %d %q", response.StatusCode, body)
	}
}

// A refused CONNECT must tell the client, which is often an agent, what the
// sandbox allows and how the user adds the target.
func TestConnectDeniedExplains(t *testing.T) {
	dialProxy, serverHost, _ := startTestProxy(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	})
	conn := dialProxy()
	reader := bufio.NewReader(conn)

	rawRequest := "CONNECT wttr.in:443 HTTP/1.1\r\nHost: wttr.in:443\r\n\r\n"
	response, body := sendRequest(t, conn, reader, rawRequest)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403", response.StatusCode)
	}
	if want := "403 Blocked by curimata allowlist: wttr.in:443"; response.Status != want {
		t.Errorf("status %q, want %q", response.Status, want)
	}
	for _, part := range []string{"wttr.in:443 is not on the network allowlist", "Allowed: " + serverHost, "-allow wttr.in:443"} {
		if !strings.Contains(body, part) {
			t.Errorf("body %q lacks %q", body, part)
		}
		if !strings.Contains(response.Header.Get("Proxy-Status"), part) {
			t.Errorf("Proxy-Status %q lacks %q", response.Header.Get("Proxy-Status"), part)
		}
	}
}
