package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"golang.org/x/sys/unix"
)

// defaultImage is the image that run uses when you give it no rootfs.
const defaultImage = "debian:stable-slim"

// Media types that a registry may answer with. We send all of them in the
// Accept header, because a registry gives us the OCI or the Docker variant
// depending on how the image was pushed.
var manifestTypes = []string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}

// pullRootfs makes sure that an extracted root filesystem for ref exists on
// disk, and returns its path. It downloads the image only when the cached
// copy is missing or out of date.
func pullRootfs(ref string, force bool) (string, error) {
	img, err := parseRef(ref)
	if err != nil {
		return "", err
	}

	base, err := imageCacheDir(img)
	if err != nil {
		return "", err
	}
	rootfs := filepath.Join(base, "rootfs")
	stamp := filepath.Join(base, "digest")

	client := &registryClient{http: &http.Client{Timeout: 10 * time.Minute}}

	body, digest, err := client.manifest(img, img.tag)
	if err != nil {
		// Work offline when we already hold a copy.
		if cached, readErr := os.ReadFile(stamp); readErr == nil {
			fmt.Fprintf(os.Stderr, "curimata: cannot reach registry (%v); using cached %s\n", err, strings.TrimSpace(string(cached)))
			return rootfs, nil
		}
		return "", err
	}

	if !force {
		if cached, err := os.ReadFile(stamp); err == nil && strings.TrimSpace(string(cached)) == digest {
			if info, err := os.Stat(rootfs); err == nil && info.IsDir() {
				return rootfs, nil
			}
		}
	}

	layers, err := client.layers(img, body)
	if err != nil {
		return "", err
	}

	fmt.Fprintf(os.Stderr, "curimata: pulling %s (%d layer(s))\n", ref, len(layers))

	// Extract beside the final directory, then swap it in. A failed pull
	// then never leaves a half-written rootfs behind.
	tmp := rootfs + ".tmp"
	if err := removeTree(tmp); err != nil {
		return "", fmt.Errorf("clear %s: %w", tmp, err)
	}
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", tmp, err)
	}

	for i, layer := range layers {
		fmt.Fprintf(os.Stderr, "curimata: layer %d/%d (%s)\n", i+1, len(layers), humanBytes(layer.Size))
		if err := client.extractLayer(img, layer, tmp); err != nil {
			_ = removeTree(tmp)
			return "", fmt.Errorf("layer %d: %w", i+1, err)
		}
	}

	// An older curimata let containers write into the cache, so the old
	// rootfs may hold files of subordinate IDs. removeTree handles those.
	if err := removeTree(rootfs); err != nil {
		return "", fmt.Errorf("remove old rootfs: %w", err)
	}
	if err := os.Rename(tmp, rootfs); err != nil {
		return "", fmt.Errorf("install rootfs: %w", err)
	}
	if err := os.WriteFile(stamp, []byte(digest+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write digest: %w", err)
	}

	fmt.Fprintf(os.Stderr, "curimata: %s ready at %s\n", ref, rootfs)
	return rootfs, nil
}

// imageRef names one image in one registry.
type imageRef struct {
	registry string
	repo     string
	tag      string
}

func (r imageRef) String() string { return r.registry + "/" + r.repo + ":" + r.tag }

// parseRef reads a reference such as "debian", "debian:13" or
// "ghcr.io/user/image:tag".
func parseRef(s string) (imageRef, error) {
	if s == "" {
		return imageRef{}, errors.New("empty image reference")
	}
	if strings.Contains(s, "@") {
		return imageRef{}, fmt.Errorf("digest references are not supported: %q", s)
	}

	img := imageRef{registry: "registry-1.docker.io", tag: "latest"}

	name := s
	// A first component with a dot, a port, or the name "localhost" is a
	// registry host. Everything else belongs to the repository name.
	if i := strings.Index(s, "/"); i > 0 {
		head := s[:i]
		if strings.ContainsAny(head, ".:") || head == "localhost" {
			img.registry = head
			name = s[i+1:]
		}
	}
	if i := strings.LastIndex(name, ":"); i > 0 {
		img.tag = name[i+1:]
		name = name[:i]
	}
	if name == "" {
		return imageRef{}, fmt.Errorf("invalid image reference: %q", s)
	}
	// Docker Hub keeps the official images below "library".
	if img.registry == "registry-1.docker.io" && !strings.Contains(name, "/") {
		name = "library/" + name
	}
	img.repo = name
	return img, nil
}

func imageCacheDir(img imageRef) (string, error) {
	base, err := dataDir()
	if err != nil {
		return "", err
	}
	// Tags may hold no path separator, so the repository name is the only
	// part that needs flattening.
	dir := filepath.Join(base, "images", img.registry, filepath.FromSlash(img.repo), img.tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create image cache directory: %w", err)
	}
	return dir, nil
}

// registryClient speaks the OCI distribution protocol.
type registryClient struct {
	http   *http.Client
	tokens map[string]string
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		Variant      string `json:"variant"`
	} `json:"platform"`
}

type manifestDoc struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
	Layers    []descriptor `json:"layers"`
}

// get performs an authenticated GET. On the registry's authentication
// challenge it fetches an anonymous bearer token and repeats the request.
func (c *registryClient) get(img imageRef, path string, accept []string) (*http.Response, error) {
	url := "https://" + img.registry + "/v2/" + img.repo + path

	do := func() (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		for _, a := range accept {
			req.Header.Add("Accept", a)
		}
		if tok := c.tokens[img.repo]; tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		return c.http.Do(req)
	}

	resp, err := do()
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("Www-Authenticate")
		resp.Body.Close()
		if err := c.authenticate(img, challenge); err != nil {
			return nil, err
		}
		if resp, err = do(); err != nil {
			return nil, fmt.Errorf("GET %s: %w", url, err)
		}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
	}
	return resp, nil
}

// authenticate reads a "Bearer realm=...,service=...,scope=..." challenge and
// fetches the matching anonymous token.
func (c *registryClient) authenticate(img imageRef, challenge string) error {
	rest, ok := strings.CutPrefix(challenge, "Bearer ")
	if !ok {
		return fmt.Errorf("registry %s asks for unsupported authentication: %q", img.registry, challenge)
	}

	params := map[string]string{}
	for _, part := range splitChallenge(rest) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		params[strings.TrimSpace(k)] = strings.Trim(v, `"`)
	}
	realm := params["realm"]
	if realm == "" {
		return fmt.Errorf("registry %s gave no token realm", img.registry)
	}
	if params["scope"] == "" {
		params["scope"] = "repository:" + img.repo + ":pull"
	}

	req, err := http.NewRequest(http.MethodGet, realm, nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	for _, k := range []string{"service", "scope"} {
		if params[k] != "" {
			q.Set(k, params[k])
		}
	}
	req.URL.RawQuery = q.Encode()

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("get registry token: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read only
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("get registry token: %s", resp.Status)
	}

	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return fmt.Errorf("decode registry token: %w", err)
	}
	value := tok.Token
	if value == "" {
		value = tok.AccessToken
	}
	if value == "" {
		return errors.New("registry returned an empty token")
	}
	if c.tokens == nil {
		c.tokens = map[string]string{}
	}
	c.tokens[img.repo] = value
	return nil
}

// splitChallenge splits on commas that sit outside quotes.
func splitChallenge(s string) []string {
	var parts []string
	var start, quotes int
	for i, r := range s {
		switch r {
		case '"':
			quotes++
		case ',':
			if quotes%2 == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, s[start:])
}

// manifest fetches a manifest and returns its body and its digest.
func (c *registryClient) manifest(img imageRef, reference string) ([]byte, string, error) {
	resp, err := c.get(img, "/manifests/"+reference, manifestTypes)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close() //nolint:errcheck // read only

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, "", fmt.Errorf("read manifest: %w", err)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		sum := sha256.Sum256(body)
		digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	return body, digest, nil
}

// layers resolves a manifest to the layer list for this machine's
// architecture. It follows an index one level down.
func (c *registryClient) layers(img imageRef, body []byte) ([]descriptor, error) {
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}

	if len(doc.Manifests) > 0 {
		want := runtime.GOARCH
		var chosen string
		var have []string
		for _, m := range doc.Manifests {
			if m.Platform == nil || m.Platform.OS != "linux" {
				continue
			}
			have = append(have, m.Platform.Architecture)
			if m.Platform.Architecture == want {
				chosen = m.Digest
				break
			}
		}
		if chosen == "" {
			return nil, fmt.Errorf("image %s has no linux/%s build; it offers %s", img, want, strings.Join(have, ", "))
		}
		sub, _, err := c.manifest(img, chosen)
		if err != nil {
			return nil, err
		}
		doc = manifestDoc{}
		if err := json.Unmarshal(sub, &doc); err != nil {
			return nil, fmt.Errorf("decode image manifest: %w", err)
		}
	}

	if len(doc.Layers) == 0 {
		return nil, fmt.Errorf("image %s has no layers", img)
	}
	return doc.Layers, nil
}

// extractLayer downloads one layer and unpacks it over dir.
func (c *registryClient) extractLayer(img imageRef, layer descriptor, dir string) error {
	switch {
	case strings.Contains(layer.MediaType, "zstd"):
		return fmt.Errorf("zstd layers are not supported (%s)", layer.MediaType)
	case strings.Contains(layer.MediaType, "foreign"):
		return fmt.Errorf("foreign layers are not supported (%s)", layer.MediaType)
	}

	resp, err := c.get(img, "/blobs/"+layer.Digest, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // read only

	// Hash the bytes as they arrive, so we can reject a corrupted download.
	hasher := sha256.New()
	var reader io.Reader = io.TeeReader(resp.Body, hasher)

	if strings.Contains(layer.MediaType, "gzip") || layer.MediaType == "" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return fmt.Errorf("open gzip stream: %w", err)
		}
		defer gz.Close() //nolint:errcheck // read only
		reader = gz
	}

	if err := untar(reader, dir); err != nil {
		return err
	}
	// Drain any trailing bytes so that the digest covers the whole blob.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("read rest of layer: %w", err)
	}

	got := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(got, layer.Digest) {
		return fmt.Errorf("layer digest mismatch: got %s, want %s", got, layer.Digest)
	}
	return nil
}

// untar unpacks a layer tar stream below dir.
//
// We run unprivileged, so this deliberately does less than a root-owned
// unpack: it sets no ownership, and it skips device nodes. The user
// namespace maps our own ID to container root, so the extracted files
// already belong to root inside the container.
func untar(r io.Reader, dir string) error {
	// Directory modes are applied last. A directory may arrive read-only
	// before its own contents do.
	type dirMode struct {
		path string
		mode os.FileMode
	}
	var dirModes []dirMode

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		if hdr.Name == "" || strings.HasPrefix(filepath.Base(hdr.Name), ".wh..wh.") {
			// An opaque whiteout marker. It only matters when a later
			// layer must hide an earlier one entirely.
			if filepath.Base(hdr.Name) == ".wh..wh..opq" {
				if err := clearDir(dir, filepath.Dir(hdr.Name)); err != nil {
					return err
				}
			}
			continue
		}

		target, err := joinInside(dir, hdr.Name)
		if err != nil {
			return fmt.Errorf("resolve %q: %w", hdr.Name, err)
		}

		// A whiteout entry deletes the file of the same name.
		if base := filepath.Base(hdr.Name); strings.HasPrefix(base, ".wh.") {
			victim := filepath.Join(filepath.Dir(target), strings.TrimPrefix(base, ".wh."))
			if err := os.RemoveAll(victim); err != nil {
				return fmt.Errorf("apply whiteout %q: %w", hdr.Name, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("create parent of %q: %w", hdr.Name, err)
		}
		mode := hdr.FileInfo().Mode()

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := makeRealDir(target); err != nil {
				return fmt.Errorf("create directory %q: %w", hdr.Name, err)
			}
			dirModes = append(dirModes, dirMode{target, mode.Perm()})

		case tar.TypeReg:
			if err := writeFile(target, tr, mode.Perm()); err != nil {
				return fmt.Errorf("write %q: %w", hdr.Name, err)
			}

		case tar.TypeSymlink:
			if err := os.RemoveAll(target); err != nil {
				return fmt.Errorf("replace %q: %w", hdr.Name, err)
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("link %q: %w", hdr.Name, err)
			}

		case tar.TypeLink:
			// A hard link must point at the file itself, so the last
			// component stays unresolved here too.
			source, err := joinInside(dir, hdr.Linkname)
			if err != nil {
				return fmt.Errorf("resolve hard link %q: %w", hdr.Linkname, err)
			}
			if err := os.RemoveAll(target); err != nil {
				return fmt.Errorf("replace %q: %w", hdr.Name, err)
			}
			if err := os.Link(source, target); err != nil {
				return fmt.Errorf("hard link %q: %w", hdr.Name, err)
			}

		case tar.TypeFifo:
			if err := os.RemoveAll(target); err != nil {
				return fmt.Errorf("replace %q: %w", hdr.Name, err)
			}
			if err := unix.Mkfifo(target, uint32(mode.Perm())); err != nil {
				return fmt.Errorf("create fifo %q: %w", hdr.Name, err)
			}

		case tar.TypeChar, tar.TypeBlock:
			// Only real root may call mknod. The container gets its device
			// nodes from the Devices list in the container config instead.
			continue

		default:
			continue
		}
	}

	for i := len(dirModes) - 1; i >= 0; i-- {
		// A later entry may have replaced the directory with a symlink, and
		// Chmod follows symlinks. Only a real directory gets its mode.
		info, err := os.Lstat(dirModes[i].path)
		if err != nil || !info.IsDir() {
			continue
		}
		if err := os.Chmod(dirModes[i].path, dirModes[i].mode); err != nil {
			return fmt.Errorf("set mode of %q: %w", dirModes[i].path, err)
		}
	}
	return nil
}

// joinInside resolves a tar entry name below dir, without following a
// symlink in the last component.
//
// SecureJoin resolves every component, including the last one. That is wrong
// for extraction: a tar entry replaces the name itself, and a name may point
// at a dangling or looping symlink that an earlier layer left behind. So we
// resolve only the parent directory. The last component may then still be a
// symlink that points outside dir, so a caller that follows it (MkdirAll,
// Chmod, Stat) must check it with Lstat first. See makeRealDir.
func joinInside(dir, name string) (string, error) {
	clean := filepath.Clean(string(filepath.Separator) + filepath.FromSlash(name))
	parent, base := filepath.Split(clean)

	resolved, err := securejoin.SecureJoin(dir, parent)
	if err != nil {
		return "", err
	}
	if base == "" || base == "." {
		return resolved, nil
	}
	return filepath.Join(resolved, base), nil
}

// makeRealDir makes sure that path is a real directory, not a symlink.
//
// os.MkdirAll follows a symlink in the last component. A crafted image could
// plant "x -> /home/user" and then send a directory entry "x", and a later
// Chmod would then change the user's home directory. So a symlink or a file
// at path is removed first.
func makeRealDir(path string) error {
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.IsDir():
		return nil
	case err == nil:
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	case !os.IsNotExist(err):
		return err
	}
	return os.Mkdir(path, 0o755)
}

func writeFile(path string, r io.Reader, mode os.FileMode) error {
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close() //nolint:errcheck // the copy error is the useful one
		return err
	}
	return f.Close()
}

// clearDir empties one directory, for an opaque whiteout.
func clearDir(root, rel string) error {
	target, err := securejoin.SecureJoin(root, rel)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(target, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
