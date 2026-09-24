package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// buildTar writes the given headers into one tar stream, without content.
func buildTar(t *testing.T, headers ...*tar.Header) *bytes.Buffer {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, header := range headers {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return &buffer
}

// newRootfs returns an empty extraction directory, and a directory outside
// it that stands in for the user's home directory.
func newRootfs(t *testing.T) (rootfs, outside string) {
	t.Helper()
	rootfs = filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	outside = t.TempDir()
	if err := os.Chmod(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	return rootfs, outside
}

func assertModeUnchanged(t *testing.T, outside string) {
	t.Helper()
	info, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Fatalf("directory outside the rootfs changed to %v, want -rwx------", mode)
	}
}

// A symlink that an earlier entry planted must not let a later directory
// entry change a directory outside the rootfs.
func TestUntarDirectoryOverSymlinkStaysInside(t *testing.T) {
	rootfs, outside := newRootfs(t)
	layer := buildTar(t,
		&tar.Header{Name: "x", Typeflag: tar.TypeSymlink, Linkname: outside},
		&tar.Header{Name: "x/", Typeflag: tar.TypeDir, Mode: 0o777},
	)
	if err := untar(layer, rootfs); err != nil {
		t.Fatalf("untar: %v", err)
	}
	assertModeUnchanged(t, outside)

	info, err := os.Lstat(filepath.Join(rootfs, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("x is %v, want a real directory", info.Mode())
	}
}

// The same attack over two layers: the first layer plants the symlink.
func TestUntarDirectoryOverSymlinkFromEarlierLayer(t *testing.T) {
	rootfs, outside := newRootfs(t)
	firstLayer := buildTar(t, &tar.Header{Name: "x", Typeflag: tar.TypeSymlink, Linkname: outside})
	secondLayer := buildTar(t, &tar.Header{Name: "x", Typeflag: tar.TypeDir, Mode: 0o777})
	for _, layer := range []*bytes.Buffer{firstLayer, secondLayer} {
		if err := untar(layer, rootfs); err != nil {
			t.Fatalf("untar: %v", err)
		}
	}
	assertModeUnchanged(t, outside)
}

// A directory that a later entry replaces with a symlink must not get its
// deferred mode through that symlink.
func TestUntarDeferredModeSkipsReplacedDirectory(t *testing.T) {
	rootfs, outside := newRootfs(t)
	layer := buildTar(t,
		&tar.Header{Name: "x/", Typeflag: tar.TypeDir, Mode: 0o777},
		&tar.Header{Name: "x", Typeflag: tar.TypeSymlink, Linkname: outside},
	)
	if err := untar(layer, rootfs); err != nil {
		t.Fatalf("untar: %v", err)
	}
	assertModeUnchanged(t, outside)
}
