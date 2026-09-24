package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCopyTreeKeepsFileTypesAndModes(t *testing.T) {
	source := t.TempDir()
	outside := t.TempDir()
	mustWrite := func(path, content string, mode fs.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(source, path), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(source, path), mode); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Mkdir(filepath.Join(source, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(source, "tmp"), 0o777|fs.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "readonly"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite("readonly/file", "inside a read-only directory", 0o644)
	if err := os.Chmod(filepath.Join(source, "readonly"), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(source, "readonly"), 0o755)
	})
	mustWrite("script", "#!/bin/sh\n", 0o755)
	if err := os.Link(filepath.Join(source, "script"), filepath.Join(source, "hardlink")); err != nil {
		t.Fatal(err)
	}
	// A symlink that points outside must be copied as a link, never followed.
	if err := os.Symlink(outside, filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(source, "script"), oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	destination := t.TempDir()
	if err := copyTree(source, destination); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(destination, "readonly"), 0o755)
	})

	checks := []struct {
		path string
		mode fs.FileMode
	}{
		{"tmp", fs.ModeDir | fs.ModeSticky | 0o777},
		{"readonly", fs.ModeDir | 0o555},
		{"readonly/file", 0o644},
		{"script", 0o755},
	}
	for _, check := range checks {
		info, err := os.Lstat(filepath.Join(destination, check.path))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode() != check.mode {
			t.Errorf("%s: mode %v, want %v", check.path, info.Mode(), check.mode)
		}
	}

	scriptInfo, _ := os.Lstat(filepath.Join(destination, "script"))
	if !scriptInfo.ModTime().Equal(oldTime) {
		t.Errorf("script: modification time %v, want %v", scriptInfo.ModTime(), oldTime)
	}
	hardlinkInfo, _ := os.Lstat(filepath.Join(destination, "hardlink"))
	if scriptInfo.Sys().(*syscall.Stat_t).Ino != hardlinkInfo.Sys().(*syscall.Stat_t).Ino {
		t.Error("hardlink: not the same inode as script")
	}
	linkTarget, err := os.Readlink(filepath.Join(destination, "escape"))
	if err != nil || linkTarget != outside {
		t.Errorf("escape: got link %q (err %v), want %q", linkTarget, err, outside)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("copyTree wrote %d entries outside the destination", len(entries))
	}
}

func TestValidateBoxName(t *testing.T) {
	for _, name := range []string{"box1", "my-agent", "agent_2.dev", "A"} {
		if err := validateBoxName(name); err != nil {
			t.Errorf("%q: unexpected error %v", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", "../x", "a/b", "-flag", ".hidden", "with space"} {
		if err := validateBoxName(name); err == nil {
			t.Errorf("%q: accepted, want an error", name)
		}
	}
}
