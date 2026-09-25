package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

func TestInstallBox(t *testing.T) {
	imageRootfs := t.TempDir()
	if err := os.WriteFile(filepath.Join(imageRootfs, "hello"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "box1")
	imageFile := filepath.Join(directory, "image")

	rootfs, err := installBox("box1", directory, imageRootfs, "img")
	if err != nil {
		t.Fatal(err)
	}
	if rootfs != filepath.Join(directory, "rootfs") {
		t.Errorf("rootfs = %q", rootfs)
	}
	if _, err := os.Stat(filepath.Join(rootfs, "hello")); err != nil {
		t.Errorf("box misses the image's file: %v", err)
	}
	if recorded, err := os.ReadFile(imageFile); err != nil || string(recorded) != "img\n" {
		t.Errorf("image record = %q, %v; want \"img\\n\"", recorded, err)
	}

	// A second install must neither replace the box nor its record.
	if _, err := installBox("box1", directory, imageRootfs, "other"); err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Fatalf("second install: got %v, want an \"exists already\" error", err)
	}
	if recorded, _ := os.ReadFile(imageFile); string(recorded) != "img\n" {
		t.Errorf("second install changed the record to %q", recorded)
	}
	leftovers, err := filepath.Glob(filepath.Join(directory, "rootfs.tmp-*"))
	if err != nil || len(leftovers) != 0 {
		t.Errorf("temporary directories left behind: %v, %v", leftovers, err)
	}
}

func TestPrepareBoxExistingImageCheck(t *testing.T) {
	tests := []struct {
		name        string
		record      string // "" writes no record
		image       string
		imageChosen bool
		wantErr     string // "" means success
	}{
		{"different image", "a", "b", true, "was made from"},
		{"no record, image chosen", "", "b", true, "no image record"},
		{"no record, default image", "", "b", false, ""},
		{"same image", "a", "a", true, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			directory, err := boxDir("box1")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(directory, "rootfs"), 0o700); err != nil {
				t.Fatal(err)
			}
			if test.record != "" {
				if err := os.WriteFile(filepath.Join(directory, "image"), []byte(test.record+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			// repull is false, so an existing box needs no network.
			rootfs, err := prepareBox("box1", test.image, test.imageChosen, false)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if rootfs != filepath.Join(directory, "rootfs") {
					t.Errorf("rootfs = %q", rootfs)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("got %v, want an error containing %q", err, test.wantErr)
			}
		})
	}
}
