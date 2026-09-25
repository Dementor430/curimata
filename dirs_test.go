package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestXDGDir(t *testing.T) {
	for _, test := range []struct{ value, want string }{
		{"", ""},
		{"/abs/path", "/abs/path"},
		{"relative/path", ""},
	} {
		t.Setenv("XDG_TEST_DIR", test.value)
		if got := xdgDir("XDG_TEST_DIR"); got != test.want {
			t.Errorf("xdgDir with %q: got %q, want %q", test.value, got, test.want)
		}
	}
}

func TestDataPathIgnoresRelative(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	t.Setenv("XDG_DATA_HOME", "relative")
	got, err := dataPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".local", "share", "curimata"); got != want {
		t.Errorf("relative XDG_DATA_HOME: got %q, want %q", got, want)
	}

	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	got, err = dataPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dataHome, "curimata"); got != want {
		t.Errorf("absolute XDG_DATA_HOME: got %q, want %q", got, want)
	}
}

func TestStateDirUsesRuntimeDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir+"/")

	got, err := stateDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(runtimeDir, "curimata"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	info, err := os.Stat(got)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("mode %04o, want 0700", mode)
	}
}

func TestStateDirRefusesOverlap(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T) (runtimeDir, dataHome string)
	}{
		{"same path", func(t *testing.T) (string, string) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			return filepath.Join(home, ".local", "share"), ""
		}},
		{"data inside state", func(t *testing.T) (string, string) {
			runtimeDir := t.TempDir()
			return runtimeDir, filepath.Join(runtimeDir, "curimata")
		}},
		{"state inside data", func(t *testing.T) (string, string) {
			dataHome := t.TempDir()
			return filepath.Join(dataHome, "curimata", "x"), dataHome
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			runtimeDir, dataHome := test.setup(t)
			t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
			t.Setenv("XDG_DATA_HOME", dataHome)

			if _, err := stateDir(); err == nil || !strings.Contains(err.Error(), "overlap") {
				t.Fatalf("got %v, want an \"overlap\" error", err)
			}
			if _, err := os.Lstat(filepath.Join(runtimeDir, "curimata")); !os.IsNotExist(err) {
				t.Errorf("state directory was created: %v", err)
			}
		})
	}
}

func TestFallbackRuntimeDir(t *testing.T) {
	uid := os.Getuid()
	private := func(t *testing.T, path string) {
		t.Helper()
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name       string
		setup      func(t *testing.T, userDirectory, tempDirectory string)
		wantInTemp bool
		wantError  string
	}{
		{"private user directory", func(t *testing.T, userDirectory, _ string) {
			private(t, userDirectory)
		}, false, ""},
		{"missing user directory", func(*testing.T, string, string) {}, true, ""},
		{"open user directory", func(t *testing.T, userDirectory, _ string) {
			if err := os.Mkdir(userDirectory, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(userDirectory, 0o755); err != nil {
				t.Fatal(err)
			}
		}, true, ""},
		{"user directory is a symlink", func(t *testing.T, userDirectory, _ string) {
			target := filepath.Join(t.TempDir(), "target")
			private(t, target)
			if err := os.Symlink(target, userDirectory); err != nil {
				t.Fatal(err)
			}
		}, true, ""},
		{"existing temp directory", func(t *testing.T, _, tempDirectory string) {
			private(t, tempDirectory)
		}, true, ""},
		{"temp directory is a symlink", func(t *testing.T, _, tempDirectory string) {
			target := filepath.Join(t.TempDir(), "target")
			private(t, target)
			if err := os.Symlink(target, tempDirectory); err != nil {
				t.Fatal(err)
			}
		}, false, "unsafe runtime directory"},
		{"open temp directory", func(t *testing.T, _, tempDirectory string) {
			if err := os.Mkdir(tempDirectory, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(tempDirectory, 0o755); err != nil {
				t.Fatal(err)
			}
		}, false, "open to other users"},
		{"temp path is a file", func(t *testing.T, _, tempDirectory string) {
			if err := os.WriteFile(tempDirectory, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, false, "not a directory"},
	} {
		t.Run(test.name, func(t *testing.T) {
			userRoot, tempRoot := t.TempDir(), t.TempDir()
			userDirectory := filepath.Join(userRoot, strconv.Itoa(uid))
			tempDirectory := filepath.Join(tempRoot, "curimata-"+strconv.Itoa(uid))
			test.setup(t, userDirectory, tempDirectory)

			// Twice: the second call finds the directory of the first.
			for range 2 {
				got, inTemp, err := fallbackRuntimeDir(userRoot, tempRoot, uid)
				if test.wantError != "" {
					if err == nil || !strings.Contains(err.Error(), test.wantError) {
						t.Fatalf("got %v, want an error with %q", err, test.wantError)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				want := userDirectory
				if test.wantInTemp {
					want = tempDirectory
				}
				if got != want || inTemp != test.wantInTemp {
					t.Fatalf("got (%q, %v), want (%q, %v)", got, inTemp, want, test.wantInTemp)
				}
				info, err := os.Lstat(got)
				if err != nil {
					t.Fatal(err)
				}
				if !info.IsDir() || info.Mode().Perm() != 0o700 {
					t.Errorf("%s: mode %v, want a directory with 0700", got, info.Mode())
				}
			}
		})
	}
}

func TestOverlaps(t *testing.T) {
	for _, test := range []struct {
		first, second string
		want          bool
	}{
		{"/a", "/a", true},
		{"/a/b", "/a", true},
		{"/a", "/a/b", true},
		{"/a/b", "/a/bc", false},
		{"/a/", "/a", true},
	} {
		if got := overlaps(test.first, test.second); got != test.want {
			t.Errorf("overlaps(%q, %q) = %v, want %v", test.first, test.second, got, test.want)
		}
	}
}
