package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// flock locks per open file, so two lockBox calls in one process contend
// just as two curimata processes do.
func TestLockBox(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	first, err := lockBox("box1")
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if second, err := lockBox("box1"); err == nil || !strings.Contains(err.Error(), "in use") {
		if second != nil {
			second.Close() //nolint:errcheck // test cleanup
		}
		t.Fatalf("second lock of the same name: got %v, want an \"in use\" error", err)
	}

	other, err := lockBox("box2")
	if err != nil {
		t.Fatalf("lock of another name: %v", err)
	}
	other.Close() //nolint:errcheck // test cleanup

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := lockBox("box1")
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again.Close() //nolint:errcheck // test cleanup
}

func TestRemoveBoxesRefusesLockedBox(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	directory, err := boxDir("box1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(directory, "rootfs"), 0o700); err != nil {
		t.Fatal(err)
	}

	boxLock, err := lockBox("box1")
	if err != nil {
		t.Fatal(err)
	}
	if err := removeBoxes([]string{"box1"}); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("rm of a locked box: got %v, want an \"in use\" error", err)
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("rm of a locked box touched the box: %v", err)
	}

	if err := boxLock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeBoxes([]string{"box1"}); err != nil {
		t.Fatalf("rm after release: %v", err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("box still exists after rm: %v", err)
	}
}
