package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Every "run" and "rm" of a box name holds the lock of that name, "run" for
// as long as it runs. Two curimata processes then never prepare, start or
// remove the same box at once.
//
// The lock files live below the state directory, not in the box: "rm"
// deletes the box directory, and a lock on a deleted file protects nothing.
// A box name never starts with a dot, so ".locks" never meets the
// libcontainer state of a box. Lock files are never deleted, because a new
// file at the same path would be a second, independent lock. The kernel
// drops the lock when the process ends, also after SIGKILL.

// lockBox takes the lock of the box name, which must be valid. It fails at
// once when another curimata holds it. Close the file to release the lock,
// and keep it reachable until then: the garbage collector closes a lost
// file.
func lockBox(name string) (*os.File, error) {
	stateDirectory, err := stateDir()
	if err != nil {
		return nil, err
	}
	lockDirectory := filepath.Join(stateDirectory, ".locks")
	if err := os.MkdirAll(lockDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	lockFile, err := os.OpenFile(filepath.Join(lockDirectory, name), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock of box %q: %w", name, err)
	}
	for {
		err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		lockFile.Close() //nolint:errcheck // the lock error is the useful one
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("box %q is in use by another curimata process", name)
		}
		return nil, fmt.Errorf("lock box %q: %w", name, err)
	}
	return lockFile, nil
}
