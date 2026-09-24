package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// A box may hold files that belong to a subordinate ID, for example the
// files that apt creates as its own user "_apt". On the host these belong
// to an ID such as 100042, not to us, so we cannot delete them. Inside a
// user namespace with the container's ID map we are root, and root there
// may delete them.
//
// The helper runs in two stages, for the same reason as the network helper
// in netns.go: a process that executes before its ID map exists loses every
// capability. Stage one waits for the map, then executes this binary again
// as root of the namespace.
const (
	removeTreeCommand = "remove-tree"
	removeTreeStage2  = "remove-tree-run"
)

// removeTreeReadyFD carries the go-ahead from the parent to stage one.
const removeTreeReadyFD = 3

// removeTree deletes path and everything below it.
//
// It first tries as our own user. Only when that fails for lack of
// permission does it start the helper in a user namespace.
func removeTree(path string) error {
	err := os.RemoveAll(path)
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	return removeTreeInUserNamespace(path)
}

// removeTreeInUserNamespace starts the helper and waits until it is done.
func removeTreeInUserNamespace(path string) error {
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create helper pipe: %w", err)
	}
	defer readyWriter.Close() //nolint:errcheck // closed once the go-ahead is sent

	helper := exec.Command("/proc/self/exe", removeTreeCommand, path)
	helper.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER}
	helper.ExtraFiles = []*os.File{readyReader}
	helper.Stdout = os.Stdout
	helper.Stderr = os.Stderr

	if err := helper.Start(); err != nil {
		readyReader.Close() //nolint:errcheck // the helper never started
		return fmt.Errorf("start remove helper: %w", err)
	}
	readyReader.Close() //nolint:errcheck // the helper holds its own copy

	if err := writeIDMaps(helper.Process.Pid); err != nil {
		_ = helper.Process.Kill()
		_ = helper.Wait()
		return err
	}
	if _, err := readyWriter.Write([]byte{1}); err != nil {
		_ = helper.Process.Kill()
		_ = helper.Wait()
		return fmt.Errorf("release remove helper: %w", err)
	}
	if err := helper.Wait(); err != nil {
		return fmt.Errorf("remove %s in user namespace: %w", path, err)
	}
	return nil
}

// runRemoveTreeStage1 waits for the parent to write the ID map, then
// executes this binary again so that the kernel returns our capabilities.
func runRemoveTreeStage1(args []string) error {
	if len(args) != 1 {
		return errors.New(removeTreeCommand + " takes one path")
	}
	ready := os.NewFile(removeTreeReadyFD, "ready")
	if _, err := ready.Read(make([]byte, 1)); err != nil {
		return fmt.Errorf("wait for id map: %w", err)
	}
	if err := unix.Exec("/proc/self/exe", []string{"curimata", removeTreeStage2, args[0]}, os.Environ()); err != nil {
		return fmt.Errorf("re-execute as %s: %w", removeTreeStage2, err)
	}
	return nil
}

// runRemoveTree is stage two. It runs as root of the user namespace.
func runRemoveTree(args []string) error {
	if len(args) != 1 {
		return errors.New(removeTreeStage2 + " takes one path")
	}
	return os.RemoveAll(args[0])
}
