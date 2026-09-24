package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/containerd/console"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/utils"
	"golang.org/x/sys/unix"
)

// terminal connects the host terminal to a pseudo terminal in the container.
//
// The contained shell cannot use the host terminal directly. It runs in its
// own session, and only the host shell's session owns that terminal. Without
// a terminal of its own the shell reports "can't access tty; job control
// turned off". So libcontainer creates a pty inside the container, sends the
// master end back over a socket, and we copy bytes between the two.
type terminal struct {
	hostConsole      console.Console
	containerConsole console.Console
	parentSocket     *os.File
	childSocket      *os.File
	done             chan struct{}
	outputDone       chan struct{}
}

// newTerminal prepares the process for a pty. It returns nil when our own
// streams are not a terminal, for example when input comes from a pipe.
func newTerminal(process *libcontainer.Process) (*terminal, error) {
	hostConsole, err := console.ConsoleFromFile(os.Stdin)
	if err != nil {
		return nil, nil //nolint:nilnil // no terminal is not an error
	}

	parentSocket, childSocket, err := utils.NewSockPair("console")
	if err != nil {
		return nil, fmt.Errorf("create console socket: %w", err)
	}
	if windowSize, err := hostConsole.Size(); err == nil {
		process.ConsoleWidth, process.ConsoleHeight = windowSize.Width, windowSize.Height
	}
	// libcontainer refuses a console socket together with stream fields.
	process.Stdin, process.Stdout, process.Stderr = nil, nil, nil
	process.ConsoleSocket = childSocket

	return &terminal{
		hostConsole:  hostConsole,
		parentSocket: parentSocket,
		childSocket:  childSocket,
		done:         make(chan struct{}),
		outputDone:   make(chan struct{}),
	}, nil
}

// attach takes over the host terminal. Call it after container.Run.
func (term *terminal) attach() error {
	_ = term.childSocket.Close()

	consoleFile, err := utils.RecvFile(term.parentSocket)
	if err != nil {
		return fmt.Errorf("receive container console: %w", err)
	}
	containerConsole, err := console.ConsoleFromFile(consoleFile)
	if err != nil {
		return fmt.Errorf("wrap container console: %w", err)
	}
	// The container does the newline translation, so the master must not.
	if err := console.ClearONLCR(containerConsole.Fd()); err != nil {
		return fmt.Errorf("clear ONLCR: %w", err)
	}
	term.containerConsole = containerConsole

	// Raw mode gives the container every key stroke, including Ctrl-C.
	if err := term.hostConsole.SetRaw(); err != nil {
		return fmt.Errorf("set host terminal to raw mode: %w", err)
	}
	rawTerminal.Store(true)
	term.resize()

	resizeSignals := make(chan os.Signal, 1)
	signal.Notify(resizeSignals, unix.SIGWINCH)
	go func() {
		for {
			select {
			case <-resizeSignals:
				term.resize()
			case <-term.done:
				signal.Stop(resizeSignals)
				return
			}
		}
	}()

	// Copy key strokes into the container.
	go func() {
		_, _ = io.Copy(term.containerConsole, os.Stdin)
	}()
	// Copy container output to the screen. close waits for this copy.
	go func() {
		defer close(term.outputDone)
		_, _ = io.Copy(os.Stdout, term.containerConsole)
	}()
	return nil
}

func (term *terminal) resize() {
	if windowSize, err := term.hostConsole.Size(); err == nil {
		_ = term.containerConsole.Resize(windowSize)
	}
}

// close restores the host terminal. It first lets the output copy drain, so
// that the last lines of the container reach the screen.
func (term *terminal) close() {
	select {
	case <-term.outputDone:
	case <-time.After(2 * time.Second):
	}
	close(term.done)
	rawTerminal.Store(false)
	_ = term.hostConsole.Reset()
	if term.containerConsole != nil {
		_ = term.containerConsole.Close()
	}
	_ = term.parentSocket.Close()
}
