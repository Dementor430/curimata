package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/opencontainers/runc/libcontainer"
	"golang.org/x/sys/unix"
)

// forwardedSignals are passed on to the contained process.
//
// Without this, SIGTERM or SIGHUP would end curimata at once. The deferred
// cleanup would then never run: the container would keep running without
// its proxies, and its state would block the name.
var forwardedSignals = []os.Signal{
	unix.SIGTERM,
	unix.SIGINT,
	unix.SIGHUP,
	unix.SIGQUIT,
	unix.SIGUSR1,
	unix.SIGUSR2,
}

// stopGracePeriod is how long the container gets to exit after a stop
// signal, before we kill it.
//
// The contained command is PID 1 of its PID namespace. The kernel does not
// deliver a signal to PID 1 unless it has a handler for it, and shells and
// most programs have no SIGTERM handler. So a stop signal alone often does
// nothing, and we must follow it with SIGKILL.
const stopGracePeriod = 10 * time.Second

// isStopSignal reports whether a signal asks the container to end.
func isStopSignal(received os.Signal) bool {
	return received == unix.SIGTERM || received == unix.SIGINT || received == unix.SIGHUP
}

// signalForwarder catches signals for curimata and passes them on to the
// contained process.
type signalForwarder struct {
	received chan os.Signal
	done     chan struct{}
}

// catchSignals starts to catch the forwarded signals. Call it before the
// container starts, so that no signal between creation and start ends
// curimata without cleanup. Signals that arrive before forwardTo are kept
// and passed on then.
func catchSignals() *signalForwarder {
	forwarder := &signalForwarder{
		received: make(chan os.Signal, 16),
		done:     make(chan struct{}),
	}
	signal.Notify(forwarder.received, forwardedSignals...)
	return forwarder
}

// forwardTo passes every caught signal on to process.
//
// The first stop signal is passed on, and SIGKILL follows after
// stopGracePeriod if the container still runs. A second stop signal kills
// the container at once.
func (forwarder *signalForwarder) forwardTo(process *libcontainer.Process) {
	go func() {
		var killTimer <-chan time.Time
		stopRequested := false
		for {
			select {
			case received := <-forwarder.received:
				if !isStopSignal(received) {
					_ = process.Signal(received)
					continue
				}
				if stopRequested {
					netlogf("second %s: killing the container", signalName(received))
					_ = process.Signal(unix.SIGKILL)
					continue
				}
				stopRequested = true
				netlogf("%s: stopping the container; it is killed in %s if it does not exit", signalName(received), stopGracePeriod)
				_ = process.Signal(received)
				killTimer = time.After(stopGracePeriod)

			case <-killTimer:
				netlogf("the container did not exit: killing it")
				_ = process.Signal(unix.SIGKILL)

			case <-forwarder.done:
				return
			}
		}
	}()
}

// stop gives the signals back to their default handling.
func (forwarder *signalForwarder) stop() {
	signal.Stop(forwarder.received)
	close(forwarder.done)
}

func signalName(received os.Signal) string {
	if number, ok := received.(syscall.Signal); ok {
		return unix.SignalName(number)
	}
	return received.String()
}

// exitCodeOf returns the exit code that a shell would report for the
// contained process: its own exit code, or 128 plus the number of the
// signal that killed it. os.ProcessState.ExitCode returns -1 for a killed
// process, which os.Exit would turn into 255.
func exitCodeOf(state *os.ProcessState) int {
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return state.ExitCode()
}
