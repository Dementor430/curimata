package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// netnsHolder owns the user namespace and the network namespace that the
// container runs in.
//
// We cannot open a socket inside a namespace that libcontainer made for us:
// setns into another network namespace needs CAP_SYS_ADMIN in our own user
// namespace, and an unprivileged process has none. So we turn it around. A
// helper process creates both namespaces, opens the proxy listeners there,
// and hands the sockets back. The container then joins those same two
// namespaces by path.
//
// The helper only holds the namespaces open. It runs outside the container's
// root filesystem, has no part in the container's process tree, and the
// sandboxed program can neither see it nor reach it.
type netnsHolder struct {
	cmd       *exec.Cmd
	alive     *os.File // closing it tells the helper that we are gone
	userPath  string
	netPath   string
	listeners []net.Listener
}

// The helper runs in two stages. Stage one only waits for its ID map,
// because a process that execs before the map exists is nobody in its new
// user namespace, and the kernel takes every capability away from it. Once
// the map is in place, stage one executes this binary again. That second
// exec happens as user 0 of the namespace, so the kernel grants the full
// capability set, and stage two can configure the network.
const (
	holderCommand = "netns-holder"
	holderStage2  = "netns-holder-run"
)

// File descriptors that the helper inherits.
const (
	holderSockFD  = 3 // sends the listening sockets to the parent
	holderAliveFD = 4 // carries the go-ahead, then reports the parent's end
)

// startNetnsHolder starts the helper and collects one listener per address.
func startNetnsHolder(addrs []string) (*netnsHolder, error) {
	parentSock, childSock, err := utils.NewSockPair("netns")
	if err != nil {
		return nil, fmt.Errorf("create helper socket: %w", err)
	}
	defer parentSock.Close() //nolint:errcheck // the listeners outlive it

	readyR, readyW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create helper pipe: %w", err)
	}

	cmd := exec.Command("/proc/self/exe", holderCommand, strings.Join(addrs, ","))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// The helper creates both namespaces. Because it creates the user
		// namespace, it holds every capability inside it, which is what
		// lets it configure the network.
		Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNET,
	}
	// Child file descriptors 3 and 4.
	cmd.ExtraFiles = []*os.File{childSock, readyR}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start network helper: %w", err)
	}
	// Drop our copies of the child's ends at once. While we hold them, a
	// dead child never closes the socket, and every read below would wait
	// for a message that can no longer come.
	childSock.Close() //nolint:errcheck // the child holds its own copy
	readyR.Close()    //nolint:errcheck // the child holds its own copy

	holder := &netnsHolder{
		cmd:      cmd,
		alive:    readyW,
		userPath: fmt.Sprintf("/proc/%d/ns/user", cmd.Process.Pid),
		netPath:  fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid),
	}

	// The helper waits with an empty ID map. We fill it in from here, with
	// the same two entries the container would use, and then release it.
	if err := writeIDMaps(cmd.Process.Pid); err != nil {
		holder.stop()
		return nil, err
	}
	if _, err := readyW.Write([]byte{1}); err != nil {
		holder.stop()
		return nil, fmt.Errorf("release network helper: %w", err)
	}

	for range addrs {
		f, err := utils.RecvFile(parentSock)
		if err != nil {
			holder.stop()
			return nil, fmt.Errorf("receive proxy socket: %w", err)
		}
		l, err := net.FileListener(f)
		f.Close() //nolint:errcheck // FileListener took its own copy
		if err != nil {
			holder.stop()
			return nil, fmt.Errorf("adopt proxy socket: %w", err)
		}
		holder.listeners = append(holder.listeners, l)
	}
	return holder, nil
}

func (h *netnsHolder) stop() {
	for _, l := range h.listeners {
		_ = l.Close()
	}
	// Closing this end ends the helper's read, which is how it learns that
	// we are finished. Killing it afterwards only covers a helper that is
	// stuck somewhere else.
	if h.alive != nil {
		_ = h.alive.Close()
	}
	if h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		_, _ = h.cmd.Process.Wait()
	}
}

// writeIDMaps gives the helper's user namespace the same ID map that a
// private container namespace would get. newuidmap and newgidmap are set-user
// -ID programs, and they are the only way to map a subordinate range.
func writeIDMaps(pid int) error {
	uidArgs, err := idMapArgs(os.Getuid(), "/etc/subuid")
	if err != nil {
		return err
	}
	gidArgs, err := idMapArgs(os.Getgid(), "/etc/subgid")
	if err != nil {
		return err
	}

	for _, step := range []struct {
		tool string
		args []string
	}{
		{"newuidmap", uidArgs},
		{"newgidmap", gidArgs},
	} {
		path, err := exec.LookPath(step.tool)
		if err != nil {
			return fmt.Errorf("%s is needed to map user IDs but was not found; install the uidmap package: %w", step.tool, err)
		}
		cmd := exec.Command(path, append([]string{strconv.Itoa(pid)}, step.args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s failed: %w: %s", step.tool, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// idMapArgs renders the mapping as the argument list that newuidmap takes:
// triples of container ID, host ID and count.
func idMapArgs(id int, subFile string) ([]string, error) {
	maps, err := idMappings(id, subFile)
	if err != nil {
		return nil, err
	}
	var args []string
	for _, m := range maps {
		args = append(args,
			strconv.FormatInt(m.ContainerID, 10),
			strconv.FormatInt(m.HostID, 10),
			strconv.FormatInt(m.Size, 10),
		)
	}
	return args, nil
}

// runNetnsHolderStage1 waits for the parent to write the ID map, then
// executes this binary again so that the kernel returns our capabilities.
func runNetnsHolderStage1(args []string) error {
	if len(args) != 1 {
		return errors.New(holderCommand + " takes one address list")
	}
	ready := os.NewFile(holderAliveFD, "ready")
	if _, err := ready.Read(make([]byte, 1)); err != nil {
		return fmt.Errorf("wait for id map: %w", err)
	}

	// An exec closes a descriptor that carries the close-on-exec flag, and
	// stage two needs both of these.
	for _, fd := range []int{holderSockFD, holderAliveFD} {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
			return fmt.Errorf("keep descriptor %d across exec: %w", fd, err)
		}
	}

	self := "/proc/self/exe"
	if err := unix.Exec(self, []string{"curimata", holderStage2, args[0]}, os.Environ()); err != nil {
		return fmt.Errorf("re-execute as %s: %w", holderStage2, err)
	}
	return nil
}

// runNetnsHolder is stage two. It owns a fresh user namespace and a fresh
// network namespace, opens the listeners, sends them to the parent, and then
// stays alive only to keep the namespaces from going away.
func runNetnsHolder(args []string) error {
	if len(args) != 1 {
		return errors.New(holderStage2 + " takes one address list")
	}
	sock := os.NewFile(holderSockFD, "parent")
	ready := os.NewFile(holderAliveFD, "ready")

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find loopback: %w", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("bring loopback up: %w", err)
	}

	for _, addr := range strings.Split(args[0], ",") {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", addr, err)
		}
		f, err := l.(*net.TCPListener).File()
		if err != nil {
			return fmt.Errorf("export listener %s: %w", addr, err)
		}
		if err := utils.SendFile(sock, f); err != nil {
			return fmt.Errorf("send listener %s: %w", addr, err)
		}
		f.Close() //nolint:errcheck // the parent holds it now
		// The parent serves the socket. Our own copy must stay open, or
		// the namespace would drop the binding.
	}
	sock.Close() //nolint:errcheck // nothing more to send

	// Stay alive only as long as the parent does. The read ends when the
	// parent closes its end, whether it finished normally or crashed, and
	// the namespaces go away with us.
	_, _ = io.Copy(io.Discard, ready)
	return nil
}
