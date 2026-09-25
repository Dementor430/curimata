package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/opencontainers/cgroups/devices/config"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"golang.org/x/sys/unix"
)

// defaultCapabilities is the set that container root holds.
//
// Every one of them is limited to the container's own user namespace, so
// they grant no power over the host. The narrower set of the runc example
// was too small for a real distribution: apt drops to its own user before it
// downloads, and that needs CAP_SETUID and CAP_SETGID.
//
// CAP_SYS_ADMIN and CAP_NET_ADMIN stay out on purpose. Without CAP_NET_ADMIN
// the sandboxed program cannot change the network of its own namespace, and
// so cannot work around the proxy.
var defaultCapabilities = []string{
	"CAP_AUDIT_WRITE",
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_MKNOD",
	"CAP_NET_BIND_SERVICE",
	"CAP_SETFCAP",
	"CAP_SETGID",
	"CAP_SETPCAP",
	"CAP_SETUID",
	"CAP_SYS_CHROOT",
}

// containerConfig builds the libcontainer configuration for one container.
func containerConfig(rootfs, name string, resourceLimits limits, namespaceHolder *netnsHolder) (*configs.Config, error) {
	// The mappings are stated in both cases. When we create the namespace
	// they are applied; when we join the helper's namespace they only tell
	// libcontainer which host ID container root stands for, which it needs
	// in order to own the files it creates.
	uidMappings, err := idMappings(os.Getuid(), "/etc/subuid")
	if err != nil {
		return nil, fmt.Errorf("uid mappings: %w", err)
	}
	gidMappings, err := idMappings(os.Getgid(), "/etc/subgid")
	if err != nil {
		return nil, fmt.Errorf("gid mappings: %w", err)
	}

	return &configs.Config{
		Rootfs: rootfs,

		// We run as an unprivileged user. RootlessEUID makes libcontainer
		// bind-mount the host device nodes instead of calling mknod, which
		// only real root may do. RootlessCgroups lets it continue without a
		// cgroup when it may not create one; it still fails on any memory,
		// pids or CPU limit that it cannot write.
		RootlessEUID:    true,
		RootlessCgroups: true,

		Capabilities: &configs.Capabilities{
			Bounding:  defaultCapabilities,
			Effective: defaultCapabilities,
			Permitted: defaultCapabilities,
		},
		Namespaces: containerNamespaces(namespaceHolder),
		Cgroups:    cgroupConfig(name, resourceLimits, allowedDeviceRules()),
		MaskPaths: []string{
			"/proc/kcore",
			"/sys/firmware",
		},
		ReadonlyPaths: []string{
			"/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus",
		},
		// If curimata dies while runc still starts the container, the
		// kernel kills the start helper. This covers only the first start
		// stage; init() in main.go covers the running container.
		ParentDeathSignal: int(unix.SIGKILL),

		Devices:     specconv.AllowedDevices,
		Hostname:    name,
		Mounts:      containerMounts(),
		UIDMappings: uidMappings,
		GIDMappings: gidMappings,
		Networks:    loopbackNetwork(namespaceHolder),
		Rlimits: []configs.Rlimit{
			{
				Type: unix.RLIMIT_NOFILE,
				Hard: uint64(1025),
				Soft: uint64(1025),
			},
		},
	}, nil
}

// containerNamespaces lists the namespaces of the container.
//
// Without networking the container makes its own user and network
// namespaces. With networking it joins the helper's, which already hold
// the proxy sockets and the very same ID map.
func containerNamespaces(namespaceHolder *netnsHolder) configs.Namespaces {
	namespaces := configs.Namespaces{
		{Type: configs.NEWUSER},
		{Type: configs.NEWNET},
	}
	if namespaceHolder != nil {
		namespaces = configs.Namespaces{
			{Type: configs.NEWUSER, Path: namespaceHolder.userPath},
			{Type: configs.NEWNET, Path: namespaceHolder.netPath},
		}
	}
	return append(namespaces,
		configs.Namespace{Type: configs.NEWNS},
		configs.Namespace{Type: configs.NEWUTS},
		configs.Namespace{Type: configs.NEWIPC},
		configs.Namespace{Type: configs.NEWPID},
		configs.Namespace{Type: configs.NEWCGROUP},
	)
}

// allowedDeviceRules returns the cgroup rules for the default device set.
func allowedDeviceRules() []*config.Rule {
	var devices []*config.Rule
	for _, device := range specconv.AllowedDevices {
		devices = append(devices, &device.Rule)
	}
	return devices
}

// containerMounts lists the file systems mounted into the container.
func containerMounts() []*configs.Mount {
	const defaultMountFlags = unix.MS_NOEXEC | unix.MS_NOSUID | unix.MS_NODEV

	return []*configs.Mount{
		{
			Source:      "proc",
			Destination: "/proc",
			Device:      "proc",
			Flags:       defaultMountFlags,
		},
		{
			Source:      "tmpfs",
			Destination: "/dev",
			Device:      "tmpfs",
			Flags:       unix.MS_NOSUID | unix.MS_STRICTATIME,
			Data:        "mode=755",
		},
		{
			Source:      "devpts",
			Destination: "/dev/pts",
			Device:      "devpts",
			Flags:       unix.MS_NOSUID | unix.MS_NOEXEC,
			Data:        "newinstance,ptmxmode=0666,mode=0620",
		},
		{
			Device:      "tmpfs",
			Source:      "shm",
			Destination: "/dev/shm",
			Data:        "mode=1777,size=65536k",
			Flags:       defaultMountFlags,
		},
		{
			Source:      "mqueue",
			Destination: "/dev/mqueue",
			Device:      "mqueue",
			Flags:       defaultMountFlags,
		},
		{
			// A rootless container may not mount a fresh sysfs, because
			// it does not own the host network namespace's sysfs. Bind
			// the host /sys read-only instead.
			//
			// MS_RDONLY makes only the top mount read-only. The mounts
			// below it (cgroupfs, debugfs, tracefs, configfs) would stay
			// writable, and the host cgroupfs of this user would then be
			// open to the container. RecAttr applies read-only to every
			// mount below /sys with mount_setattr(AT_RECURSIVE).
			Source:      "/sys",
			Destination: "/sys",
			Device:      "bind",
			Flags:       defaultMountFlags | unix.MS_BIND | unix.MS_REC | unix.MS_RDONLY,
			RecAttr:     &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY},
		},
		{
			// Cover the host cgroup tree with a cgroup2 mount of the
			// container's own cgroup namespace. The container then sees
			// only its own cgroup and its limits, not the whole host.
			//
			// It stays read-only: the scope's own files, such as
			// memory.max, belong to our user, so the container could
			// otherwise raise its own limits.
			Source:      "cgroup",
			Destination: "/sys/fs/cgroup",
			Device:      "cgroup",
			Flags:       defaultMountFlags | unix.MS_RDONLY,
		},
	}
}

// idMappings builds the user namespace mapping for an unprivileged user.
//
// The kernel only lets us map IDs we own: our own ID, plus the subordinate
// range that /etc/subuid or /etc/subgid grants us. Mapping anything else
// fails with EPERM when libcontainer writes /proc/<pid>/uid_map.
func idMappings(hostID int, subIDFile string) ([]configs.IDMap, error) {
	mappings := []configs.IDMap{
		{ContainerID: 0, HostID: int64(hostID), Size: 1},
	}
	start, count, err := subIDRange(subIDFile, hostID)
	if err != nil {
		return nil, err
	}
	mappings = append(mappings, configs.IDMap{ContainerID: 1, HostID: start, Size: count})
	return mappings, nil
}

// subIDRange reads the subordinate ID range granted to the current user.
// Entries are keyed by user name or by numeric ID.
func subIDRange(subIDFile string, hostID int) (start, count int64, err error) {
	userName := strconv.Itoa(hostID)
	if currentUser, err := user.Current(); err == nil {
		userName = currentUser.Username
	}

	file, err := os.Open(subIDFile)
	if err != nil {
		return 0, 0, fmt.Errorf("open %s: %w", subIDFile, err)
	}
	defer file.Close() //nolint:errcheck // read only

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(strings.TrimSpace(scanner.Text()), ":")
		if len(fields) != 3 {
			continue
		}
		if fields[0] != userName && fields[0] != strconv.Itoa(hostID) {
			continue
		}
		start, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		count, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			continue
		}
		return start, count, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, fmt.Errorf("read %s: %w", subIDFile, err)
	}
	return 0, 0, fmt.Errorf("no entry for %q in %s; add one with usermod --add-subuids", userName, subIDFile)
}

// loopbackNetwork asks libcontainer to bring loopback up. The helper has
// already done that when it owns the namespace, and a joined namespace is
// not ours to configure.
func loopbackNetwork(namespaceHolder *netnsHolder) []*configs.Network {
	if namespaceHolder != nil {
		return nil
	}
	return []*configs.Network{{Type: "loopback"}}
}
