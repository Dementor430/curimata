package main

import (
	"os"
	"path/filepath"

	"github.com/opencontainers/cgroups"
	"github.com/opencontainers/cgroups/devices/config"
	"github.com/opencontainers/cgroups/systemd"
)

// limits holds the resource limits for one container.
type limits struct {
	memoryMiB int64
	pids      int64
	cpus      float64
	noSystemd bool
}

// cgroupConfig decides how the container's cgroup is managed.
//
// A systemd transient scope is the only way an unprivileged user gets real
// limits. systemd owns the delegated subtree below user@<uid>.service and
// creates the scope for us. Direct writes to /sys/fs/cgroup fail, because
// this user does not own that directory.
func cgroupConfig(name string, resourceLimits limits, devices []*config.Rule) *cgroups.Cgroup {
	cgroup := &cgroups.Cgroup{
		Name:     name,
		Rootless: true,
		Resources: &cgroups.Resources{
			MemorySwappiness: nil,
			Devices:          devices,
		},
	}

	if !resourceLimits.noSystemd && hasSystemdUserSession() {
		cgroup.Systemd = true
		// systemd names the unit "<ScopePrefix>-<Name>.scope".
		cgroup.ScopePrefix = "curimata"
		// An empty Parent puts the scope in the user's own slice below
		// user@<uid>.service. A Parent must otherwise end with ".slice".
		cgroup.Parent = ""
	} else {
		// No systemd scope is available. The limits below will not apply.
		// RootlessCgroups makes libcontainer ignore the resulting errors.
		cgroup.Parent = "curimata"
	}

	if resourceLimits.memoryMiB > 0 {
		cgroup.Resources.Memory = resourceLimits.memoryMiB * 1024 * 1024
		// Without this the container can swap past its memory limit.
		cgroup.Resources.MemorySwap = cgroup.Resources.Memory
	}
	if resourceLimits.pids > 0 {
		cgroup.Resources.PidsLimit = &resourceLimits.pids
	}
	if resourceLimits.cpus > 0 {
		const cpuPeriodMicroseconds = 100000
		cgroup.Resources.CpuPeriod = cpuPeriodMicroseconds
		cgroup.Resources.CpuQuota = int64(resourceLimits.cpus * cpuPeriodMicroseconds)
	}
	return cgroup
}

// hasSystemdUserSession reports whether we can ask a per-user systemd
// instance to create a scope for us.
func hasSystemdUserSession() bool {
	if !cgroups.IsCgroup2UnifiedMode() || !systemd.IsRunningSystemd() {
		return false
	}
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		return true
	}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		_, err := os.Stat(filepath.Join(runtimeDir, "bus"))
		return err == nil
	}
	return false
}
