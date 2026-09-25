package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/opencontainers/cgroups"
	"github.com/opencontainers/cgroups/devices/config"
	"github.com/opencontainers/cgroups/systemd"
)

// cpuPeriodMicroseconds is the CFS period of the container's cgroup.
const cpuPeriodMicroseconds = 100000

// minCPUQuotaMicroseconds is the smallest quota that the kernel accepts in
// cpu.max (min_bw_quota_period_us in kernel/sched/core.c).
const minCPUQuotaMicroseconds = 1000

// maxMemoryMiB is the largest memory limit whose size in bytes still fits
// in an int64.
const maxMemoryMiB = math.MaxInt64 >> 20

// limits holds the resource limits for one container.
type limits struct {
	memoryMiB int64
	pids      int64
	cpus      float64
	noSystemd bool
}

// check refuses values that cgroupConfig cannot convert correctly or that
// the kernel refuses. A value of 0 means no limit.
//
// The checks run before any conversion. A float that is out of range for
// int64 converts to a different number on each architecture.
func (l limits) check(maxCPUs int) error {
	if l.memoryMiB < 0 || l.memoryMiB > maxMemoryMiB {
		return fmt.Errorf("memory limit %d MiB is out of range: use 1 to %d, or 0 for no limit", l.memoryMiB, maxMemoryMiB)
	}
	if l.pids < 0 {
		return fmt.Errorf("process limit %d is out of range: use 1 or more, or 0 for no limit", l.pids)
	}
	const minCPUs = float64(minCPUQuotaMicroseconds) / cpuPeriodMicroseconds
	// The comparison is false for NaN, so NaN is refused too.
	if !(l.cpus >= 0 && l.cpus <= float64(maxCPUs)) ||
		(l.cpus > 0 && int64(l.cpus*cpuPeriodMicroseconds) < minCPUQuotaMicroseconds) {
		return fmt.Errorf("CPU limit %v is out of range: use %g to %d, or 0 for no limit", l.cpus, minCPUs, maxCPUs)
	}
	return nil
}

// requested reports whether any resource limit is set.
func (l limits) requested() bool {
	return l.memoryMiB > 0 || l.pids > 0 || l.cpus > 0
}

// systemdScope reports whether the container gets a systemd transient scope.
func (l limits) systemdScope() bool {
	return !l.noSystemd && hasSystemdUserSession()
}

// requireScope refuses limits when the container gets no systemd scope.
// Without a scope this user cannot create a cgroup, and runc would stop the
// start later with an unclear error.
func (l limits) requireScope(hasScope bool) error {
	if !l.requested() || hasScope {
		return nil
	}
	if l.noSystemd {
		return errors.New(`resource limits need a systemd scope, but -no-systemd is set; remove -no-systemd, or remove the limits (-memory, -pids, -cpus, or "limits" in the policy file)`)
	}
	return errors.New(`resource limits need cgroup v2 and a systemd user session (a D-Bus session bus), and none was found; run curimata in a systemd user session, or remove the limits (-memory, -pids, -cpus, or "limits" in the policy file)`)
}

// cgroupConfig decides how the container's cgroup is managed.
//
// A systemd transient scope is the only way an unprivileged user gets real
// limits. systemd owns the delegated subtree below user@<uid>.service and
// creates the scope for us. Direct writes to /sys/fs/cgroup fail, because
// this user does not own that directory. For this reason parseRunArgs
// refuses limits when there is no scope (see requireScope).
func cgroupConfig(name string, resourceLimits limits, devices []*config.Rule) *cgroups.Cgroup {
	cgroup := &cgroups.Cgroup{
		Name:     name,
		Rootless: true,
		Resources: &cgroups.Resources{
			MemorySwappiness: nil,
			Devices:          devices,
		},
	}

	if resourceLimits.systemdScope() {
		cgroup.Systemd = true
		// systemd names the unit "<ScopePrefix>-<Name>.scope".
		cgroup.ScopePrefix = "curimata"
		// An empty Parent puts the scope in the user's own slice below
		// user@<uid>.service. A Parent must otherwise end with ".slice".
		cgroup.Parent = ""
	} else {
		// No systemd scope. parseRunArgs allows this only without limits.
		// This user cannot create the cgroup, so libcontainer continues
		// without one (cgroups.ErrRootless).
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
