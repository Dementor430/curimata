package main

import (
	"math"
	"strings"
	"testing"
)

func TestLimitsRequireScope(t *testing.T) {
	cases := []struct {
		lim      limits
		hasScope bool
		wantErr  string // empty means no error
	}{
		{limits{}, false, ""},
		{limits{noSystemd: true}, false, ""},
		{limits{memoryMiB: 64}, true, ""},
		{limits{memoryMiB: 64}, false, "systemd user session"},
		{limits{pids: 1, noSystemd: true}, false, "-no-systemd"},
		{limits{cpus: 0.5, noSystemd: true}, false, "-no-systemd"},
	}
	for _, c := range cases {
		err := c.lim.requireScope(c.hasScope)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%+v, scope %v: unexpected error %v", c.lim, c.hasScope, err)
		case c.wantErr != "" && err == nil:
			t.Errorf("%+v, scope %v: accepted, want an error", c.lim, c.hasScope)
		case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
			t.Errorf("%+v, scope %v: error %q does not mention %q", c.lim, c.hasScope, err, c.wantErr)
		}
	}
}

func TestLimitsCheck(t *testing.T) {
	const maxCPUs = 4
	valid := []limits{
		{},
		{memoryMiB: 1},
		{memoryMiB: maxMemoryMiB},
		{pids: 1},
		{cpus: 0.01},
		{cpus: 1.5},
		{cpus: maxCPUs},
	}
	invalid := []limits{
		{memoryMiB: -1},
		{memoryMiB: maxMemoryMiB + 1},
		{memoryMiB: 1 << 44}, // wrapped to 0 bytes before
		{pids: -1},
		{cpus: -0.5},
		{cpus: math.NaN()},
		{cpus: math.Inf(1)},
		{cpus: math.Inf(-1)},
		{cpus: 0.00999},
		{cpus: 1e-7}, // truncated to quota 0 before
		{cpus: maxCPUs + 0.5},
		{cpus: 1e30},
	}
	for _, lim := range valid {
		if err := lim.check(maxCPUs); err != nil {
			t.Errorf("%+v: unexpected error %v", lim, err)
		}
	}
	for _, lim := range invalid {
		if err := lim.check(maxCPUs); err == nil {
			t.Errorf("%+v: accepted, want an error", lim)
		}
	}
}

func TestCgroupConfigEdgeValues(t *testing.T) {
	// noSystemd keeps the test independent of the host's systemd.
	lim := limits{memoryMiB: maxMemoryMiB, pids: 7, cpus: 0.01, noSystemd: true}
	resources := cgroupConfig("t", lim, nil).Resources

	const wantMemory = int64(maxMemoryMiB) * 1024 * 1024
	if resources.Memory != wantMemory || resources.Memory <= 0 {
		t.Errorf("Memory = %d, want %d", resources.Memory, wantMemory)
	}
	if resources.MemorySwap != resources.Memory {
		t.Errorf("MemorySwap = %d, want %d", resources.MemorySwap, resources.Memory)
	}
	if resources.PidsLimit == nil || *resources.PidsLimit != 7 {
		t.Errorf("PidsLimit = %v, want 7", resources.PidsLimit)
	}
	if resources.CpuPeriod != cpuPeriodMicroseconds {
		t.Errorf("CpuPeriod = %d, want %d", resources.CpuPeriod, cpuPeriodMicroseconds)
	}
	if resources.CpuQuota != minCPUQuotaMicroseconds {
		t.Errorf("CpuQuota = %d, want %d", resources.CpuQuota, minCPUQuotaMicroseconds)
	}
}
