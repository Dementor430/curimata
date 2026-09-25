package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyLimitsAreChecked(t *testing.T) {
	cases := []struct {
		json    string
		wantErr bool
	}{
		{`{"limits": {"cpus": 1e30}}`, true},
		{`{"limits": {"memoryMiB": 17592186044416}}`, true},
		{`{"limits": {"pids": -5}}`, true},
		{`{"limits": {"memoryMiB": 512, "pids": 256, "cpus": 1.5}}`, false},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, []byte(c.json), 0o600); err != nil {
			t.Fatal(err)
		}
		policyFile, err := loadPolicy(path)
		if err != nil {
			t.Fatalf("%s: loadPolicy: %v", c.json, err)
		}
		var (
			image string
			lim   limits
		)
		policyFile.apply(map[string]bool{}, &image, &lim)

		err = lim.check(4)
		if c.wantErr && err == nil {
			t.Errorf("%s: accepted, want an error", c.json)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: unexpected error %v", c.json, err)
		}
	}
}
