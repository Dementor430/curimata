package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// policy is the JSON configuration file for one sandbox.
//
// Every field is optional. A flag on the command line wins over the file,
// except for the allow rules: those are added together, so a policy file can
// hold the standing rules and a flag can add one for a single run.
//
//	{
//	  "image": "debian:stable-slim",
//	  "limits": { "memoryMiB": 512, "pids": 256, "cpus": 1.5 },
//	  "network": {
//	    "allow": [
//	      "deb.debian.org:443",
//	      { "host": "*.pypi.org", "ports": [443] },
//	      { "host": "10.0.0.5",   "ports": [5432] },
//	      { "host": "cache.local", "ports": [] }
//	    ]
//	  }
//	}
type policy struct {
	Image   string        `json:"image,omitzero"`
	Limits  *policyLimits `json:"limits,omitzero"`
	Network *policyNet    `json:"network,omitzero"`
}

// policyLimits mirrors the resource flags. A pointer tells a value of zero
// apart from a field that the file does not mention.
type policyLimits struct {
	MemoryMiB *int64   `json:"memoryMiB,omitzero"`
	Pids      *int64   `json:"pids,omitzero"`
	CPUs      *float64 `json:"cpus,omitzero"`
}

type policyNet struct {
	Allow []allowEntry `json:"allow,omitzero"`
}

// allowEntry is one allow rule. It accepts two spellings: the short string
// "host:port", and an object with a host and a list of ports. An empty or
// missing port list allows every port on that host.
type allowEntry struct {
	Host  string `json:"host"`
	Ports []int  `json:"ports,omitzero"`
}

func (a *allowEntry) UnmarshalJSON(raw []byte) error {
	if len(raw) > 0 && raw[0] == '"' {
		var short string
		if err := json.Unmarshal(raw, &short); err != nil {
			return err
		}
		host, port, ok := splitHostPort(short)
		if !ok {
			return fmt.Errorf("allow rule %q: expected host:port", short)
		}
		a.Host = host
		if port != "*" {
			n, err := strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("allow rule %q: bad port %q", short, port)
			}
			a.Ports = []int{n}
		}
		return nil
	}

	// The object form, with the field names checked.
	type plain allowEntry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var value plain
	if err := dec.Decode(&value); err != nil {
		return err
	}
	*a = allowEntry(value)
	return nil
}

// specs renders the entries back into the "host:port" form that the
// allowlist parser reads, so both spellings go through the same checks.
func (n *policyNet) specs() []string {
	if n == nil {
		return nil
	}
	var out []string
	for _, entry := range n.Allow {
		if len(entry.Ports) == 0 {
			out = append(out, entry.Host+":*")
			continue
		}
		for _, port := range entry.Ports {
			out = append(out, entry.Host+":"+strconv.Itoa(port))
		}
	}
	return out
}

// loadPolicy reads and checks the configuration file.
//
// Unknown fields are an error. A policy file states what the sandbox may
// reach, and a silent typo in such a file is worse than a refusal.
func loadPolicy(path string) (*policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var p policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: more than one JSON document", path)
	}

	if p.Network != nil {
		for i, entry := range p.Network.Allow {
			if entry.Host == "" {
				return nil, fmt.Errorf("%s: allow rule %d has no host", path, i+1)
			}
			for _, port := range entry.Ports {
				if port < 1 || port > 65535 {
					return nil, fmt.Errorf("%s: allow rule %d: port %d is out of range", path, i+1, port)
				}
			}
		}
	}
	return &p, nil
}

// apply copies the file's values into the run settings, but only where the
// command line stayed silent.
func (p *policy) apply(set map[string]bool, image *string, lim *limits) {
	if p == nil {
		return
	}
	if p.Image != "" && !set["image"] {
		*image = p.Image
	}
	if p.Limits == nil {
		return
	}
	if p.Limits.MemoryMiB != nil && !set["memory"] {
		lim.memoryMiB = *p.Limits.MemoryMiB
	}
	if p.Limits.Pids != nil && !set["pids"] {
		lim.pids = *p.Limits.Pids
	}
	if p.Limits.CPUs != nil && !set["cpus"] {
		lim.cpus = *p.Limits.CPUs
	}
}
