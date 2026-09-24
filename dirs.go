package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// dataDir returns the directory for data that must survive a reboot, such as
// downloaded images. The state directory below must not hold these.
func dataDir() (string, error) {
	baseDir := os.Getenv("XDG_DATA_HOME")
	if baseDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}
		baseDir = filepath.Join(homeDir, ".local", "share")
	}
	curimataDir := filepath.Join(baseDir, "curimata")
	if err := os.MkdirAll(curimataDir, 0o755); err != nil {
		return "", fmt.Errorf("create data directory: %w", err)
	}
	return curimataDir, nil
}

// stateDir returns a directory this user may write. libcontainer keeps the
// container state there. /run belongs to root, so we must not use it.
func stateDir() (string, error) {
	baseDir := os.Getenv("XDG_RUNTIME_DIR")
	if baseDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}
		baseDir = filepath.Join(homeDir, ".local", "share")
	}
	curimataDir := filepath.Join(baseDir, "curimata")
	if err := os.MkdirAll(curimataDir, 0o700); err != nil {
		return "", fmt.Errorf("create state directory: %w", err)
	}
	return curimataDir, nil
}
