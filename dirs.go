package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// printedWarnings keeps each warning about a directory to one per process.
// stateDir and dataDir run more than once in each command.
var printedWarnings sync.Map

func warnOnce(key, format string, args ...any) {
	if _, printed := printedWarnings.LoadOrStore(key, true); !printed {
		fmt.Fprintf(os.Stderr, "curimata: warning: "+format+"\n", args...)
	}
}

// xdgDir returns the value of an XDG base directory variable, or "" when it
// is unset or relative. The XDG spec makes a relative path invalid, and
// tells us to ignore it.
func xdgDir(variable string) string {
	value := os.Getenv(variable)
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	warnOnce(variable, "ignoring %s=%q, because it is not an absolute path", variable, value)
	return ""
}

// dataPath returns the directory for data that must survive a reboot, such
// as downloaded images. It does not create it. The state directory must not
// hold these.
func dataPath() (string, error) {
	baseDir := xdgDir("XDG_DATA_HOME")
	if baseDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}
		baseDir = filepath.Join(homeDir, ".local", "share")
	}
	return filepath.Join(baseDir, "curimata"), nil
}

// dataDir returns the directory of dataPath, and creates it.
func dataDir() (string, error) {
	curimataDir, err := dataPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(curimataDir, 0o755); err != nil {
		return "", fmt.Errorf("create data directory: %w", err)
	}
	return curimataDir, nil
}

// stateDir returns a directory this user may write, for the libcontainer
// state and the lock files. /run belongs to root, so we must not use it.
//
// The directory must not overlap the data directory: the state of a box
// named "boxes" would then be the directory of all boxes.
func stateDir() (string, error) {
	baseDir := xdgDir("XDG_RUNTIME_DIR")
	if baseDir == "" {
		var inTemp bool
		var err error
		baseDir, inTemp, err = fallbackRuntimeDir("/run/user", "/tmp", os.Getuid())
		if err != nil {
			return "", err
		}
		if inTemp {
			warnOnce("runtime fallback", "no usable XDG_RUNTIME_DIR; keeping container state in %s", baseDir)
		}
	}
	curimataDir := filepath.Join(baseDir, "curimata")
	dataDirectory, err := dataPath()
	if err != nil {
		return "", err
	}
	if overlaps(curimataDir, dataDirectory) {
		return "", fmt.Errorf("state directory %s and data directory %s overlap; set XDG_RUNTIME_DIR to a directory outside %s", curimataDir, dataDirectory, dataDirectory)
	}
	if err := os.MkdirAll(curimataDir, 0o700); err != nil {
		return "", fmt.Errorf("create state directory: %w", err)
	}
	return curimataDir, nil
}

// fallbackRuntimeDir returns a replacement for an unset XDG_RUNTIME_DIR,
// and reports whether it is below tempRoot. It prefers userRoot/<uid>, the
// directory that systemd-logind makes for each user. Without it, it uses
// tempRoot/curimata-<uid>. Other users can write to tempRoot, so that
// directory must be ours and private. The sticky bit of /tmp keeps others
// from replacing it after the check.
func fallbackRuntimeDir(userRoot, tempRoot string, uid int) (string, bool, error) {
	userDirectory := filepath.Join(userRoot, strconv.Itoa(uid))
	if checkPrivateDir(userDirectory, uid) == nil {
		return userDirectory, false, nil
	}
	tempDirectory := filepath.Join(tempRoot, "curimata-"+strconv.Itoa(uid))
	if err := os.Mkdir(tempDirectory, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", false, fmt.Errorf("create runtime directory: %w", err)
	}
	if err := checkPrivateDir(tempDirectory, uid); err != nil {
		return "", false, fmt.Errorf("unsafe runtime directory: %w; remove it or set XDG_RUNTIME_DIR", err)
	}
	return tempDirectory, true, nil
}

// checkPrivateDir fails unless path is a directory, not a symlink, that uid
// owns and that no group or other user can access.
func checkPrivateDir(path string, uid int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != uid {
		return fmt.Errorf("%s does not belong to user %d", path, uid)
	}
	if permissions := info.Mode().Perm(); permissions&0o077 != 0 {
		return fmt.Errorf("%s is open to other users (mode %04o)", path, permissions)
	}
	return nil
}

// overlaps reports whether one of two paths is the other or is inside it.
func overlaps(first, second string) bool {
	first, second = filepath.Clean(first), filepath.Clean(second)
	separator := string(filepath.Separator)
	return first == second ||
		strings.HasPrefix(first, second+separator) ||
		strings.HasPrefix(second, first+separator)
}
