package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/opencontainers/runc/libcontainer"
	"golang.org/x/sys/unix"
)

// A box is the writable root filesystem of one container name.
//
// The first run of a name copies the cached image into the box. Later runs
// with the same name use the box again, so installed packages stay. The
// image cache itself is never written by a container, and two boxes never
// share their files.
//
//	<data dir>/boxes/<name>/rootfs   the box's root filesystem
//	<data dir>/boxes/<name>/image    the image reference it was made from

// boxNamePattern limits names to characters that are safe in a path and in
// a systemd unit name.
var boxNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func validateBoxName(name string) error {
	if !boxNamePattern.MatchString(name) || len(name) > 64 {
		return fmt.Errorf("invalid name %q: use letters, digits, '.', '_' and '-', at most 64 characters, starting with a letter or digit", name)
	}
	return nil
}

// boxDir returns the directory of one box. It does not create it.
func boxDir(name string) (string, error) {
	baseDir, err := dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, "boxes", name), nil
}

// prepareBox returns the root filesystem of the box name, and creates it
// from image on the first run.
//
// imageChosen tells whether the user asked for image on the command line
// or in the policy file. An existing box keeps the image it was made from,
// so a different chosen image is an error rather than a silent surprise.
func prepareBox(name, image string, imageChosen, repull bool) (string, error) {
	directory, err := boxDir(name)
	if err != nil {
		return "", err
	}
	rootfs := filepath.Join(directory, "rootfs")
	imageFile := filepath.Join(directory, "image")

	if info, err := os.Stat(rootfs); err == nil && info.IsDir() {
		recorded, _ := os.ReadFile(imageFile)
		boxImage := strings.TrimSpace(string(recorded))
		if imageChosen && boxImage != "" && boxImage != image {
			return "", fmt.Errorf("box %q was made from %s, not %s; remove it first with: curimata rm %s", name, boxImage, image, name)
		}
		if repull {
			// Update the cache for new boxes. This box keeps its files.
			if _, err := pullRootfs(image, true); err != nil {
				return "", err
			}
			fmt.Fprintf(os.Stderr, "curimata: box %q keeps its files; remove it with curimata rm %s to start from the new image\n", name, name)
		}
		return rootfs, nil
	}

	imageRootfs, err := pullRootfs(image, repull)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create box directory: %w", err)
	}
	// Copy beside the final name, then rename. A failed copy then never
	// leaves a half-filled box behind, and when two first runs of the same
	// name race, only one rename wins.
	temporary, err := os.MkdirTemp(directory, "rootfs.tmp-")
	if err != nil {
		return "", fmt.Errorf("create box directory: %w", err)
	}
	start := time.Now()
	if err := copyTree(imageRootfs, temporary); err != nil {
		_ = removeTree(temporary)
		if errors.Is(err, fs.ErrPermission) {
			// An older curimata let containers write into the cache, and
			// left files of subordinate IDs there that we cannot read.
			return "", fmt.Errorf("copy image into box %q: %w; the image cache holds files of another user, download it again with: curimata run -pull ... %s", name, err, name)
		}
		return "", fmt.Errorf("copy image into box %q: %w", name, err)
	}
	if err := os.Rename(temporary, rootfs); err != nil {
		_ = removeTree(temporary)
		if info, statErr := os.Stat(rootfs); statErr == nil && info.IsDir() {
			return rootfs, nil
		}
		return "", fmt.Errorf("install box %q: %w", name, err)
	}
	if err := os.WriteFile(imageFile, []byte(image+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("record image of box %q: %w", name, err)
	}
	fmt.Fprintf(os.Stderr, "curimata: created box %q from %s in %s\n", name, image, time.Since(start).Round(time.Millisecond))
	return rootfs, nil
}

// removeBoxes deletes boxes by name. It refuses a box that still runs.
func removeBoxes(names []string) error {
	if len(names) == 0 {
		return errors.New("rm needs at least one box name")
	}
	stateDirectory, err := stateDir()
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := validateBoxName(name); err != nil {
			return err
		}

		foundState, err := clearStoppedContainer(stateDirectory, name)
		if err != nil {
			return err
		}

		directory, err := boxDir(name)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(directory); err != nil {
			if os.IsNotExist(err) && foundState {
				continue
			}
			if os.IsNotExist(err) {
				return fmt.Errorf("no box named %q", name)
			}
			return err
		}
		if err := removeTree(directory); err != nil {
			return fmt.Errorf("remove box %q: %w", name, err)
		}
		fmt.Fprintf(os.Stderr, "curimata: removed box %q\n", name)
	}
	return nil
}

// clearStoppedContainer removes the libcontainer state of name, if there is
// any and the container no longer runs. A container that was killed, or
// whose curimata was killed, leaves this state behind, and the state blocks
// the name. It reports whether there was state, and refuses a container
// that still runs.
func clearStoppedContainer(stateDirectory, name string) (bool, error) {
	container, err := libcontainer.Load(stateDirectory, name)
	if err != nil {
		// No state, or state that libcontainer cannot read: nothing to do.
		return false, nil //nolint:nilerr // missing state is the normal case
	}
	status, err := container.Status()
	if err != nil {
		return true, fmt.Errorf("check box %q: %w", name, err)
	}
	if status != libcontainer.Stopped {
		return true, fmt.Errorf("box %q is %s; stop it first", name, status)
	}
	if err := container.Destroy(); err != nil {
		return true, fmt.Errorf("clean up state of %q: %w", name, err)
	}
	fmt.Fprintf(os.Stderr, "curimata: removed state of stopped container %q\n", name)
	return true, nil
}

// copyTree copies the directory tree at source into destination, which must
// be an empty directory. It never follows a symlink.
//
// It keeps modes, including setuid, setgid and sticky bits, modification
// times and hard links. It skips sockets and device nodes, which an image
// extracted without root does not contain.
func copyTree(source, destination string) error {
	type directoryAttributes struct {
		path    string
		mode    fs.FileMode
		modTime time.Time
	}
	// Directory modes and times are applied last: a read-only directory
	// must still accept its contents, and every new entry changes the
	// directory's modification time.
	var directories []directoryAttributes

	type inodeKey struct {
		device uint64
		inode  uint64
	}
	firstPathOfInode := map[inodeKey]string{}

	err := filepath.WalkDir(source, func(sourcePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relativePath, err := filepath.Rel(source, sourcePath)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(destination, relativePath)

		// DirEntry.Info does not follow symlinks.
		info, err := entry.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		permissionBits := mode & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)

		switch {
		case mode.IsDir():
			if relativePath != "." {
				if err := os.Mkdir(targetPath, 0o700); err != nil {
					return err
				}
			}
			directories = append(directories, directoryAttributes{targetPath, permissionBits, info.ModTime()})

		case mode.IsRegular():
			if fileStat, ok := info.Sys().(*syscall.Stat_t); ok && fileStat.Nlink > 1 {
				key := inodeKey{device: fileStat.Dev, inode: fileStat.Ino}
				if firstPath, seen := firstPathOfInode[key]; seen {
					return os.Link(firstPath, targetPath)
				}
				firstPathOfInode[key] = targetPath
			}
			if err := copyFile(sourcePath, targetPath); err != nil {
				return err
			}
			if err := os.Chmod(targetPath, permissionBits); err != nil {
				return err
			}
			return os.Chtimes(targetPath, info.ModTime(), info.ModTime())

		case mode&fs.ModeSymlink != 0:
			linkTarget, err := os.Readlink(sourcePath)
			if err != nil {
				return err
			}
			return os.Symlink(linkTarget, targetPath)

		case mode&fs.ModeNamedPipe != 0:
			return unix.Mkfifo(targetPath, uint32(mode.Perm()))
		}
		return nil
	})
	if err != nil {
		return err
	}

	for index := len(directories) - 1; index >= 0; index-- {
		directory := directories[index]
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return err
		}
		if err := os.Chtimes(directory.path, directory.modTime, directory.modTime); err != nil {
			return err
		}
	}
	return nil
}

// copyFile copies the content of one regular file. The new file starts
// owner-writable; copyTree sets the real mode afterwards.
func copyFile(sourcePath, targetPath string) error {
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close() //nolint:errcheck // read only

	targetFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	// On Linux io.Copy between two files uses copy_file_range, so the data
	// does not pass through this process.
	if _, err := io.Copy(targetFile, sourceFile); err != nil {
		targetFile.Close() //nolint:errcheck // the copy error is the useful one
		return err
	}
	return targetFile.Close()
}
