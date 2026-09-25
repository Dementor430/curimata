package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	// To enable device management code, import cgroups/devices package.
	// Without it, cgroup manager won't be able to set up device access rules,
	// and will fail if devices are specified in the container configuration.
	_ "github.com/opencontainers/cgroups/devices"

	"github.com/opencontainers/runc/libcontainer"
	"golang.org/x/sys/unix"

	// Required for container enter functionality.
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
)

// init is the container bootstrap entry point.
//
// libcontainer spawns the container by re-executing this binary as
// "<self> init". That second process must call libcontainer.Init() before
// main() does anything else, otherwise container.Run blocks forever.
func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		// If curimata dies, even by SIGKILL, the kernel must kill the
		// container, or it would run on without its proxies and without
		// anybody to clean it up.
		//
		// ParentDeathSignal in the container config does not reach this
		// process: runc creates it with clone(CLONE_PARENT), and a new
		// process starts without a parent death signal. So we set it here.
		// runc keeps it through its own setup, and it survives the exec of
		// the contained command. Our parent is curimata itself.
		_ = unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0)
		libcontainer.Init()
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case holderCommand, holderStage2:
		runHolderStage := runNetnsHolderStage1
		if os.Args[1] == holderStage2 {
			runHolderStage = runNetnsHolder
		}
		if err := runHolderStage(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "curimata "+os.Args[1]+":", err)
			os.Exit(1)
		}
		os.Exit(0)
	case removeTreeCommand, removeTreeStage2:
		runRemoveStage := runRemoveTreeStage1
		if os.Args[1] == removeTreeStage2 {
			runRemoveStage = runRemoveTree
		}
		if err := runRemoveStage(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "curimata "+os.Args[1]+":", err)
			os.Exit(1)
		}
		os.Exit(0)
	case "rm":
		if err := removeBoxes(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "curimata:", err)
			os.Exit(1)
		}
		os.Exit(0)
	case "run":
		exitCode, err := startAgentEnvironment(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "curimata:", err)
			os.Exit(1)
		}
		os.Exit(exitCode)
	default:
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Println("curimata run [flags] [rootfs] <name> [command...]  Launch your agent in the sandbox")
	fmt.Println("  [rootfs]   directory holding an extracted root filesystem, used in place;")
	fmt.Println("             leave it out to run in the box <name>, made from the image")
	fmt.Println("  <name>     box name, also used as the hostname; a box keeps its files")
	fmt.Println("  [command]  command to run inside; default /bin/bash, else /bin/sh")
	fmt.Println("flags:")
	fmt.Println("  -image <ref>    image to download, default " + defaultImage)
	fmt.Println("  -pull           download the image again, even when it is cached")
	fmt.Println("  -allow <rule>   allow outbound connections; repeatable; default none")
	fmt.Println("                  host:port, *.domain:port, address:port, host:*")
	fmt.Println("  -config <path>  JSON policy file; flags win, allow rules add up")
	fmt.Println("  -memory <MiB>   memory limit; 0 means no limit")
	fmt.Println("  -pids <n>       maximum number of processes; 0 means no limit")
	fmt.Println("  -cpus <n>       CPU cores, 0.01 up to the host's count; 0 means no limit")
	fmt.Println("  -no-systemd     no systemd scope; limits are then refused")
	fmt.Println()
	fmt.Println("curimata rm <name>...  Delete boxes and their files")
}

// stringList collects a flag that may be given more than once.
type stringList []string

// String returns all collected values, separated by spaces.
// The flag package calls it to show the default value.
func (list *stringList) String() string {
	return strings.Join(*list, " ")
}

// Set adds one value. The flag package calls it once for each time the
// flag occurs on the command line.
func (list *stringList) Set(value string) error {
	*list = append(*list, value)
	return nil
}

// loadAllowlist joins the rules from the policy file and from the command
// line. It returns nil when neither gave a rule, which leaves the container
// with no outbound network at all.
func loadAllowlist(commandLineRules stringList, policyFile *policy) (*allowlist, error) {
	var ruleSpecs []string
	if policyFile != nil {
		ruleSpecs = append(ruleSpecs, policyFile.Network.specs()...)
	}
	ruleSpecs = append(ruleSpecs, commandLineRules...)
	if len(ruleSpecs) == 0 {
		return nil, nil //nolint:nilnil // no rules means no network
	}
	return parseAllowlist(ruleSpecs)
}

// runOptions is the parsed command line of "curimata run".
type runOptions struct {
	resourceLimits limits
	rootfs         string
	name           string
	command        []string
	// allow is nil when no rule was given: the container gets no network.
	allow *allowlist
	// boxLock holds the lock of name until curimata exits.
	boxLock *os.File
}

func startAgentEnvironment(commandLineArgs []string) (int, error) {
	options, err := parseRunArgs(commandLineArgs)
	if err != nil {
		return 0, err
	}
	// Deferred first, so it runs last: the name stays locked until every
	// other cleanup, including the container state, is done.
	defer options.boxLock.Close() //nolint:errcheck // the lock only has to last until here

	// The helper must exist before the container config is built: the
	// container joins the helper's namespaces by path.
	var namespaceHolder *netnsHolder
	if options.allow != nil {
		namespaceHolder, err = startNetnsHolder([]string{socksAddr, httpAddr})
		if err != nil {
			return 0, err
		}
		defer namespaceHolder.stop()
	}

	container, err := createContainer(options, namespaceHolder)
	if err != nil {
		return 0, err
	}
	defer container.Destroy() //nolint:errcheck // best effort cleanup

	// Catch signals from here on. Until the container runs they only wait
	// in the channel; the deferred cleanup above must still run.
	signals := catchSignals()
	defer signals.stop()

	process := &libcontainer.Process{
		Args: options.command,
		Env:  containerEnv(options.allow != nil),
		UID:  0,
		GID:  0,
		Cwd:  "/",
		Init: true,
	}

	interactiveTerminal, err := newTerminal(process)
	if err != nil {
		return 0, err
	}
	if interactiveTerminal == nil {
		// Our streams are not a terminal, so pass them straight through.
		process.Stdin, process.Stdout, process.Stderr = os.Stdin, os.Stdout, os.Stderr
	}

	// Start creates the container and leaves its init process waiting. That
	// gap is where we set up the network, before any command of yours runs.
	if err := container.Start(process); err != nil {
		return 0, fmt.Errorf("start container: %w", err)
	}
	signals.forwardTo(process)

	if namespaceHolder != nil {
		logPath, err := openNetlog(options.name)
		if err != nil {
			return 0, err
		}
		defer closeNetlog()
		networkGuard := startNetguard(namespaceHolder.listeners, options.allow)
		defer networkGuard.close()
		netlogf("network allowlist: %s", options.allow)
		netlogf("network log: %s (denied connections also show here)", logPath)
	}

	if interactiveTerminal != nil {
		if err := interactiveTerminal.attach(); err != nil {
			return 0, err
		}
		defer interactiveTerminal.close()
	}

	// Release the init process, so that your command starts now.
	if err := container.Exec(); err != nil {
		return 0, fmt.Errorf("release container: %w", err)
	}

	// Wait reports a non-zero exit of the contained process as an error, but
	// it still returns the process processState. Only a nil processState is a real failure.
	processState, err := process.Wait()
	if processState == nil {
		return 0, fmt.Errorf("wait for container: %w", err)
	}
	return exitCodeOf(processState), nil
}

// parseRunArgs reads the flags, the policy file and the positional
// arguments of "curimata run". It downloads the image when no rootfs is
// given.
func parseRunArgs(commandLineArgs []string) (*runOptions, error) {
	var (
		options    runOptions
		image      string
		repull     bool
		allowArgs  stringList
		configPath string
	)
	flagSet := flag.NewFlagSet("run", flag.ContinueOnError)
	flagSet.StringVar(&image, "image", defaultImage, "image to download when no rootfs is given")
	flagSet.BoolVar(&repull, "pull", false, "download the image again, even when it is cached")
	flagSet.Var(&allowArgs, "allow", "allow outbound connections to host:port; repeatable")
	flagSet.StringVar(&configPath, "config", "", "JSON policy file")
	flagSet.Int64Var(&options.resourceLimits.memoryMiB, "memory", 0, "memory limit in MiB")
	flagSet.Int64Var(&options.resourceLimits.pids, "pids", 0, "maximum number of processes")
	flagSet.Float64Var(&options.resourceLimits.cpus, "cpus", 0, "CPU cores the container may use")
	flagSet.BoolVar(&options.resourceLimits.noSystemd, "no-systemd", false, "do not use a systemd scope")
	flagSet.Usage = printUsage
	if err := flagSet.Parse(commandLineArgs); err != nil {
		return nil, err
	}

	// Remember which flags the command line really carried, so that the
	// policy file fills only the gaps.
	given := map[string]bool{}
	flagSet.Visit(func(setFlag *flag.Flag) {
		given[setFlag.Name] = true
	})

	var err error
	var policyFile *policy
	if configPath != "" {
		policyFile, err = loadPolicy(configPath)
		if err != nil {
			return nil, err
		}
		policyFile.apply(given, &image, &options.resourceLimits)
	}

	positionalArgs := flagSet.Args()
	if len(positionalArgs) == 0 {
		printUsage()
		return nil, errors.New("run needs a container name")
	}

	if err := options.resourceLimits.check(runtime.NumCPU()); err != nil {
		return nil, err
	}
	if err := options.resourceLimits.requireScope(options.resourceLimits.systemdScope()); err != nil {
		return nil, err
	}

	imageChosen := given["image"] || (policyFile != nil && policyFile.Image != "")
	options.rootfs, positionalArgs, options.boxLock, err = resolveRootfs(positionalArgs, image, imageChosen, repull)
	if err != nil {
		return nil, err
	}

	options.name = positionalArgs[0]
	options.command = positionalArgs[1:]
	warnFlagAfterName(flagSet, options.name, options.command)
	if len(options.command) == 0 {
		options.command = []string{defaultShell(options.rootfs)}
	}

	options.allow, err = loadAllowlist(allowArgs, policyFile)
	if err != nil {
		options.boxLock.Close() //nolint:errcheck // the allowlist error is the useful one
		return nil, err
	}
	return &options, nil
}

// warnFlagAfterName warns when the command starts with a flag of "run".
// The flag package stops at the container name, so such a flag goes to the
// container as its command and curimata ignores it.
func warnFlagAfterName(flagSet *flag.FlagSet, name string, command []string) {
	if len(command) == 0 || !strings.HasPrefix(command[0], "-") {
		return
	}
	flagName, _, _ := strings.Cut(strings.TrimLeft(command[0], "-"), "=")
	if flagSet.Lookup(flagName) == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "curimata: warning: %s comes after the name %q, so it is the container's command, not a flag; put flags before the name\n", command[0], name)
}

// resolveRootfs returns the absolute rootfs path and the arguments that
// follow it, starting with the container name.
//
// The first argument is a rootfs only when it is a directory that holds
// one. That directory is used in place. Otherwise the first argument is the
// container name, and the container runs in the box of that name, which is
// made from the image on the first run.
//
// It also returns the lock of the container name, taken before the box is
// touched. The caller holds it until curimata exits.
func resolveRootfs(positionalArgs []string, image string, imageChosen, repull bool) (string, []string, *os.File, error) {
	if len(positionalArgs) >= 2 && looksLikeRootfs(positionalArgs[0]) {
		if err := validateBoxName(positionalArgs[1]); err != nil {
			return "", nil, nil, err
		}
		boxLock, err := lockBox(positionalArgs[1])
		if err != nil {
			return "", nil, nil, err
		}
		absolutePath, err := filepath.Abs(positionalArgs[0])
		if err != nil {
			boxLock.Close() //nolint:errcheck // the path error is the useful one
			return "", nil, nil, fmt.Errorf("resolve rootfs: %w", err)
		}
		return absolutePath, positionalArgs[1:], boxLock, nil
	}
	if err := validateBoxName(positionalArgs[0]); err != nil {
		return "", nil, nil, err
	}
	boxLock, err := lockBox(positionalArgs[0])
	if err != nil {
		return "", nil, nil, err
	}
	boxRootfs, err := prepareBox(positionalArgs[0], image, imageChosen, repull)
	if err != nil {
		boxLock.Close() //nolint:errcheck // the box error is the useful one
		return "", nil, nil, err
	}
	return boxRootfs, positionalArgs, boxLock, nil
}

// createContainer builds the container config and registers the container
// with libcontainer. The container does not run yet.
func createContainer(options *runOptions, namespaceHolder *netnsHolder) (*libcontainer.Container, error) {
	config, err := containerConfig(options.rootfs, options.name, options.resourceLimits, namespaceHolder)
	if err != nil {
		return nil, err
	}

	stateDirectory, err := stateDir()
	if err != nil {
		return nil, err
	}

	container, err := libcontainer.Create(stateDirectory, options.name, config)
	if errors.Is(err, libcontainer.ErrExist) {
		// A container that was killed leaves its state behind. If it no
		// longer runs, clear the state and try once more.
		if _, clearErr := clearStoppedContainer(stateDirectory, options.name); clearErr != nil {
			return nil, clearErr
		}
		container, err = libcontainer.Create(stateDirectory, options.name, config)
	}
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}
	return container, nil
}

// containerEnv returns the environment of the contained process. With a
// network allowlist it also points the process at the proxy.
func containerEnv(proxied bool) []string {
	terminalType := os.Getenv("TERM")
	if terminalType == "" {
		terminalType = "xterm"
	}
	environment := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=" + terminalType,
		"HOME=/root",
	}
	if proxied {
		environment = append(environment, proxyEnv()...)
	}
	return environment
}

// looksLikeRootfs reports whether path is a directory that holds a root
// filesystem. We check for the usual top level directories, so that a
// container name does not become a rootfs by accident.
func looksLikeRootfs(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil || !fileInfo.IsDir() {
		return false
	}
	for _, topLevelDir := range []string{"bin", "usr", "etc", "sbin"} {
		if _, err := os.Stat(filepath.Join(path, topLevelDir)); err == nil {
			return true
		}
	}
	return false
}

// defaultShell picks the best shell that the rootfs actually has. Debian has
// bash. Alpine has only the busybox /bin/sh.
func defaultShell(rootfs string) string {
	for _, shell := range []string{"/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(filepath.Join(rootfs, shell)); err == nil {
			return shell
		}
	}
	return "/bin/sh"
}
