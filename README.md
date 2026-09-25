# curimata

curimata runs a program in a Linux container **without root**. It is made
for AI coding agents and other programs that you do not fully trust.

By default, the container has **no network**. You allow each host and port
that the program may reach. You can also limit memory, processes and CPU.

```bash
# A Debian shell with no network at all
curimata run mybox

# A Debian shell that may reach the Debian mirror and one HTTPS host
curimata run -allow deb.debian.org:80 -allow api.example.com:443 mybox
```

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Build](#build)
- [Usage](#usage)
- [Network allowlist](#network-allowlist)
- [Policy file](#policy-file)
- [Resource limits](#resource-limits)
- [Stopping a container](#stopping-a-container)
- [Boxes](#boxes)
- [Images](#images)
- [How it works](#how-it-works)
- [Known limitations](#known-limitations)
- [Development](#development)

## Features

- **Rootless.** You start curimata as a normal user. Container root is your
  own user on the host.
- **Isolation.** The container has its own user, network, mount, UTS, IPC,
  PID and cgroup namespaces.
- **Reduced capabilities.** `CAP_SYS_ADMIN` and `CAP_NET_ADMIN` are not
  given. Without `CAP_NET_ADMIN`, the program cannot change its own network
  and so cannot get around the proxy.
- **Protected paths.** `/proc/kcore` and `/sys/firmware` are masked.
  `/proc/sys`, `/proc/sysrq-trigger`, `/proc/irq` and `/proc/bus` are
  read-only. `/sys` is read-only, and so is every mount below it (cgroupfs,
  debugfs, tracefs, configfs).
- **Own cgroup view.** `/sys/fs/cgroup` shows only the container's own
  cgroup, read-only. A program can read its limits (`memory.max`,
  `pids.max`, `cpu.max`) but cannot change them.
- **Network allowlist.** An HTTP proxy and a SOCKS5 proxy check each
  connection. Everything that is not on the list is refused.
- **Resource limits.** Memory, number of processes and CPU cores, through a
  systemd user scope.
- **Images.** curimata downloads OCI and Docker images from a registry.
  Docker is not necessary.
- **Boxes.** Each container name gets its own copy of the image, called a
  box. A box keeps its files between runs. Boxes never share files, and the
  image cache is never changed by a container.
- **Terminal.** An interactive shell gets a real pseudo terminal, with job
  control, Ctrl-C and window resize.
- **Exit code.** curimata returns the exit code of the program in the
  container, or 128 plus the signal number when a signal killed it (for
  example 137 after an out-of-memory kill).
- **Clean stop.** Signals to curimata go to the container. If curimata is
  killed, the kernel kills the container too.

## Requirements

| Requirement | Why | How to check |
|---|---|---|
| Linux | curimata uses Linux namespaces and cgroups. | `uname -s` |
| Unprivileged user namespaces | The container runs without root. | `unshare --user true` |
| An entry in `/etc/subuid` and `/etc/subgid` | These give the user and group IDs for the container. | `grep $USER /etc/subuid /etc/subgid` |
| cgroup v2 and a systemd user session | Only for resource limits. | `stat -fc %T /sys/fs/cgroup` shows `cgroup2fs` |
| Go 1.26 and a C compiler | Only to build. The `nsenter` part of runc uses cgo. | `go version`, `gcc --version` |

If your user has no subordinate ID range, add one:

```bash
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER
```

## Build

```bash
go build -o curimata .
```

The result is one binary. The container start uses this same binary again
(`curimata init` and `curimata netns-holder`).

## Usage

```text
curimata run [flags] [rootfs] <name> [command...]
curimata rm <name>...
```

| Argument | Meaning |
|---|---|
| `rootfs` | Optional. A directory that holds an extracted root file system. curimata uses it **in place**: the container writes into this directory. If you do not give it, the container runs in the box `<name>`. |
| `name` | The box name. It is also the host name in the container. Only one running container can have a given name. Allowed characters: letters, digits, `.`, `_`, `-`; at most 64 characters. |
| `command` | Optional. The command to run. The default is `/bin/bash`, or `/bin/sh` if the image has no bash. |

curimata uses the first argument as a rootfs only when it is a directory
that contains `bin`, `usr`, `etc` or `sbin`. Otherwise it is the container
name.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-image <ref>` | `debian:stable-slim` | The image to download when you give no rootfs. |
| `-pull` | off | Download the image again, also when it is in the cache. An existing box keeps its files. |
| `-allow <rule>` | none | Allow outbound connections. You can use it more than once. See [Network allowlist](#network-allowlist). |
| `-config <path>` | none | A JSON policy file. See [Policy file](#policy-file). |
| `-memory <MiB>` | `0` (no limit) | Memory limit in MiB. Swap is not allowed above this limit. Negative values are refused. |
| `-pids <n>` | `0` (no limit) | Maximum number of processes. Negative values are refused. |
| `-cpus <n>` | `0` (no limit) | CPU cores, for example `1.5`. From `0.01` up to the number of CPUs on the host. |
| `-no-systemd` | off | Do not use a systemd scope. You cannot set limits with this flag. |

### Examples

An interactive Alpine shell from a local rootfs, with no network:

```bash
mkdir rootfs
tar -xzf alpine-minirootfs-3.19.0-x86_64.tar.gz -C rootfs
curimata run rootfs box1
```

A command that is not interactive. The exit code goes back to your shell:

```bash
curimata run box2 /bin/sh -c 'echo hello from $(hostname); exit 3'
echo $?   # 3
```

Install packages in Debian, with limits:

```bash
curimata run -allow deb.debian.org:80 -memory 512 -pids 128 -cpus 1 box3 \
  /bin/bash -c 'apt-get update && apt-get install -y git'
```

Boxes keep their files. Remove a box to start again from the image:

```bash
curimata run -allow deb.debian.org:80 dev /bin/bash -c 'apt-get update && apt-get install -y git'
curimata run dev git --version     # git is still there
curimata run other git --version   # a different box: git is not installed
curimata rm dev other
```

Another image:

```bash
curimata run -image ubuntu:24.04 box4
curimata run -image ghcr.io/owner/image:tag box5
```

## Network allowlist

Without `-allow` rules and without a policy file with rules, the container
has only a loopback interface. It has no route, no DNS and no outbound
connections.

With at least one rule, curimata starts two proxies in the container:

| Proxy | Address in the container | Environment variables |
|---|---|---|
| HTTP (with `CONNECT`) | `127.0.0.1:3128` | `http_proxy`, `https_proxy`, `HTTP_PROXY`, `HTTPS_PROXY` |
| SOCKS5 | `127.0.0.1:1080` | `ALL_PROXY`, `all_proxy` (as `socks5h://`) |

Most tools (apt, curl, git, pip, npm) read these variables and work without
more setup.

### Rule format

| Rule | Allows |
|---|---|
| `deb.debian.org:443` | One host, one port. |
| `*.pypi.org:443` | `pypi.org` and every name below it. |
| `10.0.0.5:5432` | One IP address, one port. |
| `example.com:*` | All ports on one host. |

### What the proxy checks

- **The name, not the IP address.** The proxy checks the host name that the
  client asks for. When the IP address of a CDN changes, the name stays
  allowed. When a host is allowed by name, a program cannot reach it by
  its IP address.
- **Every request.** On a keep-alive connection, the proxy checks each HTTP
  request again, because each request names its own host.
- **HTTPS stays end to end.** For HTTPS, the client sends `CONNECT`. The proxy
  only copies bytes and cannot see the content.
- **HTTPS needs CONNECT.** A request like `GET https://…` to the proxy is
  refused, because a port-80 rule must not open port 443.

Each connection is written to stderr:

```text
curimata: network allowlist: deb.debian.org:80 example.com:443
curimata: ALLOW deb.debian.org:80
curimata: DENY  github.com:443
```

## Policy file

A policy file keeps the settings for one sandbox. Every field is optional.
Unknown fields are an error.

```json
{
  "image": "debian:stable-slim",
  "limits": { "memoryMiB": 512, "pids": 256, "cpus": 1.5 },
  "network": {
    "allow": [
      "deb.debian.org:80",
      { "host": "*.pypi.org", "ports": [443] },
      { "host": "10.0.0.5", "ports": [5432] },
      { "host": "cache.local", "ports": [] }
    ]
  }
}
```

An allow rule is a `"host:port"` string or an object with `host` and
`ports`. An empty or missing `ports` list allows all ports.

```bash
curimata run -config policy.json -allow example.com:443 box6
```

- For `image` and `limits`, a command-line flag replaces the value from the
  file.
- Allow rules from the file and from `-allow` are **added together**.

## Resource limits

An unprivileged user can set cgroup limits only through systemd. curimata
asks the systemd user instance for a transient scope named
`curimata-<name>.scope`. For this, the host must use cgroup v2 and the user
must have a systemd session (a D-Bus session bus).

You can see the limits of a running container on the host:

```bash
systemctl --user status curimata-box3.scope
```

> **Important:** If there is no systemd user session, or if you use
> `-no-systemd`, curimata refuses to start a container with limits. It
> tells you why.

## Stopping a container

curimata passes `SIGTERM`, `SIGINT`, `SIGHUP`, `SIGQUIT`, `SIGUSR1` and
`SIGUSR2` on to the program in the container. When the program ends,
curimata cleans up: it stops the proxies, removes the container state and
restores the terminal.

- The contained program is PID 1 of its PID namespace. PID 1 only gets a
  signal that it has a handler for, and most shells and programs have no
  handler for `SIGTERM`. So after `SIGTERM`, `SIGINT` or `SIGHUP`, curimata
  waits **10 seconds** and then kills the container with `SIGKILL`.
- A second `SIGTERM`, `SIGINT` or `SIGHUP` kills the container at once.
- If curimata itself is killed with `SIGKILL`, the kernel kills the
  container too. The next `run` or `rm` of that name clears the old state.

```bash
curimata run box1 /bin/sleep 600 &
kill -TERM %1     # the container is killed after 10 s; exit code 137
```

## Boxes

A box is the root file system of one container name:

```text
$XDG_DATA_HOME/curimata/boxes/<name>/rootfs   # the files of the box
$XDG_DATA_HOME/curimata/boxes/<name>/image    # the image it was made from
# default: ~/.local/share/curimata/boxes/...
```

- The first `run` of a name copies the cached image into a new box.
- Later runs of the same name use the box again. Installed packages and
  other changes stay.
- A box keeps the image it was made from. `-image` with a different image
  is refused. Remove the box first.
- `curimata rm <name>` deletes a box. It refuses a box that is running. It
  also clears the state of a container that was stopped by a signal.
- Programs in a box can create files that belong to a subordinate ID (for
  example apt's `_apt` user). Your host user cannot delete these files
  directly. `curimata rm` deletes them in a user namespace with the same ID
  map, through `newuidmap` and `newgidmap`.

A rootfs directory that you give on the command line is not a box. The
container writes into it directly, and two containers on the same directory
share it.

## Images

When you give no rootfs, curimata downloads the image and keeps it in a
cache:

```text
$XDG_DATA_HOME/curimata/images/<registry>/<repository>/<tag>/rootfs
# default: ~/.local/share/curimata/images/...
```

- A name without a registry uses Docker Hub. `debian` becomes
  `registry-1.docker.io/library/debian:latest`.
- curimata selects the image for the CPU architecture of the host.
- If the registry cannot be reached, curimata uses the cached copy.
- `-pull` downloads the image again.
- Only anonymous access is possible. Private registries do not work.
- Digest references (`image@sha256:…`) are not supported.

The container state (not the images) is in `$XDG_RUNTIME_DIR/curimata/`.

## How it works

```text
host (your user)                     container
────────────────                     ─────────────────────────────
curimata run ──── starts ──────────▶ your command (PID 1)
   │                                      │
   │  netns-holder (helper)               │ http_proxy=127.0.0.1:3128
   │   owns the user and network          │ ALL_PROXY=socks5h://127.0.0.1:1080
   │   namespaces, opens the              ▼
   │   proxy sockets in them ◀────── loopback only
   │
   └─ netguard: checks each connection
      against the allowlist, then opens
      it from the host network
```

1. With an allowlist, curimata starts a helper process. The helper makes
   the user and network namespaces, and opens the two proxy sockets in
   them.
2. The container joins these namespaces. So the proxies are on the
   container's loopback interface, and the container has no other network.
3. The proxy code runs in curimata, in the host network namespace. It opens
   each allowed connection from the host.
4. libcontainer (runc) creates the container. It stops before your command
   starts. curimata starts the proxies in this gap, and then starts your
   command.

## Known limitations

- **A box is a full copy.** Each box needs the disk space of its image.
  curimata does not use overlayfs, because a rootless overlay mount does not
  fit into the way libcontainer mounts the root file system.
- **Limits need systemd.** Without a systemd user session, you cannot set
  limits. See [Resource limits](#resource-limits).
- **No DNS in the container.** Only programs that use the proxy can resolve
  names. The proxy resolves names on the host.
- **BusyBox `wget` and HTTPS.** BusyBox `wget` (Alpine) sends
  `GET https://…` instead of `CONNECT`, and the proxy refuses it. Use
  `curl` or GNU `wget`.
- **Few commands.** There are only `run` and `rm`. There is no `list`,
  `stop` or `exec`.
- **State directory fallback.** If `XDG_RUNTIME_DIR` is not set, the
  container state goes into the same directory as the image cache.

## Development

```bash
go vet ./...
go test -race ./...
```

| File | Contents |
|---|---|
| `main.go` | Entry point, command line, run sequence |
| `container.go` | libcontainer configuration: namespaces, mounts, capabilities, ID maps |
| `cgroup.go` | cgroup and systemd scope configuration |
| `terminal.go` | Pseudo terminal between the host and the container |
| `netns.go` | Helper process that holds the namespaces |
| `netguard.go` | Allowlist, HTTP proxy and SOCKS5 proxy |
| `policy.go` | Policy file |
| `image.go` | Registry client, image cache, layer extraction |
| `dirs.go` | Data and state directories |
| `box.go` | Boxes: creation from an image, copy, `rm` |
| `removetree.go` | Deletion of files that belong to subordinate IDs |
| `signals.go` | Signal forwarding, stop timeout, exit codes |
