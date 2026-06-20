# SeaweedFS kernel VFS module

[![kernel build matrix](https://github.com/seaweedfs/seaweedvfs-kmod/actions/workflows/build-matrix.yml/badge.svg)](https://github.com/seaweedfs/seaweedvfs-kmod/actions/workflows/build-matrix.yml)

`seaweedvfs` is a Linux kernel filesystem client for [SeaweedFS](https://github.com/seaweedfs/seaweedfs):
a real `mount -t seaweedvfs` filesystem. The kernel module owns the VFS (inodes,
dentries, page cache) and does **zero networking**; all SeaweedFS I/O is handled
by a userspace daemon over the `/dev/seaweedvfs` character device.

This repository contains the GPL-2.0 kernel module (`seaweedvfs.ko`). The module
does not, by itself, give you a working mount — the userspace daemon that drives
`/dev/seaweedvfs` is a separate component, available with SeaweedFS.

## Supported kernels

The [build matrix CI](.github/workflows/build-matrix.yml) validates every commit
across the following kernels:

| Kernel | Distro | Status |
|--------|--------|--------|
| 6.1 LTS | Debian 12 (bookworm) | required |
| 6.8 | Ubuntu 24.04 | required |
| 6.12 | Debian 13 (trixie), RHEL 10 | required |
| 7.0 | Debian sid | required |
| newest | Fedora rawhide | canary (non-blocking) |

## License

GPL-2.0 — see [`LICENSE`](LICENSE). Each source file carries an
`SPDX-License-Identifier: GPL-2.0` tag.

## Install

Pre-built packages are published per release at
**[seaweedfs/artifactory releases](https://github.com/seaweedfs/artifactory/releases)**.
You usually don't build by hand — pick one of these. (Each path also installs the
separate userspace `sw-kd` daemon; the module alone does not give you a mount.)

### One-line installer (easiest)

Detects your package manager (apt/dnf/yum/zypper) and arch, installs the module
(via DKMS) + the daemon, and can configure a filer in one shot:

```sh
curl -fsSL https://raw.githubusercontent.com/seaweedfs/artifactory/main/seaweed-vfs/install.sh \
  | sudo FILER=10.0.0.1:18888 bash
```

Useful env vars: `SEAWEEDFS_VFS_KMOD=1` (install a precompiled `.ko` for *this*
exact kernel instead of DKMS — no toolchain needed, for fleets / hardened hosts),
`SEAWEEDFS_VFS_UPGRADE=1` (in-place upgrade), `SEAWEEDFS_VFS_RELEASE` (default
`vfs-latest`), `SEAWEEDFS_VFS_BASE_URL` (mirror your own download point).

### Pre-built packages (manual)

Three packages per release — pick **one** module package + the daemon:

| Package | What | When |
|---------|------|------|
| `seaweedfs-vfs-dkms` (noarch) | module **source**; DKMS rebuilds it per kernel | varied / changing kernels |
| `seaweedfs-vfs-kmod-<kver>` | **precompiled** `.ko` for one exact kernel | pinned-kernel fleets, no toolchain |
| `seaweedfs-vfs` (per arch) | the `sw-kd` userspace daemon | always |

```sh
# Debian / Ubuntu — DKMS module + daemon
sudo apt install ./seaweedfs-vfs-dkms_<ver>_all.deb ./seaweedfs-vfs_<ver>_amd64.deb
# ...or a precompiled module (no compiler/headers on the box):
sudo apt install --no-install-recommends \
  ./seaweedfs-vfs-kmod-$(uname -r)_amd64.deb ./seaweedfs-vfs_<ver>_amd64.deb

# RHEL / Fedora  (on SUSE swap `dnf` -> `zypper install`)
sudo dnf install ./seaweedfs-vfs-dkms-<ver>.noarch.rpm ./seaweedfs-vfs-<ver>.x86_64.rpm
```

### Kubernetes / immutable hosts

A container shares the **host** kernel, so the module always loads there. Ready-made
node images (`ghcr.io/seaweedfs/seaweedfs-vfs`) run as a privileged DaemonSet that
loads the module, runs the daemon, and mounts on each node:

- `:<ver>` — loads the module from the host's `/lib/modules` (DKMS / kmod package).
- `:<ver>-k<kver>` — a vermagic-matching `.ko` baked in, for nodes with no package
  manager (non-Secure-Boot **Talos**, **Flatcar**, **Fedora CoreOS**).

On **Secure Boot** Talos the kernel rejects unsigned modules, so ship a signed
**Talos system extension** instead. See the SeaweedFS VFS packaging docs
(`packaging/k8s`, `packaging/talos`) for manifests and the extension build.

### Manual install of a bare `.ko`

If you have just a `seaweedvfs.ko` (built yourself, or pulled from an image):

```sh
sudo install -D seaweedvfs.ko /lib/modules/$(uname -r)/extra/seaweedvfs.ko
sudo depmod -a
sudo modprobe seaweedvfs               # udev then creates /dev/seaweedvfs
```

Under **Secure Boot**, `modprobe` fails with *"Key was rejected by service"* unless
the `.ko` is signed by an enrolled key — sign it with the kernel's `sign-file`
(shipped with the kernel headers at `/lib/modules/$(uname -r)/build/scripts/sign-file`)
using a key you `mokutil --import` once, or use the DKMS package (it signs with a
per-box MOK key and prompts you to enroll it).

## Build from source

Out-of-tree, against the running kernel's headers:

```sh
make                                  # builds seaweedvfs.ko
sudo insmod seaweedvfs.ko             # udev then creates /dev/seaweedvfs
# ... run the SeaweedFS userspace daemon, then:
sudo mount -t seaweedvfs none /mnt/seaweed
sudo rmmod seaweedvfs                 # to unload
```

Requires the kernel headers/build tree for your running kernel
(`linux-headers-$(uname -r)` on Debian/Ubuntu, `kernel-devel` on RHEL/SUSE) and a
toolchain (`make`, `gcc`). Supported kernels: 6.1 LTS → current (see table above).

### DKMS

`dkms.conf` is included so the module rebuilds automatically across kernel
upgrades:

```sh
sudo cp -r . /usr/src/seaweedfs-vfs-<version>/
sudo dkms add -m seaweedfs-vfs -v <version>
sudo dkms build -m seaweedfs-vfs -v <version>
sudo dkms install -m seaweedfs-vfs -v <version>
```

## Module parameters

- `distributed_locks=1` — route advisory (flock/POSIX) locks through the filer's
  lock service so they are honoured across mounts/clients (off by default; pair
  with the daemon's `--distributed-locks`).

Issues and the rest of SeaweedFS: <https://github.com/seaweedfs/seaweedfs>.
