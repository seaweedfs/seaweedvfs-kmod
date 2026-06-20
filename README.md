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

## Build

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
