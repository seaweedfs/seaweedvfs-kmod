# seaweedvfs — SeaweedFS kernel VFS module

`seaweedvfs` is a Linux kernel filesystem client for [SeaweedFS](https://github.com/seaweedfs/seaweedfs):
a real `mount -t seaweedvfs` filesystem. The kernel module owns the VFS (inodes,
dentries, page cache) and does **zero networking**; all SeaweedFS I/O is handled
by a userspace daemon over the `/dev/seaweedvfs` character device (the WEKA-style
thin-module / fat-daemon split).

This repository contains **only the GPL kernel module** (`seaweedvfs.ko`). It does
not, by itself, give you a working mount — the userspace daemon that drives the
device is a separate component, available with SeaweedFS. The module is published
here as the corresponding source for the GPL-licensed `.ko` we ship.

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
toolchain (`make`, `gcc`). Targets recent (6.x) kernels.

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

## Source

This is a published mirror, kept in sync per release with the canonical source.
Issues and SeaweedFS as a whole: <https://github.com/seaweedfs/seaweedfs>.
