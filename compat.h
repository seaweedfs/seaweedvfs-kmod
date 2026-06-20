/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel-version compatibility shims for seaweedvfs.
 *
 * The Linux in-kernel API is not stable: VFS hook signatures and helpers change
 * between releases. This header isolates those differences so the rest of the
 * module stays version-agnostic. Each shim is one self-contained unit, so the
 * complexity grows with the number of *changed APIs*, not the number of kernels.
 *
 * Supported range: 6.1 LTS .. current mainline. The kernel build matrix
 * (.github/workflows/) compiles the module against each target kernel and is the
 * source of truth for what is actually supported — when a build there breaks,
 * add the shim here.
 *
 * Policy: LINUX_VERSION_CODE guards are fine for *mainline* API changes (version
 * numbers are reliable there). Enterprise distros (RHEL/SLES) backport features
 * into older version numbers, so for those add a Makefile compile-test
 * ("does symbol X exist?") instead of a version check — version numbers lie.
 */
#ifndef _SWVFS_COMPAT_H
#define _SWVFS_COMPAT_H

#include <linux/version.h>

/*
 * 6.13: inode_operations->mkdir returns `struct dentry *` instead of `int`
 * (NULL keeps the passed-in dentry, ERR_PTR(err) signals failure).
 * commit cd3e8c0c50a0e ("fs: change the signature of ->mkdir").
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
# define SWVFS_MKDIR_RET          struct dentry *
# define SWVFS_MKDIR_RESULT(err)  ((err) ? ERR_PTR(err) : NULL)
#else
# define SWVFS_MKDIR_RET          int
# define SWVFS_MKDIR_RESULT(err)  (err)
#endif

#endif /* _SWVFS_COMPAT_H */
