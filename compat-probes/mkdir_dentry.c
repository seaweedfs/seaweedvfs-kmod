// SPDX-License-Identifier: GPL-2.0
/*
 * Compat feature probe — compiles only on kernels whose ->mkdir() returns
 * struct dentry * instead of int ("fs: change the signature of ->mkdir").
 * Enterprise distros backport it below 6.13 (RHEL 10's 6.12), so the version
 * guard alone misses them. The _Static_assert makes the old signature a hard
 * compile error — see d_revalidate_dir.c. Either idmap qualification counts
 * (see const_mnt_idmap.c). The top-level Makefile turns a successful build into
 * -DHAVE_MKDIR_DENTRY.
 */
#include <linux/fs.h>
#include <linux/module.h>

typedef struct dentry *(*swvfs_mkdir_dentry_t)(struct mnt_idmap *,
					       struct inode *, struct dentry *,
					       umode_t);
typedef struct dentry *(*swvfs_mkdir_dentry_const_t)(const struct mnt_idmap *,
						     struct inode *,
						     struct dentry *, umode_t);

_Static_assert(__builtin_types_compatible_p(
		       typeof(((struct inode_operations *)0)->mkdir),
		       swvfs_mkdir_dentry_t) ||
	       __builtin_types_compatible_p(
		       typeof(((struct inode_operations *)0)->mkdir),
		       swvfs_mkdir_dentry_const_t),
	       "->mkdir returns struct dentry *");

MODULE_LICENSE("GPL");
