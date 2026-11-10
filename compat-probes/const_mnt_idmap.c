// SPDX-License-Identifier: GPL-2.0
/*
 * Compat feature probe — compiles only on kernels whose inode-op hooks take a
 * const idmap (older kernels: struct mnt_idmap *). The _Static_assert makes the
 * old signature a hard compile error — see d_revalidate_dir.c. The top-level
 * Makefile turns a successful build into -DHAVE_CONST_MNT_IDMAP.
 */
#include <linux/fs.h>
#include <linux/module.h>

typedef int (*swvfs_const_idmap_setattr_t)(const struct mnt_idmap *,
					   struct dentry *, struct iattr *);

_Static_assert(__builtin_types_compatible_p(
		       typeof(((struct inode_operations *)0)->setattr),
		       swvfs_const_idmap_setattr_t),
	       "->setattr takes a const struct mnt_idmap *");

MODULE_LICENSE("GPL");
