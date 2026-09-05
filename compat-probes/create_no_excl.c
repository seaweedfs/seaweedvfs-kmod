// SPDX-License-Identifier: GPL-2.0
/*
 * Compat feature probe — compiles only on kernels whose ->create() dropped the
 * trailing "is this O_EXCL?" boolean:
 *   int (*)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t)
 * (older kernels take a trailing bool excl). vfs_create() has passed excl=true
 * unconditionally since lookup_open() stopped calling it, so the argument was
 * removed ("vfs: remove the excl argument from the ->create() inode_operation").
 * A _Static_assert on the member type makes the old signature a hard compile
 * error regardless of the build's warning level or compiler — see
 * d_revalidate_dir.c. The top-level Makefile turns a successful build into
 * -DHAVE_CREATE_NO_EXCL.
 */
#include <linux/fs.h>
#include <linux/module.h>

typedef int (*swvfs_create_no_excl_t)(struct mnt_idmap *, struct inode *,
				      struct dentry *, umode_t);

_Static_assert(__builtin_types_compatible_p(
		       typeof(((struct inode_operations *)0)->create),
		       swvfs_create_no_excl_t),
	       "->create takes (idmap, dir, dentry, mode)");

MODULE_LICENSE("GPL");
