// SPDX-License-Identifier: GPL-2.0
/*
 * Compat feature probe — compiles only on kernels whose ->d_revalidate() takes
 * the parent inode + name:
 *   int (*)(struct inode *dir, const struct qstr *name,
 *           struct dentry *dentry, unsigned int flags)
 * (older kernels: int (*)(struct dentry *, unsigned int)). A _Static_assert on
 * the member type makes the old signature a hard compile error regardless of the
 * build's warning level or compiler — gcc and clang split the function-pointer
 * mismatch into different -W flags, so warning-as-error can't be relied on. The
 * top-level Makefile turns a successful build into -DHAVE_D_REVALIDATE_DIR.
 */
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/module.h>

typedef int (*swvfs_d_revalidate_dir_t)(struct inode *, const struct qstr *,
					struct dentry *, unsigned int);

_Static_assert(__builtin_types_compatible_p(
		       typeof(((struct dentry_operations *)0)->d_revalidate),
		       swvfs_d_revalidate_dir_t),
	       "d_revalidate takes (dir, name, dentry, flags)");

MODULE_LICENSE("GPL");
