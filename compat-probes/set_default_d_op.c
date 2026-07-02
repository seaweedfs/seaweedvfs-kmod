// SPDX-License-Identifier: GPL-2.0
/*
 * Compat feature probe — compiles only on kernels where sb->s_d_op became
 * private and the default dentry_operations are installed via
 * set_default_d_op() instead. The top-level Makefile turns a successful build
 * into -DHAVE_SET_DEFAULT_D_OP.
 */
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/module.h>

/* static __maybe_unused: a missing set_default_d_op() still fails to compile
 * (implicit-decl error), but -Wmissing-prototypes/-Wunused can't make a
 * present one falsely fail under CONFIG_WERROR. */
static __maybe_unused void
swvfs_probe_set_default_d_op(struct super_block *sb,
			     const struct dentry_operations *ops)
{
	set_default_d_op(sb, ops);
}

MODULE_LICENSE("GPL");
