// SPDX-License-Identifier: GPL-2.0
/*
 * Compat feature probe — compiles only on kernels that renamed the no-perm
 * single-component lookup helper and switched it to a qstr:
 *   lookup_one_len_unlocked(name, base, len)
 *     -> lookup_noperm_unlocked(struct qstr *, base)
 * The top-level Makefile turns a successful build into -DHAVE_LOOKUP_NOPERM.
 */
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/module.h>

/* static __maybe_unused: a missing lookup_noperm_unlocked() still fails to
 * compile (implicit-decl error), but -Wmissing-prototypes/-Wunused can't make a
 * present one falsely fail under CONFIG_WERROR. */
static __maybe_unused struct dentry *
swvfs_probe_lookup_noperm(struct dentry *base, const char *name)
{
	return lookup_noperm_unlocked(&QSTR(name), base);
}

MODULE_LICENSE("GPL");
