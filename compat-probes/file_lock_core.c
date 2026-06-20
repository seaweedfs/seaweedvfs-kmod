// SPDX-License-Identifier: GPL-2.0
/*
 * Compat feature probe — compiles only if struct file_lock has the embedded
 * file_lock_core (fl->c.flc_*) and lock_is_unlock() (~6.10). The top-level
 * Makefile turns a successful build into -DHAVE_FILE_LOCK_CORE.
 */
#include <linux/fs.h>
#if __has_include(<linux/filelock.h>)
#include <linux/filelock.h>
#endif
#include <linux/module.h>

int swvfs_probe_flc(struct file_lock *fl)
{
	return lock_is_unlock(fl) + fl->c.flc_type;
}

MODULE_LICENSE("GPL");
