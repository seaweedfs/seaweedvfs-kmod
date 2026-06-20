// SPDX-License-Identifier: GPL-2.0
/*
 * Compat feature probe — compiles only if inode_state_read_once() exists (recent
 * kernels wrapped inode->i_state in a typed struct). The top-level Makefile
 * turns a successful build of this TU into -DHAVE_INODE_STATE_READ.
 */
#include <linux/fs.h>
#include <linux/module.h>

int swvfs_probe_inode_state(struct inode *i)
{
	return inode_state_read_once(i) & I_NEW;
}

MODULE_LICENSE("GPL");
