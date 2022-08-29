/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/fs_stack.h>
#include <linux/slab.h>
#include "sefs_kernel.h"

/**
 * sefs_d_revalidate - revalidate an sefs dentry
 * @dentry: The sefs dentry
 * @flags: lookup flags
 *
 * Called when the VFS needs to revalidate a dentry. This
 * is called whenever a name lookup finds a dentry in the
 * dcache. Most filesystems leave this as NULL, because all their
 * dentries in the dcache are valid.
 *
 * Returns 1 if valid, 0 otherwise.
 *
 */
static int sefs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry *lower_dentry = sefs_dentry_to_lower(dentry);
	int rc = 1;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	if (lower_dentry->d_flags & DCACHE_OP_REVALIDATE)
		rc = lower_dentry->d_op->d_revalidate(lower_dentry, flags);

	if (d_really_is_positive(dentry)) {
		struct inode *inode = d_inode(dentry);

		fsstack_copy_attr_all(inode, sefs_inode_to_lower(inode));
		if (!inode->i_nlink)
			return 0;
	}
	return rc;
}

struct kmem_cache *sefs_dentry_info_cache;

static void sefs_dentry_free_rcu(struct rcu_head *head)
{
	kmem_cache_free(sefs_dentry_info_cache,
		container_of(head, struct sefs_dentry_info, rcu));
}

/**
 * sefs_d_release
 * @dentry: The sefs dentry
 *
 * Called when a dentry is really deallocated.
 */
static void sefs_d_release(struct dentry *dentry)
{
	struct sefs_dentry_info *p = dentry->d_fsdata;
	if (p) {
		path_put(&p->lower_path);
		call_rcu(&p->rcu, sefs_dentry_free_rcu);
	}
}

const struct dentry_operations sefs_dops = {
	.d_revalidate = sefs_d_revalidate,
	.d_release = sefs_d_release,
};
