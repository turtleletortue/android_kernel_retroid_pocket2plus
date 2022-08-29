/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2004 Erez Zadok
 * Copyright (C) 2001-2004 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Michael C. Thompsion <mcthomps@us.ibm.com>
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

#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/fs_stack.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <asm/unaligned.h>
#include "sefs_kernel.h"

static struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir;

	dir = dget_parent(dentry);
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	return dir;
}

static void unlock_dir(struct dentry *dir)
{
	inode_unlock(d_inode(dir));
	dput(dir);
}

static int sefs_inode_test(struct inode *inode, void *lower_inode)
{
	return sefs_inode_to_lower(inode) == lower_inode;
}

static int sefs_inode_set(struct inode *inode, void *opaque)
{
	struct inode *lower_inode = opaque;

	sefs_set_inode_lower(inode, lower_inode);
	fsstack_copy_attr_all(inode, lower_inode);
	/* i_size will be overwritten for encrypted regular files */
	fsstack_copy_inode_size(inode, lower_inode);
	inode->i_ino = lower_inode->i_ino;
	inode->i_version++;
	inode->i_mapping->a_ops = &sefs_aops;

	if (S_ISLNK(inode->i_mode))
		inode->i_op = &sefs_symlink_iops;
	else if (S_ISDIR(inode->i_mode))
		inode->i_op = &sefs_dir_iops;
	else
		inode->i_op = &sefs_main_iops;

	if (S_ISDIR(inode->i_mode))
		inode->i_fop = &sefs_dir_fops;
	else if (special_file(inode->i_mode))
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
	else
		inode->i_fop = &sefs_main_fops;

	return 0;
}

static struct inode *__sefs_get_inode(struct inode *lower_inode,
					  struct super_block *sb)
{
	struct inode *inode;

	if (lower_inode->i_sb != sefs_superblock_to_lower(sb))
		return ERR_PTR(-EXDEV);
	if (!igrab(lower_inode))
		return ERR_PTR(-ESTALE);
	inode = iget5_locked(sb, (unsigned long)lower_inode,
			     sefs_inode_test, sefs_inode_set,
			     lower_inode);
	if (!inode) {
		iput(lower_inode);
		return ERR_PTR(-EACCES);
	}
	if (!(inode->i_state & I_NEW))
		iput(lower_inode);

	return inode;
}

struct inode *sefs_get_inode(struct inode *lower_inode,
				 struct super_block *sb)
{
	struct inode *inode = __sefs_get_inode(lower_inode, sb);

	if (!IS_ERR(inode) && (inode->i_state & I_NEW))
		unlock_new_inode(inode);

	return inode;
}

/**
 * sefs_interpose
 * @lower_dentry: Existing dentry in the lower filesystem
 * @dentry: sefs' dentry
 * @sb: sefs's super_block
 *
 * Interposes upper and lower dentries.
 *
 * Returns zero on success; non-zero otherwise
 */
static int sefs_interpose(struct dentry *lower_dentry,
			      struct dentry *dentry, struct super_block *sb)
{
	struct inode *inode = sefs_get_inode(d_inode(lower_dentry), sb);

	if (IS_ERR(inode))
		return PTR_ERR(inode);
	d_instantiate(dentry, inode);

	return 0;
}

static int sefs_do_unlink(struct inode *dir, struct dentry *dentry,
			      struct inode *inode)
{
	struct dentry *lower_dentry = sefs_dentry_to_lower(dentry);
	struct inode *lower_dir_inode = sefs_inode_to_lower(dir);
	struct dentry *lower_dir_dentry;
	int rc;

	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
	if (rc) {
		printk(KERN_ERR "Error in vfs_unlink; rc = [%d]\n", rc);
		goto out_unlock;
	}
	fsstack_copy_attr_times(dir, lower_dir_inode);
	set_nlink(inode, sefs_inode_to_lower(inode)->i_nlink);
	inode->i_ctime = dir->i_ctime;
	d_drop(dentry);
out_unlock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	return rc;
}

/**
 * sefs_do_create
 * @directory_inode: inode of the new file's dentry's parent in sefs
 * @sefs_dentry: New file's dentry in sefs
 * @mode: The mode of the new file
 *
 * Creates the underlying file and the eCryptfs inode which will link to
 * it. It will also update the eCryptfs directory inode to mimic the
 * stat of the lower directory inode.
 *
 * Returns the new eCryptfs inode on success; an ERR_PTR on error condition
 */
static struct inode *
sefs_do_create(struct inode *directory_inode,
		   struct dentry *sefs_dentry, umode_t mode)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	struct inode *inode;

	lower_dentry = sefs_dentry_to_lower(sefs_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_create(d_inode(lower_dir_dentry), lower_dentry, mode, true);
	if (rc) {
		printk(KERN_ERR "%s: Failure to create dentry in lower fs; "
		       "rc = [%d]\n", __func__, rc);
		inode = ERR_PTR(rc);
		goto out_lock;
	}
	inode = __sefs_get_inode(d_inode(lower_dentry),
				     directory_inode->i_sb);
	if (IS_ERR(inode)) {
		vfs_unlink(d_inode(lower_dir_dentry), lower_dentry, NULL);
		goto out_lock;
	}
	fsstack_copy_attr_times(directory_inode, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(directory_inode, d_inode(lower_dir_dentry));
out_lock:
	unlock_dir(lower_dir_dentry);
	return inode;
}

/**
 * sefs_initialize_file
 *
 * Cause the file to be changed from a basic empty file to an sefs
 * file with a header and first data page.
 *
 * Returns zero on success
 */
int sefs_initialize_file(struct dentry *sefs_dentry,
			     struct inode *sefs_inode)
{
	struct sefs_crypt_stat *crypt_stat =
		&sefs_inode_to_private(sefs_inode)->crypt_stat;
	int rc = 0;

	if (S_ISDIR(sefs_inode->i_mode)) {
		sefs_printk(KERN_DEBUG, "This is a directory\n");
		crypt_stat->flags &= ~(SEFS_ENCRYPTED);
		goto out;
	}
	sefs_printk(KERN_DEBUG, "Initializing crypto context\n");
	rc = sefs_new_file_context(sefs_inode);
	if (rc) {
		sefs_printk(KERN_ERR, "Error creating new file "
				"context; rc = [%d]\n", rc);
		goto out;
	}
	rc = sefs_get_lower_file(sefs_dentry, sefs_inode);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to initialize "
			"the lower file for the dentry with name "
			"[%pd]; rc = [%d]\n", __func__,
			sefs_dentry, rc);
		goto out;
	}
	rc = sefs_write_metadata(sefs_dentry, sefs_inode);
	if (rc)
		printk(KERN_ERR "Error writing headers; rc = [%d]\n", rc);
	sefs_put_lower_file(sefs_inode);
out:
	return rc;
}

/**
 * sefs_create
 * @dir: The inode of the directory in which to create the file.
 * @dentry: The eCryptfs dentry
 * @mode: The mode of the new file.
 *
 * Creates a new file.
 *
 * Returns zero on success; non-zero on error condition
 */
static int
sefs_create(struct inode *directory_inode, struct dentry *sefs_dentry,
		umode_t mode, bool excl)
{
	struct inode *sefs_inode;
	int rc;

	sefs_inode = sefs_do_create(directory_inode, sefs_dentry,
					    mode);
	if (IS_ERR(sefs_inode)) {
		sefs_printk(KERN_WARNING, "Failed to create file in"
				"lower filesystem\n");
		rc = PTR_ERR(sefs_inode);
		goto out;
	}
	/* At this point, a file exists on "disk"; we need to make sure
	 * that this on disk file is prepared to be an sefs file */
	rc = sefs_initialize_file(sefs_dentry, sefs_inode);
	if (rc) {
		sefs_do_unlink(directory_inode, sefs_dentry,
				   sefs_inode);
		iget_failed(sefs_inode);
		goto out;
	}
	d_instantiate_new(sefs_dentry, sefs_inode);
out:
	return rc;
}

static int sefs_i_size_read(struct dentry *dentry, struct inode *inode)
{
	struct sefs_crypt_stat *crypt_stat;
	int rc;

	rc = sefs_get_lower_file(dentry, inode);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to initialize "
			"the lower file for the dentry with name "
			"[%pd]; rc = [%d]\n", __func__,
			dentry, rc);
		return rc;
	}

	crypt_stat = &sefs_inode_to_private(inode)->crypt_stat;
	/* TODO: lock for crypt_stat comparison */
	if (!(crypt_stat->flags & SEFS_POLICY_APPLIED))
		sefs_set_default_sizes(crypt_stat);

	rc = sefs_read_and_validate_header_region(inode);
	sefs_put_lower_file(inode);
	if (rc) {
		rc = sefs_read_and_validate_xattr_region(dentry, inode);
		if (!rc)
			crypt_stat->flags |= SEFS_METADATA_IN_XATTR;
	}

	/* Must return 0 to allow non-eCryptfs files to be looked up, too */
	return 0;
}

/**
 * sefs_lookup_interpose - Dentry interposition for a lookup
 */
static struct dentry *sefs_lookup_interpose(struct dentry *dentry,
				     struct dentry *lower_dentry)
{
	struct inode *inode, *lower_inode = d_inode(lower_dentry);
	struct sefs_dentry_info *dentry_info;
	struct vfsmount *lower_mnt;
	int rc = 0;

	dentry_info = kmem_cache_alloc(sefs_dentry_info_cache, GFP_KERNEL);
	if (!dentry_info) {
		printk(KERN_ERR "%s: Out of memory whilst attempting "
		       "to allocate sefs_dentry_info struct\n",
			__func__);
		dput(lower_dentry);
		return ERR_PTR(-ENOMEM);
	}

	lower_mnt = mntget(sefs_dentry_to_lower_mnt(dentry->d_parent));
	fsstack_copy_attr_atime(d_inode(dentry->d_parent),
				d_inode(lower_dentry->d_parent));
	BUG_ON(!d_count(lower_dentry));

	sefs_set_dentry_private(dentry, dentry_info);
	dentry_info->lower_path.mnt = lower_mnt;
	dentry_info->lower_path.dentry = lower_dentry;

	if (d_really_is_negative(lower_dentry)) {
		/* We want to add because we couldn't find in lower */
		d_add(dentry, NULL);
		return NULL;
	}
	inode = __sefs_get_inode(lower_inode, dentry->d_sb);
	if (IS_ERR(inode)) {
		printk(KERN_ERR "%s: Error interposing; rc = [%ld]\n",
		       __func__, PTR_ERR(inode));
		return ERR_CAST(inode);
	}
	if (S_ISREG(inode->i_mode)) {
		rc = sefs_i_size_read(dentry, inode);
		if (rc) {
			make_bad_inode(inode);
			return ERR_PTR(rc);
		}
	}

	if (inode->i_state & I_NEW)
		unlock_new_inode(inode);
	return d_splice_alias(inode, dentry);
}

/**
 * sefs_lookup
 * @sefs_dir_inode: The eCryptfs directory inode
 * @sefs_dentry: The eCryptfs dentry that we are looking up
 * @flags: lookup flags
 *
 * Find a file on disk. If the file does not exist, then we'll add it to the
 * dentry cache and continue on to read it from the disk.
 */
static struct dentry *sefs_lookup(struct inode *sefs_dir_inode,
				      struct dentry *sefs_dentry,
				      unsigned int flags)
{
	char *encrypted_and_encoded_name = NULL;
	struct sefs_mount_crypt_stat *mount_crypt_stat;
	struct dentry *lower_dir_dentry, *lower_dentry;
	const char *name = sefs_dentry->d_name.name;
	size_t len = sefs_dentry->d_name.len;
	struct dentry *res;
	int rc = 0;

	lower_dir_dentry = sefs_dentry_to_lower(sefs_dentry->d_parent);

	mount_crypt_stat = &sefs_superblock_to_private(
				sefs_dentry->d_sb)->mount_crypt_stat;
	if (mount_crypt_stat
	    && (mount_crypt_stat->flags & SEFS_GLOBAL_ENCRYPT_FILENAMES)) {
		rc = sefs_encrypt_and_encode_filename(
			&encrypted_and_encoded_name, &len,
			mount_crypt_stat, name, len);
		if (rc) {
			printk(KERN_ERR "%s: Error attempting to encrypt and encode "
			       "filename; rc = [%d]\n", __func__, rc);
			return ERR_PTR(rc);
		}
		name = encrypted_and_encoded_name;
	}

	lower_dentry = lookup_one_len_unlocked(name, lower_dir_dentry, len);
	if (IS_ERR(lower_dentry)) {
		sefs_printk(KERN_DEBUG, "%s: lookup_one_len() returned "
				"[%ld] on lower_dentry = [%s]\n", __func__,
				PTR_ERR(lower_dentry),
				name);
		res = ERR_CAST(lower_dentry);
	} else {
		res = sefs_lookup_interpose(sefs_dentry, lower_dentry);
	}
	kfree(encrypted_and_encoded_name);
	return res;
}

static int sefs_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int rc;

	file_size_save = i_size_read(d_inode(old_dentry));
	lower_old_dentry = sefs_dentry_to_lower(old_dentry);
	lower_new_dentry = sefs_dentry_to_lower(new_dentry);
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_dir_dentry = lock_parent(lower_new_dentry);
	rc = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		      lower_new_dentry, NULL);
	if (rc || d_really_is_negative(lower_new_dentry))
		goto out_lock;
	rc = sefs_interpose(lower_new_dentry, new_dentry, dir->i_sb);
	if (rc)
		goto out_lock;
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(d_inode(old_dentry),
		  sefs_inode_to_lower(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out_lock:
	unlock_dir(lower_dir_dentry);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
	return rc;
}

static int sefs_unlink(struct inode *dir, struct dentry *dentry)
{
	return sefs_do_unlink(dir, dentry, d_inode(dentry));
}

static int sefs_symlink(struct inode *dir, struct dentry *dentry,
			    const char *symname)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	char *encoded_symname;
	size_t encoded_symlen;
	struct sefs_mount_crypt_stat *mount_crypt_stat = NULL;

	lower_dentry = sefs_dentry_to_lower(dentry);
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	mount_crypt_stat = &sefs_superblock_to_private(
		dir->i_sb)->mount_crypt_stat;
	rc = sefs_encrypt_and_encode_filename(&encoded_symname,
						  &encoded_symlen,
						  mount_crypt_stat, symname,
						  strlen(symname));
	if (rc)
		goto out_lock;
	rc = vfs_symlink(d_inode(lower_dir_dentry), lower_dentry,
			 encoded_symname);
	kfree(encoded_symname);
	if (rc || d_really_is_negative(lower_dentry))
		goto out_lock;
	rc = sefs_interpose(lower_dentry, dentry, dir->i_sb);
	if (rc)
		goto out_lock;
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
out_lock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	if (d_really_is_negative(dentry))
		d_drop(dentry);
	return rc;
}

static int sefs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;

	lower_dentry = sefs_dentry_to_lower(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_mkdir(d_inode(lower_dir_dentry), lower_dentry, mode);
	if (rc || d_really_is_negative(lower_dentry))
		goto out;
	rc = sefs_interpose(lower_dentry, dentry, dir->i_sb);
	if (rc)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);
out:
	unlock_dir(lower_dir_dentry);
	if (d_really_is_negative(dentry))
		d_drop(dentry);
	return rc;
}

static int sefs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int rc;

	lower_dentry = sefs_dentry_to_lower(dentry);
	dget(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	dget(lower_dentry);
	rc = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	dput(lower_dentry);
	if (!rc && d_really_is_positive(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);
	unlock_dir(lower_dir_dentry);
	if (!rc)
		d_drop(dentry);
	dput(dentry);
	return rc;
}

static int
sefs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;

	lower_dentry = sefs_dentry_to_lower(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_mknod(d_inode(lower_dir_dentry), lower_dentry, mode, dev);
	if (rc || d_really_is_negative(lower_dentry))
		goto out;
	rc = sefs_interpose(lower_dentry, dentry, dir->i_sb);
	if (rc)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
out:
	unlock_dir(lower_dir_dentry);
	if (d_really_is_negative(dentry))
		d_drop(dentry);
	return rc;
}

static int
sefs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry,
		unsigned int flags)
{
	int rc;
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_old_dir_dentry;
	struct dentry *lower_new_dir_dentry;
	struct dentry *trap = NULL;
	struct inode *target_inode;

	if (flags)
		return -EINVAL;

	lower_old_dentry = sefs_dentry_to_lower(old_dentry);
	lower_new_dentry = sefs_dentry_to_lower(new_dentry);
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);
	target_inode = d_inode(new_dentry);
	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		rc = -EINVAL;
		goto out_lock;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		rc = -ENOTEMPTY;
		goto out_lock;
	}
	rc = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			d_inode(lower_new_dir_dentry), lower_new_dentry,
			NULL, 0);
	if (rc)
		goto out_lock;
	if (target_inode)
		fsstack_copy_attr_all(target_inode,
				      sefs_inode_to_lower(target_inode));
	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir)
		fsstack_copy_attr_all(old_dir, d_inode(lower_old_dir_dentry));
out_lock:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
	return rc;
}

static char *sefs_readlink_lower(struct dentry *dentry, size_t *bufsiz)
{
	DEFINE_DELAYED_CALL(done);
	struct dentry *lower_dentry = sefs_dentry_to_lower(dentry);
	const char *link;
	char *buf;
	int rc;

	link = vfs_get_link(lower_dentry, &done);
	if (IS_ERR(link))
		return ERR_CAST(link);

	rc = sefs_decode_and_decrypt_filename(&buf, bufsiz, dentry->d_sb,
						  link, strlen(link));
	do_delayed_call(&done);
	if (rc)
		return ERR_PTR(rc);

	return buf;
}

static const char *sefs_get_link(struct dentry *dentry,
				     struct inode *inode,
				     struct delayed_call *done)
{
	size_t len;
	char *buf;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	buf = sefs_readlink_lower(dentry, &len);
	if (IS_ERR(buf))
		return buf;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(sefs_dentry_to_lower(dentry)));
	buf[len] = '\0';
	set_delayed_call(done, kfree_link, buf);
	return buf;
}

/**
 * upper_size_to_lower_size
 * @crypt_stat: Crypt_stat associated with file
 * @upper_size: Size of the upper file
 *
 * Calculate the required size of the lower file based on the
 * specified size of the upper file. This calculation is based on the
 * number of headers in the underlying file and the extent size.
 *
 * Returns Calculated size of the lower file.
 */
static loff_t
upper_size_to_lower_size(struct sefs_crypt_stat *crypt_stat,
			 loff_t upper_size)
{
	loff_t lower_size;

	lower_size = sefs_lower_header_size(crypt_stat);
	if (upper_size != 0) {
		loff_t num_extents;

		num_extents = upper_size >> crypt_stat->extent_shift;
		if (upper_size & ~crypt_stat->extent_mask)
			num_extents++;
		lower_size += (num_extents * crypt_stat->extent_size);
	}
	return lower_size;
}

/**
 * truncate_upper
 * @dentry: The sefs layer dentry
 * @ia: Address of the sefs inode's attributes
 * @lower_ia: Address of the lower inode's attributes
 *
 * Function to handle truncations modifying the size of the file. Note
 * that the file sizes are interpolated. When expanding, we are simply
 * writing strings of 0's out. When truncating, we truncate the upper
 * inode and update the lower_ia according to the page index
 * interpolations. If ATTR_SIZE is set in lower_ia->ia_valid upon return,
 * the caller must use lower_ia in a call to notify_change() to perform
 * the truncation of the lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int truncate_upper(struct dentry *dentry, struct iattr *ia,
			  struct iattr *lower_ia)
{
	int rc = 0;
	struct inode *inode = d_inode(dentry);
	struct sefs_crypt_stat *crypt_stat;
	loff_t i_size = i_size_read(inode);
	loff_t lower_size_before_truncate;
	loff_t lower_size_after_truncate;

	if (unlikely((ia->ia_size == i_size))) {
		lower_ia->ia_valid &= ~ATTR_SIZE;
		return 0;
	}
	rc = sefs_get_lower_file(dentry, inode);
	if (rc)
		return rc;
	crypt_stat = &sefs_inode_to_private(d_inode(dentry))->crypt_stat;
	/* Switch on growing or shrinking file */
	if (ia->ia_size > i_size) {
		char zero[] = { 0x00 };

		lower_ia->ia_valid &= ~ATTR_SIZE;
		/* Write a single 0 at the last position of the file;
		 * this triggers code that will fill in 0's throughout
		 * the intermediate portion of the previous end of the
		 * file and the new and of the file */
		rc = sefs_write(inode, zero,
				    (ia->ia_size - 1), 1);
	} else { /* ia->ia_size < i_size_read(inode) */
		/* We're chopping off all the pages down to the page
		 * in which ia->ia_size is located. Fill in the end of
		 * that page from (ia->ia_size & ~PAGE_MASK) to
		 * PAGE_SIZE with zeros. */
		size_t num_zeros = (PAGE_SIZE
				    - (ia->ia_size & ~PAGE_MASK));

		if (!(crypt_stat->flags & SEFS_ENCRYPTED)) {
			truncate_setsize(inode, ia->ia_size);
			lower_ia->ia_size = ia->ia_size;
			lower_ia->ia_valid |= ATTR_SIZE;
			goto out;
		}
		if (num_zeros) {
			char *zeros_virt;

			zeros_virt = kzalloc(num_zeros, GFP_KERNEL);
			if (!zeros_virt) {
				rc = -ENOMEM;
				goto out;
			}
			rc = sefs_write(inode, zeros_virt,
					    ia->ia_size, num_zeros);
			kfree(zeros_virt);
			if (rc) {
				printk(KERN_ERR "Error attempting to zero out "
				       "the remainder of the end page on "
				       "reducing truncate; rc = [%d]\n", rc);
				goto out;
			}
		}
		truncate_setsize(inode, ia->ia_size);
		rc = sefs_write_inode_size_to_metadata(inode);
		if (rc) {
			printk(KERN_ERR	"Problem with "
			       "sefs_write_inode_size_to_metadata; "
			       "rc = [%d]\n", rc);
			goto out;
		}
		/* We are reducing the size of the sefs file, and need to
		 * know if we need to reduce the size of the lower file. */
		lower_size_before_truncate =
		    upper_size_to_lower_size(crypt_stat, i_size);
		lower_size_after_truncate =
		    upper_size_to_lower_size(crypt_stat, ia->ia_size);
		if (lower_size_after_truncate < lower_size_before_truncate) {
			lower_ia->ia_size = lower_size_after_truncate;
			lower_ia->ia_valid |= ATTR_SIZE;
		} else
			lower_ia->ia_valid &= ~ATTR_SIZE;
	}
out:
	sefs_put_lower_file(inode);
	return rc;
}

static int sefs_inode_newsize_ok(struct inode *inode, loff_t offset)
{
	struct sefs_crypt_stat *crypt_stat;
	loff_t lower_oldsize, lower_newsize;

	crypt_stat = &sefs_inode_to_private(inode)->crypt_stat;
	lower_oldsize = upper_size_to_lower_size(crypt_stat,
						 i_size_read(inode));
	lower_newsize = upper_size_to_lower_size(crypt_stat, offset);
	if (lower_newsize > lower_oldsize) {
		/*
		 * The eCryptfs inode and the new *lower* size are mixed here
		 * because we may not have the lower i_mutex held and/or it may
		 * not be appropriate to call inode_newsize_ok() with inodes
		 * from other filesystems.
		 */
		return inode_newsize_ok(inode, lower_newsize);
	}

	return 0;
}

/**
 * sefs_truncate
 * @dentry: The sefs layer dentry
 * @new_length: The length to expand the file to
 *
 * Simple function that handles the truncation of an eCryptfs inode and
 * its corresponding lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
int sefs_truncate(struct dentry *dentry, loff_t new_length)
{
	struct iattr ia = { .ia_valid = ATTR_SIZE, .ia_size = new_length };
	struct iattr lower_ia = { .ia_valid = 0 };
	int rc;

	rc = sefs_inode_newsize_ok(d_inode(dentry), new_length);
	if (rc)
		return rc;

	rc = truncate_upper(dentry, &ia, &lower_ia);
	if (!rc && lower_ia.ia_valid & ATTR_SIZE) {
		struct dentry *lower_dentry = sefs_dentry_to_lower(dentry);

		inode_lock(d_inode(lower_dentry));
		rc = notify_change(lower_dentry, &lower_ia, NULL);
		inode_unlock(d_inode(lower_dentry));
	}
	return rc;
}

static int
sefs_permission(struct inode *inode, int mask)
{
	return inode_permission(sefs_inode_to_lower(inode), mask);
}

/**
 * sefs_setattr
 * @dentry: dentry handle to the inode to modify
 * @ia: Structure with flags of what to change and values
 *
 * Updates the metadata of an inode. If the update is to the size
 * i.e. truncation, then sefs_truncate will handle the size modification
 * of both the sefs inode and the lower inode.
 *
 * All other metadata changes will be passed right to the lower filesystem,
 * and we will just update our inode to look like the lower.
 */
static int sefs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int rc = 0;
	struct dentry *lower_dentry;
	struct iattr lower_ia;
	struct inode *inode;
	struct inode *lower_inode;
	struct sefs_crypt_stat *crypt_stat;

	crypt_stat = &sefs_inode_to_private(d_inode(dentry))->crypt_stat;
	if (!(crypt_stat->flags & SEFS_STRUCT_INITIALIZED)) {
		rc = sefs_init_crypt_stat(crypt_stat);
		if (rc)
			return rc;
	}
	inode = d_inode(dentry);
	lower_inode = sefs_inode_to_lower(inode);
	lower_dentry = sefs_dentry_to_lower(dentry);
	mutex_lock(&crypt_stat->cs_mutex);
	if (d_is_dir(dentry))
		crypt_stat->flags &= ~(SEFS_ENCRYPTED);
	else if (d_is_reg(dentry)
		 && (!(crypt_stat->flags & SEFS_POLICY_APPLIED)
		     || !(crypt_stat->flags & SEFS_KEY_VALID))) {
		struct sefs_mount_crypt_stat *mount_crypt_stat;

		mount_crypt_stat = &sefs_superblock_to_private(
			dentry->d_sb)->mount_crypt_stat;
		rc = sefs_get_lower_file(dentry, inode);
		if (rc) {
			mutex_unlock(&crypt_stat->cs_mutex);
			goto out;
		}
		rc = sefs_read_metadata(dentry);
		sefs_put_lower_file(inode);
		if (rc) {
			if (!(mount_crypt_stat->flags
			      & SEFS_PLAINTEXT_PASSTHROUGH_ENABLED)) {
				rc = -EIO;
				printk(KERN_WARNING "Either the lower file "
				       "is not in a valid eCryptfs format, "
				       "or the key could not be retrieved. "
				       "Plaintext passthrough mode is not "
				       "enabled; returning -EIO\n");
				mutex_unlock(&crypt_stat->cs_mutex);
				goto out;
			}
			rc = 0;
			crypt_stat->flags &= ~(SEFS_I_SIZE_INITIALIZED
					       | SEFS_ENCRYPTED);
		}
	}
	mutex_unlock(&crypt_stat->cs_mutex);

	rc = setattr_prepare(dentry, ia);
	if (rc)
		goto out;
	if (ia->ia_valid & ATTR_SIZE) {
		rc = sefs_inode_newsize_ok(inode, ia->ia_size);
		if (rc)
			goto out;
	}

	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = sefs_file_to_lower(ia->ia_file);
	if (ia->ia_valid & ATTR_SIZE) {
		rc = truncate_upper(dentry, ia, &lower_ia);
		if (rc < 0)
			goto out;
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	inode_lock(d_inode(lower_dentry));
	rc = notify_change(lower_dentry, &lower_ia, NULL);
	inode_unlock(d_inode(lower_dentry));
out:
	fsstack_copy_attr_all(inode, lower_inode);
	return rc;
}

static int sefs_getattr_link(const struct path *path, struct kstat *stat,
				 u32 request_mask, unsigned int flags)
{
	struct dentry *dentry = path->dentry;
	struct sefs_mount_crypt_stat *mount_crypt_stat;
	int rc = 0;

	mount_crypt_stat = &sefs_superblock_to_private(
						dentry->d_sb)->mount_crypt_stat;
	generic_fillattr(d_inode(dentry), stat);
	if (mount_crypt_stat->flags & SEFS_GLOBAL_ENCRYPT_FILENAMES) {
		char *target;
		size_t targetsiz;

		target = sefs_readlink_lower(dentry, &targetsiz);
		if (!IS_ERR(target)) {
			kfree(target);
			stat->size = targetsiz;
		} else {
			rc = PTR_ERR(target);
		}
	}
	return rc;
}

static int sefs_getattr(const struct path *path, struct kstat *stat,
			    u32 request_mask, unsigned int flags)
{
	struct dentry *dentry = path->dentry;
	struct kstat lower_stat;
	int rc;

	rc = vfs_getattr(sefs_dentry_to_lower_path(dentry), &lower_stat,
			 request_mask, flags);
	if (!rc) {
		fsstack_copy_attr_all(d_inode(dentry),
				      sefs_inode_to_lower(d_inode(dentry)));
		generic_fillattr(d_inode(dentry), stat);
		stat->blocks = lower_stat.blocks;
	}
	return rc;
}

int
sefs_setxattr(struct dentry *dentry, struct inode *inode,
		  const char *name, const void *value,
		  size_t size, int flags)
{
	int rc;
	struct dentry *lower_dentry;

	lower_dentry = sefs_dentry_to_lower(dentry);
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	rc = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (!rc && inode)
		fsstack_copy_attr_all(inode, d_inode(lower_dentry));
out:
	return rc;
}

ssize_t
sefs_getxattr_lower(struct dentry *lower_dentry, struct inode *lower_inode,
			const char *name, void *value, size_t size)
{
	int rc;

	if (!(lower_inode->i_opflags & IOP_XATTR)) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	inode_lock(lower_inode);
	rc = __vfs_getxattr(lower_dentry, lower_inode, name, value, size);
	inode_unlock(lower_inode);
out:
	return rc;
}

static ssize_t
sefs_getxattr(struct dentry *dentry, struct inode *inode,
		  const char *name, void *value, size_t size)
{
	return sefs_getxattr_lower(sefs_dentry_to_lower(dentry),
				       sefs_inode_to_lower(inode),
				       name, value, size);
}

static ssize_t
sefs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = sefs_dentry_to_lower(dentry);
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	inode_lock(d_inode(lower_dentry));
	rc = d_inode(lower_dentry)->i_op->listxattr(lower_dentry, list, size);
	inode_unlock(d_inode(lower_dentry));
out:
	return rc;
}

static int sefs_removexattr(struct dentry *dentry, struct inode *inode,
				const char *name)
{
	int rc;
	struct dentry *lower_dentry;
	struct inode *lower_inode;

	lower_dentry = sefs_dentry_to_lower(dentry);
	lower_inode = sefs_inode_to_lower(inode);
	if (!(lower_inode->i_opflags & IOP_XATTR)) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	inode_lock(lower_inode);
	rc = __vfs_removexattr(lower_dentry, name);
	inode_unlock(lower_inode);
out:
	return rc;
}

const struct inode_operations sefs_symlink_iops = {
	.get_link = sefs_get_link,
	.permission = sefs_permission,
	.setattr = sefs_setattr,
	.getattr = sefs_getattr_link,
	.listxattr = sefs_listxattr,
};

const struct inode_operations sefs_dir_iops = {
	.create = sefs_create,
	.lookup = sefs_lookup,
	.link = sefs_link,
	.unlink = sefs_unlink,
	.symlink = sefs_symlink,
	.mkdir = sefs_mkdir,
	.rmdir = sefs_rmdir,
	.mknod = sefs_mknod,
	.rename = sefs_rename,
	.permission = sefs_permission,
	.setattr = sefs_setattr,
	.listxattr = sefs_listxattr,
};

const struct inode_operations sefs_main_iops = {
	.permission = sefs_permission,
	.setattr = sefs_setattr,
	.getattr = sefs_getattr,
	.listxattr = sefs_listxattr,
};

static int sefs_xattr_get(const struct xattr_handler *handler,
			      struct dentry *dentry, struct inode *inode,
			      const char *name, void *buffer, size_t size)
{
	return sefs_getxattr(dentry, inode, name, buffer, size);
}

static int sefs_xattr_set(const struct xattr_handler *handler,
			      struct dentry *dentry, struct inode *inode,
			      const char *name, const void *value, size_t size,
			      int flags)
{
	if (value)
		return sefs_setxattr(dentry, inode, name, value, size, flags);
	else {
		BUG_ON(flags != XATTR_REPLACE);
		return sefs_removexattr(dentry, inode, name);
	}
}

const struct xattr_handler sefs_xattr_handler = {
	.prefix = "",  /* match anything */
	.get = sefs_xattr_get,
	.set = sefs_xattr_set,
};

const struct xattr_handler *sefs_xattr_handlers[] = {
	&sefs_xattr_handler,
	NULL
};
