/**
 * SEFS: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Michael C. Thompson <mcthomps@us.ibm.com>
 *              Tyler Hicks <tyhicks@ou.edu>
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
#include <linux/file.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/skbuff.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/key.h>
#include <linux/parser.h>
#include <linux/fs_stack.h>
#include <linux/slab.h>
#include <linux/magic.h>
#include "sefs_kernel.h"
#include "security.h"					 

/**
 * Module parameter that defines the sefs_verbosity level.
 */
int sefs_verbosity = 0;

module_param(sefs_verbosity, int, 0);
MODULE_PARM_DESC(sefs_verbosity,
		 "Initial verbosity level (0 or 1; defaults to "
		 "0, which is Quiet)");

/**
 * Module parameter that defines the number of message buffer elements
 */
unsigned int sefs_message_buf_len = SEFS_DEFAULT_MSG_CTX_ELEMS;

module_param(sefs_message_buf_len, uint, 0);
MODULE_PARM_DESC(sefs_message_buf_len,
		 "Number of message buffer elements");

/**
 * Module parameter that defines the maximum guaranteed amount of time to wait
 * for a response from sefsd.  The actual sleep time will be, more than
 * likely, a small amount greater than this specified value, but only less if
 * the message successfully arrives.
 */
signed long sefs_message_wait_timeout = SEFS_MAX_MSG_CTX_TTL / HZ;

module_param(sefs_message_wait_timeout, long, 0);
MODULE_PARM_DESC(sefs_message_wait_timeout,
		 "Maximum number of seconds that an operation will "
		 "sleep while waiting for a message response from "
		 "userspace");

/**
 * Module parameter that is an estimate of the maximum number of users
 * that will be concurrently using SEFS. Set this to the right
 * value to balance performance and memory use.
 */
unsigned int sefs_number_of_users = SEFS_DEFAULT_NUM_USERS;

module_param(sefs_number_of_users, uint, 0);
MODULE_PARM_DESC(sefs_number_of_users, "An estimate of the number of "
		 "concurrent users of SEFS");

void __sefs_printk(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if (fmt[1] == '7') { /* KERN_DEBUG */
		if (sefs_verbosity >= 1)
			vprintk(fmt, args);
	} else
		vprintk(fmt, args);
	va_end(args);
}

/**
 * sefs_init_lower_file
 * @sefs_dentry: Fully initialized SEFS dentry object, with
 *                   the lower dentry and the lower mount set
 *
 * SEFS only ever keeps a single open file for every lower
 * inode. All I/O operations to the lower inode occur through that
 * file. When the first SEFS dentry that interposes with the first
 * lower dentry for that inode is created, this function creates the
 * lower file struct and associates it with the SEFS
 * inode. When all SEFS files associated with the inode are released, the
 * file is closed.
 *
 * The lower file will be opened with read/write permissions, if
 * possible. Otherwise, it is opened read-only.
 *
 * This function does nothing if a lower file is already
 * associated with the SEFS inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int sefs_init_lower_file(struct dentry *dentry,
				    struct file **lower_file)
{
	const struct cred *cred = current_cred();
	struct path *path = sefs_dentry_to_lower_path(dentry);
	int rc;

	rc = sefs_privileged_open(lower_file, path->dentry, path->mnt,
				      cred);
	if (rc) {
		printk(KERN_ERR "Error opening lower file "
		       "for lower_dentry [0x%p] and lower_mnt [0x%p]; "
		       "rc = [%d]\n", path->dentry, path->mnt, rc);
		(*lower_file) = NULL;
	}
	return rc;
}

int sefs_get_lower_file(struct dentry *dentry, struct inode *inode)
{
	struct sefs_inode_info *inode_info;
	int count, rc = 0;

	inode_info = sefs_inode_to_private(inode);
	mutex_lock(&inode_info->lower_file_mutex);
	count = atomic_inc_return(&inode_info->lower_file_count);
	if (WARN_ON_ONCE(count < 1))
		rc = -EINVAL;
	else if (count == 1) {
		rc = sefs_init_lower_file(dentry,
					      &inode_info->lower_file);
		if (rc)
			atomic_set(&inode_info->lower_file_count, 0);
	}
	mutex_unlock(&inode_info->lower_file_mutex);
	return rc;
}

void sefs_put_lower_file(struct inode *inode)
{
	struct sefs_inode_info *inode_info;

	inode_info = sefs_inode_to_private(inode);
	if (atomic_dec_and_mutex_lock(&inode_info->lower_file_count,
				      &inode_info->lower_file_mutex)) {
		filemap_write_and_wait(inode->i_mapping);
		fput(inode_info->lower_file);
		inode_info->lower_file = NULL;
		mutex_unlock(&inode_info->lower_file_mutex);
	}
}

enum { sefs_opt_sig, sefs_opt_sefs_sig,
       sefs_opt_cipher, sefs_opt_sefs_cipher,
       sefs_opt_sefs_key_bytes,
       sefs_opt_passthrough, sefs_opt_xattr_metadata,
       sefs_opt_encrypted_view, sefs_opt_fnek_sig,
       sefs_opt_fn_cipher, sefs_opt_fn_cipher_key_bytes,
       sefs_opt_unlink_sigs, sefs_opt_mount_auth_tok_only,
       sefs_opt_check_dev_ruid,
       sefs_opt_err };

static const match_table_t tokens = {
	{sefs_opt_sig, "sig=%s"},
	{sefs_opt_sefs_sig, "sefs_sig=%s"},
	{sefs_opt_cipher, "cipher=%s"},
	{sefs_opt_sefs_cipher, "sefs_cipher=%s"},
	{sefs_opt_sefs_key_bytes, "sefs_key_bytes=%u"},
	{sefs_opt_passthrough, "sefs_passthrough"},
	{sefs_opt_xattr_metadata, "sefs_xattr_metadata"},
	{sefs_opt_encrypted_view, "sefs_encrypted_view"},
	{sefs_opt_fnek_sig, "sefs_fnek_sig=%s"},
	{sefs_opt_fn_cipher, "sefs_fn_cipher=%s"},
	{sefs_opt_fn_cipher_key_bytes, "sefs_fn_key_bytes=%u"},
	{sefs_opt_unlink_sigs, "sefs_unlink_sigs"},
	{sefs_opt_mount_auth_tok_only, "sefs_mount_auth_tok_only"},
	{sefs_opt_check_dev_ruid, "sefs_check_dev_ruid"},
	{sefs_opt_err, NULL}
};

static int sefs_init_global_auth_toks(
	struct sefs_mount_crypt_stat *mount_crypt_stat)
{
	struct sefs_global_auth_tok *global_auth_tok;
	struct sefs_auth_tok *auth_tok;
	int rc = 0;

	list_for_each_entry(global_auth_tok,
			    &mount_crypt_stat->global_auth_tok_list,
			    mount_crypt_stat_list) {
		rc = sefs_keyring_auth_tok_for_sig(
			&global_auth_tok->global_auth_tok_key, &auth_tok,
			global_auth_tok->sig);
		if (rc) {
			printk(KERN_ERR "Could not find valid key in user "
			       "session keyring for sig specified in mount "
			       "option: [%s]\n", global_auth_tok->sig);
			global_auth_tok->flags |= SEFS_AUTH_TOK_INVALID;
			goto out;
		} else {
			global_auth_tok->flags &= ~SEFS_AUTH_TOK_INVALID;
			up_write(&(global_auth_tok->global_auth_tok_key)->sem);
		}
	}
out:
	return rc;
}

static void sefs_init_mount_crypt_stat(
	struct sefs_mount_crypt_stat *mount_crypt_stat)
{
	memset((void *)mount_crypt_stat, 0,
	       sizeof(struct sefs_mount_crypt_stat));
	INIT_LIST_HEAD(&mount_crypt_stat->global_auth_tok_list);
	mutex_init(&mount_crypt_stat->global_auth_tok_list_mutex);
	mount_crypt_stat->flags |= SEFS_MOUNT_CRYPT_STAT_INITIALIZED;
}

/**
 * sefs_parse_options
 * @sb: The sefs super block
 * @options: The options passed to the kernel
 * @check_ruid: set to 1 if device uid should be checked against the ruid
 *
 * Parse mount options:
 * debug=N 	   - sefs_verbosity level for debug output
 * sig=XXX	   - description(signature) of the key to use
 *
 * Returns the dentry object of the lower-level (lower/interposed)
 * directory; We want to mount our stackable file system on top of
 * that lower directory.
 *
 * The signature of the key to use must be the description of a key
 * already in the keyring. Mounting will fail if the key can not be
 * found.
 *
 * Returns zero on success; non-zero on error
 */
static int sefs_parse_options(struct sefs_sb_info *sbi, char *options,
				  uid_t *check_ruid)
{
	char *p;
	int rc = 0;
	int sig_set = 0;
	int cipher_name_set = 0;
	int fn_cipher_name_set = 0;
	int cipher_key_bytes;
	int cipher_key_bytes_set = 0;
	int fn_cipher_key_bytes;
	int fn_cipher_key_bytes_set = 0;
	struct sefs_mount_crypt_stat *mount_crypt_stat =
		&sbi->mount_crypt_stat;
	substring_t args[MAX_OPT_ARGS];
	int token;
	char *sig_src;
	char *cipher_name_dst;
	char *cipher_name_src;
	char *fn_cipher_name_dst;
	char *fn_cipher_name_src;
	char *fnek_dst;
	char *fnek_src;
	char *cipher_key_bytes_src;
	char *fn_cipher_key_bytes_src;
	u8 cipher_code;

	*check_ruid = 0;

	if (!options) {
		rc = -EINVAL;
		goto out;
	}
	sefs_init_mount_crypt_stat(mount_crypt_stat);
	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case sefs_opt_sig:
		case sefs_opt_sefs_sig:
			sig_src = args[0].from;
			rc = sefs_add_global_auth_tok(mount_crypt_stat,
							  sig_src, 0);
			if (rc) {
				printk(KERN_ERR "Error attempting to register "
				       "global sig; rc = [%d]\n", rc);
				goto out;
			}
			sig_set = 1;
			break;
		case sefs_opt_cipher:
		case sefs_opt_sefs_cipher:
			cipher_name_src = args[0].from;
			cipher_name_dst =
				mount_crypt_stat->
				global_default_cipher_name;
			strncpy(cipher_name_dst, cipher_name_src,
				SEFS_MAX_CIPHER_NAME_SIZE);
			cipher_name_dst[SEFS_MAX_CIPHER_NAME_SIZE] = '\0';
			cipher_name_set = 1;
			break;
		case sefs_opt_sefs_key_bytes:
			cipher_key_bytes_src = args[0].from;
			cipher_key_bytes =
				(int)simple_strtol(cipher_key_bytes_src,
						   &cipher_key_bytes_src, 0);
			mount_crypt_stat->global_default_cipher_key_size =
				cipher_key_bytes;
			cipher_key_bytes_set = 1;
			break;
		case sefs_opt_passthrough:
			mount_crypt_stat->flags |=
				SEFS_PLAINTEXT_PASSTHROUGH_ENABLED;
			break;
		case sefs_opt_xattr_metadata:
			mount_crypt_stat->flags |=
				SEFS_XATTR_METADATA_ENABLED;
			break;
		case sefs_opt_encrypted_view:
			mount_crypt_stat->flags |=
				SEFS_XATTR_METADATA_ENABLED;
			mount_crypt_stat->flags |=
				SEFS_ENCRYPTED_VIEW_ENABLED;
			break;
		case sefs_opt_fnek_sig:
			fnek_src = args[0].from;
			fnek_dst =
				mount_crypt_stat->global_default_fnek_sig;
			strncpy(fnek_dst, fnek_src, SEFS_SIG_SIZE_HEX);
			mount_crypt_stat->global_default_fnek_sig[
				SEFS_SIG_SIZE_HEX] = '\0';
			rc = sefs_add_global_auth_tok(
				mount_crypt_stat,
				mount_crypt_stat->global_default_fnek_sig,
				SEFS_AUTH_TOK_FNEK);
			if (rc) {
				printk(KERN_ERR "Error attempting to register "
				       "global fnek sig [%s]; rc = [%d]\n",
				       mount_crypt_stat->global_default_fnek_sig,
				       rc);
				goto out;
			}
			mount_crypt_stat->flags |=
				(SEFS_GLOBAL_ENCRYPT_FILENAMES
				 | SEFS_GLOBAL_ENCFN_USE_MOUNT_FNEK);
			break;
		case sefs_opt_fn_cipher:
			fn_cipher_name_src = args[0].from;
			fn_cipher_name_dst =
				mount_crypt_stat->global_default_fn_cipher_name;
			strncpy(fn_cipher_name_dst, fn_cipher_name_src,
				SEFS_MAX_CIPHER_NAME_SIZE);
			mount_crypt_stat->global_default_fn_cipher_name[
				SEFS_MAX_CIPHER_NAME_SIZE] = '\0';
			fn_cipher_name_set = 1;
			break;
		case sefs_opt_fn_cipher_key_bytes:
			fn_cipher_key_bytes_src = args[0].from;
			fn_cipher_key_bytes =
				(int)simple_strtol(fn_cipher_key_bytes_src,
						   &fn_cipher_key_bytes_src, 0);
			mount_crypt_stat->global_default_fn_cipher_key_bytes =
				fn_cipher_key_bytes;
			fn_cipher_key_bytes_set = 1;
			break;
		case sefs_opt_unlink_sigs:
			mount_crypt_stat->flags |= SEFS_UNLINK_SIGS;
			break;
		case sefs_opt_mount_auth_tok_only:
			mount_crypt_stat->flags |=
				SEFS_GLOBAL_MOUNT_AUTH_TOK_ONLY;
			break;
		case sefs_opt_check_dev_ruid:
			*check_ruid = 1;
			break;
		case sefs_opt_err:
		default:
			printk(KERN_WARNING
			       "%s: SEFS: unrecognized option [%s]\n",
			       __func__, p);
		}
	}
	if (!sig_set) {
		rc = -EINVAL;
		sefs_printk(KERN_ERR, "You must supply at least one valid "
				"auth tok signature as a mount "
				"parameter; see the SEFS README\n");
		goto out;
	}
	if (!cipher_name_set) {
		int cipher_name_len = strlen(SEFS_DEFAULT_CIPHER);

		BUG_ON(cipher_name_len > SEFS_MAX_CIPHER_NAME_SIZE);
		strcpy(mount_crypt_stat->global_default_cipher_name,
		       SEFS_DEFAULT_CIPHER);
	}
	if ((mount_crypt_stat->flags & SEFS_GLOBAL_ENCRYPT_FILENAMES)
	    && !fn_cipher_name_set)
		strcpy(mount_crypt_stat->global_default_fn_cipher_name,
		       mount_crypt_stat->global_default_cipher_name);
	if (!cipher_key_bytes_set)
		mount_crypt_stat->global_default_cipher_key_size = 0;
	if ((mount_crypt_stat->flags & SEFS_GLOBAL_ENCRYPT_FILENAMES)
	    && !fn_cipher_key_bytes_set)
		mount_crypt_stat->global_default_fn_cipher_key_bytes =
			mount_crypt_stat->global_default_cipher_key_size;

	cipher_code = sefs_code_for_cipher_string(
		mount_crypt_stat->global_default_cipher_name,
		mount_crypt_stat->global_default_cipher_key_size);
	if (!cipher_code) {
		sefs_printk(KERN_ERR,
				"SEFS doesn't support cipher: %s",
				mount_crypt_stat->global_default_cipher_name);
		rc = -EINVAL;
		goto out;
	}

	mutex_lock(&key_tfm_list_mutex);
	if (!sefs_tfm_exists(mount_crypt_stat->global_default_cipher_name,
				 NULL)) {
		rc = sefs_add_new_key_tfm(
			NULL, mount_crypt_stat->global_default_cipher_name,
			mount_crypt_stat->global_default_cipher_key_size);
		if (rc) {
			printk(KERN_ERR "Error attempting to initialize "
			       "cipher with name = [%s] and key size = [%td]; "
			       "rc = [%d]\n",
			       mount_crypt_stat->global_default_cipher_name,
			       mount_crypt_stat->global_default_cipher_key_size,
			       rc);
			rc = -EINVAL;
			mutex_unlock(&key_tfm_list_mutex);
			goto out;
		}
	}
	if ((mount_crypt_stat->flags & SEFS_GLOBAL_ENCRYPT_FILENAMES)
	    && !sefs_tfm_exists(
		    mount_crypt_stat->global_default_fn_cipher_name, NULL)) {
		rc = sefs_add_new_key_tfm(
			NULL, mount_crypt_stat->global_default_fn_cipher_name,
			mount_crypt_stat->global_default_fn_cipher_key_bytes);
		if (rc) {
			printk(KERN_ERR "Error attempting to initialize "
			       "cipher with name = [%s] and key size = [%td]; "
			       "rc = [%d]\n",
			       mount_crypt_stat->global_default_fn_cipher_name,
			       mount_crypt_stat->global_default_fn_cipher_key_bytes,
			       rc);
			rc = -EINVAL;
			mutex_unlock(&key_tfm_list_mutex);
			goto out;
		}
	}
	mutex_unlock(&key_tfm_list_mutex);
	rc = sefs_init_global_auth_toks(mount_crypt_stat);
	if (rc)
		printk(KERN_WARNING "One or more global auth toks could not "
		       "properly register; rc = [%d]\n", rc);
out:
	return rc;
}

struct kmem_cache *sefs_sb_info_cache;
static struct file_system_type sefs_fs_type;

/**
 * sefs_get_sb
 * @fs_type
 * @flags
 * @dev_name: The path to mount over
 * @raw_data: The options passed into the kernel
 */
static struct dentry *sefs_mount(struct file_system_type *fs_type, int flags,
			const char *dev_name, void *raw_data)
{
	struct super_block *s;
	struct sefs_sb_info *sbi;
	struct sefs_mount_crypt_stat *mount_crypt_stat;
	struct sefs_dentry_info *root_info;
	const char *err = "Getting sb failed";
	struct inode *inode;
	struct path path;
	uid_t check_ruid;
	int rc;

	sbi = kmem_cache_zalloc(sefs_sb_info_cache, GFP_KERNEL);
	if (!sbi) {
		rc = -ENOMEM;
		goto out;
	}

	rc = sefs_parse_options(sbi, raw_data, &check_ruid);
	if (rc) {
		err = "Error parsing options";
		goto out;
	}
	mount_crypt_stat = &sbi->mount_crypt_stat;

	s = sget(fs_type, NULL, set_anon_super, flags, NULL);
	if (IS_ERR(s)) {
		rc = PTR_ERR(s);
		goto out;
	}

	rc = super_setup_bdi(s);
	if (rc)
		goto out1;

	sefs_set_superblock_private(s, sbi);

	/* ->kill_sb() will take care of sbi after that point */
	sbi = NULL;
	s->s_op = &sefs_sops;
	s->s_xattr = sefs_xattr_handlers;
	s->s_d_op = &sefs_dops;

	err = "Reading sb failed";
	rc = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
	if (rc) {
		sefs_printk(KERN_WARNING, "kern_path() failed\n");
		goto out1;
	}
	if (path.dentry->d_sb->s_type == &sefs_fs_type) {
		rc = -EINVAL;
		printk(KERN_ERR "Mount on filesystem of type "
			"SEFS explicitly disallowed due to "
			"known incompatibilities\n");
		goto out_free;
	}

	if (check_ruid && !uid_eq(d_inode(path.dentry)->i_uid, current_uid())) {
		rc = -EPERM;
		printk(KERN_ERR "Mount of device (uid: %d) not owned by "
		       "requested user (uid: %d)\n",
			i_uid_read(d_inode(path.dentry)),
			from_kuid(&init_user_ns, current_uid()));
		goto out_free;
	}

	sefs_set_superblock_lower(s, path.dentry->d_sb);

	/**
	 * Set the POSIX ACL flag based on whether they're enabled in the lower
	 * mount.
	 */
	s->s_flags = flags & ~MS_POSIXACL;
	s->s_flags |= path.dentry->d_sb->s_flags & MS_POSIXACL;

	/**
	 * Force a read-only SEFS mount when:
	 *   1) The lower mount is ro
	 *   2) The sefs_encrypted_view mount option is specified
	 */
	if (sb_rdonly(path.dentry->d_sb) || mount_crypt_stat->flags & SEFS_ENCRYPTED_VIEW_ENABLED)
		s->s_flags |= MS_RDONLY;

	s->s_maxbytes = path.dentry->d_sb->s_maxbytes;
	s->s_blocksize = path.dentry->d_sb->s_blocksize;
	s->s_magic = SEFS_SUPER_MAGIC;
	s->s_stack_depth = path.dentry->d_sb->s_stack_depth + 1;

	rc = -EINVAL;
	if (s->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("SEFS: maximum fs stacking depth exceeded\n");
		goto out_free;
	}

	inode = sefs_get_inode(d_inode(path.dentry), s);
	rc = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_free;

	s->s_root = d_make_root(inode);
	if (!s->s_root) {
		rc = -ENOMEM;
		goto out_free;
	}

	rc = -ENOMEM;
	root_info = kmem_cache_zalloc(sefs_dentry_info_cache, GFP_KERNEL);
	if (!root_info)
		goto out_free;

	/* ->kill_sb() will take care of root_info */
	sefs_set_dentry_private(s->s_root, root_info);
	root_info->lower_path = path;

	s->s_flags |= MS_ACTIVE;
	return dget(s->s_root);

out_free:
	path_put(&path);
out1:
	deactivate_locked_super(s);
out:
	if (sbi) {
		sefs_destroy_mount_crypt_stat(&sbi->mount_crypt_stat);
		kmem_cache_free(sefs_sb_info_cache, sbi);
	}
	printk(KERN_ERR "%s; rc = [%d]\n", err, rc);
	return ERR_PTR(rc);
}

/**
 * sefs_kill_block_super
 * @sb: The sefs super block
 *
 * Used to bring the superblock down and free the private data.
 */
static void sefs_kill_block_super(struct super_block *sb)
{
	struct sefs_sb_info *sb_info = sefs_superblock_to_private(sb);
	kill_anon_super(sb);
	if (!sb_info)
		return;
	sefs_destroy_mount_crypt_stat(&sb_info->mount_crypt_stat);
	kmem_cache_free(sefs_sb_info_cache, sb_info);
}

static struct file_system_type sefs_fs_type = {
	.owner = THIS_MODULE,
	.name = "sefs",
	.mount = sefs_mount,
	.kill_sb = sefs_kill_block_super,
	.fs_flags = 0
};
MODULE_ALIAS_FS("sefs");

/**
 * inode_info_init_once
 *
 * Initializes the sefs_inode_info_cache when it is created
 */
static void
inode_info_init_once(void *vptr)
{
	struct sefs_inode_info *ei = (struct sefs_inode_info *)vptr;

	inode_init_once(&ei->vfs_inode);
}

static struct sefs_cache_info {
	struct kmem_cache **cache;
	const char *name;
	size_t size;
	unsigned long flags;
	void (*ctor)(void *obj);
} sefs_cache_infos[] = {
	{
		.cache = &sefs_auth_tok_list_item_cache,
		.name = "sefs_auth_tok_list_item",
		.size = sizeof(struct sefs_auth_tok_list_item),
	},
	{
		.cache = &sefs_file_info_cache,
		.name = "sefs_file_cache",
		.size = sizeof(struct sefs_file_info),
	},
	{
		.cache = &sefs_dentry_info_cache,
		.name = "sefs_dentry_info_cache",
		.size = sizeof(struct sefs_dentry_info),
	},
	{
		.cache = &sefs_inode_info_cache,
		.name = "sefs_inode_cache",
		.size = sizeof(struct sefs_inode_info),
		.flags = SLAB_ACCOUNT,
		.ctor = inode_info_init_once,
	},
	{
		.cache = &sefs_sb_info_cache,
		.name = "sefs_sb_cache",
		.size = sizeof(struct sefs_sb_info),
	},
	{
		.cache = &sefs_header_cache,
		.name = "sefs_headers",
		.size = PAGE_SIZE,
	},
	{
		.cache = &sefs_xattr_cache,
		.name = "sefs_xattr_cache",
		.size = PAGE_SIZE,
	},
	{
		.cache = &sefs_key_record_cache,
		.name = "sefs_key_record_cache",
		.size = sizeof(struct sefs_key_record),
	},
	{
		.cache = &sefs_key_sig_cache,
		.name = "sefs_key_sig_cache",
		.size = sizeof(struct sefs_key_sig),
	},
	{
		.cache = &sefs_global_auth_tok_cache,
		.name = "sefs_global_auth_tok_cache",
		.size = sizeof(struct sefs_global_auth_tok),
	},
	{
		.cache = &sefs_key_tfm_cache,
		.name = "sefs_key_tfm_cache",
		.size = sizeof(struct sefs_key_tfm),
	},
};

static void sefs_free_kmem_caches(void)
{
	int i;

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();

	for (i = 0; i < ARRAY_SIZE(sefs_cache_infos); i++) {
		struct sefs_cache_info *info;

		info = &sefs_cache_infos[i];
		kmem_cache_destroy(*(info->cache));
	}
}

/**
 * sefs_init_kmem_caches
 *
 * Returns zero on success; non-zero otherwise
 */
static int sefs_init_kmem_caches(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sefs_cache_infos); i++) {
		struct sefs_cache_info *info;

		info = &sefs_cache_infos[i];
		*(info->cache) = kmem_cache_create(info->name, info->size, 0,
				SLAB_HWCACHE_ALIGN | info->flags, info->ctor);
		if (!*(info->cache)) {
			sefs_free_kmem_caches();
			sefs_printk(KERN_WARNING, "%s: "
					"kmem_cache_create failed\n",
					info->name);
			return -ENOMEM;
		}
	}
	return 0;
}

static struct kobject *sefs_kobj;

static ssize_t version_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buff)
{
	return snprintf(buff, PAGE_SIZE, "%d\n", SEFS_VERSIONING_MASK);
}

static struct kobj_attribute version_attr = __ATTR_RO(version);

static struct attribute *attributes[] = {
	&version_attr.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attributes,
};

static int do_sysfs_registration(void)
{
	int rc;

	sefs_kobj = kobject_create_and_add("sefs", fs_kobj);
	if (!sefs_kobj) {
		printk(KERN_ERR "Unable to create sefs kset\n");
		rc = -ENOMEM;
		goto out;
	}
	rc = sysfs_create_group(sefs_kobj, &attr_group);
	if (rc) {
		printk(KERN_ERR
		       "Unable to create sefs version attributes\n");
		kobject_put(sefs_kobj);
	}
out:
	return rc;
}

static void do_sysfs_unregistration(void)
{
	sysfs_remove_group(sefs_kobj, &attr_group);
	kobject_put(sefs_kobj);
}

static int __init sefs_init(void)
{
	int rc;
	printk(KERN_EMERG "sysfs sefs_init\n");
	  
	if (SEFS_DEFAULT_EXTENT_SIZE > PAGE_SIZE) {
		rc = -EINVAL;
		sefs_printk(KERN_ERR, "The SEFS extent size is "
				"larger than the host's page size, and so "
				"SEFS cannot run on this system. The "
				"default SEFS extent size is [%u] bytes; "
				"the page size is [%lu] bytes.\n",
				SEFS_DEFAULT_EXTENT_SIZE,
				(unsigned long)PAGE_SIZE);
		goto out;
	}
	rc = sefs_init_kmem_caches();
	if (rc) {
		printk(KERN_ERR
		       "Failed to allocate one or more kmem_cache objects\n");
		goto out;
	}
	rc = do_sysfs_registration();
	if (rc) {
		printk(KERN_ERR "sysfs registration failed\n");
		goto out_free_kmem_caches;
	}
	rc = sefs_init_kthread();
	if (rc) {
		printk(KERN_ERR "%s: kthread initialization failed; "
		       "rc = [%d]\n", __func__, rc);
		goto out_do_sysfs_unregistration;
	}
	rc = sefs_init_messaging();
	if (rc) {
		printk(KERN_ERR "Failure occurred while attempting to "
				"initialize the communications channel to "
				"sefsd\n");
		goto out_destroy_kthread;
	}
	rc = sefs_init_crypto();
	if (rc) {
		printk(KERN_ERR "Failure whilst attempting to init crypto; "
		       "rc = [%d]\n", rc);
		goto out_release_messaging;
	}
	rc = register_filesystem(&sefs_fs_type);
	if (rc) {
		printk(KERN_ERR "Failed to register filesystem\n");
		goto out_destroy_crypto;
	}
	if (sefs_verbosity > 0)
		printk(KERN_CRIT "SEFS verbosity set to %d. Secret values "
			"will be written to the syslog!\n", sefs_verbosity);

	printk(KERN_EMERG "dywu efs_init_module return: %d!\n", efs_init_module());

	goto out;
out_destroy_crypto:
	sefs_destroy_crypto();
out_release_messaging:
	sefs_release_messaging();
out_destroy_kthread:
	sefs_destroy_kthread();
out_do_sysfs_unregistration:
	do_sysfs_unregistration();
out_free_kmem_caches:
	sefs_free_kmem_caches();
out:
	return rc;
}

static void __exit sefs_exit(void)
{
	int rc;

	efs_cleanup_module();
	
	rc = sefs_destroy_crypto();
	if (rc)
		printk(KERN_ERR "Failure whilst attempting to destroy crypto; "
		       "rc = [%d]\n", rc);
	sefs_release_messaging();
	sefs_destroy_kthread();
	do_sysfs_unregistration();
	unregister_filesystem(&sefs_fs_type);
	sefs_free_kmem_caches();
}

MODULE_AUTHOR("Michael A. Halcrow <mhalcrow@us.ibm.com>");
MODULE_DESCRIPTION("SEFS");

MODULE_LICENSE("GPL");

module_init(sefs_init)
module_exit(sefs_exit)
