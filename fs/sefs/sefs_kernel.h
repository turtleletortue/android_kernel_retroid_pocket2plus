/**
 * eCryptfs: Linux filesystem encryption layer
 * Kernel declarations.
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2008 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Trevor S. Highland <trevor.highland@gmail.com>
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

#ifndef SEFS_KERNEL_H
#define SEFS_KERNEL_H

#include <crypto/skcipher.h>
#include <keys/user-type.h>
#include <keys/encrypted-type.h>
#include <linux/fs.h>
#include <linux/fs_stack.h>
#include <linux/namei.h>
#include <linux/scatterlist.h>
#include <linux/hash.h>
#include <linux/nsproxy.h>
#include <linux/backing-dev.h>
#include <linux/sefs.h>

#define SEFS_DEFAULT_IV_BYTES 16
#define SEFS_DEFAULT_EXTENT_SIZE 4096
#define SEFS_MINIMUM_HEADER_EXTENT_SIZE 8192
#define SEFS_DEFAULT_MSG_CTX_ELEMS 32
#define SEFS_DEFAULT_SEND_TIMEOUT HZ
#define SEFS_MAX_MSG_CTX_TTL (HZ*3)
#define SEFS_DEFAULT_NUM_USERS 4
#define SEFS_MAX_NUM_USERS 32768
#define SEFS_XATTR_NAME "user.sefs"

void sefs_dump_auth_tok(struct sefs_auth_tok *auth_tok);
extern void sefs_to_hex(char *dst, char *src, size_t src_size);
extern void sefs_from_hex(char *dst, char *src, int dst_size);

struct sefs_key_record {
	unsigned char type;
	size_t enc_key_size;
	unsigned char sig[SEFS_SIG_SIZE];
	unsigned char enc_key[SEFS_MAX_ENCRYPTED_KEY_BYTES];
};

struct sefs_auth_tok_list {
	struct sefs_auth_tok *auth_tok;
	struct list_head list;
};

struct sefs_crypt_stat;
struct sefs_mount_crypt_stat;

struct sefs_page_crypt_context {
	struct page *page;
#define SEFS_PREPARE_COMMIT_MODE 0
#define SEFS_WRITEPAGE_MODE      1
	unsigned int mode;
	union {
		struct file *lower_file;
		struct writeback_control *wbc;
	} param;
};

#if defined(CONFIG_ENCRYPTED_KEYS) || defined(CONFIG_ENCRYPTED_KEYS_MODULE)
static inline struct sefs_auth_tok *
sefs_get_encrypted_key_payload_data(struct key *key)
{
	struct encrypted_key_payload *payload;

	if (key->type != &key_type_encrypted)
		return NULL;

	payload = key->payload.data[0];
	if (!payload)
		return ERR_PTR(-EKEYREVOKED);

	return (struct sefs_auth_tok *)payload->payload_data;
}

static inline struct key *sefs_get_encrypted_key(char *sig)
{
	return request_key(&key_type_encrypted, sig, NULL);
}

#else
static inline struct sefs_auth_tok *
sefs_get_encrypted_key_payload_data(struct key *key)
{
	return NULL;
}

static inline struct key *sefs_get_encrypted_key(char *sig)
{
	return ERR_PTR(-ENOKEY);
}

#endif /* CONFIG_ENCRYPTED_KEYS */

static inline struct sefs_auth_tok *
sefs_get_key_payload_data(struct key *key)
{
	struct sefs_auth_tok *auth_tok;
	struct user_key_payload *ukp;

	auth_tok = sefs_get_encrypted_key_payload_data(key);
	if (auth_tok)
		return auth_tok;

	ukp = user_key_payload_locked(key);
	if (!ukp)
		return ERR_PTR(-EKEYREVOKED);

	return (struct sefs_auth_tok *)ukp->data;
}

#define SEFS_MAX_KEYSET_SIZE 1024
#define SEFS_MAX_CIPHER_NAME_SIZE 31
#define SEFS_MAX_NUM_ENC_KEYS 64
#define SEFS_MAX_IV_BYTES 16	/* 128 bits */
#define SEFS_SALT_BYTES 2
#define MAGIC_SEFS_MARKER 0x3c81b7f5
#define MAGIC_SEFS_MARKER_SIZE_BYTES 8	/* 4*2 */
#define SEFS_FILE_SIZE_BYTES (sizeof(u64))
#define SEFS_SIZE_AND_MARKER_BYTES (SEFS_FILE_SIZE_BYTES \
					+ MAGIC_SEFS_MARKER_SIZE_BYTES)
#define SEFS_DEFAULT_CIPHER "aes"
#define SEFS_DEFAULT_KEY_BYTES 16
#define SEFS_DEFAULT_HASH "md5"
#define SEFS_TAG_70_DIGEST SEFS_DEFAULT_HASH
#define SEFS_TAG_1_PACKET_TYPE 0x01
#define SEFS_TAG_3_PACKET_TYPE 0x8C
#define SEFS_TAG_11_PACKET_TYPE 0xED
#define SEFS_TAG_64_PACKET_TYPE 0x40
#define SEFS_TAG_65_PACKET_TYPE 0x41
#define SEFS_TAG_66_PACKET_TYPE 0x42
#define SEFS_TAG_67_PACKET_TYPE 0x43
#define SEFS_TAG_70_PACKET_TYPE 0x46 /* FNEK-encrypted filename
					  * as dentry name */
#define SEFS_TAG_71_PACKET_TYPE 0x47 /* FNEK-encrypted filename in
					  * metadata */
#define SEFS_TAG_72_PACKET_TYPE 0x48 /* FEK-encrypted filename as
					  * dentry name */
#define SEFS_TAG_73_PACKET_TYPE 0x49 /* FEK-encrypted filename as
					  * metadata */
#define SEFS_MIN_PKT_LEN_SIZE 1 /* Min size to specify packet length */
#define SEFS_MAX_PKT_LEN_SIZE 2 /* Pass at least this many bytes to
				     * sefs_parse_packet_length() and
				     * sefs_write_packet_length()
				     */
/* Constraint: SEFS_FILENAME_MIN_RANDOM_PREPEND_BYTES >=
 * SEFS_MAX_IV_BYTES */
#define SEFS_FILENAME_MIN_RANDOM_PREPEND_BYTES 16
#define SEFS_NON_NULL 0x42 /* A reasonable substitute for NULL */
#define MD5_DIGEST_SIZE 16
#define SEFS_TAG_70_DIGEST_SIZE MD5_DIGEST_SIZE
#define SEFS_TAG_70_MIN_METADATA_SIZE (1 + SEFS_MIN_PKT_LEN_SIZE \
					   + SEFS_SIG_SIZE + 1 + 1)
#define SEFS_TAG_70_MAX_METADATA_SIZE (1 + SEFS_MAX_PKT_LEN_SIZE \
					   + SEFS_SIG_SIZE + 1 + 1)
#define SEFS_FEK_ENCRYPTED_FILENAME_PREFIX "SEFS_FEK_ENCRYPTED."
#define SEFS_FEK_ENCRYPTED_FILENAME_PREFIX_SIZE 23
#define SEFS_FNEK_ENCRYPTED_FILENAME_PREFIX "SEFS_FNEK_ENCRYPTED."
#define SEFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE 24
#define SEFS_ENCRYPTED_DENTRY_NAME_LEN (18 + 1 + 4 + 1 + 32)

#ifdef CONFIG_ECRYPT_FS_MESSAGING
# define SEFS_VERSIONING_MASK_MESSAGING (SEFS_VERSIONING_DEVMISC \
					     | SEFS_VERSIONING_PUBKEY)
#else
# define SEFS_VERSIONING_MASK_MESSAGING 0
#endif

#define SEFS_VERSIONING_MASK (SEFS_VERSIONING_PASSPHRASE \
				  | SEFS_VERSIONING_PLAINTEXT_PASSTHROUGH \
				  | SEFS_VERSIONING_XATTR \
				  | SEFS_VERSIONING_MULTKEY \
				  | SEFS_VERSIONING_MASK_MESSAGING \
				  | SEFS_VERSIONING_FILENAME_ENCRYPTION)
struct sefs_key_sig {
	struct list_head crypt_stat_list;
	char keysig[SEFS_SIG_SIZE_HEX + 1];
};

struct sefs_filename {
	struct list_head crypt_stat_list;
#define SEFS_FILENAME_CONTAINS_DECRYPTED 0x00000001
	u32 flags;
	u32 seq_no;
	char *filename;
	char *encrypted_filename;
	size_t filename_size;
	size_t encrypted_filename_size;
	char fnek_sig[SEFS_SIG_SIZE_HEX];
	char dentry_name[SEFS_ENCRYPTED_DENTRY_NAME_LEN + 1];
};

/**
 * This is the primary struct associated with each encrypted file.
 *
 * TODO: cache align/pack?
 */
struct sefs_crypt_stat {
#define SEFS_STRUCT_INITIALIZED   0x00000001
#define SEFS_POLICY_APPLIED       0x00000002
#define SEFS_ENCRYPTED            0x00000004
#define SEFS_SECURITY_WARNING     0x00000008
#define SEFS_ENABLE_HMAC          0x00000010
#define SEFS_ENCRYPT_IV_PAGES     0x00000020
#define SEFS_KEY_VALID            0x00000040
#define SEFS_METADATA_IN_XATTR    0x00000080
#define SEFS_VIEW_AS_ENCRYPTED    0x00000100
#define SEFS_KEY_SET              0x00000200
#define SEFS_ENCRYPT_FILENAMES    0x00000400
#define SEFS_ENCFN_USE_MOUNT_FNEK 0x00000800
#define SEFS_ENCFN_USE_FEK        0x00001000
#define SEFS_UNLINK_SIGS          0x00002000
#define SEFS_I_SIZE_INITIALIZED   0x00004000
	u32 flags;
	unsigned int file_version;
	size_t iv_bytes;
	size_t metadata_size;
	size_t extent_size; /* Data extent size; default is 4096 */
	size_t key_size;
	size_t extent_shift;
	unsigned int extent_mask;
	struct sefs_mount_crypt_stat *mount_crypt_stat;
	struct crypto_skcipher *tfm;
	struct crypto_shash *hash_tfm; /* Crypto context for generating
					* the initialization vectors */
	unsigned char cipher[SEFS_MAX_CIPHER_NAME_SIZE + 1];
	unsigned char key[SEFS_MAX_KEY_BYTES];
	unsigned char root_iv[SEFS_MAX_IV_BYTES];
	struct list_head keysig_list;
	struct mutex keysig_list_mutex;
	struct mutex cs_tfm_mutex;
	struct mutex cs_mutex;
};

/* inode private data. */
struct sefs_inode_info {
	struct inode vfs_inode;
	struct inode *wii_inode;
	struct mutex lower_file_mutex;
	atomic_t lower_file_count;
	struct file *lower_file;
	struct sefs_crypt_stat crypt_stat;
};

/* dentry private data. Each dentry must keep track of a lower
 * vfsmount too. */
struct sefs_dentry_info {
	struct path lower_path;
	union {
		struct sefs_crypt_stat *crypt_stat;
		struct rcu_head rcu;
	};
};

/**
 * sefs_global_auth_tok - A key used to encrypt all new files under the mountpoint
 * @flags: Status flags
 * @mount_crypt_stat_list: These auth_toks hang off the mount-wide
 *                         cryptographic context. Every time a new
 *                         inode comes into existence, eCryptfs copies
 *                         the auth_toks on that list to the set of
 *                         auth_toks on the inode's crypt_stat
 * @global_auth_tok_key: The key from the user's keyring for the sig
 * @global_auth_tok: The key contents
 * @sig: The key identifier
 *
 * sefs_global_auth_tok structs refer to authentication token keys
 * in the user keyring that apply to newly created files. A list of
 * these objects hangs off of the mount_crypt_stat struct for any
 * given eCryptfs mount. This struct maintains a reference to both the
 * key contents and the key itself so that the key can be put on
 * unmount.
 */
struct sefs_global_auth_tok {
#define SEFS_AUTH_TOK_INVALID 0x00000001
#define SEFS_AUTH_TOK_FNEK    0x00000002
	u32 flags;
	struct list_head mount_crypt_stat_list;
	struct key *global_auth_tok_key;
	unsigned char sig[SEFS_SIG_SIZE_HEX + 1];
};

/**
 * sefs_key_tfm - Persistent key tfm
 * @key_tfm: crypto API handle to the key
 * @key_size: Key size in bytes
 * @key_tfm_mutex: Mutex to ensure only one operation in eCryptfs is
 *                 using the persistent TFM at any point in time
 * @key_tfm_list: Handle to hang this off the module-wide TFM list
 * @cipher_name: String name for the cipher for this TFM
 *
 * Typically, eCryptfs will use the same ciphers repeatedly throughout
 * the course of its operations. In order to avoid unnecessarily
 * destroying and initializing the same cipher repeatedly, eCryptfs
 * keeps a list of crypto API contexts around to use when needed.
 */
struct sefs_key_tfm {
	struct crypto_skcipher *key_tfm;
	size_t key_size;
	struct mutex key_tfm_mutex;
	struct list_head key_tfm_list;
	unsigned char cipher_name[SEFS_MAX_CIPHER_NAME_SIZE + 1];
};

extern struct mutex key_tfm_list_mutex;

/**
 * This struct is to enable a mount-wide passphrase/salt combo. This
 * is more or less a stopgap to provide similar functionality to other
 * crypto filesystems like EncFS or CFS until full policy support is
 * implemented in eCryptfs.
 */
struct sefs_mount_crypt_stat {
	/* Pointers to memory we do not own, do not free these */
#define SEFS_PLAINTEXT_PASSTHROUGH_ENABLED 0x00000001
#define SEFS_XATTR_METADATA_ENABLED        0x00000002
#define SEFS_ENCRYPTED_VIEW_ENABLED        0x00000004
#define SEFS_MOUNT_CRYPT_STAT_INITIALIZED  0x00000008
#define SEFS_GLOBAL_ENCRYPT_FILENAMES      0x00000010
#define SEFS_GLOBAL_ENCFN_USE_MOUNT_FNEK   0x00000020
#define SEFS_GLOBAL_ENCFN_USE_FEK          0x00000040
#define SEFS_GLOBAL_MOUNT_AUTH_TOK_ONLY    0x00000080
	u32 flags;
	struct list_head global_auth_tok_list;
	struct mutex global_auth_tok_list_mutex;
	size_t global_default_cipher_key_size;
	size_t global_default_fn_cipher_key_bytes;
	unsigned char global_default_cipher_name[SEFS_MAX_CIPHER_NAME_SIZE
						 + 1];
	unsigned char global_default_fn_cipher_name[
		SEFS_MAX_CIPHER_NAME_SIZE + 1];
	char global_default_fnek_sig[SEFS_SIG_SIZE_HEX + 1];
};

/* superblock private data. */
struct sefs_sb_info {
	struct super_block *wsi_sb;
	struct sefs_mount_crypt_stat mount_crypt_stat;
};

/* file private data. */
struct sefs_file_info {
	struct file *wfi_file;
	struct sefs_crypt_stat *crypt_stat;
};

/* auth_tok <=> encrypted_session_key mappings */
struct sefs_auth_tok_list_item {
	unsigned char encrypted_session_key[SEFS_MAX_KEY_BYTES];
	struct list_head list;
	struct sefs_auth_tok auth_tok;
};

struct sefs_message {
	/* Can never be greater than sefs_message_buf_len */
	/* Used to find the parent msg_ctx */
	/* Inherits from msg_ctx->index */
	u32 index;
	u32 data_len;
	u8 data[];
};

struct sefs_msg_ctx {
#define SEFS_MSG_CTX_STATE_FREE     0x01
#define SEFS_MSG_CTX_STATE_PENDING  0x02
#define SEFS_MSG_CTX_STATE_DONE     0x03
#define SEFS_MSG_CTX_STATE_NO_REPLY 0x04
	u8 state;
#define SEFS_MSG_HELO 100
#define SEFS_MSG_QUIT 101
#define SEFS_MSG_REQUEST 102
#define SEFS_MSG_RESPONSE 103
	u8 type;
	u32 index;
	/* Counter converts to a sequence number. Each message sent
	 * out for which we expect a response has an associated
	 * sequence number. The response must have the same sequence
	 * number as the counter for the msg_stc for the message to be
	 * valid. */
	u32 counter;
	size_t msg_size;
	struct sefs_message *msg;
	struct task_struct *task;
	struct list_head node;
	struct list_head daemon_out_list;
	struct mutex mux;
};

struct sefs_daemon {
#define SEFS_DAEMON_IN_READ      0x00000001
#define SEFS_DAEMON_IN_POLL      0x00000002
#define SEFS_DAEMON_ZOMBIE       0x00000004
#define SEFS_DAEMON_MISCDEV_OPEN 0x00000008
	u32 flags;
	u32 num_queued_msg_ctx;
	struct file *file;
	struct mutex mux;
	struct list_head msg_ctx_out_queue;
	wait_queue_head_t wait;
	struct hlist_node euid_chain;
};

#ifdef CONFIG_ECRYPT_FS_MESSAGING
extern struct mutex sefs_daemon_hash_mux;
#endif

static inline size_t
sefs_lower_header_size(struct sefs_crypt_stat *crypt_stat)
{
	if (crypt_stat->flags & SEFS_METADATA_IN_XATTR)
		return 0;
	return crypt_stat->metadata_size;
}

static inline struct sefs_file_info *
sefs_file_to_private(struct file *file)
{
	return file->private_data;
}

static inline void
sefs_set_file_private(struct file *file,
			  struct sefs_file_info *file_info)
{
	file->private_data = file_info;
}

static inline struct file *sefs_file_to_lower(struct file *file)
{
	return ((struct sefs_file_info *)file->private_data)->wfi_file;
}

static inline void
sefs_set_file_lower(struct file *file, struct file *lower_file)
{
	((struct sefs_file_info *)file->private_data)->wfi_file =
		lower_file;
}

static inline struct sefs_inode_info *
sefs_inode_to_private(struct inode *inode)
{
	return container_of(inode, struct sefs_inode_info, vfs_inode);
}

static inline struct inode *sefs_inode_to_lower(struct inode *inode)
{
	return sefs_inode_to_private(inode)->wii_inode;
}

static inline void
sefs_set_inode_lower(struct inode *inode, struct inode *lower_inode)
{
	sefs_inode_to_private(inode)->wii_inode = lower_inode;
}

static inline struct sefs_sb_info *
sefs_superblock_to_private(struct super_block *sb)
{
	return (struct sefs_sb_info *)sb->s_fs_info;
}

static inline void
sefs_set_superblock_private(struct super_block *sb,
				struct sefs_sb_info *sb_info)
{
	sb->s_fs_info = sb_info;
}

static inline struct super_block *
sefs_superblock_to_lower(struct super_block *sb)
{
	return ((struct sefs_sb_info *)sb->s_fs_info)->wsi_sb;
}

static inline void
sefs_set_superblock_lower(struct super_block *sb,
			      struct super_block *lower_sb)
{
	((struct sefs_sb_info *)sb->s_fs_info)->wsi_sb = lower_sb;
}

static inline struct sefs_dentry_info *
sefs_dentry_to_private(struct dentry *dentry)
{
	return (struct sefs_dentry_info *)dentry->d_fsdata;
}

static inline void
sefs_set_dentry_private(struct dentry *dentry,
			    struct sefs_dentry_info *dentry_info)
{
	dentry->d_fsdata = dentry_info;
}

static inline struct dentry *
sefs_dentry_to_lower(struct dentry *dentry)
{
	return ((struct sefs_dentry_info *)dentry->d_fsdata)->lower_path.dentry;
}

static inline struct vfsmount *
sefs_dentry_to_lower_mnt(struct dentry *dentry)
{
	return ((struct sefs_dentry_info *)dentry->d_fsdata)->lower_path.mnt;
}

static inline struct path *
sefs_dentry_to_lower_path(struct dentry *dentry)
{
	return &((struct sefs_dentry_info *)dentry->d_fsdata)->lower_path;
}

#define sefs_printk(type, fmt, arg...) \
        __sefs_printk(type "%s: " fmt, __func__, ## arg);
__printf(1, 2)
void __sefs_printk(const char *fmt, ...);

extern const struct file_operations sefs_main_fops;
extern const struct file_operations sefs_dir_fops;
extern const struct inode_operations sefs_main_iops;
extern const struct inode_operations sefs_dir_iops;
extern const struct inode_operations sefs_symlink_iops;
extern const struct super_operations sefs_sops;
extern const struct dentry_operations sefs_dops;
extern const struct address_space_operations sefs_aops;
extern int sefs_verbosity;
extern unsigned int sefs_message_buf_len;
extern signed long sefs_message_wait_timeout;
extern unsigned int sefs_number_of_users;

extern struct kmem_cache *sefs_auth_tok_list_item_cache;
extern struct kmem_cache *sefs_file_info_cache;
extern struct kmem_cache *sefs_dentry_info_cache;
extern struct kmem_cache *sefs_inode_info_cache;
extern struct kmem_cache *sefs_sb_info_cache;
extern struct kmem_cache *sefs_header_cache;
extern struct kmem_cache *sefs_xattr_cache;
extern struct kmem_cache *sefs_key_record_cache;
extern struct kmem_cache *sefs_key_sig_cache;
extern struct kmem_cache *sefs_global_auth_tok_cache;
extern struct kmem_cache *sefs_key_tfm_cache;

struct inode *sefs_get_inode(struct inode *lower_inode,
				 struct super_block *sb);
void sefs_i_size_init(const char *page_virt, struct inode *inode);
int sefs_initialize_file(struct dentry *sefs_dentry,
			     struct inode *sefs_inode);
int sefs_decode_and_decrypt_filename(char **decrypted_name,
					 size_t *decrypted_name_size,
					 struct super_block *sb,
					 const char *name, size_t name_size);
int sefs_fill_zeros(struct file *file, loff_t new_length);
int sefs_encrypt_and_encode_filename(
	char **encoded_name,
	size_t *encoded_name_size,
	struct sefs_mount_crypt_stat *mount_crypt_stat,
	const char *name, size_t name_size);
struct dentry *sefs_lower_dentry(struct dentry *this_dentry);
void sefs_dump_hex(char *data, int bytes);
int virt_to_scatterlist(const void *addr, int size, struct scatterlist *sg,
			int sg_size);
int sefs_compute_root_iv(struct sefs_crypt_stat *crypt_stat);
void sefs_rotate_iv(unsigned char *iv);
int sefs_init_crypt_stat(struct sefs_crypt_stat *crypt_stat);
void sefs_destroy_crypt_stat(struct sefs_crypt_stat *crypt_stat);
void sefs_destroy_mount_crypt_stat(
	struct sefs_mount_crypt_stat *mount_crypt_stat);
int sefs_init_crypt_ctx(struct sefs_crypt_stat *crypt_stat);
int sefs_write_inode_size_to_metadata(struct inode *sefs_inode);
int sefs_encrypt_page(struct page *page);
int sefs_decrypt_page(struct page *page);
int sefs_write_metadata(struct dentry *sefs_dentry,
			    struct inode *sefs_inode);
int sefs_read_metadata(struct dentry *sefs_dentry);
int sefs_new_file_context(struct inode *sefs_inode);
void sefs_write_crypt_stat_flags(char *page_virt,
				     struct sefs_crypt_stat *crypt_stat,
				     size_t *written);
int sefs_read_and_validate_header_region(struct inode *inode);
int sefs_read_and_validate_xattr_region(struct dentry *dentry,
					    struct inode *inode);
u8 sefs_code_for_cipher_string(char *cipher_name, size_t key_bytes);
int sefs_cipher_code_to_string(char *str, u8 cipher_code);
void sefs_set_default_sizes(struct sefs_crypt_stat *crypt_stat);
int sefs_generate_key_packet_set(char *dest_base,
				     struct sefs_crypt_stat *crypt_stat,
				     struct dentry *sefs_dentry,
				     size_t *len, size_t max);
int
sefs_parse_packet_set(struct sefs_crypt_stat *crypt_stat,
			  unsigned char *src, struct dentry *sefs_dentry);
int sefs_truncate(struct dentry *dentry, loff_t new_length);
ssize_t
sefs_getxattr_lower(struct dentry *lower_dentry, struct inode *lower_inode,
			const char *name, void *value, size_t size);
int
sefs_setxattr(struct dentry *dentry, struct inode *inode, const char *name,
		  const void *value, size_t size, int flags);
int sefs_read_xattr_region(char *page_virt, struct inode *sefs_inode);
#ifdef CONFIG_ECRYPT_FS_MESSAGING
int sefs_process_response(struct sefs_daemon *daemon,
			      struct sefs_message *msg, u32 seq);
int sefs_send_message(char *data, int data_len,
			  struct sefs_msg_ctx **msg_ctx);
int sefs_wait_for_response(struct sefs_msg_ctx *msg_ctx,
			       struct sefs_message **emsg);
int sefs_init_messaging(void);
void sefs_release_messaging(void);
#else
static inline int sefs_init_messaging(void)
{
	return 0;
}
static inline void sefs_release_messaging(void)
{ }
static inline int sefs_send_message(char *data, int data_len,
					struct sefs_msg_ctx **msg_ctx)
{
	return -ENOTCONN;
}
static inline int sefs_wait_for_response(struct sefs_msg_ctx *msg_ctx,
					     struct sefs_message **emsg)
{
	return -ENOMSG;
}
#endif

void
sefs_write_header_metadata(char *virt,
			       struct sefs_crypt_stat *crypt_stat,
			       size_t *written);
int sefs_add_keysig(struct sefs_crypt_stat *crypt_stat, char *sig);
int
sefs_add_global_auth_tok(struct sefs_mount_crypt_stat *mount_crypt_stat,
			   char *sig, u32 global_auth_tok_flags);
int sefs_get_global_auth_tok_for_sig(
	struct sefs_global_auth_tok **global_auth_tok,
	struct sefs_mount_crypt_stat *mount_crypt_stat, char *sig);
int
sefs_add_new_key_tfm(struct sefs_key_tfm **key_tfm, char *cipher_name,
			 size_t key_size);
int sefs_init_crypto(void);
int sefs_destroy_crypto(void);
int sefs_tfm_exists(char *cipher_name, struct sefs_key_tfm **key_tfm);
int sefs_get_tfm_and_mutex_for_cipher_name(struct crypto_skcipher **tfm,
					       struct mutex **tfm_mutex,
					       char *cipher_name);
int sefs_keyring_auth_tok_for_sig(struct key **auth_tok_key,
				      struct sefs_auth_tok **auth_tok,
				      char *sig);
int sefs_write_lower(struct inode *sefs_inode, char *data,
			 loff_t offset, size_t size);
int sefs_write_lower_page_segment(struct inode *sefs_inode,
				      struct page *page_for_lower,
				      size_t offset_in_page, size_t size);
int sefs_write(struct inode *inode, char *data, loff_t offset, size_t size);
int sefs_read_lower(char *data, loff_t offset, size_t size,
			struct inode *sefs_inode);
int sefs_read_lower_page_segment(struct page *page_for_sefs,
				     pgoff_t page_index,
				     size_t offset_in_page, size_t size,
				     struct inode *sefs_inode);
struct page *sefs_get_locked_page(struct inode *inode, loff_t index);
int sefs_parse_packet_length(unsigned char *data, size_t *size,
				 size_t *length_size);
int sefs_write_packet_length(char *dest, size_t size,
				 size_t *packet_size_length);
#ifdef CONFIG_ECRYPT_FS_MESSAGING
int sefs_init_sefs_miscdev(void);
void sefs_destroy_sefs_miscdev(void);
int sefs_send_miscdev(char *data, size_t data_size,
			  struct sefs_msg_ctx *msg_ctx, u8 msg_type,
			  u16 msg_flags, struct sefs_daemon *daemon);
void sefs_msg_ctx_alloc_to_free(struct sefs_msg_ctx *msg_ctx);
int
sefs_spawn_daemon(struct sefs_daemon **daemon, struct file *file);
int sefs_exorcise_daemon(struct sefs_daemon *daemon);
int sefs_find_daemon_by_euid(struct sefs_daemon **daemon);
#endif
int sefs_init_kthread(void);
void sefs_destroy_kthread(void);
int sefs_privileged_open(struct file **lower_file,
			     struct dentry *lower_dentry,
			     struct vfsmount *lower_mnt,
			     const struct cred *cred);
int sefs_get_lower_file(struct dentry *dentry, struct inode *inode);
void sefs_put_lower_file(struct inode *inode);
int
sefs_write_tag_70_packet(char *dest, size_t *remaining_bytes,
			     size_t *packet_size,
			     struct sefs_mount_crypt_stat *mount_crypt_stat,
			     char *filename, size_t filename_size);
int
sefs_parse_tag_70_packet(char **filename, size_t *filename_size,
			     size_t *packet_size,
			     struct sefs_mount_crypt_stat *mount_crypt_stat,
			     char *data, size_t max_packet_size);
int sefs_set_f_namelen(long *namelen, long lower_namelen,
			   struct sefs_mount_crypt_stat *mount_crypt_stat);
int sefs_derive_iv(char *iv, struct sefs_crypt_stat *crypt_stat,
		       loff_t offset);

extern const struct xattr_handler *sefs_xattr_handlers[];

#endif /* #ifndef SEFS_KERNEL_H */
