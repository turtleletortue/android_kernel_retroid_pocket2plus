/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2004 Erez Zadok
 * Copyright (C) 2001-2004 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *   		Michael C. Thompson <mcthomps@us.ibm.com>
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

#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/compiler.h>
#include <linux/key.h>
#include <linux/namei.h>
#include <linux/crypto.h>						 
#include <linux/file.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/unaligned.h>
#include "sefs_kernel.h"

#define DECRYPT		0
#define ENCRYPT		1

/**
 * sefs_to_hex
 * @dst: Buffer to take hex character representation of contents of
 *       src; must be at least of size (src_size * 2)
 * @src: Buffer to be converted to a hex string representation
 * @src_size: number of bytes to convert
 */
void sefs_to_hex(char *dst, char *src, size_t src_size)
{
	int x;

	for (x = 0; x < src_size; x++)
		sprintf(&dst[x * 2], "%.2x", (unsigned char)src[x]);
}

/**
 * sefs_from_hex
 * @dst: Buffer to take the bytes from src hex; must be at least of
 *       size (src_size / 2)
 * @src: Buffer to be converted from a hex string representation to raw value
 * @dst_size: size of dst buffer, or number of hex characters pairs to convert
 */
void sefs_from_hex(char *dst, char *src, int dst_size)
{
	int x;
	char tmp[3] = { 0, };

	for (x = 0; x < dst_size; x++) {
		tmp[0] = src[x * 2];
		tmp[1] = src[x * 2 + 1];
		dst[x] = (unsigned char)simple_strtol(tmp, NULL, 16);
	}
}

static int ecryptfs_hash_digest(struct crypto_shash *tfm,
				char *src, int len, char *dst)
{
	SHASH_DESC_ON_STACK(desc, tfm);
	int err;

	desc->tfm = tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	err = crypto_shash_digest(desc, src, len, dst);
	shash_desc_zero(desc);
	return err;
}

/**
 * sefs_calculate_md5 - calculates the md5 of @src
 * @dst: Pointer to 16 bytes of allocated memory
 * @crypt_stat: Pointer to crypt_stat struct for the current inode
 * @src: Data to be md5'd
 * @len: Length of @src
 *
 * Uses the allocated crypto context that crypt_stat references to
 * generate the MD5 sum of the contents of src.
 */
static int sefs_calculate_md5(char *dst,
				  struct sefs_crypt_stat *crypt_stat,
				  char *src, int len)
{
	struct crypto_shash *tfm;
	int rc = 0;

	tfm = crypt_stat->hash_tfm;
	rc = ecryptfs_hash_digest(tfm, src, len, dst);
	if (rc) {
		printk(KERN_ERR
		       "%s: Error computing crypto hash; rc = [%d]\n",
		       __func__, rc);
		goto out;
	}
out:
	return rc;
}

static int sefs_crypto_api_algify_cipher_name(char **algified_name,
						  char *cipher_name,
						  char *chaining_modifier)
{
	int cipher_name_len = strlen(cipher_name);
	int chaining_modifier_len = strlen(chaining_modifier);
	int algified_name_len;
	int rc;

	algified_name_len = (chaining_modifier_len + cipher_name_len + 3);
	(*algified_name) = kmalloc(algified_name_len, GFP_KERNEL);
	if (!(*algified_name)) {
		rc = -ENOMEM;
		goto out;
	}
	snprintf((*algified_name), algified_name_len, "%s(%s)",
		 chaining_modifier, cipher_name);
	rc = 0;
out:
	return rc;
}

/**
 * sefs_derive_iv
 * @iv: destination for the derived iv vale
 * @crypt_stat: Pointer to crypt_stat struct for the current inode
 * @offset: Offset of the extent whose IV we are to derive
 *
 * Generate the initialization vector from the given root IV and page
 * offset.
 *
 * Returns zero on success; non-zero on error.
 */
int sefs_derive_iv(char *iv, struct sefs_crypt_stat *crypt_stat,
		       loff_t offset)
{
	int rc = 0;
	char dst[MD5_DIGEST_SIZE];
	char src[SEFS_MAX_IV_BYTES + 16];

	if (unlikely(sefs_verbosity > 0)) {
		sefs_printk(KERN_DEBUG, "root iv:\n");
		sefs_dump_hex(crypt_stat->root_iv, crypt_stat->iv_bytes);
	}
	/* TODO: It is probably secure to just cast the least
	 * significant bits of the root IV into an unsigned long and
	 * add the offset to that rather than go through all this
	 * hashing business. -Halcrow */
	memcpy(src, crypt_stat->root_iv, crypt_stat->iv_bytes);
	memset((src + crypt_stat->iv_bytes), 0, 16);
	snprintf((src + crypt_stat->iv_bytes), 16, "%lld", offset);
	if (unlikely(sefs_verbosity > 0)) {
		sefs_printk(KERN_DEBUG, "source:\n");
		sefs_dump_hex(src, (crypt_stat->iv_bytes + 16));
	}
	rc = sefs_calculate_md5(dst, crypt_stat, src,
				    (crypt_stat->iv_bytes + 16));
	if (rc) {
		sefs_printk(KERN_WARNING, "Error attempting to compute "
				"MD5 while generating IV for a page\n");
		goto out;
	}
	memcpy(iv, dst, crypt_stat->iv_bytes);
	if (unlikely(sefs_verbosity > 0)) {
		sefs_printk(KERN_DEBUG, "derived iv:\n");
		sefs_dump_hex(iv, crypt_stat->iv_bytes);
	}
out:
	return rc;
}

/**
 * sefs_init_crypt_stat
 * @crypt_stat: Pointer to the crypt_stat struct to initialize.
 *
 * Initialize the crypt_stat structure.
 */
int sefs_init_crypt_stat(struct sefs_crypt_stat *crypt_stat)
{
	struct crypto_shash *tfm;
	int rc;

	tfm = crypto_alloc_shash(SEFS_DEFAULT_HASH, 0, 0);
	if (IS_ERR(tfm)) {
		rc = PTR_ERR(tfm);
		sefs_printk(KERN_ERR, "Error attempting to "
				"allocate crypto context; rc = [%d]\n",
				rc);
		return rc;
	}

	memset((void *)crypt_stat, 0, sizeof(struct sefs_crypt_stat));
	INIT_LIST_HEAD(&crypt_stat->keysig_list);
	mutex_init(&crypt_stat->keysig_list_mutex);
	mutex_init(&crypt_stat->cs_mutex);
	mutex_init(&crypt_stat->cs_tfm_mutex);
	crypt_stat->hash_tfm = tfm;
	crypt_stat->flags |= SEFS_STRUCT_INITIALIZED;

	return 0;
}

/**
 * sefs_destroy_crypt_stat
 * @crypt_stat: Pointer to the crypt_stat struct to initialize.
 *
 * Releases all memory associated with a crypt_stat struct.
 */
void sefs_destroy_crypt_stat(struct sefs_crypt_stat *crypt_stat)
{
	struct sefs_key_sig *key_sig, *key_sig_tmp;

	crypto_free_skcipher(crypt_stat->tfm);
	crypto_free_shash(crypt_stat->hash_tfm);
	list_for_each_entry_safe(key_sig, key_sig_tmp,
				 &crypt_stat->keysig_list, crypt_stat_list) {
		list_del(&key_sig->crypt_stat_list);
		kmem_cache_free(sefs_key_sig_cache, key_sig);
	}
	memset(crypt_stat, 0, sizeof(struct sefs_crypt_stat));
}

void sefs_destroy_mount_crypt_stat(
	struct sefs_mount_crypt_stat *mount_crypt_stat)
{
	struct sefs_global_auth_tok *auth_tok, *auth_tok_tmp;

	if (!(mount_crypt_stat->flags & SEFS_MOUNT_CRYPT_STAT_INITIALIZED))
		return;
	mutex_lock(&mount_crypt_stat->global_auth_tok_list_mutex);
	list_for_each_entry_safe(auth_tok, auth_tok_tmp,
				 &mount_crypt_stat->global_auth_tok_list,
				 mount_crypt_stat_list) {
		list_del(&auth_tok->mount_crypt_stat_list);
		if (!(auth_tok->flags & SEFS_AUTH_TOK_INVALID))
			key_put(auth_tok->global_auth_tok_key);
		kmem_cache_free(sefs_global_auth_tok_cache, auth_tok);
	}
	mutex_unlock(&mount_crypt_stat->global_auth_tok_list_mutex);
	memset(mount_crypt_stat, 0, sizeof(struct sefs_mount_crypt_stat));
}

/**
 * virt_to_scatterlist
 * @addr: Virtual address
 * @size: Size of data; should be an even multiple of the block size
 * @sg: Pointer to scatterlist array; set to NULL to obtain only
 *      the number of scatterlist structs required in array
 * @sg_size: Max array size
 *
 * Fills in a scatterlist array with page references for a passed
 * virtual address.
 *
 * Returns the number of scatterlist structs in array used
 */
int virt_to_scatterlist(const void *addr, int size, struct scatterlist *sg,
			int sg_size)
{
	int i = 0;
	struct page *pg;
	int offset;
	int remainder_of_page;

	sg_init_table(sg, sg_size);

	while (size > 0 && i < sg_size) {
		pg = virt_to_page(addr);
		offset = offset_in_page(addr);
		sg_set_page(&sg[i], pg, 0, offset);
		remainder_of_page = PAGE_SIZE - offset;
		if (size >= remainder_of_page) {
			sg[i].length = remainder_of_page;
			addr += remainder_of_page;
			size -= remainder_of_page;
		} else {
			sg[i].length = size;
			addr += size;
			size = 0;
		}
		i++;
	}
	if (size > 0)
		return -ENOMEM;
	return i;
}

struct extent_crypt_result {
	struct completion completion;
	int rc;
};

static void extent_crypt_complete(struct crypto_async_request *req, int rc)
{
	struct extent_crypt_result *ecr = req->data;

	if (rc == -EINPROGRESS)
		return;

	ecr->rc = rc;
	complete(&ecr->completion);
}

/**
 * crypt_scatterlist
 * @crypt_stat: Pointer to the crypt_stat struct to initialize.
 * @dst_sg: Destination of the data after performing the crypto operation
 * @src_sg: Data to be encrypted or decrypted
 * @size: Length of data
 * @iv: IV to use
 * @op: ENCRYPT or DECRYPT to indicate the desired operation
 *
 * Returns the number of bytes encrypted or decrypted; negative value on error
 */
static int crypt_scatterlist(struct sefs_crypt_stat *crypt_stat,
			     struct scatterlist *dst_sg,
			     struct scatterlist *src_sg, int size,
			     unsigned char *iv, int op)
{
	struct skcipher_request *req = NULL;
	struct extent_crypt_result ecr;
	int rc = 0;

	BUG_ON(!crypt_stat || !crypt_stat->tfm
	       || !(crypt_stat->flags & SEFS_STRUCT_INITIALIZED));
	if (unlikely(sefs_verbosity > 0)) {
		sefs_printk(KERN_DEBUG, "Key size [%zd]; key:\n",
				crypt_stat->key_size);
		sefs_dump_hex(crypt_stat->key,
				  crypt_stat->key_size);
	}

	init_completion(&ecr.completion);

	mutex_lock(&crypt_stat->cs_tfm_mutex);
	req = skcipher_request_alloc(crypt_stat->tfm, GFP_NOFS);
	if (!req) {
		mutex_unlock(&crypt_stat->cs_tfm_mutex);
		rc = -ENOMEM;
		goto out;
	}

	skcipher_request_set_callback(req,
			CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			extent_crypt_complete, &ecr);
	/* Consider doing this once, when the file is opened */
	if (!(crypt_stat->flags & SEFS_KEY_SET)) {
		rc = crypto_skcipher_setkey(crypt_stat->tfm, crypt_stat->key,
					    crypt_stat->key_size);
		if (rc) {
			sefs_printk(KERN_ERR,
					"Error setting key; rc = [%d]\n",
					rc);
			mutex_unlock(&crypt_stat->cs_tfm_mutex);
			rc = -EINVAL;
			goto out;
		}
		crypt_stat->flags |= SEFS_KEY_SET;
	}
	mutex_unlock(&crypt_stat->cs_tfm_mutex);
	skcipher_request_set_crypt(req, src_sg, dst_sg, size, iv);
	rc = op == ENCRYPT ? crypto_skcipher_encrypt(req) :
			     crypto_skcipher_decrypt(req);
	if (rc == -EINPROGRESS || rc == -EBUSY) {
		struct extent_crypt_result *ecr = req->base.data;

		wait_for_completion(&ecr->completion);
		rc = ecr->rc;
		reinit_completion(&ecr->completion);
	}
out:
	skcipher_request_free(req);
	return rc;
}

/**
 * lower_offset_for_page
 *
 * Convert an eCryptfs page index into a lower byte offset
 */
static loff_t lower_offset_for_page(struct sefs_crypt_stat *crypt_stat,
				    struct page *page)
{
	return sefs_lower_header_size(crypt_stat) +
	       ((loff_t)page->index << PAGE_SHIFT);
}

/**
 * crypt_extent
 * @crypt_stat: crypt_stat containing cryptographic context for the
 *              encryption operation
 * @dst_page: The page to write the result into
 * @src_page: The page to read from
 * @extent_offset: Page extent offset for use in generating IV
 * @op: ENCRYPT or DECRYPT to indicate the desired operation
 *
 * Encrypts or decrypts one extent of data.
 *
 * Return zero on success; non-zero otherwise
 */
static int crypt_extent(struct sefs_crypt_stat *crypt_stat,
			struct page *dst_page,
			struct page *src_page,
			unsigned long extent_offset, int op)
{
	pgoff_t page_index = op == ENCRYPT ? src_page->index : dst_page->index;
	loff_t extent_base;
	char extent_iv[SEFS_MAX_IV_BYTES];
	struct scatterlist src_sg, dst_sg;
	size_t extent_size = crypt_stat->extent_size;
	int rc;

	extent_base = (((loff_t)page_index) * (PAGE_SIZE / extent_size));
	rc = sefs_derive_iv(extent_iv, crypt_stat,
				(extent_base + extent_offset));
	if (rc) {
		sefs_printk(KERN_ERR, "Error attempting to derive IV for "
			"extent [0x%.16llx]; rc = [%d]\n",
			(unsigned long long)(extent_base + extent_offset), rc);
		goto out;
	}

	sg_init_table(&src_sg, 1);
	sg_init_table(&dst_sg, 1);

	sg_set_page(&src_sg, src_page, extent_size,
		    extent_offset * extent_size);
	sg_set_page(&dst_sg, dst_page, extent_size,
		    extent_offset * extent_size);

	rc = crypt_scatterlist(crypt_stat, &dst_sg, &src_sg, extent_size,
			       extent_iv, op);
	if (rc < 0) {
		printk(KERN_ERR "%s: Error attempting to crypt page with "
		       "page_index = [%ld], extent_offset = [%ld]; "
		       "rc = [%d]\n", __func__, page_index, extent_offset, rc);
		goto out;
	}
	rc = 0;
out:
	return rc;
}

/**
 * sefs_encrypt_page
 * @page: Page mapped from the eCryptfs inode for the file; contains
 *        decrypted content that needs to be encrypted (to a temporary
 *        page; not in place) and written out to the lower file
 *
 * Encrypt an eCryptfs page. This is done on a per-extent basis. Note
 * that eCryptfs pages may straddle the lower pages -- for instance,
 * if the file was created on a machine with an 8K page size
 * (resulting in an 8K header), and then the file is copied onto a
 * host with a 32K page size, then when reading page 0 of the eCryptfs
 * file, 24K of page 0 of the lower file will be read and decrypted,
 * and then 8K of page 1 of the lower file will be read and decrypted.
 *
 * Returns zero on success; negative on error
 */
int sefs_encrypt_page(struct page *page)
{
	struct inode *sefs_inode;
	struct sefs_crypt_stat *crypt_stat;
	char *enc_extent_virt;
	struct page *enc_extent_page = NULL;
	loff_t extent_offset;
	loff_t lower_offset;
	int rc = 0;

	sefs_inode = page->mapping->host;
	crypt_stat =
		&(sefs_inode_to_private(sefs_inode)->crypt_stat);
	BUG_ON(!(crypt_stat->flags & SEFS_ENCRYPTED));
	enc_extent_page = alloc_page(GFP_USER);
	if (!enc_extent_page) {
		rc = -ENOMEM;
		sefs_printk(KERN_ERR, "Error allocating memory for "
				"encrypted extent\n");
		goto out;
	}

	for (extent_offset = 0;
	     extent_offset < (PAGE_SIZE / crypt_stat->extent_size);
	     extent_offset++) {
		rc = crypt_extent(crypt_stat, enc_extent_page, page,
				  extent_offset, ENCRYPT);
		if (rc) {
			printk(KERN_ERR "%s: Error encrypting extent; "
			       "rc = [%d]\n", __func__, rc);
			goto out;
		}
	}

	lower_offset = lower_offset_for_page(crypt_stat, page);
	enc_extent_virt = kmap(enc_extent_page);
	rc = sefs_write_lower(sefs_inode, enc_extent_virt, lower_offset,
				  PAGE_SIZE);
	kunmap(enc_extent_page);
	if (rc < 0) {
		sefs_printk(KERN_ERR,
			"Error attempting to write lower page; rc = [%d]\n",
			rc);
		goto out;
	}
	rc = 0;
out:
	if (enc_extent_page) {
		__free_page(enc_extent_page);
	}
	return rc;
}

/**
 * sefs_decrypt_page
 * @page: Page mapped from the eCryptfs inode for the file; data read
 *        and decrypted from the lower file will be written into this
 *        page
 *
 * Decrypt an eCryptfs page. This is done on a per-extent basis. Note
 * that eCryptfs pages may straddle the lower pages -- for instance,
 * if the file was created on a machine with an 8K page size
 * (resulting in an 8K header), and then the file is copied onto a
 * host with a 32K page size, then when reading page 0 of the eCryptfs
 * file, 24K of page 0 of the lower file will be read and decrypted,
 * and then 8K of page 1 of the lower file will be read and decrypted.
 *
 * Returns zero on success; negative on error
 */
int sefs_decrypt_page(struct page *page)
{
	struct inode *sefs_inode;
	struct sefs_crypt_stat *crypt_stat;
	char *page_virt;
	unsigned long extent_offset;
	loff_t lower_offset;
	int rc = 0;

	sefs_inode = page->mapping->host;
	crypt_stat =
		&(sefs_inode_to_private(sefs_inode)->crypt_stat);
	BUG_ON(!(crypt_stat->flags & SEFS_ENCRYPTED));

	lower_offset = lower_offset_for_page(crypt_stat, page);
	page_virt = kmap(page);
	rc = sefs_read_lower(page_virt, lower_offset, PAGE_SIZE,
				 sefs_inode);
	kunmap(page);
	if (rc < 0) {
		sefs_printk(KERN_ERR,
			"Error attempting to read lower page; rc = [%d]\n",
			rc);
		goto out;
	}

	for (extent_offset = 0;
	     extent_offset < (PAGE_SIZE / crypt_stat->extent_size);
	     extent_offset++) {
		rc = crypt_extent(crypt_stat, page, page,
				  extent_offset, DECRYPT);
		if (rc) {
			printk(KERN_ERR "%s: Error encrypting extent; "
			       "rc = [%d]\n", __func__, rc);
			goto out;
		}
	}
out:
	return rc;
}

#define SEFS_MAX_SCATTERLIST_LEN 4

/**
 * sefs_init_crypt_ctx
 * @crypt_stat: Uninitialized crypt stats structure
 *
 * Initialize the crypto context.
 *
 * TODO: Performance: Keep a cache of initialized cipher contexts;
 * only init if needed
 */
int sefs_init_crypt_ctx(struct sefs_crypt_stat *crypt_stat)
{
	char *full_alg_name;
	int rc = -EINVAL;

	sefs_printk(KERN_DEBUG,
			"Initializing cipher [%s]; strlen = [%d]; "
			"key_size_bits = [%zd]\n",
			crypt_stat->cipher, (int)strlen(crypt_stat->cipher),
			crypt_stat->key_size << 3);
	mutex_lock(&crypt_stat->cs_tfm_mutex);
	if (crypt_stat->tfm) {
		rc = 0;
		goto out_unlock;
	}
	rc = sefs_crypto_api_algify_cipher_name(&full_alg_name,
						    crypt_stat->cipher, "cbc");
	if (rc)
		goto out_unlock;
	crypt_stat->tfm = crypto_alloc_skcipher(full_alg_name, 0, 0);
	if (IS_ERR(crypt_stat->tfm)) {
		rc = PTR_ERR(crypt_stat->tfm);
		crypt_stat->tfm = NULL;
		sefs_printk(KERN_ERR, "cryptfs: init_crypt_ctx(): "
				"Error initializing cipher [%s]\n",
				full_alg_name);
		goto out_free;
	}
	crypto_skcipher_set_flags(crypt_stat->tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	rc = 0;
out_free:
	kfree(full_alg_name);
out_unlock:
	mutex_unlock(&crypt_stat->cs_tfm_mutex);
	return rc;
}

static void set_extent_mask_and_shift(struct sefs_crypt_stat *crypt_stat)
{
	int extent_size_tmp;

	crypt_stat->extent_mask = 0xFFFFFFFF;
	crypt_stat->extent_shift = 0;
	if (crypt_stat->extent_size == 0)
		return;
	extent_size_tmp = crypt_stat->extent_size;
	while ((extent_size_tmp & 0x01) == 0) {
		extent_size_tmp >>= 1;
		crypt_stat->extent_mask <<= 1;
		crypt_stat->extent_shift++;
	}
}

void sefs_set_default_sizes(struct sefs_crypt_stat *crypt_stat)
{
	/* Default values; may be overwritten as we are parsing the
	 * packets. */
	crypt_stat->extent_size = SEFS_DEFAULT_EXTENT_SIZE;
	set_extent_mask_and_shift(crypt_stat);
	crypt_stat->iv_bytes = SEFS_DEFAULT_IV_BYTES;
	if (crypt_stat->flags & SEFS_METADATA_IN_XATTR)
		crypt_stat->metadata_size = SEFS_MINIMUM_HEADER_EXTENT_SIZE;
	else {
		if (PAGE_SIZE <= SEFS_MINIMUM_HEADER_EXTENT_SIZE)
			crypt_stat->metadata_size =
				SEFS_MINIMUM_HEADER_EXTENT_SIZE;
		else
			crypt_stat->metadata_size = PAGE_SIZE;
	}
}

/**
 * sefs_compute_root_iv
 * @crypt_stats
 *
 * On error, sets the root IV to all 0's.
 */
int sefs_compute_root_iv(struct sefs_crypt_stat *crypt_stat)
{
	int rc = 0;
	char dst[MD5_DIGEST_SIZE];

	BUG_ON(crypt_stat->iv_bytes > MD5_DIGEST_SIZE);
	BUG_ON(crypt_stat->iv_bytes <= 0);
	if (!(crypt_stat->flags & SEFS_KEY_VALID)) {
		rc = -EINVAL;
		sefs_printk(KERN_WARNING, "Session key not valid; "
				"cannot generate root IV\n");
		goto out;
	}
	rc = sefs_calculate_md5(dst, crypt_stat, crypt_stat->key,
				    crypt_stat->key_size);
	if (rc) {
		sefs_printk(KERN_WARNING, "Error attempting to compute "
				"MD5 while generating root IV\n");
		goto out;
	}
	memcpy(crypt_stat->root_iv, dst, crypt_stat->iv_bytes);
out:
	if (rc) {
		memset(crypt_stat->root_iv, 0, crypt_stat->iv_bytes);
		crypt_stat->flags |= SEFS_SECURITY_WARNING;
	}
	return rc;
}

static void sefs_generate_new_key(struct sefs_crypt_stat *crypt_stat)
{
	get_random_bytes(crypt_stat->key, crypt_stat->key_size);
	crypt_stat->flags |= SEFS_KEY_VALID;
	sefs_compute_root_iv(crypt_stat);
	if (unlikely(sefs_verbosity > 0)) {
		sefs_printk(KERN_DEBUG, "Generated new session key:\n");
		sefs_dump_hex(crypt_stat->key,
				  crypt_stat->key_size);
	}
}

/**
 * sefs_copy_mount_wide_flags_to_inode_flags
 * @crypt_stat: The inode's cryptographic context
 * @mount_crypt_stat: The mount point's cryptographic context
 *
 * This function propagates the mount-wide flags to individual inode
 * flags.
 */
static void sefs_copy_mount_wide_flags_to_inode_flags(
	struct sefs_crypt_stat *crypt_stat,
	struct sefs_mount_crypt_stat *mount_crypt_stat)
{
	if (mount_crypt_stat->flags & SEFS_XATTR_METADATA_ENABLED)
		crypt_stat->flags |= SEFS_METADATA_IN_XATTR;
	if (mount_crypt_stat->flags & SEFS_ENCRYPTED_VIEW_ENABLED)
		crypt_stat->flags |= SEFS_VIEW_AS_ENCRYPTED;
	if (mount_crypt_stat->flags & SEFS_GLOBAL_ENCRYPT_FILENAMES) {
		crypt_stat->flags |= SEFS_ENCRYPT_FILENAMES;
		if (mount_crypt_stat->flags
		    & SEFS_GLOBAL_ENCFN_USE_MOUNT_FNEK)
			crypt_stat->flags |= SEFS_ENCFN_USE_MOUNT_FNEK;
		else if (mount_crypt_stat->flags
			 & SEFS_GLOBAL_ENCFN_USE_FEK)
			crypt_stat->flags |= SEFS_ENCFN_USE_FEK;
	}
}

static int sefs_copy_mount_wide_sigs_to_inode_sigs(
	struct sefs_crypt_stat *crypt_stat,
	struct sefs_mount_crypt_stat *mount_crypt_stat)
{
	struct sefs_global_auth_tok *global_auth_tok;
	int rc = 0;

	mutex_lock(&crypt_stat->keysig_list_mutex);
	mutex_lock(&mount_crypt_stat->global_auth_tok_list_mutex);

	list_for_each_entry(global_auth_tok,
			    &mount_crypt_stat->global_auth_tok_list,
			    mount_crypt_stat_list) {
		if (global_auth_tok->flags & SEFS_AUTH_TOK_FNEK)
			continue;
		rc = sefs_add_keysig(crypt_stat, global_auth_tok->sig);
		if (rc) {
			printk(KERN_ERR "Error adding keysig; rc = [%d]\n", rc);
			goto out;
		}
	}

out:
	mutex_unlock(&mount_crypt_stat->global_auth_tok_list_mutex);
	mutex_unlock(&crypt_stat->keysig_list_mutex);
	return rc;
}

/**
 * sefs_set_default_crypt_stat_vals
 * @crypt_stat: The inode's cryptographic context
 * @mount_crypt_stat: The mount point's cryptographic context
 *
 * Default values in the event that policy does not override them.
 */
static void sefs_set_default_crypt_stat_vals(
	struct sefs_crypt_stat *crypt_stat,
	struct sefs_mount_crypt_stat *mount_crypt_stat)
{
	sefs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
						      mount_crypt_stat);
	sefs_set_default_sizes(crypt_stat);
	strcpy(crypt_stat->cipher, SEFS_DEFAULT_CIPHER);
	crypt_stat->key_size = SEFS_DEFAULT_KEY_BYTES;
	crypt_stat->flags &= ~(SEFS_KEY_VALID);
	crypt_stat->file_version = SEFS_FILE_VERSION;
	crypt_stat->mount_crypt_stat = mount_crypt_stat;
}

/**
 * sefs_new_file_context
 * @sefs_inode: The eCryptfs inode
 *
 * If the crypto context for the file has not yet been established,
 * this is where we do that.  Establishing a new crypto context
 * involves the following decisions:
 *  - What cipher to use?
 *  - What set of authentication tokens to use?
 * Here we just worry about getting enough information into the
 * authentication tokens so that we know that they are available.
 * We associate the available authentication tokens with the new file
 * via the set of signatures in the crypt_stat struct.  Later, when
 * the headers are actually written out, we may again defer to
 * userspace to perform the encryption of the session key; for the
 * foreseeable future, this will be the case with public key packets.
 *
 * Returns zero on success; non-zero otherwise
 */
int sefs_new_file_context(struct inode *sefs_inode)
{
	struct sefs_crypt_stat *crypt_stat =
	    &sefs_inode_to_private(sefs_inode)->crypt_stat;
	struct sefs_mount_crypt_stat *mount_crypt_stat =
	    &sefs_superblock_to_private(
		    sefs_inode->i_sb)->mount_crypt_stat;
	int cipher_name_len;
	int rc = 0;

	sefs_set_default_crypt_stat_vals(crypt_stat, mount_crypt_stat);
	crypt_stat->flags |= (SEFS_ENCRYPTED | SEFS_KEY_VALID);
	sefs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
						      mount_crypt_stat);
	rc = sefs_copy_mount_wide_sigs_to_inode_sigs(crypt_stat,
							 mount_crypt_stat);
	if (rc) {
		printk(KERN_ERR "Error attempting to copy mount-wide key sigs "
		       "to the inode key sigs; rc = [%d]\n", rc);
		goto out;
	}
	cipher_name_len =
		strlen(mount_crypt_stat->global_default_cipher_name);
	memcpy(crypt_stat->cipher,
	       mount_crypt_stat->global_default_cipher_name,
	       cipher_name_len);
	crypt_stat->cipher[cipher_name_len] = '\0';
	crypt_stat->key_size =
		mount_crypt_stat->global_default_cipher_key_size;
	sefs_generate_new_key(crypt_stat);
	rc = sefs_init_crypt_ctx(crypt_stat);
	if (rc)
		sefs_printk(KERN_ERR, "Error initializing cryptographic "
				"context for cipher [%s]: rc = [%d]\n",
				crypt_stat->cipher, rc);
out:
	return rc;
}

/**
 * sefs_validate_marker - check for the sefs marker
 * @data: The data block in which to check
 *
 * Returns zero if marker found; -EINVAL if not found
 */
static int sefs_validate_marker(char *data)
{
	u32 m_1, m_2;

	m_1 = get_unaligned_be32(data);
	m_2 = get_unaligned_be32(data + 4);
	if ((m_1 ^ MAGIC_SEFS_MARKER) == m_2)
		return 0;
	sefs_printk(KERN_DEBUG, "m_1 = [0x%.8x]; m_2 = [0x%.8x]; "
			"MAGIC_SEFS_MARKER = [0x%.8x]\n", m_1, m_2,
			MAGIC_SEFS_MARKER);
	sefs_printk(KERN_DEBUG, "(m_1 ^ MAGIC_SEFS_MARKER) = "
			"[0x%.8x]\n", (m_1 ^ MAGIC_SEFS_MARKER));
	return -EINVAL;
}

struct sefs_flag_map_elem {
	u32 file_flag;
	u32 local_flag;
};

/* Add support for additional flags by adding elements here. */
static struct sefs_flag_map_elem sefs_flag_map[] = {
	{0x00000001, SEFS_ENABLE_HMAC},
	{0x00000002, SEFS_ENCRYPTED},
	{0x00000004, SEFS_METADATA_IN_XATTR},
	{0x00000008, SEFS_ENCRYPT_FILENAMES}
};

/**
 * sefs_process_flags
 * @crypt_stat: The cryptographic context
 * @page_virt: Source data to be parsed
 * @bytes_read: Updated with the number of bytes read
 *
 * Returns zero on success; non-zero if the flag set is invalid
 */
static int sefs_process_flags(struct sefs_crypt_stat *crypt_stat,
				  char *page_virt, int *bytes_read)
{
	int rc = 0;
	int i;
	u32 flags;

	flags = get_unaligned_be32(page_virt);
	for (i = 0; i < ((sizeof(sefs_flag_map)
			  / sizeof(struct sefs_flag_map_elem))); i++)
		if (flags & sefs_flag_map[i].file_flag) {
			crypt_stat->flags |= sefs_flag_map[i].local_flag;
		} else
			crypt_stat->flags &= ~(sefs_flag_map[i].local_flag);
	/* Version is in top 8 bits of the 32-bit flag vector */
	crypt_stat->file_version = ((flags >> 24) & 0xFF);
	(*bytes_read) = 4;
	return rc;
}

/**
 * write_sefs_marker
 * @page_virt: The pointer to in a page to begin writing the marker
 * @written: Number of bytes written
 *
 * Marker = 0x3c81b7f5
 */
static void write_sefs_marker(char *page_virt, size_t *written)
{
	u32 m_1, m_2;

	get_random_bytes(&m_1, (MAGIC_SEFS_MARKER_SIZE_BYTES / 2));
	m_2 = (m_1 ^ MAGIC_SEFS_MARKER);
	put_unaligned_be32(m_1, page_virt);
	page_virt += (MAGIC_SEFS_MARKER_SIZE_BYTES / 2);
	put_unaligned_be32(m_2, page_virt);
	(*written) = MAGIC_SEFS_MARKER_SIZE_BYTES;
}

void sefs_write_crypt_stat_flags(char *page_virt,
				     struct sefs_crypt_stat *crypt_stat,
				     size_t *written)
{
	u32 flags = 0;
	int i;

	for (i = 0; i < ((sizeof(sefs_flag_map)
			  / sizeof(struct sefs_flag_map_elem))); i++)
		if (crypt_stat->flags & sefs_flag_map[i].local_flag)
			flags |= sefs_flag_map[i].file_flag;
	/* Version is in top 8 bits of the 32-bit flag vector */
	flags |= ((((u8)crypt_stat->file_version) << 24) & 0xFF000000);
	put_unaligned_be32(flags, page_virt);
	(*written) = 4;
}

struct sefs_cipher_code_str_map_elem {
	char cipher_str[16];
	u8 cipher_code;
};

/* Add support for additional ciphers by adding elements here. The
 * cipher_code is whatever OpenPGP applications use to identify the
 * ciphers. List in order of probability. */
static struct sefs_cipher_code_str_map_elem
sefs_cipher_code_str_map[] = {
	{"aes",RFC2440_CIPHER_AES_128 },
	{"blowfish", RFC2440_CIPHER_BLOWFISH},
	{"des3_ede", RFC2440_CIPHER_DES3_EDE},
	{"cast5", RFC2440_CIPHER_CAST_5},
	{"twofish", RFC2440_CIPHER_TWOFISH},
	{"cast6", RFC2440_CIPHER_CAST_6},
	{"aes", RFC2440_CIPHER_AES_192},
	{"aes", RFC2440_CIPHER_AES_256}
};

/**
 * sefs_code_for_cipher_string
 * @cipher_name: The string alias for the cipher
 * @key_bytes: Length of key in bytes; used for AES code selection
 *
 * Returns zero on no match, or the cipher code on match
 */
u8 sefs_code_for_cipher_string(char *cipher_name, size_t key_bytes)
{
	int i;
	u8 code = 0;
	struct sefs_cipher_code_str_map_elem *map =
		sefs_cipher_code_str_map;

	if (strcmp(cipher_name, "aes") == 0) {
		switch (key_bytes) {
		case 16:
			code = RFC2440_CIPHER_AES_128;
			break;
		case 24:
			code = RFC2440_CIPHER_AES_192;
			break;
		case 32:
			code = RFC2440_CIPHER_AES_256;
		}
	} else {
		for (i = 0; i < ARRAY_SIZE(sefs_cipher_code_str_map); i++)
			if (strcmp(cipher_name, map[i].cipher_str) == 0) {
				code = map[i].cipher_code;
				break;
			}
	}
	return code;
}

/**
 * sefs_cipher_code_to_string
 * @str: Destination to write out the cipher name
 * @cipher_code: The code to convert to cipher name string
 *
 * Returns zero on success
 */
int sefs_cipher_code_to_string(char *str, u8 cipher_code)
{
	int rc = 0;
	int i;

	str[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(sefs_cipher_code_str_map); i++)
		if (cipher_code == sefs_cipher_code_str_map[i].cipher_code)
			strcpy(str, sefs_cipher_code_str_map[i].cipher_str);
	if (str[0] == '\0') {
		sefs_printk(KERN_WARNING, "Cipher code not recognized: "
				"[%d]\n", cipher_code);
		rc = -EINVAL;
	}
	return rc;
}

int sefs_read_and_validate_header_region(struct inode *inode)
{
	u8 file_size[SEFS_SIZE_AND_MARKER_BYTES];
	u8 *marker = file_size + SEFS_FILE_SIZE_BYTES;
	int rc;

	rc = sefs_read_lower(file_size, 0, SEFS_SIZE_AND_MARKER_BYTES,
				 inode);
	if (rc < SEFS_SIZE_AND_MARKER_BYTES)
		return rc >= 0 ? -EINVAL : rc;
	rc = sefs_validate_marker(marker);
	if (!rc)
		sefs_i_size_init(file_size, inode);
	return rc;
}

void
sefs_write_header_metadata(char *virt,
			       struct sefs_crypt_stat *crypt_stat,
			       size_t *written)
{
	u32 header_extent_size;
	u16 num_header_extents_at_front;

	header_extent_size = (u32)crypt_stat->extent_size;
	num_header_extents_at_front =
		(u16)(crypt_stat->metadata_size / crypt_stat->extent_size);
	put_unaligned_be32(header_extent_size, virt);
	virt += 4;
	put_unaligned_be16(num_header_extents_at_front, virt);
	(*written) = 6;
}

struct kmem_cache *sefs_header_cache;

/**
 * sefs_write_headers_virt
 * @page_virt: The virtual address to write the headers to
 * @max: The size of memory allocated at page_virt
 * @size: Set to the number of bytes written by this function
 * @crypt_stat: The cryptographic context
 * @sefs_dentry: The eCryptfs dentry
 *
 * Format version: 1
 *
 *   Header Extent:
 *     Octets 0-7:        Unencrypted file size (big-endian)
 *     Octets 8-15:       eCryptfs special marker
 *     Octets 16-19:      Flags
 *      Octet 16:         File format version number (between 0 and 255)
 *      Octets 17-18:     Reserved
 *      Octet 19:         Bit 1 (lsb): Reserved
 *                        Bit 2: Encrypted?
 *                        Bits 3-8: Reserved
 *     Octets 20-23:      Header extent size (big-endian)
 *     Octets 24-25:      Number of header extents at front of file
 *                        (big-endian)
 *     Octet  26:         Begin RFC 2440 authentication token packet set
 *   Data Extent 0:
 *     Lower data (CBC encrypted)
 *   Data Extent 1:
 *     Lower data (CBC encrypted)
 *   ...
 *
 * Returns zero on success
 */
static int sefs_write_headers_virt(char *page_virt, size_t max,
				       size_t *size,
				       struct sefs_crypt_stat *crypt_stat,
				       struct dentry *sefs_dentry)
{
	int rc;
	size_t written;
	size_t offset;

	offset = SEFS_FILE_SIZE_BYTES;
	write_sefs_marker((page_virt + offset), &written);
	offset += written;
	sefs_write_crypt_stat_flags((page_virt + offset), crypt_stat,
					&written);
	offset += written;
	sefs_write_header_metadata((page_virt + offset), crypt_stat,
				       &written);
	offset += written;
	rc = sefs_generate_key_packet_set((page_virt + offset), crypt_stat,
					      sefs_dentry, &written,
					      max - offset);
	if (rc)
		sefs_printk(KERN_WARNING, "Error generating key packet "
				"set; rc = [%d]\n", rc);
	if (size) {
		offset += written;
		*size = offset;
	}
	return rc;
}

static int
sefs_write_metadata_to_contents(struct inode *sefs_inode,
				    char *virt, size_t virt_len)
{
	int rc;

	rc = sefs_write_lower(sefs_inode, virt,
				  0, virt_len);
	if (rc < 0)
		printk(KERN_ERR "%s: Error attempting to write header "
		       "information to lower file; rc = [%d]\n", __func__, rc);
	else
		rc = 0;
	return rc;
}

static int
sefs_write_metadata_to_xattr(struct dentry *sefs_dentry,
				 struct inode *sefs_inode,
				 char *page_virt, size_t size)
{
	int rc;

	rc = sefs_setxattr(sefs_dentry, sefs_inode,
			       SEFS_XATTR_NAME, page_virt, size, 0);
	return rc;
}

static unsigned long sefs_get_zeroed_pages(gfp_t gfp_mask,
					       unsigned int order)
{
	struct page *page;

	page = alloc_pages(gfp_mask | __GFP_ZERO, order);
	if (page)
		return (unsigned long) page_address(page);
	return 0;
}

/**
 * sefs_write_metadata
 * @sefs_dentry: The eCryptfs dentry, which should be negative
 * @sefs_inode: The newly created eCryptfs inode
 *
 * Write the file headers out.  This will likely involve a userspace
 * callout, in which the session key is encrypted with one or more
 * public keys and/or the passphrase necessary to do the encryption is
 * retrieved via a prompt.  Exactly what happens at this point should
 * be policy-dependent.
 *
 * Returns zero on success; non-zero on error
 */
int sefs_write_metadata(struct dentry *sefs_dentry,
			    struct inode *sefs_inode)
{
	struct sefs_crypt_stat *crypt_stat =
		&sefs_inode_to_private(sefs_inode)->crypt_stat;
	unsigned int order;
	char *virt;
	size_t virt_len;
	size_t size = 0;
	int rc = 0;

	if (likely(crypt_stat->flags & SEFS_ENCRYPTED)) {
		if (!(crypt_stat->flags & SEFS_KEY_VALID)) {
			printk(KERN_ERR "Key is invalid; bailing out\n");
			rc = -EINVAL;
			goto out;
		}
	} else {
		printk(KERN_WARNING "%s: Encrypted flag not set\n",
		       __func__);
		rc = -EINVAL;
		goto out;
	}
	virt_len = crypt_stat->metadata_size;
	order = get_order(virt_len);
	/* Released in this function */
	virt = (char *)sefs_get_zeroed_pages(GFP_KERNEL, order);
	if (!virt) {
		printk(KERN_ERR "%s: Out of memory\n", __func__);
		rc = -ENOMEM;
		goto out;
	}
	/* Zeroed page ensures the in-header unencrypted i_size is set to 0 */
	rc = sefs_write_headers_virt(virt, virt_len, &size, crypt_stat,
					 sefs_dentry);
	if (unlikely(rc)) {
		printk(KERN_ERR "%s: Error whilst writing headers; rc = [%d]\n",
		       __func__, rc);
		goto out_free;
	}
	if (crypt_stat->flags & SEFS_METADATA_IN_XATTR)
		rc = sefs_write_metadata_to_xattr(sefs_dentry, sefs_inode,
						      virt, size);
	else
		rc = sefs_write_metadata_to_contents(sefs_inode, virt,
							 virt_len);
	if (rc) {
		printk(KERN_ERR "%s: Error writing metadata out to lower file; "
		       "rc = [%d]\n", __func__, rc);
		goto out_free;
	}
out_free:
	free_pages((unsigned long)virt, order);
out:
	return rc;
}

#define SEFS_DONT_VALIDATE_HEADER_SIZE 0
#define SEFS_VALIDATE_HEADER_SIZE 1
static int parse_header_metadata(struct sefs_crypt_stat *crypt_stat,
				 char *virt, int *bytes_read,
				 int validate_header_size)
{
	int rc = 0;
	u32 header_extent_size;
	u16 num_header_extents_at_front;

	header_extent_size = get_unaligned_be32(virt);
	virt += sizeof(__be32);
	num_header_extents_at_front = get_unaligned_be16(virt);
	crypt_stat->metadata_size = (((size_t)num_header_extents_at_front
				     * (size_t)header_extent_size));
	(*bytes_read) = (sizeof(__be32) + sizeof(__be16));
	if ((validate_header_size == SEFS_VALIDATE_HEADER_SIZE)
	    && (crypt_stat->metadata_size
		< SEFS_MINIMUM_HEADER_EXTENT_SIZE)) {
		rc = -EINVAL;
		printk(KERN_WARNING "Invalid header size: [%zd]\n",
		       crypt_stat->metadata_size);
	}
	return rc;
}

/**
 * set_default_header_data
 * @crypt_stat: The cryptographic context
 *
 * For version 0 file format; this function is only for backwards
 * compatibility for files created with the prior versions of
 * eCryptfs.
 */
static void set_default_header_data(struct sefs_crypt_stat *crypt_stat)
{
	crypt_stat->metadata_size = SEFS_MINIMUM_HEADER_EXTENT_SIZE;
}

void sefs_i_size_init(const char *page_virt, struct inode *inode)
{
	struct sefs_mount_crypt_stat *mount_crypt_stat;
	struct sefs_crypt_stat *crypt_stat;
	u64 file_size;

	crypt_stat = &sefs_inode_to_private(inode)->crypt_stat;
	mount_crypt_stat =
		&sefs_superblock_to_private(inode->i_sb)->mount_crypt_stat;
	if (mount_crypt_stat->flags & SEFS_ENCRYPTED_VIEW_ENABLED) {
		file_size = i_size_read(sefs_inode_to_lower(inode));
		if (crypt_stat->flags & SEFS_METADATA_IN_XATTR)
			file_size += crypt_stat->metadata_size;
	} else
		file_size = get_unaligned_be64(page_virt);
	i_size_write(inode, (loff_t)file_size);
	crypt_stat->flags |= SEFS_I_SIZE_INITIALIZED;
}

/**
 * sefs_read_headers_virt
 * @page_virt: The virtual address into which to read the headers
 * @crypt_stat: The cryptographic context
 * @sefs_dentry: The eCryptfs dentry
 * @validate_header_size: Whether to validate the header size while reading
 *
 * Read/parse the header data. The header format is detailed in the
 * comment block for the sefs_write_headers_virt() function.
 *
 * Returns zero on success
 */
static int sefs_read_headers_virt(char *page_virt,
				      struct sefs_crypt_stat *crypt_stat,
				      struct dentry *sefs_dentry,
				      int validate_header_size)
{
	int rc = 0;
	int offset;
	int bytes_read;

	sefs_set_default_sizes(crypt_stat);
	crypt_stat->mount_crypt_stat = &sefs_superblock_to_private(
		sefs_dentry->d_sb)->mount_crypt_stat;
	offset = SEFS_FILE_SIZE_BYTES;
	rc = sefs_validate_marker(page_virt + offset);
	if (rc)
		goto out;
	if (!(crypt_stat->flags & SEFS_I_SIZE_INITIALIZED))
		sefs_i_size_init(page_virt, d_inode(sefs_dentry));
	offset += MAGIC_SEFS_MARKER_SIZE_BYTES;
	rc = sefs_process_flags(crypt_stat, (page_virt + offset),
				    &bytes_read);
	if (rc) {
		sefs_printk(KERN_WARNING, "Error processing flags\n");
		goto out;
	}
	if (crypt_stat->file_version > SEFS_SUPPORTED_FILE_VERSION) {
		sefs_printk(KERN_WARNING, "File version is [%d]; only "
				"file version [%d] is supported by this "
				"version of eCryptfs\n",
				crypt_stat->file_version,
				SEFS_SUPPORTED_FILE_VERSION);
		rc = -EINVAL;
		goto out;
	}
	offset += bytes_read;
	if (crypt_stat->file_version >= 1) {
		rc = parse_header_metadata(crypt_stat, (page_virt + offset),
					   &bytes_read, validate_header_size);
		if (rc) {
			sefs_printk(KERN_WARNING, "Error reading header "
					"metadata; rc = [%d]\n", rc);
		}
		offset += bytes_read;
	} else
		set_default_header_data(crypt_stat);
	rc = sefs_parse_packet_set(crypt_stat, (page_virt + offset),
				       sefs_dentry);
out:
	return rc;
}

/**
 * sefs_read_xattr_region
 * @page_virt: The vitual address into which to read the xattr data
 * @sefs_inode: The eCryptfs inode
 *
 * Attempts to read the crypto metadata from the extended attribute
 * region of the lower file.
 *
 * Returns zero on success; non-zero on error
 */
int sefs_read_xattr_region(char *page_virt, struct inode *sefs_inode)
{
	struct dentry *lower_dentry =
		sefs_inode_to_private(sefs_inode)->lower_file->f_path.dentry;
	ssize_t size;
	int rc = 0;

	size = sefs_getxattr_lower(lower_dentry,
				       sefs_inode_to_lower(sefs_inode),
				       SEFS_XATTR_NAME,
				       page_virt, SEFS_DEFAULT_EXTENT_SIZE);
	if (size < 0) {
		if (unlikely(sefs_verbosity > 0))
			printk(KERN_INFO "Error attempting to read the [%s] "
			       "xattr from the lower file; return value = "
			       "[%zd]\n", SEFS_XATTR_NAME, size);
		rc = -EINVAL;
		goto out;
	}
out:
	return rc;
}

int sefs_read_and_validate_xattr_region(struct dentry *dentry,
					    struct inode *inode)
{
	u8 file_size[SEFS_SIZE_AND_MARKER_BYTES];
	u8 *marker = file_size + SEFS_FILE_SIZE_BYTES;
	int rc;

	rc = sefs_getxattr_lower(sefs_dentry_to_lower(dentry),
				     sefs_inode_to_lower(inode),
				     SEFS_XATTR_NAME, file_size,
				     SEFS_SIZE_AND_MARKER_BYTES);
	if (rc < SEFS_SIZE_AND_MARKER_BYTES)
		return rc >= 0 ? -EINVAL : rc;
	rc = sefs_validate_marker(marker);
	if (!rc)
		sefs_i_size_init(file_size, inode);
	return rc;
}

/**
 * sefs_read_metadata
 *
 * Common entry point for reading file metadata. From here, we could
 * retrieve the header information from the header region of the file,
 * the xattr region of the file, or some other repository that is
 * stored separately from the file itself. The current implementation
 * supports retrieving the metadata information from the file contents
 * and from the xattr region.
 *
 * Returns zero if valid headers found and parsed; non-zero otherwise
 */
int sefs_read_metadata(struct dentry *sefs_dentry)
{
	int rc;
	char *page_virt;
	struct inode *sefs_inode = d_inode(sefs_dentry);
	struct sefs_crypt_stat *crypt_stat =
	    &sefs_inode_to_private(sefs_inode)->crypt_stat;
	struct sefs_mount_crypt_stat *mount_crypt_stat =
		&sefs_superblock_to_private(
			sefs_dentry->d_sb)->mount_crypt_stat;

	sefs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
						      mount_crypt_stat);
	/* Read the first page from the underlying file */
	page_virt = kmem_cache_alloc(sefs_header_cache, GFP_USER);
	if (!page_virt) {
		rc = -ENOMEM;
		printk(KERN_ERR "%s: Unable to allocate page_virt\n",
		       __func__);
		goto out;
	}
	rc = sefs_read_lower(page_virt, 0, crypt_stat->extent_size,
				 sefs_inode);
	if (rc >= 0)
		rc = sefs_read_headers_virt(page_virt, crypt_stat,
						sefs_dentry,
						SEFS_VALIDATE_HEADER_SIZE);
	if (rc) {
		/* metadata is not in the file header, so try xattrs */
		memset(page_virt, 0, PAGE_SIZE);
		rc = sefs_read_xattr_region(page_virt, sefs_inode);
		if (rc) {
			printk(KERN_DEBUG "Valid eCryptfs headers not found in "
			       "file header region or xattr region, inode %lu\n",
				sefs_inode->i_ino);
			rc = -EINVAL;
			goto out;
		}
		rc = sefs_read_headers_virt(page_virt, crypt_stat,
						sefs_dentry,
						SEFS_DONT_VALIDATE_HEADER_SIZE);
		if (rc) {
			printk(KERN_DEBUG "Valid eCryptfs headers not found in "
			       "file xattr region either, inode %lu\n",
				sefs_inode->i_ino);
			rc = -EINVAL;
		}
		if (crypt_stat->mount_crypt_stat->flags
		    & SEFS_XATTR_METADATA_ENABLED) {
			crypt_stat->flags |= SEFS_METADATA_IN_XATTR;
		} else {
			printk(KERN_WARNING "Attempt to access file with "
			       "crypto metadata only in the extended attribute "
			       "region, but eCryptfs was mounted without "
			       "xattr support enabled. eCryptfs will not treat "
			       "this like an encrypted file, inode %lu\n",
				sefs_inode->i_ino);
			rc = -EINVAL;
		}
	}
out:
	if (page_virt) {
		memset(page_virt, 0, PAGE_SIZE);
		kmem_cache_free(sefs_header_cache, page_virt);
	}
	return rc;
}

   
											   
  
																
																
													 
  
											  
   
		  
															 
														
 
			

									 
									   
												 
												   
					 
						 

									
			  
									  
						  
							
		   
														
												   
			  
										 
			
   
								
														  
									  
														 
											   
											 
				
			
   
													  
																 
						 
					 
						 
						   
								 
		   
													  
												 
			  
									   
									   
										 
			
   
												  
		 
														  
														  
				   
		   
  
	
		   
 

static int sefs_copy_filename(char **copied_name, size_t *copied_name_size,
				  const char *name, size_t name_size)
{
	int rc = 0;

	(*copied_name) = kmalloc((name_size + 1), GFP_KERNEL);
	if (!(*copied_name)) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy((void *)(*copied_name), (void *)name, name_size);
	(*copied_name)[(name_size)] = '\0';	/* Only for convenience
						 * in printing out the
						 * string in debug
						 * messages */
	(*copied_name_size) = name_size;
out:
	return rc;
}

/**
 * sefs_process_key_cipher - Perform key cipher initialization.
 * @key_tfm: Crypto context for key material, set by this function
 * @cipher_name: Name of the cipher
 * @key_size: Size of the key in bytes
 *
 * Returns zero on success. Any crypto_tfm structs allocated here
 * should be released by other functions, such as on a superblock put
 * event, regardless of whether this function succeeds for fails.
 */
static int
sefs_process_key_cipher(struct crypto_skcipher **key_tfm,
			    char *cipher_name, size_t *key_size)
{
	char dummy_key[SEFS_MAX_KEY_BYTES];
	char *full_alg_name = NULL;
	int rc;

	*key_tfm = NULL;
	if (*key_size > SEFS_MAX_KEY_BYTES) {
		rc = -EINVAL;
		printk(KERN_ERR "Requested key size is [%zd] bytes; maximum "
		      "allowable is [%d]\n", *key_size, SEFS_MAX_KEY_BYTES);
		goto out;
	}
	rc = sefs_crypto_api_algify_cipher_name(&full_alg_name, cipher_name,
						    "ecb");
	if (rc)
		goto out;
	*key_tfm = crypto_alloc_skcipher(full_alg_name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(*key_tfm)) {
		rc = PTR_ERR(*key_tfm);
		printk(KERN_ERR "Unable to allocate crypto cipher with name "
		       "[%s]; rc = [%d]\n", full_alg_name, rc);
		goto out;
	}
	crypto_skcipher_set_flags(*key_tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	if (*key_size == 0)
		*key_size = crypto_skcipher_default_keysize(*key_tfm);
	get_random_bytes(dummy_key, *key_size);
	rc = crypto_skcipher_setkey(*key_tfm, dummy_key, *key_size);
	if (rc) {
		printk(KERN_ERR "Error attempting to set key of size [%zd] for "
		       "cipher [%s]; rc = [%d]\n", *key_size, full_alg_name,
		       rc);
		rc = -EINVAL;
		goto out;
	}
out:
	kfree(full_alg_name);
	return rc;
}

struct kmem_cache *sefs_key_tfm_cache;
static struct list_head key_tfm_list;
struct mutex key_tfm_list_mutex;

int __init sefs_init_crypto(void)
{
	mutex_init(&key_tfm_list_mutex);
	INIT_LIST_HEAD(&key_tfm_list);
	return 0;
}

/**
 * sefs_destroy_crypto - free all cached key_tfms on key_tfm_list
 *
 * Called only at module unload time
 */
int sefs_destroy_crypto(void)
{
	struct sefs_key_tfm *key_tfm, *key_tfm_tmp;

	mutex_lock(&key_tfm_list_mutex);
	list_for_each_entry_safe(key_tfm, key_tfm_tmp, &key_tfm_list,
				 key_tfm_list) {
		list_del(&key_tfm->key_tfm_list);
		crypto_free_skcipher(key_tfm->key_tfm);
		kmem_cache_free(sefs_key_tfm_cache, key_tfm);
	}
	mutex_unlock(&key_tfm_list_mutex);
	return 0;
}

int
sefs_add_new_key_tfm(struct sefs_key_tfm **key_tfm, char *cipher_name,
			 size_t key_size)
{
	struct sefs_key_tfm *tmp_tfm;
	int rc = 0;

	BUG_ON(!mutex_is_locked(&key_tfm_list_mutex));

	tmp_tfm = kmem_cache_alloc(sefs_key_tfm_cache, GFP_KERNEL);
	if (key_tfm != NULL)
		(*key_tfm) = tmp_tfm;
	if (!tmp_tfm) {
		rc = -ENOMEM;
		printk(KERN_ERR "Error attempting to allocate from "
		       "sefs_key_tfm_cache\n");
		goto out;
	}
	mutex_init(&tmp_tfm->key_tfm_mutex);
	strncpy(tmp_tfm->cipher_name, cipher_name,
		SEFS_MAX_CIPHER_NAME_SIZE);
	tmp_tfm->cipher_name[SEFS_MAX_CIPHER_NAME_SIZE] = '\0';
	tmp_tfm->key_size = key_size;
	rc = sefs_process_key_cipher(&tmp_tfm->key_tfm,
					 tmp_tfm->cipher_name,
					 &tmp_tfm->key_size);
	if (rc) {
		printk(KERN_ERR "Error attempting to initialize key TFM "
		       "cipher with name = [%s]; rc = [%d]\n",
		       tmp_tfm->cipher_name, rc);
		kmem_cache_free(sefs_key_tfm_cache, tmp_tfm);
		if (key_tfm != NULL)
			(*key_tfm) = NULL;
		goto out;
	}
	list_add(&tmp_tfm->key_tfm_list, &key_tfm_list);
out:
	return rc;
}

/**
 * sefs_tfm_exists - Search for existing tfm for cipher_name.
 * @cipher_name: the name of the cipher to search for
 * @key_tfm: set to corresponding tfm if found
 *
 * Searches for cached key_tfm matching @cipher_name
 * Must be called with &key_tfm_list_mutex held
 * Returns 1 if found, with @key_tfm set
 * Returns 0 if not found, with @key_tfm set to NULL
 */
int sefs_tfm_exists(char *cipher_name, struct sefs_key_tfm **key_tfm)
{
	struct sefs_key_tfm *tmp_key_tfm;

	BUG_ON(!mutex_is_locked(&key_tfm_list_mutex));

	list_for_each_entry(tmp_key_tfm, &key_tfm_list, key_tfm_list) {
		if (strcmp(tmp_key_tfm->cipher_name, cipher_name) == 0) {
			if (key_tfm)
				(*key_tfm) = tmp_key_tfm;
			return 1;
		}
	}
	if (key_tfm)
		(*key_tfm) = NULL;
	return 0;
}

/**
 * sefs_get_tfm_and_mutex_for_cipher_name
 *
 * @tfm: set to cached tfm found, or new tfm created
 * @tfm_mutex: set to mutex for cached tfm found, or new tfm created
 * @cipher_name: the name of the cipher to search for and/or add
 *
 * Sets pointers to @tfm & @tfm_mutex matching @cipher_name.
 * Searches for cached item first, and creates new if not found.
 * Returns 0 on success, non-zero if adding new cipher failed
 */
int sefs_get_tfm_and_mutex_for_cipher_name(struct crypto_skcipher **tfm,
					       struct mutex **tfm_mutex,
					       char *cipher_name)
{
	struct sefs_key_tfm *key_tfm;
	int rc = 0;

	(*tfm) = NULL;
	(*tfm_mutex) = NULL;

	mutex_lock(&key_tfm_list_mutex);
	if (!sefs_tfm_exists(cipher_name, &key_tfm)) {
		rc = sefs_add_new_key_tfm(&key_tfm, cipher_name, 0);
		if (rc) {
			printk(KERN_ERR "Error adding new key_tfm to list; "
					"rc = [%d]\n", rc);
			goto out;
		}
	}
	(*tfm) = key_tfm->key_tfm;
	(*tfm_mutex) = &key_tfm->key_tfm_mutex;
out:
	mutex_unlock(&key_tfm_list_mutex);
	return rc;
}
				   

/* We could either offset on every reverse map or just pad some 0x00's
 * at the front here */
static const unsigned char filename_rev_map[256] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 7 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 15 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 23 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 31 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 39 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, /* 47 */
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, /* 55 */
	0x0A, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 63 */
	0x00, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, /* 71 */
	0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, /* 79 */
	0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, /* 87 */
	0x23, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, /* 95 */
	0x00, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, /* 103 */
	0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, /* 111 */
	0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, /* 119 */
	0x3D, 0x3E, 0x3F /* 123 - 255 initialized to 0x00 */
};


static char sefs_map_index[]={
					45,48,49,50,51,52,53,54,55,56,57,65,66,67,68,69,70,71,72,
					73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,95,
					97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,
					113,114,115,116,117,118,119,120,121,122};

static char sefs_map[] = {
			67,79,51,90,104,109,74,49,87,95,45,76,88,56,105,89,118,113,86,103,
			106,57,81,52,66,107,73,97,121,75,85,101,119,50,78,122,54,98,69,70,
			71,110,80,115,117,84,48,65,114,111,55,53,102,120,100,77,68,82,112,116,
			108,99,83,72,74,71,77,99,111,97,72,52,53,79,121,66,114,118,112,101,
			80,68,116,55,120,89,73,84,100,85,113,82,51,122,106,104,88,87,108,50,
			119,81,76,98,110,107,69,103,56,57,95,49,105,86,75,90,45,102,70,48,
			67,117,83,65,54,115,109,78,71,69,80,88,98,57,48,87,75,52,72,116,
			109,100,51,67,68,97,103,119,106,50,105,49,55,45,110,104,114,66,78,73,
			102,84,54,82,65,53,74,121,95,85,115,90,81,56,76,79,113,118,117,120,
			107,70,86,99,112,83,101,77,89,122,111,108,116,104,122,79,78,103,45,112,
			67,110,76,71,117,54,101,49,69,80,105,107,102,77,70,114,115,111,89,108,
			82,75,88,51,119,97,95,85,66,83,98,90,68,81,56,87,57,109,74,113,
			121,53,48,52,100,84,73,99,55,106,86,72,120,118,65,50,113,114,97,108,
			57,95,100,79,89,67,122,120,71,86,66,77,117,52,68,106,104,51,48,99,
			72,78,50,83,118,116,119,53,98,103,109,121,87,111,115,101,55,56,107,82,
			73,102,90,69,65,74,84,88,70,105,49,80,45,76,110,54,85,112,75,81,
			73,114,115,65,104,54,90,118,77,109,89,84,85,106,98,88,99,48,95,83,
			110,66,102,45,69,103,81,113,100,122,76,67,56,75,55,74,117,52,87,82,
			116,121,120,50,111,51,119,105,57,72,68,112,71,101,70,49,97,86,80,53,
			78,107,79,108,81,55,110,57,97,105,68,95,54,88,106,75,84,76,112,109,
			116,85,120,49,50,66,45,70,121,104,71,117,56,90,73,51,72,74,99,67,
			115,82,53,83,80,113,100,69,79,119,86,102,122,98,52,114,65,48,78,101,
			103,89,87,107,108,118,77,111,79,100,66,70,98,87,116,119,108,97,53,54,
			120,105,114,77,51,121,103,80,83,115,104,110,82,89,85,52,76,109,50,81,
			118,65,55,68,90,48,112,86,111,101,71,69,56,99,67,122,74,57,117,106,
			84,102,113,107,75,73,72,45,88,49,95,78,49,75,81,89,109,88,86,105,
			119,77,84,113,90,76,73,110,106,57,45,108,52,83,107,118,48,50,65,101,
			66,103,51,71,116,100,115,54,114,67,95,99,112,80,85,122,70,102,69,120,
			53,56,121,82,87,68,111,72,97,74,98,55,79,78,104,117,80,57,76,77,
			100,51,115,106,68,112,53,110,74,49,88,108,52,120,78,90,109,65,104,113,
			107,71,122,117,79,114,73,89,121,84,66,55,111,70,118,83,103,87,116,86,
			67,99,85,82,45,81,54,56,95,98,97,69,48,102,119,72,75,105,50,101,
			122,70,78,113,56,117,57,50,90,45,88,101,99,102,98,87,103,77,109,81,
			86,71,83,48,73,52,84,121,54,67,115,100,119,110,89,112,79,55,53,66,
			65,105,49,106,107,80,114,120,85,108,69,72,95,82,104,116,75,97,68,118,
			74,111,51,76,75,73,54,71,112,52,81,89,122,87,82,72,65,76,121,117,
			116,90,98,51,74,97,49,86,107,57,110,69,45,55,103,114,101,105,68,79,
			77,113,83,50,100,66,120,115,95,53,70,119,88,102,85,108,78,106,109,56,
			48,67,99,118,104,80,84,111,112,56,100,67,119,122,66,95,110,105,97,81,
			72,90,113,103,80,106,48,98,120,77,51,104,68,99,84,75,57,101,79,55,
			74,53,85,69,89,78,87,86,82,83,108,107,118,121,102,52,65,115,114,73,
			50,70,45,117,109,49,88,76,54,116,111,71,89,122,83,119,81,75,72,111,
			84,68,120,74,80,112,117,118,78,55,65,102,49,107,71,104,66,95,79,101,
			77,69,109,70,54,116,67,57,48,121,45,56,76,85,110,88,52,73,82,100,
			106,108,90,50,105,97,113,98,115,114,103,51,53,99,86,87,88,118,90,75,
			67,66,56,121,85,104,52,49,99,116,57,73,115,102,95,77,82,54,65,68,
			101,108,107,81,72,80,53,45,103,51,87,69,105,84,50,97,76,112,122,98,
			109,120,111,117,78,106,113,74,71,110,79,86,48,89,83,100,114,119,55,70,
			71,89,68,90,88,75,109,97,81,85,80,48,79,115,106,111,49,122,78,82,
			57,72,102,101,69,113,98,50,65,52,74,117,112,53,105,95,107,87,103,66,
			108,100,77,67,55,116,83,114,73,76,70,120,45,118,121,86,56,110,99,51,
			119,84,104,54,100,49,73,80,108,117,54,88,99,105,112,87,51,84,85,76,
			56,98,89,111,72,52,48,81,75,101,113,67,106,119,53,74,120,90,95,109,
			121,115,71,86,66,103,104,122,116,69,50,57,82,68,77,107,83,65,110,97,
			79,102,55,114,70,45,78,118,50,107,118,80,88,122,112,117,78,56,65,72,
			53,106,52,109,89,73,54,100,103,105,113,77,55,57,49,104,108,116,90,45,
			76,120,66,95,69,115,75,85,101,111,82,51,110,70,98,83,99,87,74,102,
			48,81,119,68,86,84,71,114,67,121,97,79,118,66,82,111,95,106,89,120,
			98,97,68,88,122,48,119,52,73,76,87,78,117,51,54,84,65,107,53,112,
			102,99,83,100,75,79,101,45,104,113,69,49,86,74,80,57,67,115,110,81,
			70,116,50,105,90,109,77,114,55,108,72,56,85,71,103,121,103,95,104,86,
			83,72,57,68,89,100,78,56,73,119,117,97,87,69,109,66,67,114,110,120,
			106,52,49,84,71,105,88,118,116,74,101,113,112,85,75,121,50,48,82,80,
			55,51,98,65,108,99,70,79,81,111,122,77,76,54,102,53,45,115,107,90,
			89,109,99,106,50,83,66,116,84,86,88,95,81,117,104,97,68,67,57,111,
			85,54,70,110,51,78,69,114,101,77,100,115,71,108,107,56,87,98,102,120,
			48,53,121,90,105,45,55,82,76,119,112,118,72,122,103,49,113,73,79,52,
			74,75,65,80,49,111,78,104,57,50,81,65,54,106,103,110,67,120,52,84,
			97,116,102,86,48,118,108,55,99,115,45,88,85,77,68,100,98,73,69,117,
			90,83,109,89,122,79,72,112,51,75,53,80,70,101,113,107,74,71,87,66,
			119,82,114,121,56,95,105,76,68,56,117,75,57,87,72,115,121,99,69,65,
			48,114,81,106,88,49,50,108,77,84,95,73,111,76,116,105,67,113,112,85,
			53,51,86,66,71,45,98,122,80,79,90,104,100,103,55,101,82,119,89,110,
			97,107,78,74,109,54,70,118,102,83,52,120,78,49,57,88,106,114,48,82,
			50,112,101,71,102,104,119,67,79,111,45,86,77,110,105,118,108,103,122,66,
			72,120,98,74,113,68,81,54,85,55,69,84,83,51,99,73,116,107,87,121,
			89,53,80,76,115,97,109,117,52,90,65,95,75,56,70,100,97,67,99,113,
			84,107,74,108,82,118,83,106,111,78,114,79,76,70,121,95,115,81,57,122,
			102,87,117,68,85,101,98,88,109,77,110,65,90,75,66,86,105,48,51,116,
			80,72,52,112,71,103,69,120,100,104,89,56,119,50,45,73,54,55,53,49,
			98,101,81,116,115,48,117,57,110,95,54,103,122,114,107,71,45,111,104,108,
			85,121,75,112,67,106,68,51,53,120,119,118,87,69,56,73,66,70,84,82,
			72,88,65,76,74,102,109,113,100,83,49,52,80,86,97,90,50,78,79,77,
			99,89,105,55,121,95,73,119,76,115,52,100,55,113,79,72,116,102,68,110,
			114,97,56,117,81,99,48,69,66,82,104,67,107,77,87,57,118,105,65,83,
			109,74,101,80,108,112,106,120,111,88,45,103,84,49,71,50,54,75,90,51,
			85,86,122,98,70,78,53,89,72,90,54,56,77,70,105,49,78,57,106,74,
			75,113,50,53,118,120,111,80,68,88,85,121,55,115,112,67,114,66,119,107,
			102,99,51,69,104,116,84,98,100,89,110,122,103,48,71,101,117,52,82,108,
			45,86,79,73,87,65,95,109,81,83,76,97,87,117,118,51,55,95,71,103,
			114,76,88,116,53,101,67,48,84,110,70,98,54,79,45,105,115,100,90,65,
			81,57,111,50,107,122,112,73,77,74,108,82,104,69,119,75,106,113,89,72,
			80,109,83,85,49,99,68,120,86,78,52,56,102,97,66,121,48,45,122,117,
			51,106,76,83,89,82,49,101,116,88,114,72,55,74,121,71,100,52,81,53,
			119,95,110,113,73,104,105,90,54,50,85,115,75,84,67,112,111,57,69,107,
			103,102,98,77,120,118,79,70,99,80,97,68,66,108,56,87,65,109,78,86,
			99,57,117,114,108,85,45,82,109,78,87,77,54,83,116,112,100,113,70,98,
			95,69,103,106,86,55,90,76,104,97,122,119,74,71,115,52,79,81,102,107,
			51,101,75,118,66,120,73,121,72,84,68,89,80,56,49,88,67,50,48,65,
			53,105,111,110,104,102,77,109,78,86,119,106,83,105,95,87,117,82,50,71,
			112,110,73,107,74,114,55,57,113,79,98,115,70,52,69,116,100,90,51,97,
			65,66,67,56,121,68,108,45,103,122,81,72,111,49,76,80,99,120,118,84,
			75,88,54,101,85,48,53,89,95,84,76,81,71,73,83,68,90,116,111,53,
			54,52,113,121,110,56,88,75,78,55,98,106,107,119,72,105,87,50,80,79,
			115,70,100,74,51,114,45,65,67,66,86,101,57,118,97,49,120,82,109,85,
			122,117,48,104,69,112,89,103,108,102,99,77,76,67,49,97,53,121,89,48,
			108,56,100,52,104,51,99,74,103,50,66,80,95,78,88,111,83,71,119,120,
			54,77,116,107,81,114,84,73,101,90,98,118,55,122,106,112,109,117,86,110,
			85,68,115,57,69,105,82,75,113,72,87,70,102,65,79,45,80,51,105,118,
			115,45,90,77,98,99,119,108,48,66,57,102,53,111,83,74,67,85,109,56,
			116,52,88,103,107,72,122,106,110,95,101,79,89,70,81,73,117,65,84,86,
			112,114,121,82,75,68,97,113,50,54,55,120,49,87,76,78,100,104,71,69,
			49,81,122,57,98,89,54,101,114,121,119,72,74,99,67,110,105,66,112,83,
			84,69,106,90,50,68,97,65,75,48,45,115,55,116,73,95,85,108,118,113,
			77,53,107,70,71,102,88,79,52,82,80,100,78,117,103,51,86,109,87,56,
			104,120,111,76,100,101,87,74,113,56,98,48,53,88,67,66,122,107,112,71,
			117,77,79,90,73,45,118,103,65,85,52,109,111,57,70,114,119,115,105,97,
			69,68,89,121,116,86,72,50,106,104,99,49,95,102,110,51,55,84,108,120,
			75,76,54,78,83,80,81,82,48,75,106,110,73,115,69,82,95,52,50,86,
			53,51,81,57,88,121,107,85,65,118,90,74,122,56,80,101,72,102,117,87,
			120,79,97,103,76,99,111,77,113,55,45,83,109,108,78,114,112,70,119,89,
			71,54,49,105,100,98,67,68,66,116,84,104,80,54,86,70,81,117,53,110,
			103,98,56,120,88,52,102,100,114,68,72,122,45,75,101,87,74,90,95,51,
			66,79,107,119,57,89,105,78,82,99,121,48,104,65,115,77,69,83,84,116,
			67,73,85,76,109,113,108,49,50,112,55,97,118,111,106,71,122,53,76,48,
			118,45,95,84,72,115,97,77,73,65,51,104,66,100,110,50,103,83,114,57,
			69,98,55,87,71,105,111,121,107,75,109,80,101,52,90,113,86,56,99,54,
			67,81,117,70,112,120,68,74,88,78,82,49,79,116,106,119,89,108,85,102,
			108,88,85,51,67,107,71,99,66,83,89,114,116,73,57,112,74,105,69,54,
			103,104,117,109,121,52,122,90,68,101,115,100,77,80,65,118,98,82,110,49,
			48,111,50,119,84,97,95,75,102,72,56,53,45,81,70,120,106,55,113,76,
			86,87,79,78,121,82,86,54,72,75,53,55,114,69,122,108,81,110,85,74,
			89,77,98,109,51,103,117,67,112,90,116,49,102,99,88,101,104,56,70,68,
			111,120,79,107,80,50,78,84,87,100,83,76,95,66,105,73,113,119,48,65,
			52,118,97,115,71,57,106,45,66,98,118,89,65,72,49,113,74,75,83,48,
			104,111,86,78,103,79,116,57,112,50,76,80,53,95,88,100,55,117,71,87,
			51,108,120,110,52,101,102,115,105,97,84,107,70,85,54,73,114,56,99,45,
			121,106,69,122,82,67,109,81,119,68,90,77,122,73,52,55,74,86,104,87,
			76,77,117,98,71,56,51,54,79,48,110,66,84,113,101,97,88,81,80,83,
			103,68,114,49,115,120,75,82,111,78,119,53,72,112,65,106,85,108,121,107,
			95,89,105,116,67,109,70,45,99,69,100,57,50,118,102,90,107,50,80,103,
			79,120,68,75,83,76,81,70,67,110,56,55,105,117,97,87,111,88,121,49,
			109,118,52,54,77,48,66,73,78,100,122,85,104,45,98,72,114,102,82,51,
			116,99,86,84,69,89,71,74,108,101,113,57,65,115,53,106,95,112,90,119,
			66,45,115,119,82,104,55,89,103,116,87,111,97,51,108,90,99,56,84,107,
			69,98,68,81,49,106,118,112,117,95,86,102,88,65,120,113,100,114,79,57,
			53,54,67,80,76,48,85,71,78,121,74,83,50,73,110,72,70,101,77,105,
			52,109,122,75,97,83,45,104,121,112,117,68,54,116,79,77,51,69,108,114,
			53,119,81,76,102,99,73,80,111,106,120,78,95,55,87,122,115,88,109,52,
			48,56,84,57,67,70,98,66,75,100,72,85,50,49,71,74,103,113,82,90,
			118,89,110,86,65,101,107,105,102,51,118,98,115,106,86,69,89,57,87,108,
			120,119,81,65,117,105,77,70,75,66,116,113,68,109,52,48,45,95,55,99,
			80,56,78,121,111,82,74,72,101,107,53,85,97,114,73,49,79,90,122,83,
			50,104,54,84,67,88,100,112,103,110,71,76,68,90,110,65,103,88,102,121,
			50,75,85,120,54,53,87,48,76,112,67,77,118,57,83,74,106,100,51,79,
			89,109,78,107,71,105,70,117,82,104,116,97,72,119,69,99,45,115,49,86,
			114,113,101,66,98,81,55,108,122,52,84,80,95,111,73,56,112,50,66,109,
			121,71,49,69,90,98,97,81,56,120,80,79,105,51,82,110,107,85,88,122,
			106,48,77,73,67,52,74,89,86,104,116,54,111,53,45,70,95,55,115,101,
			72,119,83,84,78,103,118,76,114,65,117,102,68,100,113,99,87,108,75,57,
			120,86,111,117,105,45,54,109,121,118,69,74,95,50,82,112,73,71,89,102,
			65,85,51,122,68,80,70,119,116,99,107,100,113,104,48,114,53,66,106,115,
			97,75,55,79,84,98,88,103,108,87,110,76,77,49,57,52,78,101,56,67,
			81,72,83,90,110,106,88,100,80,45,101,104,71,114,75,77,82,76,53,112,
			78,74,122,85,56,108,95,118,117,89,69,120,87,116,68,107,84,51,70,54,
			79,105,115,52,119,66,86,121,109,98,48,99,103,102,97,81,111,65,57,49,
			55,90,67,83,50,73,72,113,115,50,99,78,53,84,90,81,86,109,45,73,
			51,114,65,48,106,87,108,54,49,95,102,76,66,107,122,71,89,112,111,100,
			52,97,119,103,116,70,67,98,77,85,80,69,57,105,83,56,104,79,121,75,
			55,82,88,110,120,118,68,113,74,117,72,101,100,45,87,103,118,69,77,66,
			112,75,84,88,122,50,95,113,53,107,67,57,81,105,56,110,99,117,108,102,
			86,82,74,49,121,97,89,65,71,54,76,73,78,72,80,48,115,85,104,109,
			98,83,119,101,52,111,70,55,116,120,114,68,79,51,90,106,97,72,112,95,
			86,105,107,102,78,108,101,56,65,99,87,119,104,111,106,54,45,114,66,50,
			89,81,77,113,122,117,79,70,82,71,51,55,73,100,85,75,49,98,90,116,
			74,76,120,67,52,68,80,88,109,83,103,121,48,115,57,69,53,84,110,118,
			117,115,45,107,75,51,116,99,85,105,84,66,90,97,86,113,110,57,49,55,
			88,87,98,50,54,53,70,108,78,82,103,48,89,73,102,56,80,81,83,68,
			95,104,112,120,121,122,72,79,71,74,119,101,111,76,118,65,67,100,106,109,
			77,52,69,114,102,66,104,65,100,98,77,87,90,72,76,105,57,71,95,106,
			54,82,75,85,107,103,67,51,81,118,111,48,116,97,79,108,73,112,55,69,
			121,68,56,109,88,120,89,83,86,78,49,50,117,53,80,52,70,84,119,114,
			122,45,101,74,113,99,110,115,49,72,69,106,78,105,95,82,66,53,112,120,
			67,109,89,85,107,101,55,88,110,74,100,52,116,80,48,75,70,99,83,102,
			115,122,114,90,45,51,87,84,113,56,103,77,79,86,68,71,65,54,117,73,
			119,121,76,118,111,108,81,57,97,50,98,104,122,70,104,89,81,65,66,86,
			53,100,119,77,72,69,79,84,67,57,114,106,103,121,109,115,107,76,50,97,
			87,118,75,99,90,116,74,111,49,95,88,105,85,98,108,120,80,48,83,73,
			71,55,113,52,110,54,117,102,56,78,82,45,112,68,101,51,77,87,85,119,
			52,74,81,65,114,88,89,68,69,105,110,75,113,117,83,56,102,66,118,109,
			45,78,53,99,120,70,48,67,72,104,103,57,122,50,116,80,112,111,54,84,
			97,55,79,121,86,101,82,73,115,107,49,71,98,95,76,108,106,51,90,100,
			101,99,49,98,88,117,68,79,77,105,102,78,80,108,71,67,48,95,76,55,
			81,97,109,70,110,86,73,118,56,69,66,121,53,45,51,72,50,65,106,122,
			104,83,116,52,85,90,100,120,107,89,87,75,84,114,74,113,54,103,119,112,
			111,115,82,57,95,56,107,50,86,113,76,78,122,102,65,77,45,97,118,84,
			106,51,82,114,111,105,48,70,110,75,108,83,117,119,54,69,74,68,103,73,
			99,89,109,101,79,112,90,80,85,72,53,55,121,120,115,98,49,67,57,52,
			116,71,87,66,100,104,81,88,115,106,121,54,77,52,109,56,57,122,89,86,
			70,87,117,108,99,113,82,84,118,53,111,65,95,97,101,71,116,114,67,105,
			50,88,51,110,74,72,120,73,98,55,103,90,104,66,79,85,75,69,100,83,
			76,107,80,78,68,48,102,81,49,119,45,112,86,77,87,45,88,56,112,70,
			72,68,52,81,69,107,102,103,74,80,55,84,71,97,79,117,116,85,90,82,
			114,111,105,101,57,106,95,118,98,99,67,121,49,83,73,76,109,54,122,89,
			51,115,48,100,50,104,110,113,75,78,108,66,120,119,65,53};

					
#define INDEX_SIZE 64//(sizeof(sefs_map_index))

static char find_encrypt_byte(char rand,char c)
{
	char *p;
	int i;
	int size;

	size = INDEX_SIZE;
	p = sefs_map + rand*size;
	for(i=0;i<size;i++)
	{
	  if(sefs_map_index[i] == c)
		  return p[i];
	}
	return c;
}
												

static char find_decrypt_byte(char rand,char c)
{
	char *p;
	int i;
	int size;

	size = INDEX_SIZE;
	p = sefs_map + rand*size;
	for(i=0;i<size;i++)
	{
	  if(p[i] == c)
		  return sefs_map_index[i];				
	}
	
	
	return c;
}

/**
 * sefs_encrypt_and_encode_filename - converts a plaintext file name to cipher text
 * @crypt_stat: The crypt_stat struct associated with the file anem to encode
 * @name: The plaintext name
 * @length: The length of the plaintext
 * @encoded_name: The encypted name
 *
 * Encrypts and encodes a filename into something that constitutes a
 * valid filename for a filesystem, with printable characters.
 *
 * We assume that we have a properly initialized crypto context,
 * pointed to by crypt_stat->tfm.
 *
 * Returns zero on success; non-zero on otherwise
 */
int sefs_encrypt_and_encode_filename(
	char **encoded_name,
	size_t *encoded_name_size,
	struct sefs_mount_crypt_stat *mount_crypt_stat,
	const char *name, size_t name_size)
{
									
	int rc = 0;
	int i;
	char byte1 = -1;
	char byte2 = -1;
	char byte3 = -1;
	int pos1 = -1;
	int pos2 = -1;
	int pos3 = -1;
	unsigned int rand1;
	unsigned int rand2;

	(*encoded_name) = NULL;
	(*encoded_name_size) = 0;
	if (mount_crypt_stat && (mount_crypt_stat->flags
				     & SEFS_GLOBAL_ENCRYPT_FILENAMES)) {
		(*encoded_name) = kzalloc(name_size, GFP_KERNEL);
		if(name_size < 5){
			rand1 = name_size%INDEX_SIZE;
			rand2 = INDEX_SIZE - rand1;
		}else{				   				   
			pos1 = (name_size>>2);
			byte1 = find_encrypt_byte(((pos1+10)%INDEX_SIZE),name[pos1]);									 								 
			pos2 = (name_size>>1);
			byte2 = find_encrypt_byte((pos2%INDEX_SIZE),name[pos2]);
			pos3 = name_size - (name_size>>2);
			byte3 = find_encrypt_byte((pos3%INDEX_SIZE),name[pos3]);
			rand1 = name[pos1] + name[pos2] + name[pos3];
			rand2 = rand1 + name_size;
			rand1 = rand1%INDEX_SIZE;
			rand2 = rand2%INDEX_SIZE;									
		}
		for(i=0; i < (name_size>>1) ; i++)
			(*encoded_name)[i] = find_encrypt_byte(rand1,name[i]);
		for(i=(name_size>>1); i < name_size ; i++)
			(*encoded_name)[i] = find_encrypt_byte(rand2,name[i]);
		if(pos1 != -1)
			(*encoded_name)[pos1] = byte1;
		if(pos2 != -1)
			(*encoded_name)[pos2] = byte2;
		if(pos3 != -1)
			(*encoded_name)[pos3] = byte3;
		(*encoded_name_size) = name_size;
		#if 1
		printk("pos1:%d pos2:%d pos3:%d byte1:%c bypte2:%c byte3:%c rand1:%d rand2:%d name[pos1]:%c name[pos2]:%c name[pos3]:%c\n",
			   pos1,pos2,pos3,byte1,byte2,byte3,rand1,rand2,name[pos1],name[pos2],name[pos3]);
		#endif
	} else {
		rc = sefs_copy_filename(encoded_name,
					    encoded_name_size,
					    name, name_size);
	}
	
#if 1
	printk("sefs encode name:");
	for(i=0;i<name_size;i++)
		printk("%c",name[i]);
	printk("\n");
	printk("sefs encode encoded_name:");
	for(i=0;i<name_size;i++)
		printk("%c",(*encoded_name)[i]);
	printk("\n");
#endif
	return rc;
}

/**
 * sefs_decode_and_decrypt_filename - converts the encoded cipher text name to decoded plaintext
 * @plaintext_name: The plaintext name
 * @plaintext_name_size: The plaintext name size
 * @sefs_dir_dentry: eCryptfs directory dentry
 * @name: The filename in cipher text
 * @name_size: The cipher text name size
 *
 * Decrypts and decodes the filename.
 *
 * Returns zero on error; non-zero otherwise
 */
int sefs_decode_and_decrypt_filename(char **plaintext_name,
					 size_t *plaintext_name_size,
					 struct super_block *sb,
					 const char *name, size_t name_size)
{
	struct sefs_mount_crypt_stat *mount_crypt_stat =
		&sefs_superblock_to_private(sb)->mount_crypt_stat;											 
									
	int rc = 0;
	int i;
	char byte1 = -1;
	char byte2 = -1;
	char byte3 = -1;
	int pos1 = -1;
	int pos2 = -1;
	int pos3 = -1;
	unsigned int rand1;
	unsigned int rand2;
	
	if ((mount_crypt_stat->flags & SEFS_GLOBAL_ENCRYPT_FILENAMES) &&
	    !(mount_crypt_stat->flags & SEFS_ENCRYPTED_VIEW_ENABLED)) {
														 
		if(strcmp(name,".") == 0 || strcmp(name,"..") == 0)
		{
			rc = sefs_copy_filename(plaintext_name,
					    plaintext_name_size,
					  
														 
											   
					    name, name_size);
				
			goto out;
		}
		(*plaintext_name) = NULL;
		(*plaintext_name_size) = 0;
		(*plaintext_name) = kzalloc((name_size), GFP_KERNEL);
		if(name_size < 5){
			rand1 = name_size%INDEX_SIZE;
			rand2 = INDEX_SIZE - rand1;
		}else{
			pos1 = (name_size>>2);
						 
			byte1 = find_decrypt_byte(((pos1+10)%INDEX_SIZE),name[pos1]);
			pos2 = (name_size>>1);
			byte2 = find_decrypt_byte((pos2%INDEX_SIZE),name[pos2]);
			pos3 = name_size - (name_size>>2);
			byte3 = find_decrypt_byte((pos3%INDEX_SIZE),name[pos3]);
			rand1 = byte1 + byte2 + byte3;
											  
			rand2 = rand1 + name_size;
			rand1 = rand1%INDEX_SIZE;
			rand2 = rand2%INDEX_SIZE;
		}
		for(i=0; i < (name_size>>1) ; i++)
			(*plaintext_name)[i] = find_decrypt_byte(rand1,name[i]);
		for(i=(name_size>>1); i < name_size ; i++)
			(*plaintext_name)[i] = find_decrypt_byte(rand2,name[i]);
		if(pos1 != -1)
			(*plaintext_name)[pos1] = byte1;
		if(pos2 != -1)
			(*plaintext_name)[pos2] = byte2;
		if(pos3 != -1)
			(*plaintext_name)[pos3] = byte3;
		(*plaintext_name_size) = name_size;
		#if 1
		printk("pos1:%d pos2:%d pos3:%d byte1:%c bypte2:%c byte3:%c rand1:%d rand2:%d name[pos1]:%c name[pos2]:%c name[pos3]:%c\n",
			   pos1,pos2,pos3,byte1,byte2,byte3,rand1,rand2,name[pos1],name[pos2],name[pos3]);
		#endif
	} else {
		rc = sefs_copy_filename(plaintext_name,
					    plaintext_name_size,
					    name, name_size);
		goto out;
	}				 
out:
#if 1
	printk("sefs decode name:");
	for(i=0;i<name_size;i++)
		printk("%c",name[i]);
	printk("\n");
	printk("sefs plaintext_name:");
	for(i=0;i<name_size;i++)
		printk("%c",(*plaintext_name)[i]);
	printk("\n");
#endif
	return rc;
}

#define ENC_NAME_MAX_BLOCKLEN_8_OR_16	143

int sefs_set_f_namelen(long *namelen, long lower_namelen,
			   struct sefs_mount_crypt_stat *mount_crypt_stat)
{												
	(*namelen) = lower_namelen;
	return 0;
}
