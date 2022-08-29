/**
 * eCryptfs: Linux filesystem encryption layer
 * Functions only useful for debugging.
 *
 * Copyright (C) 2006 International Business Machines Corp.
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

#include "sefs_kernel.h"

/**
 * sefs_dump_auth_tok - debug function to print auth toks
 *
 * This function will print the contents of an sefs authentication
 * token.
 */
void sefs_dump_auth_tok(struct sefs_auth_tok *auth_tok)
{
	char salt[SEFS_SALT_SIZE * 2 + 1];
	char sig[SEFS_SIG_SIZE_HEX + 1];

	sefs_printk(KERN_DEBUG, "Auth tok at mem loc [%p]:\n",
			auth_tok);
	if (auth_tok->flags & SEFS_PRIVATE_KEY) {
		sefs_printk(KERN_DEBUG, " * private key type\n");
	} else {
		sefs_printk(KERN_DEBUG, " * passphrase type\n");
		sefs_to_hex(salt, auth_tok->token.password.salt,
				SEFS_SALT_SIZE);
		salt[SEFS_SALT_SIZE * 2] = '\0';
		sefs_printk(KERN_DEBUG, " * salt = [%s]\n", salt);
		if (auth_tok->token.password.flags &
		    SEFS_PERSISTENT_PASSWORD) {
			sefs_printk(KERN_DEBUG, " * persistent\n");
		}
		memcpy(sig, auth_tok->token.password.signature,
		       SEFS_SIG_SIZE_HEX);
		sig[SEFS_SIG_SIZE_HEX] = '\0';
		sefs_printk(KERN_DEBUG, " * signature = [%s]\n", sig);
	}
	sefs_printk(KERN_DEBUG, " * session_key.flags = [0x%x]\n",
			auth_tok->session_key.flags);
	if (auth_tok->session_key.flags
	    & SEFS_USERSPACE_SHOULD_TRY_TO_DECRYPT)
		sefs_printk(KERN_DEBUG,
				" * Userspace decrypt request set\n");
	if (auth_tok->session_key.flags
	    & SEFS_USERSPACE_SHOULD_TRY_TO_ENCRYPT)
		sefs_printk(KERN_DEBUG,
				" * Userspace encrypt request set\n");
	if (auth_tok->session_key.flags & SEFS_CONTAINS_DECRYPTED_KEY) {
		sefs_printk(KERN_DEBUG, " * Contains decrypted key\n");
		sefs_printk(KERN_DEBUG,
				" * session_key.decrypted_key_size = [0x%x]\n",
				auth_tok->session_key.decrypted_key_size);
		sefs_printk(KERN_DEBUG, " * Decrypted session key "
				"dump:\n");
		if (sefs_verbosity > 0)
			sefs_dump_hex(auth_tok->session_key.decrypted_key,
					  SEFS_DEFAULT_KEY_BYTES);
	}
	if (auth_tok->session_key.flags & SEFS_CONTAINS_ENCRYPTED_KEY) {
		sefs_printk(KERN_DEBUG, " * Contains encrypted key\n");
		sefs_printk(KERN_DEBUG,
				" * session_key.encrypted_key_size = [0x%x]\n",
				auth_tok->session_key.encrypted_key_size);
		sefs_printk(KERN_DEBUG, " * Encrypted session key "
				"dump:\n");
		if (sefs_verbosity > 0)
			sefs_dump_hex(auth_tok->session_key.encrypted_key,
					  auth_tok->session_key.
					  encrypted_key_size);
	}
}

/**
 * sefs_dump_hex - debug hex printer
 * @data: string of bytes to be printed
 * @bytes: number of bytes to print
 *
 * Dump hexadecimal representation of char array
 */
void sefs_dump_hex(char *data, int bytes)
{
	int i = 0;
	int add_newline = 1;

	if (sefs_verbosity < 1)
		return;
	if (bytes != 0) {
		printk(KERN_DEBUG "0x%.2x.", (unsigned char)data[i]);
		i++;
	}
	while (i < bytes) {
		printk("0x%.2x.", (unsigned char)data[i]);
		i++;
		if (i % 16 == 0) {
			printk("\n");
			add_newline = 0;
		} else
			add_newline = 1;
	}
	if (add_newline)
		printk("\n");
}

