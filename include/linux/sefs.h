#ifndef _LINUX_SEFS_H
#define _LINUX_SEFS_H

/* Version verification for shared data structures w/ userspace */
#define SEFS_VERSION_MAJOR 0x00
#define SEFS_VERSION_MINOR 0x04
#define SEFS_SUPPORTED_FILE_VERSION 0x03
/* These flags indicate which features are supported by the kernel
 * module; userspace tools such as the mount helper read the feature
 * bits from a sysfs handle in order to determine how to behave. */
#define SEFS_VERSIONING_PASSPHRASE            0x00000001
#define SEFS_VERSIONING_PUBKEY                0x00000002
#define SEFS_VERSIONING_PLAINTEXT_PASSTHROUGH 0x00000004
#define SEFS_VERSIONING_POLICY                0x00000008
#define SEFS_VERSIONING_XATTR                 0x00000010
#define SEFS_VERSIONING_MULTKEY               0x00000020
#define SEFS_VERSIONING_DEVMISC               0x00000040
#define SEFS_VERSIONING_HMAC                  0x00000080
#define SEFS_VERSIONING_FILENAME_ENCRYPTION   0x00000100
#define SEFS_VERSIONING_GCM                   0x00000200
#define SEFS_MAX_PASSWORD_LENGTH 64
#define SEFS_MAX_PASSPHRASE_BYTES SEFS_MAX_PASSWORD_LENGTH
#define SEFS_SALT_SIZE 8
#define SEFS_SALT_SIZE_HEX (SEFS_SALT_SIZE*2)
/* The original signature size is only for what is stored on disk; all
 * in-memory representations are expanded hex, so it better adapted to
 * be passed around or referenced on the command line */
#define SEFS_SIG_SIZE 8
#define SEFS_SIG_SIZE_HEX (SEFS_SIG_SIZE*2)
#define SEFS_PASSWORD_SIG_SIZE SEFS_SIG_SIZE_HEX
#define SEFS_MAX_KEY_BYTES 64
#define SEFS_MAX_ENCRYPTED_KEY_BYTES 512
#define SEFS_FILE_VERSION 0x03
#define SEFS_MAX_PKI_NAME_BYTES 16

#define RFC2440_CIPHER_DES3_EDE 0x02
#define RFC2440_CIPHER_CAST_5 0x03
#define RFC2440_CIPHER_BLOWFISH 0x04
#define RFC2440_CIPHER_AES_128 0x07
#define RFC2440_CIPHER_AES_192 0x08
#define RFC2440_CIPHER_AES_256 0x09
#define RFC2440_CIPHER_TWOFISH 0x0a
#define RFC2440_CIPHER_CAST_6 0x0b

#define RFC2440_CIPHER_RSA 0x01

/**
 * For convenience, we may need to pass around the encrypted session
 * key between kernel and userspace because the authentication token
 * may not be extractable.  For example, the TPM may not release the
 * private key, instead requiring the encrypted data and returning the
 * decrypted data.
 */
struct sefs_session_key {
#define SEFS_USERSPACE_SHOULD_TRY_TO_DECRYPT 0x00000001
#define SEFS_USERSPACE_SHOULD_TRY_TO_ENCRYPT 0x00000002
#define SEFS_CONTAINS_DECRYPTED_KEY 0x00000004
#define SEFS_CONTAINS_ENCRYPTED_KEY 0x00000008
	u32 flags;
	u32 encrypted_key_size;
	u32 decrypted_key_size;
	u8 encrypted_key[SEFS_MAX_ENCRYPTED_KEY_BYTES];
	u8 decrypted_key[SEFS_MAX_KEY_BYTES];
};

struct sefs_password {
	u32 password_bytes;
	s32 hash_algo;
	u32 hash_iterations;
	u32 session_key_encryption_key_bytes;
#define SEFS_PERSISTENT_PASSWORD 0x01
#define SEFS_SESSION_KEY_ENCRYPTION_KEY_SET 0x02
	u32 flags;
	/* Iterated-hash concatenation of salt and passphrase */
	u8 session_key_encryption_key[SEFS_MAX_KEY_BYTES];
	u8 signature[SEFS_PASSWORD_SIG_SIZE + 1];
	/* Always in expanded hex */
	u8 salt[SEFS_SALT_SIZE];
};

enum sefs_token_types {SEFS_PASSWORD, SEFS_PRIVATE_KEY};

struct sefs_private_key {
	u32 key_size;
	u32 data_len;
	u8 signature[SEFS_PASSWORD_SIG_SIZE + 1];
	char pki_type[SEFS_MAX_PKI_NAME_BYTES + 1];
	u8 data[];
};

/* May be a password or a private key */
struct sefs_auth_tok {
	u16 version; /* 8-bit major and 8-bit minor */
	u16 token_type;
#define SEFS_ENCRYPT_ONLY 0x00000001
	u32 flags;
	struct sefs_session_key session_key;
	u8 reserved[32];
	union {
		struct sefs_password password;
		struct sefs_private_key private_key;
	} token;
} __attribute__ ((packed));

#endif /* _LINUX_SEFS_H */
