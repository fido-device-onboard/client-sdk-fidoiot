/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for AES encryption routines of openssl library.
 */

#include "fdoCryptoHal.h"
#include "util.h"
#include "crypto_utils.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "safe_lib.h"

#ifdef AES_256_BIT

#ifdef AES_MODE_CTR_ENABLED
#define CIPHER_TYPE EVP_aes_256_ctr()
#else
#define CIPHER_TYPE EVP_aes_256_cbc()
#endif /* AES_MODE_CTR_ENABLED */
#define KEY_LENGTH_LOCAL 32 //256 bit

#else

#ifdef AES_MODE_CTR_ENABLED
#define CIPHER_TYPE EVP_aes_128_ctr()
#else
#define CIPHER_TYPE EVP_aes_128_cbc()
#endif /* AES_MODE_CTR_ENABLED */
#define KEY_LENGTH_LOCAL 16 //128 bit

#endif /* AES_256_BIT */

/**
 * crypto_hal_aes_encrypt -  Perform AES encryption of the input text.
 *
 * @param clear_text
 *        Input text to be encrypted.
 * @param clear_text_length
 *        Plain text size in bytes.
 * @param cipher_text
 *        Encrypted text(output).
 * @param cipher_length
 *        Encrypted text size of cipher_text in bytes. [INOUT]
 * @param block_size
 *        AES encryption block size in bytes. always 128 bits.
 * @param iv
 *        AES encryption initialization vector.
 * @param key
 *        Key in Byte_array format used in encryption.
 * @param key_length
 *        Key size in Bytes.
 * @return ret
 *        return 0 on success. -1 on failure.
 *        fills cipher_length in bytes while cipher_text passed as NULL, & all
 *        other parameters are passed as it is.
 */
int32_t crypto_hal_aes_encrypt(const uint8_t *clear_text,
			       uint32_t clear_text_length, uint8_t *cipher_text,
			       uint32_t *cipher_length, size_t block_size,
			       const uint8_t *iv, const uint8_t *key,
			       uint32_t key_length)
{
	int ret = -1;
	int outlen = 0;
	int offset = 0;
	size_t exp_cipher_len = clear_text_length;
	EVP_CIPHER_CTX *ctx = NULL;

	/*
	 * Check all parameters except cipher_text, as if it's NULL,
	 * cipher_length needs to be filled in with the expected size
	 */
	if (!clear_text || !clear_text_length || !cipher_length ||
	    FDO_AES_BLOCK_SIZE != block_size || !iv || !key ||
	    KEY_LENGTH_LOCAL != key_length) {
		LOG(LOG_ERROR, "Invalid parameters received\n");
		goto end;
	}

/*
 * CTR: cipher_length = clear_text_length
 * CBC: cipher_length = clear_text_length + padding bytes
 * Padding:
 * a. For non AES block aligned cleartext, padding extends
 *    the size to be multiple of AES block.
 * b. For AES block aligned cleartext, padding extends the
 *    size by 1 AES block.
 */
#ifdef AES_MODE_CBC_ENABLED
	exp_cipher_len = ((clear_text_length / block_size) + 1) * block_size;
#endif /* AES_MODE_CTR_ENABLED */

	/* Fill in the expected cipher text length */
	if (!cipher_text) {
		*cipher_length = exp_cipher_len;
		ret = 0;
		goto end;
	}

	/* If we reach here, cipher_text is non-NULL, no need to check */
	if (*cipher_length < exp_cipher_len) {
		LOG(LOG_ERROR, "Invalid cleartext/ciphertext size received\n");
		goto end;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		goto end;
	}

	if (1 != EVP_EncryptInit_ex(ctx, CIPHER_TYPE, NULL, key, iv)) {
		goto end;
	}

	/* Common for cbc and ctr */
	if (1 != EVP_EncryptUpdate(ctx, cipher_text, &outlen, clear_text,
				   clear_text_length)) {
		goto end;
	}

	offset += outlen;

	if (!EVP_EncryptFinal_ex(ctx, cipher_text + offset, &outlen)) {
		goto end;
	}

	ret = 0;

end:
	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
	}
	return ret;
}

/**
 * crypto_hal_aes_decrypt -  Perform AES decryption of the cipher text.
 *
 * @param clear_text
 *        Decrypted text(output).
 * @param clear_text_length
 *        Decrypted text size in Byte. (IN/OUT)
 * @param cipher_text
 *        Encrypted text(input).
 * @param cipher_length
 *        Encrypted text size in Byte.
 * @param block_size
 *        AES encryption block size in Byte. FDO_AES_BLOCK_SIZE
 * @param iv
 *        AES encryption initialization vector.
 * @param key
 *        Key in Byte_array format used in encryption.
 * @param key_length
 *        Key size in Bytes.
 * @return ret
 *        return 0 on success. -1 on failure.
 *        fills clear_text_length in bytes for maximum possible buffer size
 *        required to fill in the clear_text, when clear_text is passed as NULL
 */
int32_t crypto_hal_aes_decrypt(uint8_t *clear_text, uint32_t *clear_text_length,
			       const uint8_t *cipher_text,
			       uint32_t cipher_length, size_t block_size,
			       const uint8_t *iv, const uint8_t *key,
			       uint32_t key_length)
{
	int ret = -1;
	int outlen = 0;
	int offset = 0;
	EVP_CIPHER_CTX *ctx = NULL;

	/* Check all the incoming parameters */
	if (!clear_text_length || !cipher_text || !cipher_length ||
	    FDO_AES_BLOCK_SIZE != block_size || !iv || !key ||
	    KEY_LENGTH_LOCAL != key_length) {
		LOG(LOG_ERROR, "Invalid paramters received\n");
		goto end;
	}

	/*
	 * If clear_text is NULL, then return the size of clear_text. Since,
	 * for CBC, we cannot tell the precise length of clear_text without
	 * decryption, so, clear_text_length is returned to be same as
	 * cipher_length. After decryption, clear_text_length will be updated
	 * with the precise length.
	 */
	if (!clear_text) {
		*clear_text_length = cipher_length;
		ret = 0;
		goto end;
	}

	/*
	 * The caller has to ensure that the clear_text is big enough to hold
	 * complete clear data. The padding scheme is already known to caller,
	 * so, expecting that the buffer sent in is at minimum equal to
	 * ciphertext size.
	 */
	if (*clear_text_length < cipher_length) {
		LOG(LOG_ERROR, "Invalid cleartext/ciphertext size received\n");
		goto end;
	}

	/* Allocate the cipher context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		goto end;
	}

#if defined(AES_DEBUG)
	LOG(LOG_DEBUG, "ciphered msg size: %d\n", cipher_length);
	hexdump("Cipher txt to decrypt", cipher_text, cipher_length);
#endif

	if (1 != EVP_DecryptInit_ex(ctx, CIPHER_TYPE, NULL, key, iv)) {
		goto end;
	}

	if (1 != EVP_DecryptUpdate(ctx, clear_text, &outlen, cipher_text,
				   cipher_length)) {
		goto end;
	}

	offset += outlen; /* Backup the number of output bytes */

	if (1 != EVP_DecryptFinal_ex(ctx, clear_text + offset, &outlen))
		goto end;

	*clear_text_length = offset + outlen;
	ret = 0; /* Mark the operation as success */

end:
	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
	}
	return ret;
}
