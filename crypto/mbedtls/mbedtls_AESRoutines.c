/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for AES encryption routines of mbedTLS library.
 */

#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/platform.h"
#include "mbedtls/cipher.h"
#include "mbedtls/cipher_internal.h"

#include "util.h"
#include "sdoCryptoHal.h"
#include "util.h"
#include "BN_support.h"
#include "safe_lib.h"

#define STREAM_BLOCK_SIZE SDO_AES_BLOCK_SIZE

#ifdef AES_256_BIT

#ifdef AES_MODE_CTR_ENABLED
#define CIPHER_TYPE MBEDTLS_CIPHER_AES_256_CTR
#else
#define CIPHER_TYPE MBEDTLS_CIPHER_AES_256_CBC
#endif /* AES_MODE_CTR_ENABLED */
#define KEY_LENGTH_LOCAL 32 //256 bit 

#else

#ifdef AES_MODE_CTR_ENABLED
#define CIPHER_TYPE MBEDTLS_CIPHER_AES_128_CTR
#else
#define CIPHER_TYPE MBEDTLS_CIPHER_AES_128_CBC
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
 *        Encrypted text size in bytes. [INOUT]
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
	size_t exp_cipher_len = 0;
	static mbedtls_cipher_context_t cipher_ctx;
	const mbedtls_cipher_info_t *cipher_info;
	size_t olen = 0;

	/*
	 * Check all parameters except cipher_text, as if it's NULL,
	 * cipher_length needs to be filled in with the expected size
	 */
	if (!clear_text || !clear_text_length || !cipher_length ||
	    SDO_AES_BLOCK_SIZE != block_size || !iv || !key ||
	    KEY_LENGTH_LOCAL != key_length) {
		LOG(LOG_ERROR, "Invalid parameters received\n");
		return -1;
	}

	mbedtls_cipher_init(&cipher_ctx);

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
#else
	exp_cipher_len = clear_text_length;
#endif /* AES_MODE_CBC_ENABLED */

	/* Fill in the expected cipher text length */
	if (!cipher_text) {
		*cipher_length = exp_cipher_len;
		ret = 0;
		goto end;
	}

	cipher_info = mbedtls_cipher_info_from_type(CIPHER_TYPE);
	if (cipher_info == NULL) {
		LOG(LOG_ERROR, "failed to get cipher info\n");
		goto end;
	}

	ret = mbedtls_cipher_setup(&cipher_ctx, cipher_info);
	if (ret != 0) {
		LOG(LOG_ERROR, "failed to setup the cipher\n");
		goto end;
	}

	ret = mbedtls_cipher_setkey(&cipher_ctx, key, 8 * key_length,
				     MBEDTLS_ENCRYPT);
	if (ret != 0) {
		LOG(LOG_ERROR, "failed to set the key\n");
		goto end;
	}

	ret = mbedtls_cipher_set_iv(&cipher_ctx, iv, SDO_AES_IV_SIZE);
	if (ret != 0) {
		LOG(LOG_ERROR, "failed to set IV\n");
		goto end;
	}

	ret = mbedtls_cipher_reset(&cipher_ctx);
	if (ret != 0) {
		LOG(LOG_ERROR, "failed to reset the cipher\n");
		goto end;
	}

	/* encrypt */
	ret = mbedtls_cipher_update(&cipher_ctx, clear_text,
				    clear_text_length, cipher_text,
				    &olen);
	if (ret != 0) {
		LOG(LOG_ERROR, "cipher_update failed\n");
		goto end;
	}

	ret = mbedtls_cipher_finish(&cipher_ctx, cipher_text + olen,
				    &olen);
	if (ret != 0) {
		LOG(LOG_ERROR, "cipher failed\n");
		goto end;
	}

	if (ret != EXIT_SUCCESS) {
		ret = -1;
		goto end;
	}

	ret = 0;

end:
	mbedtls_cipher_free(&cipher_ctx);
	return ret;
}

/**
 * crypto_hal_aes_decrypt -  Perform AES ecryption of the cipher text.
 *
 * @param clear_text
 *        Decrypted text(output).
 * @param clear_text_length
 *        Decrypted text size in Byte.
 * @param cipher_text
 *        Encrypted text(input).
 * @param cipher_length
 *        Encrypted text size in Byte.
 * @param block_size
 *        AES encryption block size in Byte. SDO_AES_BLOCK_SIZE
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
	size_t olen = 0, ofs = 0;
	static mbedtls_cipher_context_t cipher_ctx;
	const mbedtls_cipher_info_t *cipher_info = NULL;

	/* Check all the incoming parameters */
	if (!clear_text_length || !cipher_text || !cipher_length ||
	    SDO_AES_BLOCK_SIZE != block_size || !iv || !key ||
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

#if defined(AES_DEBUG)
	hexdump("Cipher txt to decrypt", cipher_text, cipher_length);
#endif

	/* Initialize the cipher context */
	mbedtls_cipher_init(&cipher_ctx);

	/* Setup the cipher context with cbc */
	cipher_info = mbedtls_cipher_info_from_type(CIPHER_TYPE);

	if (!cipher_info) {
		LOG(LOG_ERROR, "Failed to find cipher type\n");
		goto err;
	}

	if (mbedtls_cipher_setup(&cipher_ctx, cipher_info)) {
		LOG(LOG_ERROR, "Failed to configure cipher with type\n");
		goto err;
	}

	/* Set the key and iv on the context */
	if (mbedtls_cipher_setkey(&cipher_ctx, key, 8 * key_length,
				  MBEDTLS_DECRYPT)) {
		LOG(LOG_ERROR, "Failed to set the key for decryption\n");
		goto err;
	}

	if (mbedtls_cipher_set_iv(&cipher_ctx, iv, AES_IV)) {
		LOG(LOG_ERROR, "Failed to set IV for decryption\n");
		goto err;
	}

	/* Roll for decryption */
	if (mbedtls_cipher_update(&cipher_ctx, cipher_text, cipher_length,
				  clear_text, &ofs)) {
		LOG(LOG_ERROR, "Failed to decrypt cipher\n");
		goto err;
	}

	if (mbedtls_cipher_finish(&cipher_ctx, clear_text + ofs, &olen)) {
		LOG(LOG_ERROR, "Finishing cipher failed\n");
		goto err;
	}

	*clear_text_length = ofs + olen;
	ret = 0; /* Mark as success */

err:
	mbedtls_cipher_free(&cipher_ctx);
end:
	return ret;
}
