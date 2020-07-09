/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for AES_GCM (authenticated- encryption) routines of
 * mbedtls library.
 */

#include "sdoCryptoHal.h"
#include "util.h"
#include "platform_utils.h"
#include "crypto_utils.h"
#include "safe_lib.h"
/**
 * sdo_crypto_aes_gcm_encrypt -  Perform Authenticated AES encryption on the
 * input plain text.
 *
 * @param plain_text
 *        input plain-text to modify.
 * @param plain_text_length
 *        plain-text size in bytes.
 * @param cipher_text
 *        Encrypted text(output).
 * @param cipher_text_length
 *	  Max length of Cipher Text
 * @param iv
 *        AES encryption IV.
 * @param iv_length
 *        AES encryption IV size in bytes.
 * @param key
 *        Key in Byte_array format used in encryption.
 * @param key_length
 *        Key size in Bytes. Only AES128 is supported
 * @param tag
 *        tag added during encryption (output).
 * @param tag_length
 *        tag size in Bytes.
 * @return ret
 *        return cipher_length in bytes during success and -1 during any error.
 */
int32_t sdo_crypto_aes_gcm_encrypt(const uint8_t *plain_text,
				   uint32_t plain_text_length,
				   uint8_t *cipher_text,
				   uint32_t cipher_text_length,
				   const uint8_t *iv, uint32_t iv_length,
				   const uint8_t *key, uint32_t key_length,
				   uint8_t *tag, uint32_t tag_length)
{
	int32_t retval = -1;
	static mbedtls_gcm_context ctx;

	if (NULL == plain_text || 0 == plain_text_length ||
	    NULL == cipher_text || NULL == iv || 0 == iv_length ||
	    NULL == key || key_length != PLATFORM_AES_KEY_DEFAULT_LEN ||
	    NULL == tag || tag_length != AES_GCM_TAG_LEN) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		return retval;
	}

	if (cipher_text_length < plain_text_length) {
		LOG(LOG_ERROR, "Output buffer is not sufficient!\n");
		return retval;
	}

	/* Initialise the context */
	mbedtls_gcm_init(&ctx);

	/* Initialise the GCM key */
	retval = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
				    (const unsigned char *)key, key_length * 8);
	if (retval != 0) {
		LOG(LOG_ERROR, "Key initialization failed!\n");
		retval = -1;
		goto end;
	}

	/* Do gcm crypt on data */
	retval = mbedtls_gcm_crypt_and_tag(
	    &ctx, MBEDTLS_GCM_ENCRYPT, plain_text_length,
	    (const unsigned char *)iv, iv_length, NULL, 0,
	    (const unsigned char *)plain_text, cipher_text, tag_length, tag);
	if (retval != 0) {
		LOG(LOG_ERROR, "AES GCM encrypt failed!\n");
		retval = -1;
		goto end;
	} else {
		retval = plain_text_length;
	}

end:
	/* Clean up and free allocated memory */
	mbedtls_gcm_free(&ctx);
	return retval;
}

/**
 * sdo_crypto_aes_gcm_decrypt -  Perform Authenticated AES decryption on the
 * input cipher text.
 *
 * @param clear_text
 *        output clear-text.
 * @param clear_text_length
 *        max plain-text buffer size in bytes.
 * @param cipher_text
 *        Encrypted text(input).
 * @param cipher_text_length
 *        Encrypted cipher-text size in Byte.
 * @param iv
 *        AES encryption IV.
 * @param iv_length
 *        AES encryption IV size in bytes.
 * @param key
 *        Key in Byte_array format used in encryption.
 * @param key_length
 *        Key size in Bytes. Only AES128 is supported
 * @param tag
 *        input authenticated tag which got added during encryption.
 * @param tag_length
 *        tag size in Bytes.
 * @return ret
 *        return clear_text_length in bytes during success and -1 during any
 * error.
 */
int32_t sdo_crypto_aes_gcm_decrypt(uint8_t *clear_text,
				   uint32_t clear_text_length,
				   const uint8_t *cipher_text,
				   uint32_t cipher_text_length,
				   const uint8_t *iv, uint32_t iv_length,
				   const uint8_t *key, uint32_t key_length,
				   uint8_t *tag, uint32_t tag_length)
{
	int32_t retval = -1;
	static mbedtls_gcm_context ctx;

	if (NULL == clear_text || NULL == cipher_text ||
	    0 == cipher_text_length || NULL == iv || 0 == iv_length ||
	    NULL == key || key_length != PLATFORM_AES_KEY_DEFAULT_LEN ||
	    NULL == tag || tag_length != AES_GCM_TAG_LEN) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		return retval;
	}

	if (clear_text_length < cipher_text_length) {
		LOG(LOG_ERROR, "Output buffer is not sufficient!\n");
		return retval;
	}

	/* Initialise the context */
	mbedtls_gcm_init(&ctx);

	/* Initialise the GCM key */
	retval = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
				    (const unsigned char *)key, key_length * 8);
	if (retval != 0) {
		LOG(LOG_ERROR, "Key initialization failed!\n");
		retval = -1;
		goto end;
	}

	/* Do gcm crypt on data */
	retval = mbedtls_gcm_auth_decrypt(
	    &ctx, cipher_text_length, (const unsigned char *)iv, iv_length,
	    NULL, 0, (const unsigned char *)tag, tag_length,
	    (const unsigned char *)cipher_text, clear_text);
	if (retval != 0) {
		LOG(LOG_ERROR, "AES GCM encrypt failed!\n");
		retval = -1;
		goto end;
	} else {
		retval = cipher_text_length;
	}

end:
	/* Clean up and free allocated memory */
	mbedtls_gcm_free(&ctx);
	return retval;
}
