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
 * sdoCryptoAESGcmEncrypt -  Perform Authenticated AES encryption on the input
 * plain text.
 *
 * @param plainText
 *        input plain-text to modify.
 * @param plainTextLength
 *        plain-text size in bytes.
 * @param cipherText
 *        Encrypted text(output).
 * @param cipherTextLength
 * 	  Max length of Cipher Text
 * @param iv
 *        AES encryption IV.
 * @param ivLength
 *        AES encryption IV size in bytes.
 * @param key
 *        Key in ByteArray format used in encryption.
 * @param keyLength
 *        Key size in Bytes. Only AES128 is supported
 * @param tag
 *        tag added during encryption (output).
 * @param tagLength
 *        tag size in Bytes.
 * @return ret
 *        return cipherLength in bytes during success and -1 during any error.
 */
int32_t sdoCryptoAESGcmEncrypt(const uint8_t *plainText,
			       uint32_t plainTextLength, uint8_t *cipherText,
			       uint32_t cipherTextLength, const uint8_t *iv,
			       uint32_t ivLength, const uint8_t *key,
			       uint32_t keyLength, uint8_t *tag,
			       uint32_t tagLength)
{
	int32_t retval = -1;
	mbedtls_gcm_context ctx = {0};

	if (NULL == plainText || 0 == plainTextLength || NULL == cipherText ||
	    NULL == iv || 0 == ivLength || NULL == key ||
	    keyLength != PLATFORM_AES_KEY_DEFAULT_LEN || NULL == tag ||
	    tagLength != AES_GCM_TAG_LEN) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		goto end;
	}

	if (cipherTextLength < plainTextLength) {
		LOG(LOG_ERROR, "Output buffer is not sufficient!\n");
		goto end;
	}

	/* Initialise the context */
	mbedtls_gcm_init(&ctx);

	/* Initialise the GCM key */
	retval = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
				    (const unsigned char *)key, keyLength * 8);
	if (retval != 0) {
		LOG(LOG_ERROR, "Key initialization failed!\n");
		retval = -1;
		goto end;
	}

	/* Do gcm crypt on data */
	retval = mbedtls_gcm_crypt_and_tag(
	    &ctx, MBEDTLS_GCM_ENCRYPT, plainTextLength,
	    (const unsigned char *)iv, ivLength, NULL, 0,
	    (const unsigned char *)plainText, cipherText, tagLength, tag);
	if (retval != 0) {
		LOG(LOG_ERROR, "AES GCM encrypt failed!\n");
		retval = -1;
		goto end;
	} else {
		retval = plainTextLength;
	}

end:
	/* Clean up and free allocated memory */
	mbedtls_gcm_free(&ctx);
	return retval;
}

/**
 * sdoCryptoAESGcmDecrypt -  Perform Authenticated AES decryption on the input
 * cipher text.
 *
 * @param clearText
 *        output clear-text.
 * @param clearTextLength
 *        max plain-text buffer size in bytes.
 * @param cipherText
 *        Encrypted text(input).
 * @param cipherTextLength
 *        Encrypted cipher-text size in Byte.
 * @param iv
 *        AES encryption IV.
 * @param ivLength
 *        AES encryption IV size in bytes.
 * @param key
 *        Key in ByteArray format used in encryption.
 * @param keyLength
 *        Key size in Bytes. Only AES128 is supported
 * @param tag
 *        input authenticated tag which got added during encryption.
 * @param tagLength
 *        tag size in Bytes.
 * @return ret
 *        return clearTextLength in bytes during success and -1 during any
 * error.
 */
int32_t sdoCryptoAESGcmDecrypt(uint8_t *clearText, uint32_t clearTextLength,
			       const uint8_t *cipherText,
			       uint32_t cipherTextLength, const uint8_t *iv,
			       uint32_t ivLength, const uint8_t *key,
			       uint32_t keyLength, uint8_t *tag,
			       uint32_t tagLength)
{
	int32_t retval = -1;
	mbedtls_gcm_context ctx = {0};

	if (NULL == clearText || NULL == cipherText || 0 == cipherTextLength ||
	    NULL == iv || 0 == ivLength || NULL == key ||
	    keyLength != PLATFORM_AES_KEY_DEFAULT_LEN || NULL == tag ||
	    tagLength != AES_GCM_TAG_LEN) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		goto end;
	}

	if (clearTextLength < cipherTextLength) {
		LOG(LOG_ERROR, "Output buffer is not sufficient!\n");
		goto end;
	}

	/* Initialise the context */
	mbedtls_gcm_init(&ctx);

	/* Initialise the GCM key */
	retval = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
				    (const unsigned char *)key, keyLength * 8);
	if (retval != 0) {
		LOG(LOG_ERROR, "Key initialization failed!\n");
		retval = -1;
		goto end;
	}

	/* Do gcm crypt on data */
	retval = mbedtls_gcm_auth_decrypt(
	    &ctx, cipherTextLength, (const unsigned char *)iv, ivLength, NULL,
	    0, (const unsigned char *)tag, tagLength,
	    (const unsigned char *)cipherText, clearText);
	if (retval != 0) {
		LOG(LOG_ERROR, "AES GCM encrypt failed!\n");
		retval = -1;
		goto end;
	} else {
		retval = cipherTextLength;
	}

end:
	/* Clean up and free allocated memory */
	mbedtls_gcm_free(&ctx);
	return retval;
}
