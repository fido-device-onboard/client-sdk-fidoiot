/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for AES_GCM (authenticated- encryption) routines of
 * openssl library.
 */

#include "fdoCryptoHal.h"
#include "util.h"
#include "crypto_utils.h"
#include "safe_lib.h"
#include <atca_basic.h>
#include <atca_basic_aes_gcm.h>
#include "se_config.h"

/**
 * fdo_crypto_aes_gcm_encrypt -  Perform Authenticated AES encryption on the
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
 *        Key size in Bytes.
 * @param tag
 *        tag added during encryption (output).
 * @param tag_length
 *        tag size in Bytes.
 * @return ret
 *        return cipher_length in bytes during success and -1 during any error.
 */
int32_t fdo_crypto_aes_gcm_encrypt(const uint8_t *plain_text,
				   uint32_t plain_text_length,
				   uint8_t *cipher_text,
				   uint32_t cipher_text_length,
				   const uint8_t *iv, uint32_t iv_length,
				   const uint8_t *key, uint32_t key_length,
				   uint8_t *tag, uint32_t tag_length)
{
	atca_aes_gcm_ctx_t ctx;

	if (NULL == plain_text || 0 == plain_text_length ||
	    NULL == cipher_text || NULL == iv || 0 == iv_length ||
	    NULL == key || 0 == key_length || NULL == tag ||
	    tag_length != AES_GCM_TAG_LEN) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		return -1;
	}

	if (cipher_text_length < plain_text_length) {
		LOG(LOG_ERROR, "Output buffer is not sufficient!\n");
		return -1;
	}

	if (ATCA_SUCCESS != atcab_aes_gcm_init(&ctx, AES_KEY_ID, AES_KEY_BLOCK,
					       iv, iv_length)) {
		LOG(LOG_ERROR, " AES GCM Init on SE failed with errno %d\n",
		    errno);
		return -1;
	}

	if (ATCA_SUCCESS != atcab_aes_gcm_encrypt_update(&ctx, plain_text,
							 plain_text_length,
							 cipher_text)) {
		LOG(LOG_ERROR,
		    " AES GCM encrypt update on SE failed with errno %d\n",
		    errno);
		return -1;
	}

	if (ATCA_SUCCESS !=
	    atcab_aes_gcm_encrypt_finish(&ctx, tag, AES_GCM_TAG_LEN)) {
		LOG(LOG_ERROR,
		    " AES GCM Init encrypt finish on SE failed with errno %d\n",
		    errno);
		return -1;
	}

	return 0;
}

/**
 * fdo_crypto_aes_gcm_decrypt -  Perform Authenticated AES decryption on the
 * input cipher text.
 *
 * @param clear_text
 *        output clear-text.
 * @param clear_text_length
 *        plain-text buffer size in bytes.
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
 *        Key size in Bytes.
 * @param tag
 *        input authenticated tag which got added during encryption.
 * @param tag_length
 *        tag size in Bytes.
 * @return ret
 *        return clear_text_length in bytes during success and -1 during any
 * error.
 */
int32_t fdo_crypto_aes_gcm_decrypt(uint8_t *clear_text,
				   uint32_t clear_text_length,
				   const uint8_t *cipher_text,
				   uint32_t cipher_text_length,
				   const uint8_t *iv, uint32_t iv_length,
				   const uint8_t *key, uint32_t key_length,
				   uint8_t *tag, uint32_t tag_length)
{
	atca_aes_gcm_ctx_t ctx;
	bool verified;

	if (NULL == clear_text || NULL == cipher_text ||
	    0 == cipher_text_length || NULL == iv || 0 == iv_length ||
	    NULL == key || 0 == key_length || NULL == tag ||
	    tag_length != AES_GCM_TAG_LEN) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		return -1;
	}

	if (clear_text_length < cipher_text_length) {
		LOG(LOG_ERROR, "Output buffer is not sufficient!\n");
		return -1;
	}

	if (ATCA_SUCCESS != atcab_aes_gcm_init(&ctx, AES_KEY_ID, AES_KEY_BLOCK,
					       iv, iv_length)) {
		LOG(LOG_ERROR, " AES GCM Init on SE failed with errno %d\n",
		    errno);
		return -1;
	}

	if (ATCA_SUCCESS != atcab_aes_gcm_decrypt_update(&ctx, cipher_text,
							 cipher_text_length,
							 clear_text)) {
		LOG(LOG_ERROR,
		    " AES GCM decrypt update on SE failed with errno %d\n",
		    errno);
		return -1;
	}

	if (ATCA_SUCCESS != atcab_aes_gcm_decrypt_finish(
				&ctx, tag, AES_GCM_TAG_LEN, &verified)) {
		LOG(LOG_ERROR,
		    " AES GCM decrypt finish on SE failed with errno %d\n",
		    errno);
		return -1;
	}

	if (true != verified) {
		LOG(LOG_ERROR, "GCM decrypt authentication failure\n");
		return -1;
	}

	return 0;
}
