/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for AES_GCM (authenticated- encryption) routines of
 * openssl library.
 */

#include "sdoCryptoHal.h"
#include "util.h"
#include "crypto_utils.h"
#include "platform_utils.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
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
	int retval = -1;
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;

	if (NULL == plain_text || 0 == plain_text_length ||
	    NULL == cipher_text || NULL == iv || 0 == iv_length ||
	    NULL == key || key_length != PLATFORM_AES_KEY_DEFAULT_LEN ||
	    NULL == tag || tag_length != AES_GCM_TAG_LEN) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		goto end;
	}

	if (cipher_text_length < plain_text_length) {
		LOG(LOG_ERROR, "Output buffer is not sufficient!\n");
		goto end;
	}

	/* Initialise the context */
	ctx = EVP_CIPHER_CTX_new();
	if (NULL == ctx) {
		LOG(LOG_ERROR, "Error during Initializing EVP cipher ctx!\n");
		goto end;
	}

	/* Initialise the AES GCM encryption operation. */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
		LOG(LOG_ERROR, "Error during Initializing EVP AES GCM encrypt "
			       "operation!\n");
		goto end;
	}

	/* Set IV length if default 12 bytes (96 bits) is not appropriate
	 * NIST strongly recommends AES IV of length 12 bytes (96 bits) to use
	 * while AES GCM operations
	 * TODO: change this in coming iteration
	 */
	if (1 !=
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_length, NULL)) {
		LOG(LOG_ERROR, "Error during setting AES GCM IV length!\n");
		goto end;
	}

	/* Initialise key and IV */
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
		LOG(LOG_ERROR, "Key and IV initialization failed!\n");
		goto end;
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, cipher_text, &len, plain_text,
				   plain_text_length)) {
		LOG(LOG_ERROR, "AES GCM: EVP_EncryptUpdate() failed!\n");
		goto end;
	}

	cipher_text_length = len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if (1 != EVP_EncryptFinal_ex(ctx, cipher_text + len, &len)) {
		LOG(LOG_ERROR, "AES GCM: EVP_EncryptFinal_ex() failed!\n");
		goto end;
	}

	cipher_text_length += len;

	/* Get the tag */
	if (1 !=
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_length, tag)) {
		LOG(LOG_ERROR, "AES GCM: could not get required tag value "
			       "during encryption!\n");
		goto end;
	}

	retval = cipher_text_length;
end:
	/* Clean up and free allocated memory */
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return retval;
}

/**
 * sdo_crypto_aes_gcm_decrypt -  Perform Authenticated AES decryption on the
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
	int retval = -1;
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;

	if (NULL == clear_text || NULL == cipher_text ||
	    0 == cipher_text_length || NULL == iv || 0 == iv_length ||
	    NULL == key || key_length != PLATFORM_AES_KEY_DEFAULT_LEN ||
	    NULL == tag || tag_length != AES_GCM_TAG_LEN) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		goto end;
	}

	if (clear_text_length < cipher_text_length) {
		LOG(LOG_ERROR, "Output buffer is not sufficient!\n");
		goto end;
	}

	/* Create and initialise the context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		LOG(LOG_ERROR, "Error during Initializing EVP cipher ctx!\n");
		goto end;
	}

	/* Initialise the AES GCM decryption operation. */
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
		LOG(LOG_ERROR, "Error during Initializing EVP AES GCM decrypt "
			       "operation!\n");
		goto end;
	}

	/* TODO: change IV from 16 to 12 bytes in coming iteration */
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_length,
				 NULL)) {
		LOG(LOG_ERROR, "Error during setting AES GCM IV length!\n");
		goto end;
	}

	/* Initialise key and IV */
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
		LOG(LOG_ERROR, "Key and IV initialization failed!\n");
		goto end;
	}

	/* Provide the message to be decrypted, and obtain the clear_text
	 * output. EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (!EVP_DecryptUpdate(ctx, clear_text, &len, cipher_text,
			       cipher_text_length)) {
		LOG(LOG_ERROR, "AES GCM: EVP_DecryptUpdate() failed!\n");
		goto end;
	}

	clear_text_length = len;

	/* Set expected tag value */
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_length, tag)) {
		LOG(LOG_ERROR, "AES GCM: could not set exptected tag value "
			       "during decryption!\n");
		goto end;
	}

	/* Finalise the decryption. A positive return value indicates success
	 * anything else is a failure i.e. the plaintext is not trustworthy.
	 */
	retval = EVP_DecryptFinal_ex(ctx, clear_text + len, &len);

	if (retval > 0) {
		/* Success: authentication passed */
		clear_text_length += len;
		retval = clear_text_length;
	} else {
		/* Failure: authentication failed */
		retval = -1;
	}

end:
	/* Clean up and free allocated memory */
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return retval;
}
