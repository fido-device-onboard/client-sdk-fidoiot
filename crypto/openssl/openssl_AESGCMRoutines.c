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
	int retval = -1;
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;

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
	if (NULL == (ctx = EVP_CIPHER_CTX_new())) {
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
	 * TODO: change this in coming iteration */
	if (1 !=
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL)) {
		LOG(LOG_ERROR, "Error during setting AES GCM IV length!\n");
		goto end;
	}

	/* Initialise key and IV */
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
		LOG(LOG_ERROR, "Key and IV initialization failed!\n");
		goto end;
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary */
	if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText,
				   plainTextLength)) {
		LOG(LOG_ERROR, "AES GCM: EVP_EncryptUpdate() failed!\n");
		goto end;
	}

	cipherTextLength = len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode */
	if (1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len)) {
		LOG(LOG_ERROR, "AES GCM: EVP_EncryptFinal_ex() failed!\n");
		goto end;
	}

	cipherTextLength += len;

	/* Get the tag */
	if (1 !=
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tagLength, tag)) {
		LOG(LOG_ERROR, "AES GCM: could not get required tag value "
			       "during encryption!\n");
		goto end;
	}

	retval = cipherTextLength;
end:
	/* Clean up and free allocated memory */
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return retval;
}

/**
 * sdoCryptoAESGcmDecrypt -  Perform Authenticated AES decryption on the input
 * cipher text.
 *
 * @param clearText
 *        output clear-text.
 * @param clearTextLength
 *        plain-text buffer size in bytes.
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
	int retval = -1;
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;

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

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
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
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL)) {
		LOG(LOG_ERROR, "Error during setting AES GCM IV length!\n");
		goto end;
	}

	/* Initialise key and IV */
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
		LOG(LOG_ERROR, "Key and IV initialization failed!\n");
		goto end;
	}

	/* Provide the message to be decrypted, and obtain the clearText output.
	 * EVP_DecryptUpdate can be called multiple times if necessary */
	if (!EVP_DecryptUpdate(ctx, clearText, &len, cipherText,
			       cipherTextLength)) {
		LOG(LOG_ERROR, "AES GCM: EVP_DecryptUpdate() failed!\n");
		goto end;
	}

	clearTextLength = len;

	/* Set expected tag value */
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLength, tag)) {
		LOG(LOG_ERROR, "AES GCM: could not set exptected tag value "
			       "during decryption!\n");
		goto end;
	}

	/* Finalise the decryption. A positive return value indicates success
	 * anything else is a failure i.e. the plaintext is not trustworthy. */
	retval = EVP_DecryptFinal_ex(ctx, clearText + len, &len);

	if (retval > 0) {
		/* Success: authentication passed */
		clearTextLength += len;
		retval = clearTextLength;
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
