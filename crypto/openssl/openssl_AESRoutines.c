/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for AES encryption routines of openssl library.
 * Supported modes are:
 * - AES-GCM-128 (Key = 128 bits)
 * - AES-GCM-256 (Key = 256 bits)
 * - AES-CCM-64-128-128 (L=64 (8 octets,2^64 bytes message length), Tag = 128
 * bits, Key = 128 bits)
 * - AES-CCM-64-128-256 (L=64 (8 octets,2^64 bytes message length), Tag = 128
 * bits, Key = 256 bits)
 *
 * \NOTE: The IV/Nonce length 'N' for CCM mode is dependent on the maximum
 * message length 'L' value and should be equal to 15-L (in octets). Refer to
 * [RFC3610](https://datatracker.ietf.org/doc/html/rfc3610) for more information
 * on trade-offs between 'L' and 'N' value. The current implementation uses L=8,
 * and hence the IV/Nonce length N = 15-8 = 7 octets As per FDO and COSE
 * [RFC8152](https://datatracker.ietf.org/doc/html/rfc8152) specifications, L=2
 * could also be used. N=13 MUST be used in this case.
 */

#include "fdoCryptoHal.h"
#include "util.h"
#include "crypto_utils.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "safe_lib.h"

// Specify Openssl constants depending on the AES MODES (GCM/CCM)
#ifdef AES_MODE_GCM_ENABLED
// GCM mode enabled

#ifdef AES_256_BIT
// 256 bit keys
#define CIPHER_TYPE EVP_aes_256_gcm()
#define KEY_LENGTH_LOCAL 32
#else
// 128 bit keys
#define CIPHER_TYPE EVP_aes_128_gcm()
#define KEY_LENGTH_LOCAL 16
#endif

#define TAG_LENGTH AES_GCM_TAG_LEN
#define IV_LENGTH AES_GCM_IV_LEN

#define SET_IV EVP_CTRL_GCM_SET_IVLEN
#define GET_TAG EVP_CTRL_GCM_GET_TAG
#define SET_TAG EVP_CTRL_GCM_SET_TAG

#else
// CCM mode enabled

#ifdef AES_256_BIT
#define CIPHER_TYPE EVP_aes_256_ccm()
#define KEY_LENGTH_LOCAL 32 // 256 bits
#else
#define CIPHER_TYPE EVP_aes_128_ccm()
#define KEY_LENGTH_LOCAL 16 // 128 bit
#endif

#define TAG_LENGTH AES_CCM_TAG_LEN
#define IV_LENGTH AES_CCM_IV_LEN
// 'L' value of 8 octets. A change to this value MUST be matched with a
// corresponding change of IV_LENGTH, 'N' to '15-L'. For example, for
// L_VALUE_BYTES(L)=2, IV_LENGTH(N)=13
#define L_VALUE_BYTES 8

#define SET_IV EVP_CTRL_CCM_SET_IVLEN
#define GET_TAG EVP_CTRL_CCM_GET_TAG
#define SET_TAG EVP_CTRL_CCM_SET_TAG

#endif

/**
 * crypto_hal_aes_encrypt -  Perform AES encryption of the input text.
 *
 * @param clear_text
 *        Input text to be encrypted.
 * @param clear_text_length
 *        Plain text size in BYTES.
 * @param cipher_text
 *        Encrypted text(output).
 * @param cipher_length
 *        Encrypted text size of cipher_text in BYTES. [INOUT]
 * @param block_size
 *        AES encryption block size in BYTES. always 128 bits.
 * @param iv
 *        AES encryption initialization vector.
 * @param key
 *        Key in Byte_array format used in encryption.
 * @param key_length
 *        Key size in BYTES.
 * @param tag
 *        Tag in Byte_array format (output).
 * @param tag_length
 *        Fixed tag length in BYTES (output).
 * @param aad
 *        Additional Authenticated Data(AAD) in Byte_array format used in
 * encryption.
 * @param aad_length
 *        Additional Authenticated Data(AAD) size in BYTES.
 * @return ret
 *        return 0 on success. -1 on failure.
 *        fills cipher_length in bytes while cipher_text passed as NULL, & all
 *        other parameters are passed as it is.
 */
int32_t crypto_hal_aes_encrypt(const uint8_t *clear_text,
			       uint32_t clear_text_length, uint8_t *cipher_text,
			       uint32_t *cipher_length, size_t block_size,
			       const uint8_t *iv, const uint8_t *key,
			       uint32_t key_length, uint8_t *tag,
			       size_t tag_length, const uint8_t *aad,
			       size_t aad_length)
{
	int ret = -1;
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;

	/*
	 * Check all parameters except cipher_text, as if it's NULL,
	 * cipher_length needs to be filled in with the expected size
	 */
	if (!clear_text || !clear_text_length || !cipher_length ||
	    FDO_AES_BLOCK_SIZE != block_size || !iv || !key ||
	    KEY_LENGTH_LOCAL != key_length || !tag ||
	    tag_length != TAG_LENGTH) {
		LOG(LOG_ERROR, "Invalid parameters received\n");
		goto end;
	}

	if (*cipher_length < clear_text_length) {
		LOG(LOG_ERROR, "Output buffer is not sufficient!\n");
		goto end;
	}

	// Initialise the context
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		LOG(LOG_ERROR, "Error during Initializing EVP cipher ctx!\n");
		goto end;
	}

	// Initialise the AES GCM encryption operation
	if (!EVP_EncryptInit_ex(ctx, CIPHER_TYPE, NULL, NULL, NULL)) {
		LOG(LOG_ERROR,
		    "Error during Initializing AES encrypt operation!\n");
		goto end;
	}

	// Set IV length
	if (!EVP_CIPHER_CTX_ctrl(ctx, SET_IV, IV_LENGTH, NULL)) {
		LOG(LOG_ERROR, "Error during setting AES IV length!\n");
		goto end;
	}

	// Set tag length and L value (only for CCM mode)
#ifdef AES_MODE_CCM_ENABLED
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_length, NULL)) {
		LOG(LOG_ERROR, "Error during setting AES tag length!\n");
		goto end;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, L_VALUE_BYTES,
				 NULL)) {
		LOG(LOG_ERROR, "Error during setting AES tag length!\n");
		goto end;
	}
#endif

	// Initialise key and IV
	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
		LOG(LOG_ERROR, "Key and IV initialization failed!\n");
		goto end;
	}

	// Specify AAD, only if available
	if (aad && aad_length > 0) {
#ifdef AES_MODE_CCM_ENABLED
		// Specify Plain data length (only required in case of CCM)
		if (!EVP_EncryptUpdate(ctx, NULL, &len, NULL,
				       clear_text_length)) {
			LOG(LOG_ERROR,
			    "Plain data length initialization failed!\n");
			goto end;
		}
#endif
		if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_length)) {
			LOG(LOG_ERROR, "AAD initialization failed!\n");
			goto end;
		}
	}

	// Provide the message to be encrypted, and obtain the encrypted output.
	// EVP_EncryptUpdate can be called multiple times if necessary
	if (!EVP_EncryptUpdate(ctx, cipher_text, &len, clear_text,
			       clear_text_length)) {
		LOG(LOG_ERROR, "EVP_EncryptUpdate() failed!\n");
		goto end;
	}

	*cipher_length = len;

	// Finalise the encryption, get no output
	if (!EVP_EncryptFinal_ex(ctx, cipher_text + len, &len)) {
		LOG(LOG_ERROR, "EVP_EncryptFinal_ex() failed!\n");
		goto end;
	}

	// Get the tag
	if (!EVP_CIPHER_CTX_ctrl(ctx, GET_TAG, tag_length, tag)) {
		LOG(LOG_ERROR, "Failed to get required tag value!\n");
		goto end;
	}

	ret = 0;
end:
	// Clean up and free allocated memory
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
 *        Decrypted text size in BYTES. (IN/OUT)
 * @param cipher_text
 *        Encrypted text(input).
 * @param cipher_length
 *        Encrypted text size in BYTES.
 * @param block_size
 *        AES encryption block size in BYTES. FDO_AES_BLOCK_SIZE
 * @param iv
 *        AES encryption initialization vector.
 * @param key
 *        Key in Byte_array format used in encryption.
 * @param key_length
 *        Key size in BYTES.
 * @param tag
 *        Tag in Byte_array format that will be verified.
 * @param tag_length
 *        Fixed tag length in BYTES.
 * @param aad
 *        Additional Authenticated Data(AAD) in Byte_array format used in
 * decryption.
 * @param aad_length
 *        Additional Authenticated Data(AAD) size in BYTES.
 * @return ret
 *        return 0 on success. -1 on failure.
 *        fills clear_text_length in bytes for maximum possible buffer size
 *        required to fill in the clear_text, when clear_text is passed as NULL
 */
int32_t crypto_hal_aes_decrypt(uint8_t *clear_text, uint32_t *clear_text_length,
			       const uint8_t *cipher_text,
			       uint32_t cipher_length, size_t block_size,
			       const uint8_t *iv, const uint8_t *key,
			       uint32_t key_length, uint8_t *tag,
			       size_t tag_length, const uint8_t *aad,
			       size_t aad_length)
{
	int ret = -1;
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;

	// Check all the incoming parameters
	if (!clear_text_length || !cipher_text || cipher_length <= 0 ||
	    FDO_AES_BLOCK_SIZE != block_size || !iv || !key ||
	    KEY_LENGTH_LOCAL != key_length || !tag ||
	    tag_length != AES_TAG_LEN) {
		LOG(LOG_ERROR, "Invalid paramters received\n");
		goto end;
	}

	if (*clear_text_length < cipher_length) {
		LOG(LOG_ERROR, "Output buffer is not sufficient!\n");
		goto end;
	}

	// Create and initialise the context
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		LOG(LOG_ERROR, "Error during Initializing EVP cipher ctx!\n");
		goto end;
	}

	// Initialise the AES decryption operation
	if (!EVP_DecryptInit_ex(ctx, CIPHER_TYPE, NULL, NULL, NULL)) {
		LOG(LOG_ERROR,
		    "Error during Initializing EVP AES decrypt operation!\n");
		goto end;
	}

	// Set IV
	if (!EVP_CIPHER_CTX_ctrl(ctx, SET_IV, IV_LENGTH, NULL)) {
		LOG(LOG_ERROR, "Error during setting AES IV length!\n");
		goto end;
	}

	// NOTE: As per Openssl's documentation, Tag is specified for CCM before
	// EVP_DecryptUpdate, while the same is specified for GCM after
	// EVP_DecryptUpdate. As a result, the tag for GCM is specified later.
	// L value is set for CCM separately here.
#ifdef AES_MODE_CCM_ENABLED
	// Set tag
	if (!EVP_CIPHER_CTX_ctrl(ctx, SET_TAG, tag_length, tag)) {
		LOG(LOG_ERROR, "Error during setting AES IV length!\n");
		goto end;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, L_VALUE_BYTES,
				 NULL)) {
		LOG(LOG_ERROR, "Error during setting AES tag length!\n");
		goto end;
	}
#endif

	// Initialise key and IV
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
		LOG(LOG_ERROR, "Key and IV initialization failed!\n");
		goto end;
	}

	// Specify AAD, only if available
	if (aad && aad_length > 0) {

#ifdef AES_MODE_CCM_ENABLED
		// Set ciphertext length (only required for CCM)
		if (!EVP_DecryptUpdate(ctx, NULL, &len, NULL, cipher_length)) {
			LOG(LOG_ERROR, "Cipher length set failed!\n");
			goto end;
		}
#endif
		if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_length)) {
			LOG(LOG_ERROR, "AAD initialization failed!\n");
			goto end;
		}
	}

#ifdef AES_MODE_CCM_ENABLED
	// Decrypt the message. Can only be called once.
	ret = EVP_DecryptUpdate(ctx, clear_text, &len, cipher_text,
				cipher_length);
	if (ret > 0) {
		// Success: decrypted and authentication passed
		*clear_text_length = len;
		ret = 0;
	} else {
		// Failure: decryption/authentication failed
		ret = -1;
		LOG(LOG_ERROR, "Decrypt: EVP_DecryptUpdate failed\n");
		goto end;
	}
#else
	// Provide message to be decrypted. Can be called multiple times.
	if (!EVP_DecryptUpdate(ctx, clear_text, &len, cipher_text,
			       cipher_length)) {
		LOG(LOG_ERROR, "EVP_DecryptUpdate() failed!\n");
		goto end;
	}
	*clear_text_length = len;

	// Set tag
	if (!EVP_CIPHER_CTX_ctrl(ctx, SET_TAG, tag_length, tag)) {
		LOG(LOG_ERROR, "Error during setting AES tag length!\n");
		goto end;
	}

	// Finalise the decryption. A positive return value indicates success
	// anything else is a failure i.e. the plaintext is not trustworthy.
	ret = EVP_DecryptFinal_ex(ctx, clear_text + len, &len);
	if (ret > 0) {
		// Success: authentication passed
		ret = 0;
	} else {
		// Failure: authentication failed
		// reset clear text length since tag couldn't be verified
		*clear_text_length = 0;
		ret = -1;
	}
#endif

end:
	/* Clean up and free allocated memory */
	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
	}
	return ret;
}
