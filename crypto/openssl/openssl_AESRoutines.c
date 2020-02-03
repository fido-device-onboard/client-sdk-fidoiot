/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for AES encryption routines of openssl library.
 */

#include "sdoCryptoHal.h"
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

#else

#ifdef AES_MODE_CTR_ENABLED
#define CIPHER_TYPE EVP_aes_128_ctr()
#else
#define CIPHER_TYPE EVP_aes_128_cbc()
#endif /* AES_MODE_CTR_ENABLED */

#endif /* AES_256_BIT */

/**
 * sdoCryptoAESEncrypt -  Perform AES encryption of the input text.
 *
 * @param clearText
 *        Input text to be encrypted.
 * @param clearTextLength
 *        Plain text size in bytes.
 * @param cipherText
 *        Encrypted text(output).
 * @param cipherLength
 *        Encrypted text size of cipherText in bytes. [INOUT]
 * @param blockSize
 *        AES encryption block size in bytes. always 128 bits.
 * @param iv
 *        AES encryption initialization vector.
 * @param key
 *        Key in ByteArray format used in encryption.
 * @param keyLength
 *        Key size in Bytes.
 * @return ret
 *        return 0 on success. -1 on failure.
 *        fills cipherLength in bytes while cipherText passed as NULL, & all
 *        other parameters are passed as it is.
 */
int32_t sdoCryptoAESEncrypt(const uint8_t *clearText, uint32_t clearTextLength,
			    uint8_t *cipherText, uint32_t *cipherLength,
			    size_t blockSize, const uint8_t *iv,
			    const uint8_t *key, uint32_t keyLength)
{
	int ret = -1;
	int outlen = 0;
	int offset = 0;
	size_t exp_cipher_len = clearTextLength;
	EVP_CIPHER_CTX *ctx = NULL;

	/*
	 * Check all parameters except cipherText, as if it's NULL,
	 * cipherLength needs to be filled in with the expected size
	 */
	if (!clearText || !clearTextLength || !cipherLength ||
	    SDO_AES_BLOCK_SIZE != blockSize || !iv || !key || !keyLength) {
		LOG(LOG_ERROR, "Invalid parameters received\n");
		goto end;
	}

/*
 * CTR: cipherLength = clearTextLength
 * CBC: cipherLength = clearTextLength + padding bytes
 * Padding:
 * a. For non AES block aligned cleartext, padding extends
 *    the size to be multiple of AES block.
 * b. For AES block aligned cleartext, padding extends the
 *    size by 1 AES block.
 */
#ifdef AES_MODE_CBC_ENABLED
	exp_cipher_len = ((clearTextLength / blockSize) + 1) * blockSize;
#endif /* AES_MODE_CTR_ENABLED */

	/* Fill in the expected cipher text length */
	if (!cipherText) {
		*cipherLength = exp_cipher_len;
		ret = 0;
		goto end;
	}

	/* If we reach here, cipherText is non-NULL, no need to check */
	if (*cipherLength < exp_cipher_len) {
		LOG(LOG_ERROR, "Invalid cleartext/ciphertext size received\n");
		goto end;
	}

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		goto end;
	}

	if (1 != EVP_EncryptInit_ex(ctx, CIPHER_TYPE, NULL, key, iv)) {
		goto end;
	}

	/* Common for cbc and ctr */
	if (1 != EVP_EncryptUpdate(ctx, cipherText, &outlen, clearText,
				   clearTextLength)) {
		goto end;
	}

	offset += outlen;

	if (!EVP_EncryptFinal_ex(ctx, cipherText + offset, &outlen)) {
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
 * sdoCryptoAESDecrypt -  Perform AES decryption of the cipher text.
 *
 * @param clearText
 *        Decrypted text(output).
 * @param clearTextLength
 *        Decrypted text size in Byte. (IN/OUT)
 * @param cipherText
 *        Encrypted text(input).
 * @param cipherLength
 *        Encrypted text size in Byte.
 * @param blockSize
 *        AES encryption block size in Byte. SDO_AES_BLOCK_SIZE
 * @param iv
 *        AES encryption initialization vector.
 * @param key
 *        Key in ByteArray format used in encryption.
 * @param keyLength
 *        Key size in Bytes.
 * @return ret
 *        return 0 on success. -1 on failure.
 *        fills clearTextLength in bytes for maximum possible buffer size
 *        required to fill in the clearText, when clearText is passed as NULL
 */
int32_t sdoCryptoAESDecrypt(uint8_t *clearText, uint32_t *clearTextLength,
			    const uint8_t *cipherText, uint32_t cipherLength,
			    size_t blockSize, const uint8_t *iv,
			    const uint8_t *key, uint32_t keyLength)
{
	int ret = -1;
	int outlen = 0;
	int offset = 0;
	EVP_CIPHER_CTX *ctx = NULL;

	/* Check all the incoming parameters */
	if (!clearTextLength || !cipherText || !cipherLength ||
	    SDO_AES_BLOCK_SIZE != blockSize || !iv || !key || !keyLength) {
		LOG(LOG_ERROR, "Invalid paramters received\n");
		goto end;
	}

	/*
	 * If clearText is NULL, then return the size of clearText. Since,
	 * for CBC, we cannot tell the precise length of clearText without
	 * decryption, so, clearTextLength is returned to be same as
	 * cipherLength. After decryption, clearTextLength will be updated
	 * with the precise length.
	 */
	if (!clearText) {
		*clearTextLength = cipherLength;
		ret = 0;
		goto end;
	}

	/*
	 * The caller has to ensure that the clearText is big enough to hold
	 * complete clear data. The padding scheme is already known to caller,
	 * so, expecting that the buffer sent in is at minimum equal to
	 * ciphertext size.
	 */
	if (*clearTextLength < cipherLength) {
		LOG(LOG_ERROR, "Invalid cleartext/ciphertext size received\n");
		goto end;
	}

	/* Allocate the cipher context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		goto end;

#if defined(AES_DEBUG)
	LOG(LOG_DEBUG, "ciphered msg size: %d \n", cipherLength);
	hexdump("Cipher txt to decrypt", cipherText, cipherLength);
#endif

	if (1 != EVP_DecryptInit_ex(ctx, CIPHER_TYPE, NULL, key, iv)) {
		goto end;
	}

	if (1 != EVP_DecryptUpdate(ctx, clearText, &outlen, cipherText,
				   cipherLength)) {
		goto end;
	}

	offset += outlen; /* Backup the number of output bytes */

	if (1 != EVP_DecryptFinal_ex(ctx, clearText + offset, &outlen))
		goto end;

	*clearTextLength = offset + outlen;
	ret = 0; /* Mark the operation as success */

end:
	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
	}
	return ret;
}
