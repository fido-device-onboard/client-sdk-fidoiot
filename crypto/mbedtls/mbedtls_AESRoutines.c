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

#else

#ifdef AES_MODE_CTR_ENABLED
#define CIPHER_TYPE MBEDTLS_CIPHER_AES_128_CTR
#else
#define CIPHER_TYPE MBEDTLS_CIPHER_AES_128_CBC
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
 *        Encrypted text size in bytes. [INOUT]
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
	size_t exp_cipher_len = 0;
	mbedtls_cipher_context_t cipher_ctx;
	const mbedtls_cipher_info_t *cipher_info;
	size_t olen = 0;

	/*
	 * Check all parameters except cipherText, as if it's NULL,
	 * cipherLength needs to be filled in with the expected size
	 */
	if (!clearText || !clearTextLength || !cipherLength ||
	    SDO_AES_BLOCK_SIZE != blockSize || !iv || !key || !keyLength) {
		LOG(LOG_ERROR, "Invalid parameters received\n");
		return -1;
	}

	mbedtls_cipher_init(&cipher_ctx);

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
#else
	exp_cipher_len = clearTextLength;
#endif /* AES_MODE_CBC_ENABLED */

	/* Fill in the expected cipher text length */
	if (!cipherText) {
		*cipherLength = exp_cipher_len;
		ret = 0;
		goto end;
	}

	if ((cipher_info = mbedtls_cipher_info_from_type(CIPHER_TYPE)) ==
	    NULL) {
		LOG(LOG_ERROR, "failed to get cipher info\n");
		goto end;
	}

	if ((ret = mbedtls_cipher_setup(&cipher_ctx, cipher_info)) != 0) {
		LOG(LOG_ERROR, "failed to setup the cipher\n");
		goto end;
	}

	if ((ret = mbedtls_cipher_setkey(&cipher_ctx, key, 8 * keyLength,
					 MBEDTLS_ENCRYPT)) != 0) {
		LOG(LOG_ERROR, "failed to set the key\n");
		goto end;
	}

	if ((ret = mbedtls_cipher_set_iv(&cipher_ctx, iv, SDO_AES_IV_SIZE)) !=
	    0) {
		LOG(LOG_ERROR, "failed to set IV\n");
		goto end;
	}
	if ((ret = mbedtls_cipher_reset(&cipher_ctx)) != 0) {
		LOG(LOG_ERROR, "failed to reset the cipher\n");
		goto end;
	}

	/* encrypt */
	if ((ret = mbedtls_cipher_update(&cipher_ctx, clearText,
					 clearTextLength, cipherText, &olen)) !=
	    0) {
		LOG(LOG_ERROR, "cipher_update failed\n");
		goto end;
	}
	if ((ret = mbedtls_cipher_finish(&cipher_ctx, cipherText + olen,
					 &olen)) != 0) {
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
 * sdoCryptoAESDecrypt -  Perform AES ecryption of the cipher text.
 *
 * @param clearText
 *        Decrypted text(output).
 * @param clearTextLength
 *        Decrypted text size in Byte.
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
	size_t olen = 0, ofs = 0;
	mbedtls_cipher_context_t cipher_ctx;
	const mbedtls_cipher_info_t *cipher_info = NULL;

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

#if defined(AES_DEBUG)
	hexdump("Cipher txt to decrypt", cipherText, cipherLength);
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
	if (mbedtls_cipher_setkey(&cipher_ctx, key, 8 * keyLength,
				  MBEDTLS_DECRYPT)) {
		LOG(LOG_ERROR, "Failed to set the key for decryption\n");
		goto err;
	}

	if (mbedtls_cipher_set_iv(&cipher_ctx, iv, AES_IV)) {
		LOG(LOG_ERROR, "Failed to set IV for decryption\n");
		goto err;
	}

	/* Roll for decryption */
	if (mbedtls_cipher_update(&cipher_ctx, cipherText, cipherLength,
				  clearText, &ofs)) {
		LOG(LOG_ERROR, "Failed to decrypt cipher\n");
		goto err;
	}

	if (mbedtls_cipher_finish(&cipher_ctx, clearText + ofs, &olen)) {
		LOG(LOG_ERROR, "Finishing cipher failed\n");
		goto err;
	}

	*clearTextLength = ofs + olen;
	ret = 0; /* Mark as success */

err:
	mbedtls_cipher_free(&cipher_ctx);
end:
	return ret;
}
