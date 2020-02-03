/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "sdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"
#include "sdoCryptoCtx.h"
#include "sdoCryptoApi.h"
#include "network_al.h"

/**
 * This API helps compute the size of the buffer that holds the ciphertext
 * without performing the encryption.
 * @param clearLength In Size of the clear text data
 * @param cipherLength Out Pointer to the size of the buffer required for
 * cipher text. The memory for the pointer must be allocated
 * before calling this API
 * @return length of the cipher text needed on success else -1 for failures.
 */
int32_t sdoMsgEncryptGetCipherLen(uint32_t clearLength, uint32_t *cipherLength)
{
	if (!clearLength || !cipherLength) {
		return -1;
	}

#ifdef AES_MODE_CBC_ENABLED
	*cipherLength =
	    ((clearLength / SDO_AES_BLOCK_SIZE) + 1) * SDO_AES_BLOCK_SIZE;
#elif AES_MODE_CTR_ENABLED
	*cipherLength = clearLength;
#endif
	return 0;
}

static int32_t getIV(uint8_t *iv, uint32_t clearTextLength)
{
/* Generate IV for encription */
#ifdef AES_MODE_CBC_ENABLED
	return sdoCryptoRandomBytes(iv, AES_IV);
#else
	uint32_t *ctr_value;
	uint64_t temp_ctr_value;
	uint32_t iv_ctr_ntohl;
	sdoTo2SymEncCtx_t *to2sym_ctx = getsdoTO2Ctx();

	if (NULL == to2sym_ctx) {
		return -1;
	}

	ctr_value = &to2sym_ctx->ctr_value;
	temp_ctr_value = (uint64_t)*ctr_value;

	if (0 == *ctr_value) {
		to2sym_ctx->initializationVector =
		    sdoAlloc(sizeof(uint8_t) * AES_CTR_IV);

		if (NULL == to2sym_ctx->initializationVector) {
			return -1;
		}

		if (sdoCryptoRandomBytes(to2sym_ctx->initializationVector,
					 AES_CTR_IV)) {
			return -1;
		}
	}

	if (memcpy_s(iv, AES_CTR_IV, to2sym_ctx->initializationVector,
		     AES_CTR_IV) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return -1;
	}

	iv_ctr_ntohl = sdoNetToHostLong(*ctr_value);

	if (memcpy_s(iv + AES_CTR_IV, AES_IV - AES_CTR_IV, &iv_ctr_ntohl,
		     AES_CTR_IV_COUNTER) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return -1;
	}
	temp_ctr_value +=
	    (clearTextLength / SDO_AES_BLOCK_SIZE) +
	    (uint32_t)((clearTextLength % SDO_AES_BLOCK_SIZE) != 0);

	if (temp_ctr_value >= 0xFFFFFFFF) {
		LOG(LOG_ERROR, "CTR value reset occurred\n");
		return -1;
	}

	*ctr_value = (uint32_t)temp_ctr_value;
	return 0;
#endif
}

/**
 * This function encrypts clear text in the buffer clearText of length
 * clearTextLength using the AES key specified by SEK, and initialization
 * vector specified in sdoTo2MsgCryptoCtx. The encryption mode is specified
 *  by mode field in sdoTo2MsgCryptoCtx.
 * The caller is expected to allocate a buffer for ciphertext before calling
 * this API, with the help of sdoMsgEncryptGetCipherLen to determine the length
 * of ciphertext. The length of the buffer is specified in *cipherLength as an
 * input to the function. The cipherLength returns the actual size of cipher
 * on successful return from the function.
 * The buffer specified by iv contains the initialization vector used for
 * encryption.
 * @param clearText InPointer to cleartext data that is to be encrypted
 * @param clearTextLength In Size of the clearText
 * @param cipher Out Pointer to the buffer where the cipher text is stored after
 * encryption operation is completed. This buffer must be
 * allocated before calling this API
 * @param cipherLength In/Out In: Size of the cipher
 * Out: Size of the cipher text stored in cipher
 * @param iv Out Pointer to the initialization vector (IV) used for AES
 * encryption.
 * The IV is 16 bytes long, so the buffer specified by iv must be
 * at least 16 bytes long
 * @return 0 on success and -1 on failures.
 */
int32_t sdoMsgEncrypt(uint8_t *clearText, uint32_t clearTextLength,
		      uint8_t *cipher, uint32_t *cipherLength, uint8_t *iv)
{
	SDOAESKeyset_t *keyset = getKeyset();
	uint8_t *sek;
	uint8_t sekLen;

	if (!keyset) {
		goto error;
	}

	sek = keyset->sek->bytes;
	sekLen = keyset->sek->byteSz;

	if (!iv || !sek || !sekLen) {
		goto error;
	}

	if (0 != getIV(iv, clearTextLength)) {
		LOG(LOG_ERROR, "IV generation failed");
		goto error;
	}

	if (0 != sdoCryptoAESEncrypt(clearText, clearTextLength, cipher,
				     cipherLength, SDO_AES_BLOCK_SIZE, iv, sek,
				     sekLen)) {
		goto error;
	}
	return 0;
error:
	return -1;
}

/**
 * This API helps compute the size of the buffer without performing the
 * decryption operation.
 * @param cipherLength In Size of the cipher text
 * @param clearTextLength Out Pointer to the size of the buffer required for
 *                        clear text. The memory for the pointer must be
 * allocated before
 *    calling this API
 * @return 0 on success and -1 on failures.
 */
int32_t sdoMsgDecryptGetPTLen(uint32_t cipherLength, uint32_t *clearTextLength)
{
	if (cipherLength && clearTextLength != NULL) {
		*clearTextLength = cipherLength;
		return 0;
	}
	return -1;
}

/**
 * This function decrypts cipher text specified by cipher and cipherLength using
 * the AES key specified by to2_aes_key and to2_aes_keylen in sdoMsgCryptoCtx,
 * and the initialization vector specified by iv parameter. The decryption mode
 * is
 * specified by the mode in sdoMsgCryptoCtx. Decrypted ciphertext is returned in
 * the clearText buffer. The caller is expected to allocate a buffer for
 * clearText before calling this API, with the help of sdoMsgEncryptGetPTLen
 * to determine the length of clear text.
 * The clearTextLength shall return the actual size of the clearText
 * @param clearText Out Pointer to the buffer where clear text data is stored
 * after
 *  decryption operation is completed. This buffer must be
 *  allocated before calling this API
 * @param clearTextLength In/Out In: Size of the buffer pointed to by clearText
 * Out: Size of the clear text data stored in clearText
 * @param cipher In Pointer to cipher text that is to be decrypted
 * @param cipherLength In Size of the cipher
 * @param iv In Pointer to the initialization vector (IV) used for AES
 * decryption. The IV is 16 bytes long, so the buffer specified by
 * iv must be at least 16 bytes long
 * @return 0 on success and -1 on failures.
 */
int32_t sdoMsgDecrypt(uint8_t *clearText, uint32_t *clearTextLength,
		      uint8_t *cipher, uint32_t cipherLength, uint8_t *iv)
{
	SDOAESKeyset_t *keyset = getKeyset();
	uint8_t *sek;
	uint8_t sekLen;

	if (!keyset) {
		goto error;
	}
	sek = keyset->sek->bytes;
	sekLen = keyset->sek->byteSz;

	if (!iv || !sek || !sekLen) {
		goto error;
	}

	if (0 != sdoCryptoAESDecrypt(clearText, clearTextLength, cipher,
				     cipherLength, SDO_AES_BLOCK_SIZE, iv, sek,
				     sekLen)) {
		LOG(LOG_ERROR, "decrypt failed\n");
		goto error;
	}
	return 0;
error:
	return -1;
}
