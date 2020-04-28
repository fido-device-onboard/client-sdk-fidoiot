/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "sdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"
#include "sdoCryptoCtx.h"
#include "sdoCrypto.h"
#include "network_al.h"

/**
 * This API helps compute the size of the buffer that holds the ciphertext
 * without performing the encryption.
 * @param clear_length In Size of the clear text data
 * @param cipher_length Out Pointer to the size of the buffer required for
 * cipher text. The memory for the pointer must be allocated
 * before calling this API
 * @return length of the cipher text needed on success else -1 for failures.
 */
int32_t sdo_msg_encrypt_get_cipher_len(uint32_t clear_length,
				       uint32_t *cipher_length)
{
	if (!clear_length || !cipher_length) {
		return -1;
	}

#ifdef AES_MODE_CBC_ENABLED
	*cipher_length =
	    ((clear_length / SDO_AES_BLOCK_SIZE) + 1) * SDO_AES_BLOCK_SIZE;
#elif AES_MODE_CTR_ENABLED
	*cipher_length = clear_length;
#endif
	return 0;
}

static int32_t getIV(uint8_t *iv, uint32_t clear_text_length)
{
/* Generate IV for encription */
#ifdef AES_MODE_CBC_ENABLED
	(void)clear_text_length;
	return sdo_crypto_random_bytes(iv, AES_IV);
#else
	int ret = -1;
	uint32_t *ctr_value;
	uint64_t temp_ctr_value;
	uint32_t iv_ctr_ntohl;
	sdo_to2Sym_enc_ctx_t *to2sym_ctx = get_sdo_to2_ctx();

	if (NULL == to2sym_ctx) {
		return -1;
	}

	ctr_value = &to2sym_ctx->ctr_value;
	temp_ctr_value = (uint64_t)*ctr_value;

	if (0 == *ctr_value) {
		to2sym_ctx->initialization_vector =
		    sdo_alloc(sizeof(uint8_t) * AES_CTR_IV);

		if (NULL == to2sym_ctx->initialization_vector) {
			goto error;
		}

		if (0 !=
		    sdo_crypto_random_bytes(to2sym_ctx->initialization_vector,
					    AES_CTR_IV)) {
			goto error;
		}
	}

	if (memcpy_s(iv, AES_CTR_IV, to2sym_ctx->initialization_vector,
		     AES_CTR_IV) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto error;
	}

	iv_ctr_ntohl = sdo_net_to_host_long(*ctr_value);

	if (memcpy_s(iv + AES_CTR_IV, AES_IV - AES_CTR_IV, &iv_ctr_ntohl,
		     AES_CTR_IV_COUNTER) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto error;
	}
	temp_ctr_value +=
	    (clear_text_length / SDO_AES_BLOCK_SIZE) +
	    (uint32_t)((clear_text_length % SDO_AES_BLOCK_SIZE) != 0);

	if (temp_ctr_value >= UINT32_MAX) {
		LOG(LOG_ERROR, "CTR value reset occurred\n");
		goto error;
	}
	*ctr_value = (uint32_t)temp_ctr_value;

	ret = 0;

 error:
	if (0 != ret) {
		if(NULL != to2sym_ctx->initialization_vector) {
			sdo_free(to2sym_ctx->initialization_vector);
		}
	}
	return ret;
#endif
}

/**
 * This function encrypts clear text in the buffer clear_text of length
 * clear_text_length using the AES key specified by SEK, and initialization
 * vector specified in sdo_to2Msg_crypto_ctx. The encryption mode is specified
 *  by mode field in sdo_to2Msg_crypto_ctx.
 * The caller is expected to allocate a buffer for ciphertext before calling
 * this API, with the help of sdo_msg_encrypt_get_cipher_len to determine the
 * length of ciphertext. The length of the buffer is specified in *cipher_length
 * as an input to the function. The cipher_length returns the actual size of
 * cipher on successful return from the function. The buffer specified by iv
 * contains the initialization vector used for encryption.
 * @param clear_text In_pointer to cleartext data that is to be encrypted
 * @param clear_text_length In Size of the clear_text
 * @param cipher Out Pointer to the buffer where the cipher text is stored after
 * encryption operation is completed. This buffer must be
 * allocated before calling this API
 * @param cipher_length In/Out In: Size of the cipher
 * Out: Size of the cipher text stored in cipher
 * @param iv Out Pointer to the initialization vector (IV) used for AES
 * encryption.
 * The IV is 16 bytes long, so the buffer specified by iv must be
 * at least 16 bytes long
 * @return 0 on success and -1 on failures.
 */
int32_t sdo_msg_encrypt(uint8_t *clear_text, uint32_t clear_text_length,
			uint8_t *cipher, uint32_t *cipher_length, uint8_t *iv)
{
	sdo_aes_keyset_t *keyset = get_keyset();
	uint8_t *sek;
	uint8_t sek_len;

	if (!keyset) {
		goto error;
	}

	sek = keyset->sek->bytes;
	sek_len = keyset->sek->byte_sz;

	if (!iv || !sek || !sek_len) {
		goto error;
	}

	if (0 != getIV(iv, clear_text_length)) {
		LOG(LOG_ERROR, "IV generation failed");
		goto error;
	}

	if (0 != crypto_hal_aes_encrypt(clear_text, clear_text_length, cipher,
					cipher_length, SDO_AES_BLOCK_SIZE, iv,
					sek, sek_len)) {
		goto error;
	}
	return 0;
error:
	return -1;
}

/**
 * This API helps compute the size of the buffer without performing the
 * decryption operation.
 * @param cipher_length In Size of the cipher text
 * @param clear_text_length Out Pointer to the size of the buffer required for
 *                        clear text. The memory for the pointer must be
 * allocated before
 *    calling this API
 * @return 0 on success and -1 on failures.
 */
int32_t sdo_msg_decrypt_get_pt_len(uint32_t cipher_length,
				   uint32_t *clear_text_length)
{
	if (cipher_length && clear_text_length != NULL) {
		*clear_text_length = cipher_length;
		return 0;
	}
	return -1;
}

/**
 * This function decrypts cipher text specified by cipher and cipher_length
 * using the AES key specified by to2_aes_key and to2_aes_keylen in
 * sdo_msg_crypto_ctx, and the initialization vector specified by iv parameter.
 * The decryption mode is specified by the mode in sdo_msg_crypto_ctx. Decrypted
 * ciphertext is returned in the clear_text buffer. The caller is expected to
 * allocate a buffer for clear_text before calling this API, with the help of
 * sdo_msg_encrypt_getPTLen to determine the length of clear text. The
 * clear_text_length shall return the actual size of the clear_text
 * @param clear_text Out Pointer to the buffer where clear text data is stored
 * after
 *  decryption operation is completed. This buffer must be
 *  allocated before calling this API
 * @param clear_text_length In/Out In: Size of the buffer pointed to by
 * clear_text Out: Size of the clear text data stored in clear_text
 * @param cipher In Pointer to cipher text that is to be decrypted
 * @param cipher_length In Size of the cipher
 * @param iv In Pointer to the initialization vector (IV) used for AES
 * decryption. The IV is 16 bytes long, so the buffer specified by
 * iv must be at least 16 bytes long
 * @return 0 on success and -1 on failures.
 */
int32_t sdo_msg_decrypt(uint8_t *clear_text, uint32_t *clear_text_length,
			uint8_t *cipher, uint32_t cipher_length, uint8_t *iv)
{
	sdo_aes_keyset_t *keyset = get_keyset();
	uint8_t *sek;
	uint8_t sek_len;

	if (!keyset) {
		goto error;
	}
	sek = keyset->sek->bytes;
	sek_len = keyset->sek->byte_sz;

	if (!iv || !sek || !sek_len) {
		goto error;
	}

	if (0 != crypto_hal_aes_decrypt(clear_text, clear_text_length, cipher,
					cipher_length, SDO_AES_BLOCK_SIZE, iv,
					sek, sek_len)) {
		LOG(LOG_ERROR, "decrypt failed\n");
		goto error;
	}
	return 0;
error:
	return -1;
}
