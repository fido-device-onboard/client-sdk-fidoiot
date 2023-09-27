/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "fdo_crypto_hal.h"
#include "util.h"
#include "safe_lib.h"
#include "fdo_crypto_ctx.h"
#include "fdo_crypto.h"
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
int32_t fdo_msg_encrypt_get_cipher_len(uint32_t clear_length,
				       uint32_t *cipher_length)
{
	if (!clear_length || !cipher_length) {
		return -1;
	}

	// for both AES GCM/CCM modes, same cipher data length is the same as
	// plain data length
	*cipher_length = clear_length;
	return 0;
}

static int32_t getIV(uint8_t *iv, uint32_t clear_text_length)
{
	// unused
	(void)clear_text_length;
	// Generate IV for encryption
	return fdo_crypto_random_bytes(iv, AES_IV_LEN);
}

/**
 * This function encrypts clear text in the buffer clear_text of length
 * clear_text_length using the AES key specified by SEK, and initialization
 * vector specified in fdo_to2Msg_crypto_ctx. The encryption mode is specified
 *  by mode field in fdo_to2Msg_crypto_ctx.
 * The caller is expected to allocate a buffer for ciphertext before calling
 * this API, with the help of fdo_msg_encrypt_get_cipher_len to determine the
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
 * The IV length is dependent of AES mode used (GCM/CCM).
 * @param tag Out Pointer to the buffer where the authentication tag is stored
 * after encryption. This buffer must be
 * allocated before calling this API
 * @param tag_length In/Out In: Size of the tag
 * Out: Size of the authentication tag stored in tag
 * @param aad In Pointer to the buffer containing the Additonal Authenticated
 * Data (AAD) used during encryption
 * @param aad_length In Size of the aad
 * @return 0 on success and -1 on failures.
 */
int32_t fdo_msg_encrypt(const uint8_t *clear_text, uint32_t clear_text_length,
			uint8_t *cipher, uint32_t *cipher_length, uint8_t *iv,
			uint8_t *tag, size_t tag_length, const uint8_t *aad,
			size_t aad_length)
{
	fdo_aes_keyset_t *keyset = get_keyset();
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
					cipher_length, FDO_AES_BLOCK_SIZE, iv,
					sek, sek_len, tag, tag_length, aad,
					aad_length)) {
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
int32_t fdo_msg_decrypt_get_pt_len(uint32_t cipher_length,
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
 * fdo_msg_crypto_ctx, and the initialization vector specified by iv parameter.
 * The decryption mode is specified by the mode in fdo_msg_crypto_ctx. Decrypted
 * ciphertext is returned in the clear_text buffer. The caller is expected to
 * allocate a buffer for clear_text before calling this API, with the help of
 * fdo_msg_encrypt_getPTLen to determine the length of clear text. The
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
 * decryption. The IV length is dependent on AES mode used (GCM/CCM).
 * @param tag In Pointer to the buffer containing the authentication tag that is
 * used for decryption.
 * @param tag_length In/Out In: Size of the tag
 * Out: Size of the authentication tag stored in tag
 * @param aad In Pointer to the buffer containing the Additonal Authenticated
 * Data (AAD) used during encryption
 * @param aad_length In Size of the aad
 * @return 0 on success and -1 on failures.
 */
int32_t fdo_msg_decrypt(uint8_t *clear_text, uint32_t *clear_text_length,
			const uint8_t *cipher, uint32_t cipher_length,
			uint8_t *iv, uint8_t *tag, size_t tag_length,
			const uint8_t *aad, size_t aad_length)
{
	fdo_aes_keyset_t *keyset = get_keyset();
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
					cipher_length, FDO_AES_BLOCK_SIZE, iv,
					sek, sek_len, tag, tag_length, aad,
					aad_length)) {
		LOG(LOG_ERROR, "decrypt failed\n");
		goto error;
	}
	return 0;
error:
	return -1;
}
