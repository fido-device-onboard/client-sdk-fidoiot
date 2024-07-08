/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of interface between crypto library and FDO library.
 */

#include "crypto_utils.h"
#include "util.h"
#include <stdlib.h>
#include "safe_lib.h"
#include "snprintf_s.h"
#include "fdo_crypto.h"

/**
 * Encrypt the characters in the clear_txt buffer, place the result
 * of the clear text in the cipher_txt object, which must be pre allocated.
 *
 * @param cipher_txt
 *        Encrypted text and HMAC.
 * @param clear_txt
 *        Input text to be encrypted.
 * @param clear_txt_size
 *        Plain text size.
 * @param aad
 *        Buffer containing the Additonal Authenticated Data (AAD).
 * @param aad_length
 *        Size of the aad
 * @return ret
 *        return 0 on success. -1 on failure.
 */
int aes_encrypt_packet(fdo_encrypted_packet_t *cipher_txt, uint8_t *clear_txt,
		       size_t clear_txt_size, const uint8_t *aad,
		       size_t aad_length)
{
	if (!cipher_txt || !clear_txt || 0 == clear_txt_size || !aad ||
	    0 == aad_length) {
		return -1;
	}

	int ret = -1;
	uint8_t *temp = NULL;
	uint8_t *ct = clear_txt;
	uint8_t *cipher_text = NULL;
	uint32_t cipher_length = 0;

	/* Get cipher text length  */
	if (0 !=
	    fdo_msg_encrypt_get_cipher_len(clear_txt_size, &cipher_length)) {
		LOG(LOG_ERROR, "Failed to get ciphertext buffer size.\n");
		goto end;
	}

	/* Allocate cyphertxt placeholder */
	cipher_txt->em_body = fdo_byte_array_alloc(cipher_length);
	if (NULL == cipher_txt->em_body) {
		goto end;
	}

	cipher_text = cipher_txt->em_body->bytes;

	// get encryted data
	if (0 != fdo_msg_encrypt(ct, clear_txt_size, cipher_text,
				 &cipher_length, cipher_txt->iv,
				 cipher_txt->tag, sizeof(cipher_txt->tag), aad,
				 aad_length)) {
		LOG(LOG_ERROR, "Failed to get encrypt.\n");
		goto end;
	}

	ret = 0;
end:
	if (temp) {
		fdo_free(temp);
	}

	if (ret) {
		if (cipher_txt->em_body) {
			fdo_byte_array_free(cipher_txt->em_body);
			cipher_txt->em_body = NULL;
		}
	}
	return ret;
}

/**
 * Decrypt a FDOEncrypted_packet object to an fdo_string_t. Also calculate HMAC
 * of decrypted text and compare it with received HMAC.
 *
 * @param cipher_txt
 *        Cipher text to be decrypted and HMAC to be verified.
 * @param clear_txt
 *        Buffer to place the decrypted text.
 * @param aad
 *        Buffer containing the Additonal Authenticated Data (AAD).
 * @param aad_length
 *        Size of the aad
 * @return ret
 *        return 0 on success. -1 on failure.
 */
int aes_decrypt_packet(fdo_encrypted_packet_t *cipher_txt,
		       fdo_byte_array_t *clear_txt, const uint8_t *aad,
		       size_t aad_length)
{
	int ret = -1;
	uint32_t clear_text_length = 0;
	uint8_t *cleartext = NULL;
	int result = -1;

	if (!cipher_txt || !cipher_txt->em_body || !aad || 0 == aad_length) {
		return -1;
	}

	clear_text_length = cipher_txt->em_body->byte_sz;

	result = fdo_msg_decrypt_get_pt_len(cipher_txt->em_body->byte_sz,
					    &clear_text_length);
	if (result != 0) {
		LOG(LOG_ERROR, "Can't get required clear text size\n");
		goto end;
	}

	cleartext = fdo_alloc(clear_text_length);
	if (!cleartext) {
		LOG(LOG_ERROR, "Failed to allocate cleartext buffer\n");
		goto end;
	}

	if (0 != fdo_msg_decrypt(cleartext, &clear_text_length,
				 cipher_txt->em_body->bytes,
				 cipher_txt->em_body->byte_sz, cipher_txt->iv,
				 cipher_txt->tag, sizeof(cipher_txt->tag), aad,
				 aad_length)) {
		LOG(LOG_ERROR, "Failed to Decrypt\n");
		goto end;
	}

	/*
	 * TODO: Since, clear_txt is defined with a string data structure, so,
	 * resizing using that API, and memcpy to it as cleartext is
	 * without NULL termination. So, it must be moved to a different
	 * data structure.
	 */
	if (fdo_byte_array_resize(clear_txt, clear_text_length) == false) {
		LOG(LOG_ERROR, "Failed to resize clear text buffer\n");
		goto end;
	}

	if (memcpy_s(clear_txt->bytes, clear_text_length, cleartext,
		     clear_text_length)) {
		LOG(LOG_ERROR, "Copying cleartext failed\n");
		goto end;
	}

	ret = 0;
end:
	if (cleartext) {
		fdo_free(cleartext);
	}
	return ret;
}
