/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of interface between crypto library and SDO library.
 */

#include "crypto_utils.h"
#include "util.h"
#include <stdlib.h>
#include "safe_lib.h"
#include "snprintf_s.h"
#include "base64.h"
#include "sdoCrypto.h"

/**
 * Encrypt the characters in the clear_txt buffer, place the result and a HMAC
 * of the clear text in the cipher_txt object, which must be pre allocated.
 *
 * @param cipher_txt
 *        Encrypted text and HMAC.
 * @param clear_txt
 *        Input text to be encrypted.
 * @param clear_txt_size
 *        Plain text size.
 * @return ret
 *        return 0 on success. -1 on failure.
 */
int aes_encrypt_packet(sdo_encrypted_packet_t *cipher_txt, uint8_t *clear_txt,
		       size_t clear_txt_size)
{
	if (NULL == cipher_txt || NULL == clear_txt || 0 == clear_txt_size)
		return -1;

	int ret = -1;
	uint8_t *temp = NULL;
	uint8_t *ct = clear_txt;
	uint8_t *cipher_text = NULL;
	uint32_t cipher_length = 0;
	sdo_hash_t *cipher_txt_hmac = NULL;
	uint32_t size_of_b64iv;
	uint8_t *temp_buf_iv = NULL;
	uint32_t size_of_b64ct;
	uint8_t *temp_buf_ct = NULL;
	uint32_t total_size_local_buf;
	char *local_buf = NULL;
	int bytes_written = 0, cnt = 0;

	cipher_txt_hmac =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);

	if (!cipher_txt_hmac || !cipher_txt_hmac->hash)
		return -1;

	/* Get cipher text length  */
	if (0 !=
	    sdo_msg_encrypt_get_cipher_len(clear_txt_size, &cipher_length)) {
		LOG(LOG_ERROR, "Failed to get ciphertext buffer size.\n");
		goto end;
	}

	/* Allocate cyphertxt placeholder */
	cipher_txt->em_body = sdo_byte_array_alloc(cipher_length);
	if (NULL == cipher_txt->em_body) {
		goto end;
	}

	cipher_text = cipher_txt->em_body->bytes;

	/* Get cypher text */
	if (0 != sdo_msg_encrypt(ct, clear_txt_size, cipher_text,
				 &cipher_length, cipher_txt->iv)) {
		LOG(LOG_ERROR, "Failed to get encrypt.\n");
		goto end;
	}

	/* one extra byte for null */
	size_of_b64iv = bin_toB64Length(AES_IV) + 2;
	temp_buf_iv = sdo_alloc(size_of_b64iv);

	size_of_b64ct = bin_toB64Length(cipher_length) + 2;
	temp_buf_ct = sdo_alloc(size_of_b64ct);

	(void)bin_toB64(AES_IV, cipher_txt->iv, 0, size_of_b64iv, temp_buf_iv,
			0);

	(void)bin_toB64(cipher_length, cipher_text, 0, size_of_b64ct,
			temp_buf_ct, 0);

	/* total size of the string is size of iv + iv + size of cipher text +
	 * cipher text + 11 json string characters.
	 */
	total_size_local_buf = sizeof(uint16_t) + size_of_b64iv +
			       size_of_b64ct + 11 + sizeof(uint16_t);
	local_buf = sdo_alloc(total_size_local_buf);
	if (!local_buf) {
		LOG(LOG_ERROR, "Alloc failed\n");
		goto end;
	}

	/* Create a string on which the hmac is calculated.
	 * According to spec [[ivsize,"iv"],size,"cipher_text"]
	 */
	cnt = snprintf_s_i(local_buf, total_size_local_buf, "[[%u,",
			   AES_IV);
	if (cnt < 0) {
		LOG(LOG_ERROR, "unable to create the ct string\n");
		goto end;
	}
	bytes_written = cnt;
	cnt = snprintf_s_si(local_buf + bytes_written,
			    total_size_local_buf - bytes_written,
			    "\"%s\"],%u,\"", (char *)temp_buf_iv,
			    cipher_length);
	if (cnt < 0) {
		LOG(LOG_ERROR, "unable to create the ct string\n");
		goto end;
	}
	bytes_written += cnt;
	if (strcat_s(local_buf + bytes_written,
		     total_size_local_buf - bytes_written,
		     (char *)temp_buf_ct) < 0) {
		LOG(LOG_ERROR, "unable to create the ct string\n");
		goto end;
	}
	bytes_written += strnlen_s((char *)temp_buf_ct, size_of_b64ct);
	if (strcat_s(local_buf + bytes_written,
		     total_size_local_buf - bytes_written, "\"]") < 0) {
		LOG(LOG_ERROR, "unable to create the ct string\n");
		goto end;
	}

	/* Make an HMAC. */
	if (0 != sdo_to2_hmac((uint8_t *)local_buf, strlen(local_buf),
			      cipher_txt_hmac->hash->bytes,
			      cipher_txt_hmac->hash->byte_sz)) {
		goto end;
	}

	cipher_txt->hmac = cipher_txt_hmac;
	ret = 0;
end:
	if (temp) {
		sdo_free(temp);
	}
	if (NULL != temp_buf_iv) {
		sdo_free(temp_buf_iv);
	}
	if (NULL != temp_buf_ct) {
		sdo_free(temp_buf_ct);
	}
	if (NULL != local_buf) {
		sdo_free(local_buf);
	}
	if (ret) {
		if (cipher_txt_hmac)
			sdo_hash_free(cipher_txt_hmac);
		if (cipher_txt->em_body) {
			sdo_byte_array_free(cipher_txt->em_body);
			cipher_txt->em_body = NULL;
		}
	}
	return ret;
}

/**
 * Decrypt a SDOEncrypted_packet object to an sdo_string_t. Also calculate HMAC
 * of decrypted text and compare it with received HMAC.
 *
 * @param cipher_txt
 *        Cipher text to be decrypted and HMAC to be verified.
 * @param clear_txt
 *        Buffer to place the decrypted text.
 * @return ret
 *        return 0 on success. -1 on failure.
 */
int aes_decrypt_packet(sdo_encrypted_packet_t *cipher_txt,
		       sdo_string_t *clear_txt)
{
	int ret = -1;
	uint32_t clear_text_length = 0;
	sdo_hash_t *cipher_txt_hmac = NULL;
	uint8_t *cleartext = NULL;
	int result = -1;

	if (NULL == cipher_txt || NULL == cipher_txt->em_body ||
	    NULL == cipher_txt->hmac || NULL == cipher_txt->ct_string) {
		return -1;
	}

	clear_text_length = cipher_txt->em_body->byte_sz;

	result = sdo_msg_decrypt_get_pt_len(cipher_txt->em_body->byte_sz,
					    &clear_text_length);
	if (result != 0) {
		LOG(LOG_ERROR, "Can't get required clear text size\n");
		goto end;
	}

	cleartext = sdo_alloc(clear_text_length);
	if (!cleartext) {
		LOG(LOG_ERROR, "Failed to allocate cleartext buffer\n");
		goto end;
	}

	/* Create an HMAC of the decrypted message. */
	cipher_txt_hmac =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);

	if (!cipher_txt_hmac) {
		LOG(LOG_ERROR, "failed to allocated memory: sdo-hash struct\n");
		goto end;
	}

	if (0 != sdo_to2_hmac(cipher_txt->ct_string->bytes,
			      cipher_txt->ct_string->byte_sz - 1,
			      cipher_txt_hmac->hash->bytes,
			      cipher_txt_hmac->hash->byte_sz)) {
		LOG(LOG_ERROR, "Failed to perform HMAC\n");
		goto end;
	}

	/* If the HMACs do not match, give an error. */
	memcmp_s(cipher_txt_hmac->hash->bytes, cipher_txt_hmac->hash->byte_sz,
		 cipher_txt->hmac->hash->bytes, cipher_txt_hmac->hash->byte_sz,
		 &result);

	if (result != 0) {
		LOG(LOG_ERROR, "sdoAESDecrypt_packet : FAILED, HMACs do "
			       "not compare\n");
		goto end;
	}

	if (0 != sdo_msg_decrypt(
		     cleartext, &clear_text_length, cipher_txt->em_body->bytes,
		     cipher_txt->em_body->byte_sz, cipher_txt->iv)) {
		LOG(LOG_ERROR, "Failed to Decrypt\n");
		goto end;
	}

	/*
	 * TODO: Since, clear_txt is defined with a string data structure, so,
	 * resizing using that API, and memcpy to it as cleartext is
	 * without NULL termination. So, it must be moved to a different
	 * data structure.
	 */
	if (sdo_string_resize(clear_txt, clear_text_length) == false) {
		LOG(LOG_ERROR, "Failed to resize clear text buffer\n");
		goto end;
	}

	if (memcpy_s(clear_txt->bytes, clear_text_length, cleartext,
		     clear_text_length)) {
		LOG(LOG_ERROR, "Copying cleartext failed\n");
		goto end;
	}

#ifdef AES_MODE_CTR_ENABLED
	cipher_txt->offset = cipher_txt->em_body->byte_sz % SDO_AES_BLOCK_SIZE;
#endif
	ret = 0;
end:
	if (cleartext)
		sdo_free(cleartext);
	if (cipher_txt_hmac)
		sdo_hash_free(cipher_txt_hmac);
	return ret;
}
