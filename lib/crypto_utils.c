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
#include "sdoCryptoApi.h"

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
int aes_encrypt_packet(SDOEncryptedPacket_t *cipher_txt, uint8_t *clear_txt,
		       size_t clear_txt_size)
{
	if (NULL == cipher_txt || NULL == clear_txt || 0 == clear_txt_size)
		return -1;

	int ret = -1;
	uint8_t *temp = NULL;
	uint8_t *ct = clear_txt;
	uint8_t *cipherText = NULL;
	uint32_t cipherLength = 0;
	SDOHash_t *cipher_txt_hmac = NULL;
	uint32_t size_of_b64iv;
	uint8_t *temp_buf_iv = NULL;
	uint32_t size_of_b64ct;
	uint8_t *temp_buf_ct = NULL;
	uint32_t total_size_local_buf;
	char *local_buf = NULL;
	int bytes_written = 0, cnt = 0;

	cipher_txt_hmac =
	    sdoHashAlloc(SDO_CRYPTO_HMAC_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);

	if (!cipher_txt_hmac || !cipher_txt_hmac->hash)
		return -1;

	/* Get cipher text length  */
	if (0 != sdoMsgEncryptGetCipherLen(clear_txt_size, &cipherLength)) {
		LOG(LOG_ERROR, "Failed to get ciphertext buffer size.\n");
		goto end;
	}

	/* Allocate cyphertxt placeholder */
	if (NULL == (cipher_txt->emBody = sdoByteArrayAlloc(cipherLength))) {
		goto end;
	}

	cipherText = cipher_txt->emBody->bytes;

	/* Get cypher text */
	if (0 != sdoMsgEncrypt(ct, clear_txt_size, cipherText, &cipherLength,
			       cipher_txt->iv)) {
		LOG(LOG_ERROR, "Failed to get encrypt.\n");
		goto end;
	}

	/* one extra byte for null */
	size_of_b64iv = binToB64Length(AES_IV) + 2;
	temp_buf_iv = sdoAlloc(size_of_b64iv);

	size_of_b64ct = binToB64Length(cipherLength) + 2;
	temp_buf_ct = sdoAlloc(size_of_b64ct);

	(void)binToB64(AES_IV, cipher_txt->iv, 0, size_of_b64iv, temp_buf_iv,
		       0);

	(void)binToB64(cipherLength, cipherText, 0, size_of_b64ct, temp_buf_ct,
		       0);

	/* total size of the string is size of iv + iv + size of cipher text +
	 * cipher text + 11 json string characters.
	 */
	total_size_local_buf = sizeof(uint16_t) + size_of_b64iv +
			       size_of_b64ct + 11 + sizeof(uint16_t);
	local_buf = sdoAlloc(total_size_local_buf);
	if (!local_buf) {
		LOG(LOG_ERROR, "Alloc failed \n");
		goto end;
	}

	/* Create a string on which the hmac is calculated.
	 * According to spec [[ivsize,"iv"],size,"cipher_text"]
	 */
	if ((cnt = snprintf_s_i(local_buf, total_size_local_buf, "[[%u,",
				AES_IV)) < 0) {
		LOG(LOG_ERROR, "unable to create the ct string\n");
		goto end;
	}
	bytes_written = cnt;
	if ((cnt = snprintf_s_si(local_buf + bytes_written,
				 total_size_local_buf - bytes_written,
				 "\"%s\"],%u,\"", (char *)temp_buf_iv,
				 cipherLength)) < 0) {
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
	if (0 != sdoTo2HMAC((uint8_t *)local_buf, strlen(local_buf),
			    cipher_txt_hmac->hash->bytes,
			    cipher_txt_hmac->hash->byteSz)) {
		goto end;
	}

	cipher_txt->hmac = cipher_txt_hmac;
	ret = 0;
end:
	if (temp) {
		sdoFree(temp);
	}
	if (NULL != temp_buf_iv) {
		sdoFree(temp_buf_iv);
	}
	if (NULL != temp_buf_ct) {
		sdoFree(temp_buf_ct);
	}
	if (NULL != local_buf) {
		sdoFree(local_buf);
	}
	if (ret) {
		if (cipher_txt_hmac)
			sdoHashFree(cipher_txt_hmac);
		if (cipher_txt->emBody) {
			sdoByteArrayFree(cipher_txt->emBody);
			cipher_txt->emBody = NULL;
		}
	}
	return ret;
}

/**
 * Decrypt a SDOEncryptedPacket object to an SDOString_t. Also calculate HMAC of
 * decrypted text and compare it with received HMAC.
 *
 * @param cipher_txt
 *        Cipher text to be decrypted and HMAC to be verified.
 * @param clear_txt
 *        Buffer to place the decrypted text.
 * @return ret
 *        return 0 on success. -1 on failure.
 */
int aes_decrypt_packet(SDOEncryptedPacket_t *cipher_txt, SDOString_t *clear_txt)
{
	int ret = -1;
	uint32_t clearTextLength = 0;
	SDOHash_t *cipher_txt_hmac = NULL;
	uint8_t *cleartext = NULL;
	int result = 0;

	if (NULL == cipher_txt || NULL == cipher_txt->emBody ||
	    NULL == cipher_txt->hmac || NULL == cipher_txt->ctString) {
		return -1;
	}

	clearTextLength = cipher_txt->emBody->byteSz;

	ret =
	    sdoMsgDecryptGetPTLen(cipher_txt->emBody->byteSz, &clearTextLength);
	if (ret != 0) {
		LOG(LOG_ERROR, "Can't get required clear text size\n");
		goto end;
	}

	cleartext = sdoAlloc(clearTextLength);
	if (!cleartext) {
		LOG(LOG_ERROR, "Failed to allocate cleartext buffer\n");
		goto end;
	}

	/* Create an HMAC of the decrypted message. */
	cipher_txt_hmac =
	    sdoHashAlloc(SDO_CRYPTO_HMAC_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);

	if (!cipher_txt_hmac) {
		LOG(LOG_ERROR, "failed to allocated memory: sdo-hash struct\n");
		goto end;
	}

	if (0 != sdoTo2HMAC(cipher_txt->ctString->bytes,
			    cipher_txt->ctString->byteSz - 1,
			    cipher_txt_hmac->hash->bytes,
			    cipher_txt_hmac->hash->byteSz)) {
		LOG(LOG_ERROR, "Failed to perform HMAC\n");
		goto end;
	}

	/* If the HMACs do not match, give an error. */
	memcmp_s(cipher_txt_hmac->hash->bytes, cipher_txt_hmac->hash->byteSz,
		 cipher_txt->hmac->hash->bytes, cipher_txt_hmac->hash->byteSz,
		 &result);

	if (result != 0) {
		LOG(LOG_ERROR, "sdoAESDecryptPacket : FAILED, HMACs do "
			       "not compare\n");
		goto end;
	}

	if (0 != sdoMsgDecrypt(cleartext, &clearTextLength,
			       cipher_txt->emBody->bytes,
			       cipher_txt->emBody->byteSz, cipher_txt->iv)) {
		LOG(LOG_ERROR, "Failed to Decrypt\n");
		goto end;
	}

	/*
	 * TODO: Since, clear_txt is defined with a string data structure, so,
	 * resizing using that API, and memcpy to it as cleartext is
	 * without NULL termination. So, it must be moved to a different
	 * data structure.
	 */
	if (sdoStringResize(clear_txt, clearTextLength) == false) {
		LOG(LOG_ERROR, "Failed to resize clear text buffer\n");
		goto end;
	}

	if (memcpy_s(clear_txt->bytes, clearTextLength, cleartext,
		     clearTextLength)) {
		LOG(LOG_ERROR, "Copying cleartext failed\n");
		goto end;
	}

#ifdef AES_MODE_CTR_ENABLED
	cipher_txt->offset = cipher_txt->emBody->byteSz % SDO_AES_BLOCK_SIZE;
#endif
	ret = 0;
end:
	if (cleartext)
		sdoFree(cleartext);
	if (cipher_txt_hmac)
		sdoHashFree(cipher_txt_hmac);
	return ret;
}
