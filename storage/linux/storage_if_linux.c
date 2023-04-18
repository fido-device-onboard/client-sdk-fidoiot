/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Storage Abstraction Layer Library
 *
 * The file implements storage abstraction layer for Linux OS running on PC.
 */

#include "storage_al.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include "safe_lib.h"
#include "util.h"
#include "fdoCryptoHal.h"
#include "fdoCrypto.h"
#include "crypto_utils.h"
#include "platform_utils.h"

/****************************************************
 *
 * Note on secure blob storage implementation
 *   1. The current IV used is 12 bytes – this allows the IV to be
 *      used directly to build the counter by OpenSSL and mbedTLS
 *   2. When the IV is read from the file in order to perform encryption:
 *	a.Calculate the number of AES blocks the encryption will perform
 *	(datalength/16)
 *	b.If number of AES blocks < 2^32, increment the IV by one; otherwise
 *	increment the IV by 2
 *   3.	If the IV “rolls over” , further encryption is not allowed.
 *
 * How we handle roll over?
 *   1.	Rollover occurs when the IV has been incremented back to the original
 *	value set by the IV (2^(12*8) = 2^96)
 *   2.	we handle roll-over by follwing way:
 *	a. We save original IV value in first 12 byte of platform iv storage.
 *	b. We keep updated iv (counter) in last 12 byte of platform iv storage.
 *	c. During increment of iv we compare with original iv with the
 *	incrementd value.
 *	d. If rollover not detected, update the new iv in file and use the new
 *	iv for encryption.
 *	e. If rollover detected, further encryption is not allowed.
 *
 **********************************************************/

/**
 * fdo_blob_size Get specified FDO blob(file) size
 * Note: FDO_SDK_OTP_DATA flag is not supported for this platform.
 * @param name - pointer to the blob/file name
 * @param flags - descriptor telling type of file
* @return file size on success, 0 if file does not exist or on other failure
 */

size_t fdo_blob_size(const char *name, fdo_sdk_blob_flags flags)
{
	size_t retval = 0;
	const size_t NORMAL_BLOB_OVERHEAD = PLATFORM_HMAC_SIZE + BLOB_CONTENT_SIZE;
	const size_t SECURE_BLOB_OVERHEAD = AES_TAG_LEN +
					PLATFORM_IV_DEFAULT_LEN + BLOB_CONTENT_SIZE;

	if (!name) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		goto end;
	}

	if (file_exists(name) == false) {
		LOG(LOG_DEBUG, "%s file does not exist!\n", name);
		retval = 0;
		goto end;
	}

	// Return 0 if the file is empty.
	if (get_file_size(name) == 0) {
		LOG(LOG_DEBUG, "%s file is empty!\n", name);
		retval = 0;
		goto end;
	}

	switch (flags) {
	case FDO_SDK_RAW_DATA:
		/* Raw Files are stored as plain files */
		retval = get_file_size(name);
		break;
	case FDO_SDK_NORMAL_DATA:
		/* Normal blob is stored as:
		 * [HMAC(32bytes)||data-content-size(4bytes)||data-content(?)]
		 */
		retval = get_file_size(name);
		if (retval >= NORMAL_BLOB_OVERHEAD) {
			retval -= NORMAL_BLOB_OVERHEAD;
		} else {
			/* File format is not correct, not enough data in the file */
			retval = 0;
		}
		break;
	case FDO_SDK_SECURE_DATA:
		/* Secure blob is stored as:
		 * [IV_data(12byte)||TAG(16bytes)||
		 * data-content-size(4bytes)||data-content(?)]
		 */
		retval = get_file_size(name);
		if (retval >= SECURE_BLOB_OVERHEAD) {
			retval -= SECURE_BLOB_OVERHEAD;
		} else {
			/* File format is not correct, not enough data in the file */
			retval = 0;
		}
		break;
	default:
		LOG(LOG_ERROR, "Invalid storage flag:%d!\n", flags);
		goto end;
	}

end:
	if (retval > R_MAX_SIZE) {
		LOG(LOG_ERROR, "File size is more than R_MAX_SIZE\n");
		retval = 0;
	}
	return retval;
}

/**
 * fdo_blob_read Read FDO blob(file) into specified buffer,
 * fdo_blob_read ensures authenticity &  integrity for non-secure
 * data & additionally confidentiality for secure data.
 * Note: FDO_SDK_OTP_DATA flag is not supported for this platform.
 * @param name - pointer to the blob/file name
 * @param flags - descriptor telling type of file
 * @param buf - pointer to buf where data is read into
 * @param n_bytes - length of data(in bytes) to be read
 * @return num of bytes read if success, -1 on error
 */
int32_t fdo_blob_read(const char *name, fdo_sdk_blob_flags flags, uint8_t *buf,
		      uint32_t n_bytes)
{
	int retval = -1;
	uint8_t *data = NULL;
	uint32_t data_length = 0;
	uint8_t *sealed_data = NULL;
	uint32_t sealed_data_len = 0;
	uint8_t *encrypted_data = NULL;
	uint32_t encrypted_data_len = 0;
	uint8_t stored_hmac[PLATFORM_HMAC_SIZE] = {0};
	uint8_t computed_hmac[PLATFORM_HMAC_SIZE] = {0};
	uint8_t stored_tag[AES_TAG_LEN] = {0};
	int strcmp_result = -1;
	uint8_t iv[PLATFORM_IV_DEFAULT_LEN] = {0};
	uint8_t aes_key[PLATFORM_AES_KEY_DEFAULT_LEN] = {0};
	size_t dat_len_offst = 0;

	if (!name || !buf || n_bytes == 0) {
		LOG(LOG_ERROR, "Invalid parameters in %s!\n", __func__);
		goto exit;
	}

	if (n_bytes > R_MAX_SIZE) {
		LOG(LOG_ERROR,
		    "file read buffer is more than R_MAX_SIZE in "
		    "%s!\n",
		    __func__);
		goto exit;
	}

	switch (flags) {
	case FDO_SDK_RAW_DATA:
		// Raw Files are stored as plain files
		if (0 != read_buffer_from_file(name, buf, n_bytes)) {
			LOG(LOG_ERROR, "Failed to read %s file!\n", name);
			goto exit;
		}
		break;

	case FDO_SDK_NORMAL_DATA:
		/* HMAC-256 is being used to store files under
		 * FDO_SDK_NORMAL_DATA flag.
		 * File content to be stored as:
		 * [HMAC(32 bytes)||Sizeof_plaintext(4 bytes)||Plaintext(n_bytes
		 * bytes)]
		 */

		sealed_data_len =
		    PLATFORM_HMAC_SIZE + BLOB_CONTENT_SIZE + n_bytes;

		sealed_data = fdo_alloc(sealed_data_len);
		if (NULL == sealed_data) {
			LOG(LOG_ERROR, "Malloc Failed in %s!\n", __func__);
			goto exit;
		}

		if (0 !=
		    read_buffer_from_file(name, sealed_data, sealed_data_len)) {
			LOG(LOG_ERROR, "Failed to read %s file!\n", name);
			goto exit;
		}

		// get actual data length
		data_length |= sealed_data[PLATFORM_HMAC_SIZE] << 24;
		data_length |= sealed_data[PLATFORM_HMAC_SIZE + 1] << 16;
		data_length |= sealed_data[PLATFORM_HMAC_SIZE + 2] << 8;
		data_length |=
		    (sealed_data[PLATFORM_HMAC_SIZE + 3] & 0x000000FF);

		// check if input buffer is sufficient ?
		if (n_bytes < data_length) {
			LOG(LOG_ERROR,
			    "Failed to read data, Buffer is not enough, "
			    "buf_len:%d,\t Lengthstoredinfilesystem:%d\n",
			    n_bytes, data_length);
			goto exit;
		}

		if (memcpy_s(stored_hmac, PLATFORM_HMAC_SIZE, sealed_data,
			     PLATFORM_HMAC_SIZE) != 0) {
			LOG(LOG_ERROR,
			    "Copying stored HMAC failed during "
			    "%s!\n",
			    __func__);
			goto exit;
		}

		data = sealed_data + PLATFORM_HMAC_SIZE + BLOB_CONTENT_SIZE;

		if (0 != fdo_compute_storage_hmac(data, data_length,
						  computed_hmac,
						  PLATFORM_HMAC_SIZE)) {
			LOG(LOG_ERROR,
			    "HMAC computation dailed during"
			    " %s!\n",
			    __func__);
			goto exit;
		}

		// compare HMAC
		if (memcmp_s(stored_hmac, PLATFORM_HMAC_SIZE, computed_hmac,
			 PLATFORM_HMAC_SIZE, &strcmp_result) != 0) {
			LOG(LOG_ERROR, "Failed to compare HMAC\n");
			goto exit;
		}
		if (strcmp_result != 0) {
			LOG(LOG_ERROR, "%s: HMACs do not compare!\n", __func__);
			goto exit;
		}

		// copy data into supplied buffer
		if (memcpy_s(buf, n_bytes, data, data_length) != 0) {
			LOG(LOG_ERROR,
			    "%s: Copying data into "
			    "buffer failed!\n",
			    __func__);
			goto exit;
		}
		break;

	case FDO_SDK_SECURE_DATA:
		/* AES GCM authenticated encryption is being used to store files
		 * under
		 * FDO_SDK_SECURE_DATA flag. File content to be stored as:
		 * [IV_data(12byte)||[AuthenticatedTAG(16 bytes)||
		 * Sizeof_ciphertext(8 * bytes)||Ciphertet(n_bytes bytes)]
		 */

		encrypted_data_len = PLATFORM_IV_DEFAULT_LEN +
				     AES_TAG_LEN + BLOB_CONTENT_SIZE +
				     n_bytes;

		encrypted_data = fdo_alloc(encrypted_data_len);
		if (NULL == encrypted_data) {
			LOG(LOG_ERROR, "Malloc Failed in %s!\n", __func__);
			goto exit;
		}

		if (0 != read_buffer_from_file(name, encrypted_data,
					       encrypted_data_len)) {
			LOG(LOG_ERROR, "Failed to read %s file!\n", name);
			goto exit;
		}

		dat_len_offst = AES_TAG_LEN + PLATFORM_IV_DEFAULT_LEN;
		// get actual data length
		data_length |= encrypted_data[dat_len_offst] << 24;
		data_length |= encrypted_data[dat_len_offst + 1] << 16;
		data_length |= encrypted_data[dat_len_offst + 2] << 8;
		data_length |= (encrypted_data[dat_len_offst + 3] & 0x000000FF);

		// check if input buffer is sufficient ?
		if (n_bytes < data_length) {
			LOG(LOG_ERROR,
			    "Failed to read data, Buffer is not enough, "
			    "buf_len:%d,\t Lengthstoredinfilesystem:%d\n",
			    n_bytes, data_length);
			goto exit;
		}
		/* read the iv from blob */
		if (memcpy_s(iv, PLATFORM_IV_DEFAULT_LEN, encrypted_data,
			     PLATFORM_IV_DEFAULT_LEN) != 0) {
			LOG(LOG_ERROR,
			    "Copying stored IV failed during "
			    "%s!\n",
			    __func__);
			goto exit;
		}

		if (memcpy_s(stored_tag, AES_TAG_LEN,
			     encrypted_data + PLATFORM_IV_DEFAULT_LEN,
			     AES_TAG_LEN) != 0) {
			LOG(LOG_ERROR,
			    "Copying stored TAG failed during "
			    "%s!\n",
			    __func__);
			goto exit;
		}

		data = encrypted_data + PLATFORM_IV_DEFAULT_LEN +
		       AES_TAG_LEN + BLOB_CONTENT_SIZE;

		if (!get_platform_aes_key(aes_key,
					  PLATFORM_AES_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR, "Could not get platform AES Key!\n");
			goto exit;
		}

		// decrypt and authenticate cipher-text content and fill the
		// given buffer with clear-text
		if (crypto_hal_aes_decrypt(
			buf, &n_bytes, data, data_length, 16, iv,
			aes_key, PLATFORM_AES_KEY_DEFAULT_LEN,
			stored_tag, AES_TAG_LEN, NULL, 0) < 0) {
			LOG(LOG_ERROR, "Decryption failed during Secure "
				       "Blob Read!\n");
			goto exit;
		}
		break;

	default:
		LOG(LOG_ERROR, "Invalid FDO blob flag!!\n");
		goto exit;
	}

	retval = (int32_t)n_bytes;

exit:
	if (sealed_data) {
		fdo_free(sealed_data);
	}
	if (encrypted_data) {
		fdo_free(encrypted_data);
	}
	if (memset_s(aes_key, PLATFORM_AES_KEY_DEFAULT_LEN, 0)) {
		LOG(LOG_ERROR, "Failed to clear AES key\n");
		retval = -1;
	}
	return retval;
}

/**
 * fdo_blob_write Write FDO blob(file) from specified buffer
 * fdo_blob_write ensures integrity & authenticity for non-secure
 * data & additionally confidentiality for secure data.
 * Note: FDO_SDK_OTP_DATA flag is not supported for this platform.
 * @param name - pointer to the blob/file name
 * @param flags - descriptor telling type of file
 * @param buf - pointer to buf from where data is read and then written
 * @param n_bytes - length of data(in bytes) to be written
 * @return num of bytes write if success, -1 on error
 */

int32_t fdo_blob_write(const char *name, fdo_sdk_blob_flags flags,
		       const uint8_t *buf, uint32_t n_bytes)
{
	int retval = -1;
	FILE *f = NULL;
	uint32_t write_context_len = 0;
	uint32_t write_context_len_temp = 0;
	uint8_t *write_context = NULL;
	size_t bytes_written = 0;
	uint8_t tag[AES_TAG_LEN] = {0};
	uint8_t iv[PLATFORM_IV_DEFAULT_LEN] = {0};
	uint8_t aes_key[PLATFORM_AES_KEY_DEFAULT_LEN] = {0};
	size_t dat_len_offst = 0;

	if (!buf || !name || n_bytes == 0) {
		LOG(LOG_ERROR, "Invalid parameters in %s!\n", __func__);
		goto exit;
	}

	if (n_bytes > R_MAX_SIZE) {
		LOG(LOG_ERROR,
		    "file write buffer is more than R_MAX_SIZE in "
		    "%s!\n",
		    __func__);
		goto exit;
	}

	switch (flags) {
	case FDO_SDK_RAW_DATA:
		// Raw Files are stored as plain files
		write_context_len = n_bytes;

		write_context = fdo_alloc(write_context_len);
		if (NULL == write_context) {
			LOG(LOG_ERROR, "Malloc Failed in %s!\n", __func__);
			goto exit;
		}

		if (memcpy_s(write_context, write_context_len, buf, n_bytes) !=
		    0) {
			LOG(LOG_ERROR,
			    "Copying data failed during RAW Blob write!\n");
			goto exit;
		}
		break;

	case FDO_SDK_NORMAL_DATA:
		/* HMAC-256 is being used to store files under
		 * FDO_SDK_NORMAL_DATA flag.
		 * File content to be stored as:
		 * [HMAC(32 bytes)||Sizeof_plaintext(4 bytes)||Plaintext(n_bytes
		 * bytes)]
		 */
		write_context_len =
		    PLATFORM_HMAC_SIZE + BLOB_CONTENT_SIZE + n_bytes;

		write_context = fdo_alloc(write_context_len);
		if (NULL == write_context) {
			LOG(LOG_ERROR, "Malloc Failed in %s!\n", __func__);
			goto exit;
		}

		if (0 != fdo_compute_storage_hmac(buf, n_bytes, write_context,
						  PLATFORM_HMAC_SIZE)) {
			LOG(LOG_ERROR, "Computing HMAC failed during Normal "
				       "Blob write!\n");
			goto exit;
		}

		// copy plain-text size
		write_context[PLATFORM_HMAC_SIZE + 3] = n_bytes >> 0;
		write_context[PLATFORM_HMAC_SIZE + 2] = n_bytes >> 8;
		write_context[PLATFORM_HMAC_SIZE + 1] = n_bytes >> 16;
		write_context[PLATFORM_HMAC_SIZE + 0] = n_bytes >> 24;

		// copy plain-text content
		if (memcpy_s(write_context + PLATFORM_HMAC_SIZE +
				 BLOB_CONTENT_SIZE,
			     (write_context_len - PLATFORM_HMAC_SIZE -
			      BLOB_CONTENT_SIZE),
			     buf, n_bytes) != 0) {
			LOG(LOG_ERROR,
			    "Copying data failed during Normal Blob write!\n");
			goto exit;
		}
		break;

	case FDO_SDK_SECURE_DATA:
		/* AES GCM authenticated encryption is being used to store files
		 * under
		 * FDO_SDK_SECURE_DATA flag. File content to be stored as:
		 * [IV_data(12byte)||[AuthenticatedTAG(16 bytes)||
		 * Sizeof_ciphertext(8 * bytes)||Ciphertet(n_bytes bytes)]
		 */

		write_context_len = PLATFORM_IV_DEFAULT_LEN +
				    AES_TAG_LEN + BLOB_CONTENT_SIZE +
				    n_bytes;

		write_context = fdo_alloc(write_context_len);
		if (NULL == write_context) {
			LOG(LOG_ERROR, "Malloc Failed in %s!\n", __func__);
			goto exit;
		}

		if (!get_platform_iv(iv, PLATFORM_IV_DEFAULT_LEN, n_bytes)) {
			LOG(LOG_ERROR, "Could not get platform IV!\n");
			goto exit;
		}

		if (!get_platform_aes_key(aes_key,
					  PLATFORM_AES_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR, "Could not get platform AES Key!\n");
			goto exit;
		}

		write_context_len_temp = write_context_len - (PLATFORM_IV_DEFAULT_LEN +
			    AES_TAG_LEN + BLOB_CONTENT_SIZE);
		// encrypt plain-text and copy cipher-text content
		if (crypto_hal_aes_encrypt(
			buf, n_bytes,
			&write_context[PLATFORM_IV_DEFAULT_LEN +
			    AES_TAG_LEN + BLOB_CONTENT_SIZE],
			&write_context_len_temp,
			16, iv, aes_key,
			PLATFORM_AES_KEY_DEFAULT_LEN, tag,
			AES_TAG_LEN, NULL, 0) < 0) {
			LOG(LOG_ERROR, "Encypting data failed during Secure "
				       "Blob write!\n");
			goto exit;
		}
		// copy used IV for encryption
		if (memcpy_s(write_context, PLATFORM_IV_DEFAULT_LEN, iv,
			     PLATFORM_IV_DEFAULT_LEN) != 0) {
			LOG(LOG_ERROR, "Copying TAG value failed during Secure "
				       "Blob write!\n");
			goto exit;
		}

		// copy Authenticated TAG value
		if (memcpy_s(write_context + PLATFORM_IV_DEFAULT_LEN,
			     write_context_len - PLATFORM_IV_DEFAULT_LEN, tag,
			     AES_TAG_LEN) != 0) {
			LOG(LOG_ERROR, "Copying TAG value failed during Secure "
				       "Blob write!\n");
			goto exit;
		}

		dat_len_offst = AES_TAG_LEN + PLATFORM_IV_DEFAULT_LEN;
		/* copy cipher-text size; CT size= PT size (AES GCM uses AES CTR
		 * mode internally for encryption)
		 */
		write_context[dat_len_offst + 3] = n_bytes >> 0;
		write_context[dat_len_offst + 2] = n_bytes >> 8;
		write_context[dat_len_offst + 1] = n_bytes >> 16;
		write_context[dat_len_offst + 0] = n_bytes >> 24;
		break;

	default:
		LOG(LOG_ERROR, "Invalid FDO blob flag!!\n");
		goto exit;
	}

	f = fopen(name, "w");
	if (f != NULL) {
		bytes_written =
		    fwrite(write_context, sizeof(char), write_context_len, f);
		if (bytes_written != write_context_len) {
			LOG(LOG_ERROR, "file:%s not written properly\n", name);
			goto exit;
		}
	} else {
		LOG(LOG_ERROR, "Could not open file: %s\n", name);
		goto exit;
	}

	retval = (int32_t)n_bytes;

exit:
	if (write_context) {
		fdo_free(write_context);
	}
	if (f) {
		if (fclose(f) == EOF) {
			LOG(LOG_ERROR, "fclose() Failed in %s\n", __func__);
		}
	}
	if (memset_s(aes_key, PLATFORM_AES_KEY_DEFAULT_LEN, 0)) {
		LOG(LOG_ERROR, "Failed to clear AES key\n");
		retval = -1;
	}
	return retval;
}
