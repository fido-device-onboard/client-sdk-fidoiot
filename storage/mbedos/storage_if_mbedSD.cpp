/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Storage Abstraction Layer Library
 *
 * The file implements storage abstraction layer for Mbedos running on CortexM.
 */

#include "storage_al.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include "util.h"
#include "sdoCryptoHal.h"
#include "crypto_utils.h"
#include "platform_utils.h"

extern "C" {
extern int strncat_s(char *dest, size_t dmax, const char *src, size_t slen);
extern int memset_s(void *dest, size_t dmax, uint8_t value);
extern int memcpy_s(void *dest, size_t dmax, const void *src, size_t slen);
extern int memcmp_s(const void *dest, size_t dmax, const void *src, size_t slen,
		    int *diff);
extern size_t strnlen_s(const char *s, size_t smax);
}

#define SD_MOUNT_POINT "/sd/"

#define MAX_FILE_PATH 100

static int getSDfilepath(char *filepath, const char *name)
{
	int ret = -1;
	/* convert "data/filename" to "/sd/data/filename" */
	ret = strncat_s(filepath, MAX_FILE_PATH, (const char *)SD_MOUNT_POINT,
			sizeof(SD_MOUNT_POINT));
	if (ret)
		return -1;
	ret = strncat_s(filepath, MAX_FILE_PATH - sizeof(SD_MOUNT_POINT),
			(const char *)(name), strnlen_s(name, MAX_FILE_PATH));
	if (ret)
		return -1;
	return 0;
}

/****************************************************
 *
 * Note on secure blob storage implementation
 *   1. The current IV used is 12 bytes – this allows the IV to be
 *      used directly to build the counter by OpenSSL and mbedTLS
 *   2. When the IV is read from the file in order to perform encryption:
 *   	a.Calculate the number of AES blocks the encryption will perform
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
 * sdoBlobSize Get specified SDO blob(file) size
 *
 * @param name - pointer to the blob/file name
 * @param flags - descriptor telling type of file
 * @return file size on success, 0 if file does not exits, -1 on failure
 */

int32_t sdoBlobSize(const char *name, sdoSdkBlobFlags flags)
{
	int32_t retval = -1;
	char filepath[MAX_FILE_PATH + 1] = {0};
	if (name == NULL)
		return -1;

	if (getSDfilepath(filepath, name) == -1)
		return -1;

	if (file_exists(filepath) == false) {
		LOG(LOG_DEBUG, "%s file does not exist!\n", filepath);
		retval = 0;
		goto end;
	}

	switch (flags) {
	case SDO_SDK_RAW_DATA:
		/* Raw Files are stored as plain files */
		retval = (int32_t)(get_file_size(filepath));
		break;
	case SDO_SDK_NORMAL_DATA:
		/* Normal blob is stored as:
		 * [HMAC(32bytes)||data-content-size(4bytes)||data-content(?)]
		 */
		retval = (int32_t)(get_file_size(filepath) -
				   PLATFORM_HMAC_SIZE - BLOB_CONTENT_SIZE);
		break;
	case SDO_SDK_SECURE_DATA:
		/* Secure blob is stored as:
		 * [IV_data(12byte)||TAG(16bytes)||
		 * data-content-size(4bytes)||data-content(?)]
		 */
		retval =
		    (int32_t)(get_file_size(filepath) - PLATFORM_GCM_TAG_SIZE -
			      PLATFORM_IV_DEFAULT_LEN - BLOB_CONTENT_SIZE);
		break;
	default:
		LOG(LOG_ERROR, "Invalid storage flag:%d!\n", flags);
		goto end;
	}

end:
	if (retval > R_MAX_SIZE) {
		LOG(LOG_ERROR, "File size is more than R_MAX_SIZE\n");
		retval = -1;
	}
	return retval;
}

/**
 * sdoBlobRead Read SDO blob(file) into specified buffer,
 * sdoBlobRead ensures authenticity &  integrity for non-secure
 * data & additionally confidentiality for secure data.
 * Note: SDO_SDK_OTP_DATA flag is not supported for this platform.
 * @param name - pointer to the blob/file name
 * @param flags - descriptor telling type of file
 * @param buf - pointer to buf where data is read into
 * @param nBytes - length of data(in bytes) to be read
 * @return num of bytes read if success, -1 on error
 */
int32_t sdoBlobRead(const char *name, sdoSdkBlobFlags flags, uint8_t *buf,
		    uint32_t nBytes)
{
	if (!name || !buf)
		return -1;

	if (nBytes == 0) {
		LOG(LOG_ERROR, "Can not read 0 bytes!\n");
		return -1;
	}

	int retval = -1;
	char filepath[MAX_FILE_PATH + 1] = {0};
	if (getSDfilepath(filepath, name) == -1)
		return -1;

	uint8_t *data = NULL;
	uint32_t dataLength = 0;
	uint8_t *sealedData = NULL;
	uint32_t sealedDataLen = 0;
	uint8_t *encryptedData = NULL;
	uint32_t encryptedDataLen = 0;
	uint8_t storedHmac[PLATFORM_HMAC_SIZE] = {0};
	uint8_t computedHmac[PLATFORM_HMAC_SIZE] = {0};
	uint8_t storedTag[PLATFORM_GCM_TAG_SIZE] = {0};
	int strcmp_result = -1;
	uint8_t iv[PLATFORM_IV_DEFAULT_LEN] = {0};
	uint8_t aes_key[PLATFORM_AES_KEY_DEFAULT_LEN] = {0};
	uint8_t hmac_key[PLATFORM_HMAC_KEY_DEFAULT_LEN] = {0};
	size_t datLen_offst = 0;

	if (nBytes > R_MAX_SIZE) {
		LOG(LOG_ERROR, "file read buffer is more than R_MAX_SIZE in "
			       "sdoBlobRead()!\n");
		goto exit;
	}

	switch (flags) {
	case SDO_SDK_RAW_DATA:
		// Raw Files are stored as plain files
		if (0 != read_buffer_from_file(filepath, buf, nBytes)) {
			LOG(LOG_ERROR, "Failed to read %s file!\n", filepath);
			goto exit;
		}
		break;

	case SDO_SDK_NORMAL_DATA:
		/* HMAC-256 is being used to store files under
		 * SDO_SDK_NORMAL_DATA flag.
		 * File content to be stored as:
		 * [HMAC(32 bytes)||SizeofPlaintext(4 bytes)||Plaintext(nBytes
		 * bytes)] */

		sealedDataLen = PLATFORM_HMAC_SIZE + BLOB_CONTENT_SIZE + nBytes;

		if (NULL == (sealedData = (uint8_t *)sdoAlloc(sealedDataLen))) {
			LOG(LOG_ERROR, "Malloc Failed in sdoBlobRead()!\n");
			goto exit;
		}

		if (0 != read_buffer_from_file(filepath, sealedData,
					       sealedDataLen)) {
			LOG(LOG_ERROR, "Failed to read %s file!\n", filepath);
			goto exit;
		}

		// get actual data length
		dataLength |= sealedData[PLATFORM_HMAC_SIZE] << 24;
		dataLength |= sealedData[PLATFORM_HMAC_SIZE + 1] << 16;
		dataLength |= sealedData[PLATFORM_HMAC_SIZE + 2] << 8;
		dataLength |= sealedData[PLATFORM_HMAC_SIZE + 3];

		// check if input buffer is sufficient ?
		if (nBytes < dataLength) {
			LOG(LOG_ERROR,
			    "Failed to read data, Buffer is not enough, "
			    "bufLen:%d,\t Lengthstoredinfilesystem:%d\n",
			    (int)nBytes, (int)dataLength);
			goto exit;
		}

		if (memcpy_s(storedHmac, PLATFORM_HMAC_SIZE, sealedData,
			     PLATFORM_HMAC_SIZE) != 0) {
			LOG(LOG_ERROR, "Copying stored HMAC failed during "
				       "sdoBlobRead()!\n");
			goto exit;
		}

		data = sealedData + PLATFORM_HMAC_SIZE + BLOB_CONTENT_SIZE;

		if (!getPlatformHMACKey(hmac_key,
					PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR, "Could not get platform IV!\n");
			goto exit;
		}

		// compute HMAC
		if (0 != sdoCryptoHMAC(SDO_CRYPTO_HMAC_TYPE_SHA_256, data,
				       dataLength, computedHmac,
				       PLATFORM_HMAC_SIZE, hmac_key,
				       HMACSHA256_KEY_SIZE)) {
			LOG(LOG_ERROR,
			    "HMAC computation dailed during sdoBlobRead()!\n");
			goto exit;
		}

		// compare HMAC
		memcmp_s(storedHmac, PLATFORM_HMAC_SIZE, computedHmac,
			 PLATFORM_HMAC_SIZE, &strcmp_result);
		if (strcmp_result != 0) {
			LOG(LOG_ERROR,
			    "sdoBlobRead(): HMACs do not compare!\n");
			goto exit;
		}

		// copy data into supplied buffer
		if (memcpy_s(buf, nBytes, data, dataLength) != 0) {
			LOG(LOG_ERROR, "sdoBlobRead(): Copying data into "
				       "buffer failed!\n");
			goto exit;
		}
		break;

	case SDO_SDK_SECURE_DATA:
		/* AES GCM authenticated encryption is being used to store files
		 * under
		 * SDO_SDK_SECURE_DATA flag. File content to be stored as:
		 * [IV_data(12byte)||[AuthenticatedTAG(16 bytes)||
		 * SizeofCiphertext(8 * bytes)||Ciphertet(nBytes bytes)] */

		encryptedDataLen = PLATFORM_IV_DEFAULT_LEN +
				   PLATFORM_GCM_TAG_SIZE + BLOB_CONTENT_SIZE +
				   nBytes;

		if (NULL ==
		    (encryptedData = (uint8_t *)sdoAlloc(encryptedDataLen))) {
			LOG(LOG_ERROR, "Malloc Failed in sdoBlobRead()!\n");
			goto exit;
		}

		if (0 != read_buffer_from_file(filepath, encryptedData,
					       encryptedDataLen)) {
			LOG(LOG_ERROR, "Failed to read %s file!\n", filepath);
			goto exit;
		}

		datLen_offst = PLATFORM_GCM_TAG_SIZE + PLATFORM_IV_DEFAULT_LEN;
		// get actual data length
		dataLength |= encryptedData[datLen_offst] << 24;
		dataLength |= encryptedData[datLen_offst + 1] << 16;
		dataLength |= encryptedData[datLen_offst + 2] << 8;
		dataLength |= encryptedData[datLen_offst + 3];

		// check if input buffer is sufficient ?
		if (nBytes < dataLength) {
			LOG(LOG_ERROR,
			    "Failed to read data, Buffer is not enough,\
			    bufLen:%d,\t Lengthstoredinfilesystem:%d\n",
			    (int)nBytes, (int)dataLength);
			goto exit;
		}
		/* read the iv from blob */
		if (memcpy_s(iv, PLATFORM_IV_DEFAULT_LEN, encryptedData,
			     PLATFORM_IV_DEFAULT_LEN) != 0) {
			LOG(LOG_ERROR, "Copying stored IV failed during "
				       "sdoBlobRead()!\n");
			goto exit;
		}

		if (memcpy_s(storedTag, PLATFORM_GCM_TAG_SIZE,
			     encryptedData + PLATFORM_IV_DEFAULT_LEN,
			     PLATFORM_GCM_TAG_SIZE) != 0) {
			LOG(LOG_ERROR, "Copying stored TAG failed during "
				       "sdoBlobRead()!\n");
			goto exit;
		}

		data = encryptedData + PLATFORM_IV_DEFAULT_LEN +
		       PLATFORM_GCM_TAG_SIZE + BLOB_CONTENT_SIZE;

		if (!getPlatformAESKey(aes_key, PLATFORM_AES_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR, "Could not get platform AES Key!\n");
			goto exit;
		}

		// decrypt and authenticate cipher-text content and fill the
		// given buffer with clear-text
		if (sdoCryptoAESGcmDecrypt(buf, nBytes, data, dataLength, iv,
					   PLATFORM_IV_DEFAULT_LEN, aes_key,
					   PLATFORM_AES_KEY_DEFAULT_LEN,
					   storedTag, AES_GCM_TAG_LEN) < 0) {
			LOG(LOG_ERROR, "Decryption failed during Secure "
				       "Blob Read!\n");
			goto exit;
		}
		break;

	default:
		LOG(LOG_ERROR, "Invalid SDO blob flag!!\n");
		goto exit;
	}

	retval = (int32_t)nBytes;

exit:
	if (sealedData)
		sdoFree(sealedData);
	if (encryptedData)
		sdoFree(encryptedData);
	if (memset_s(hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN, 0)) {
                LOG(LOG_ERROR, "Failed to clear HMAC key\n");
		retval = -1;
	}
        if (memset_s(aes_key, PLATFORM_AES_KEY_DEFAULT_LEN, 0)) {
                LOG(LOG_ERROR, "Failed to clear AES key\n");
		retval = -1;
	}
	return retval;
}

/**
 * sdoBlobWrite Write SDO blob(file) from specified buffer
 * sdoBlobWrite ensures integrity & authenticity for non-secure
 * data & additionally confidentiality for secure data.
 * Note: SDO_SDK_OTP_DATA flag is not supported for this platform.
 * @param name - pointer to the blob/file name
 * @param flags - descriptor telling type of file
 * @param buf - pointer to buf from where data is read and then written
 * @param nBytes - length of data(in bytes) to be written
 * @return num of bytes write if success, -1 on error
 */

int32_t sdoBlobWrite(const char *name, sdoSdkBlobFlags flags,
		     const uint8_t *buf, uint32_t nBytes)
{
	if (!buf || !name)
		return -1;

	if (nBytes == 0) {
		LOG(LOG_ERROR, "Can not write 0 bytes!\n");
		return -1;
	}

	char filepath[MAX_FILE_PATH + 1] = {0};
	if (getSDfilepath(filepath, name) == -1)
		return -1;

	/*File content to be stored as HMAC_DIGEST+SizeofCipherText+CipherText
	 * for SDO_SDK_SECURE_DATA flag,
	 * HMAC_DIGEST+SizeofPlaintext+Plaintext for SDO_SDK_NORMAL_DATA flag.
	 */

	FILE *f = NULL;
	uint32_t writeContextLen = 0;
	uint8_t *writeContext = NULL;
	int retval = -1;
	size_t bytesWritten = 0;
	uint8_t tag[PLATFORM_GCM_TAG_SIZE] = {0};
	uint8_t iv[PLATFORM_IV_DEFAULT_LEN] = {0};
	uint8_t aes_key[PLATFORM_AES_KEY_DEFAULT_LEN] = {0};
	uint8_t hmac_key[PLATFORM_HMAC_KEY_DEFAULT_LEN] = {0};
	size_t datLen_offst = 0;

	if (nBytes > R_MAX_SIZE) {
		LOG(LOG_ERROR, "file write buffer is more than R_MAX_SIZE in "
			       "sdoBlobRead()!\n");
		goto exit;
	}

	switch (flags) {
	case SDO_SDK_RAW_DATA:
		// Raw Files are stored as plain files
		writeContextLen = nBytes;

		if (NULL ==
		    (writeContext = (uint8_t *)sdoAlloc(writeContextLen))) {
			LOG(LOG_ERROR, "Malloc Failed in sdoBlobWrite!\n");
			goto exit;
		}

		if (memcpy_s(writeContext, writeContextLen, buf, nBytes) != 0) {
			LOG(LOG_ERROR,
			    "Copying data failed during RAW Blob write!\n");
			goto exit;
		}
		break;

	case SDO_SDK_NORMAL_DATA:
		/* HMAC-256 is being used to store files under
		 * SDO_SDK_NORMAL_DATA flag.
		 * File content to be stored as:
		 * [HMAC(32 bytes)||SizeofPlaintext(4 bytes)||Plaintext(nBytes
		 * bytes)] */
		writeContextLen =
		    PLATFORM_HMAC_SIZE + BLOB_CONTENT_SIZE + nBytes;

		if (NULL ==
		    (writeContext = (uint8_t *)sdoAlloc(writeContextLen))) {
			LOG(LOG_ERROR, "Malloc Failed in sdoBlobWrite!\n");
			goto exit;
		}

		if (!getPlatformHMACKey(hmac_key,
					PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR, "Could not get hmac_key!\n");
			goto exit;
		}

		if (0 != sdoCryptoHMAC(SDO_CRYPTO_HMAC_TYPE_SHA_256, buf,
				       nBytes, writeContext, PLATFORM_HMAC_SIZE,
				       hmac_key, HMACSHA256_KEY_SIZE)) {
			LOG(LOG_ERROR, "Computing HMAC failed during Normal "
				       "Blob write!\n");
			goto exit;
		}

		// copy plain-text size
		writeContext[PLATFORM_HMAC_SIZE + 3] = nBytes >> 0;
		writeContext[PLATFORM_HMAC_SIZE + 2] = nBytes >> 8;
		writeContext[PLATFORM_HMAC_SIZE + 1] = nBytes >> 16;
		writeContext[PLATFORM_HMAC_SIZE + 0] = nBytes >> 24;

		// copy plain-text content
		if (memcpy_s(writeContext + PLATFORM_HMAC_SIZE +
				 BLOB_CONTENT_SIZE,
			     writeContextLen, buf, nBytes) != 0) {
			LOG(LOG_ERROR,
			    "Copying data failed during Normal Blob write!\n");
			goto exit;
		}
		break;

	case SDO_SDK_SECURE_DATA:
		/* AES GCM authenticated encryption is being used to store files
		 * under
		 * SDO_SDK_SECURE_DATA flag. File content to be stored as:
		 * [IV_data(12byte)AuthenticatedTAG(16
		 * bytes)||SizeofCiphertext(8
		 * bytes)||Ciphertet(nBytes bytes)] */
		writeContextLen = PLATFORM_IV_DEFAULT_LEN +
				  PLATFORM_GCM_TAG_SIZE + BLOB_CONTENT_SIZE +
				  nBytes;

		if (NULL ==
		    (writeContext = (uint8_t *)sdoAlloc(writeContextLen))) {
			LOG(LOG_ERROR, "Malloc Failed in sdoBlobWrite()!\n");
			goto exit;
		}

		if (!getPlatformIV(iv, PLATFORM_IV_DEFAULT_LEN, nBytes)) {
			LOG(LOG_ERROR, "Could not get platform IV!\n");
			goto exit;
		}

		if (!getPlatformAESKey(aes_key, PLATFORM_AES_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR, "Could not get platform AES Key!\n");
			goto exit;
		}

		// encrypt plain-text and copy cipher-text content
		if (sdoCryptoAESGcmEncrypt(
			buf, nBytes,
			writeContext + PLATFORM_IV_DEFAULT_LEN +
			    PLATFORM_GCM_TAG_SIZE + BLOB_CONTENT_SIZE,
			writeContextLen, iv, PLATFORM_IV_DEFAULT_LEN, aes_key,
			PLATFORM_AES_KEY_DEFAULT_LEN, tag,
			AES_GCM_TAG_LEN) < 0) {
			LOG(LOG_ERROR, "Encypting data failed during Secure "
				       "Blob write!\n");
			goto exit;
		}

		// copy used IV for encryption
		if (memcpy_s(writeContext, PLATFORM_IV_DEFAULT_LEN, iv,
			     PLATFORM_IV_DEFAULT_LEN) != 0) {
			LOG(LOG_ERROR, "Copying TAG value failed during Secure "
				       "Blob write!\n");
			goto exit;
		}
		// copy Authenticated TAG value
		if (memcpy_s(writeContext + PLATFORM_IV_DEFAULT_LEN,
			     writeContextLen, tag,
			     PLATFORM_GCM_TAG_SIZE) != 0) {
			LOG(LOG_ERROR, "Copying TAG value failed during Secure "
				       "Blob write!\n");
			goto exit;
		}

		datLen_offst = PLATFORM_GCM_TAG_SIZE + PLATFORM_IV_DEFAULT_LEN;
		/* copy cipher-text size; CT size= PT size (AES GCM uses AES CTR
		 * mode internally for encryption) */
		writeContext[datLen_offst + 3] = nBytes >> 0;
		writeContext[datLen_offst + 2] = nBytes >> 8;
		writeContext[datLen_offst + 1] = nBytes >> 16;
		writeContext[datLen_offst + 0] = nBytes >> 24;
		break;

	default:
		LOG(LOG_ERROR, "Invalid SDO blob flag!!\n");
		goto exit;
	}

	f = fopen(filepath, "w");
	if (f != NULL) {
		bytesWritten =
		    fwrite(writeContext, sizeof(char), writeContextLen, f);
		if (bytesWritten != writeContextLen) {
			LOG(LOG_ERROR, "file:%s not written properly\n",
			    filepath);
			goto exit;
		}
	} else {
		LOG(LOG_ERROR, "Could not open file: %s\n", filepath);
		goto exit;
	}

	retval = (int32_t)nBytes;

exit:
	if (writeContext)
		sdoFree(writeContext);
	if (f)
		if (fclose(f) == EOF) {
			LOG(LOG_ERROR, "fclose() Failed in sdoBlobWrite\n");
			retval = -1;
		}
	if (memset_s(hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN, 0)) {
		LOG(LOG_ERROR, "Failed to clear HMAC key\n");
		retval = -1;
	}
	if (memset_s(aes_key, PLATFORM_AES_KEY_DEFAULT_LEN, 0)) {
		LOG(LOG_ERROR, "Failed to clear AES key\n");
		retval = -1;
	}
	return retval;
}

/**
 * sdoReadEPIDKey will read the key from file/partition(raw)
 * @param buffer - pointer to the buufer
 * @param size - length of buffer passed in buffer
 * @return num of bytes write if success, -1 on error
 */
int32_t sdoReadEPIDKey(uint8_t *buffer, uint32_t *size)
{
	char filepath[MAX_FILE_PATH + 1] = {0};
	if (!buffer || !size)
		return -1;

	if (*size == 0) {
		LOG(LOG_ERROR, "Can not read 0 bytes!\n");
		return -1;
	}
	if (getSDfilepath(filepath, (char *)EPID_PRIVKEY) == -1)
		return -1;

	if (0 != read_buffer_from_file(filepath, buffer, *size)) {
		LOG(LOG_ERROR, "Failed to read %s file!\n", EPID_PRIVKEY);
		return -1;
	}

	return (int32_t)*size;
}
