/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Platform key generation application
 *
 * The file implements platform level keys.
 * Note : ideally we shouldnot use hal api from application. as its reference
 * app we used it.
 * Note on implementation:
 *
 * 1) Generate platform hmac key, platform iv and platform aes_key using
 * platform random number generator. 2) Use generated hmac key to generate hmac
 * of normal blob data and prepend it to normal blob data in Normal.blob Format
 * : HMAC(32 byte) ||data size(4byte) || data-content (size ?) Pristine
 * Normal.blob have content `{"ST":1}`, Once its prepended with hmac during
 * configureNormalBlob call, new hmac generation is not tried on whole
 * Normal.blob data furter. Only hmac update happens for data content change.
 *
 */
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include "safe_lib.h"
#if defined(USE_OPENSSL)
#include <openssl/hmac.h>
#include <openssl/rand.h>
#elif defined(USE_MBEDTLS)
#include "mbedtls/md.h"
#endif
#include "storage_al.h"
#include "blob.h"
#include "sdoCryptoApi.h"
#if defined(DEVICE_TPM20_ENABLED)
#include "tpm20_Utils.h"
#endif

#if !defined(DEVICE_TPM20_ENABLED)
/* platform level rand no generation reference */
static int32_t *gen_rdm_bytestream(uint8_t *randomBuffer, size_t numBytes)
{
	size_t i;
	for (i = 0; i < numBytes; i++) {
		randomBuffer[i] = (uint8_t)(rand() % 255);
	}
	return 0;
}
#endif

int32_t configureNormalBlob(void)
{
	/* From the platfrom, read unsealed Normal Blob for the very first time
	 * and
	 * write back
	 * sealed Normal blob for SDO.
	 */
	size_t bytesWritten = 0;
	uint8_t *rawNormalBlob = NULL;
	size_t rawNormalBlobSize = 0;
	uint8_t *signedNormalBlob = NULL;
	size_t signedNormalBlobSize = 0;
	int32_t ret = -1;

#if defined(DEVICE_TPM20_ENABLED)
	if (0 == isValidTPMDataProtectionKeyPresent()) {
		if (0 != sdoGenerateStorageHMACKey()) {
			LOG(LOG_ERROR, "Failed to generate TPM data protection"
				       "key.\n");
			goto err;
		}

		LOG(LOG_DEBUG,
		    "TPM data protection key generated successfully.\n");
	}
#else
	uint8_t hmac_key[PLATFORM_HMAC_KEY_DEFAULT_LEN] = {0};

	size_t key_size_stored =
	    sdoBlobSize((const char *)PLATFORM_HMAC_KEY, SDO_SDK_RAW_DATA);
	if (key_size_stored == 0) {
		LOG(LOG_DEBUG,
		    "Platform HMAC key size is zero, DI not done!\n");

		if (0 != gen_rdm_bytestream((uint8_t *)hmac_key,
					    PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR, "Unable to generate hmac key for the "
				       "very first time!\n");
			goto err;
		}

		if (PLATFORM_HMAC_KEY_DEFAULT_LEN !=
		    sdoBlobWrite((const char *)PLATFORM_HMAC_KEY,
				 SDO_SDK_RAW_DATA, hmac_key,
				 PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR, "Plaform HMAC Key file is not written"
				       " properly!\n");
			goto err;
		}
	}

	if (sdoBlobRead((const char *)PLATFORM_HMAC_KEY, SDO_SDK_RAW_DATA,
			hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN) <= 0) {
		LOG(LOG_ERROR, "Failed to read plain Normal blob!\n");
		goto err;
	}
#endif

	rawNormalBlobSize =
	    sdoBlobSize((char *)SDO_CRED_NORMAL, SDO_SDK_RAW_DATA);

	if (rawNormalBlobSize <= 0) {
		LOG(LOG_ERROR, "Trouble getting plain Normal blob size!\n");
		goto err;
	} else if (rawNormalBlobSize >
		   PLATFORM_HMAC_KEY_DEFAULT_LEN + DATA_CONTENT_SIZE) {
		ret = 0;
		goto err;
	}

	rawNormalBlob = sdoAlloc(rawNormalBlobSize);

	if (!rawNormalBlob) {
		LOG(LOG_ERROR, "Buffer Allocation failed for plain "
			       "Normal blob!\n");
		goto err;
	}

	if (sdoBlobRead((char *)SDO_CRED_NORMAL, SDO_SDK_RAW_DATA,
			(uint8_t *)rawNormalBlob, rawNormalBlobSize) == -1) {
		LOG(LOG_ERROR, "Failed to read plain Normal blob!\n");
		goto err;
	}

	/* HMAC-256 is used to platform-sealing, format used to store
	 * sealed-data:
	 * [HMAC(32 bytes)||SizeofRawData(4 bytes)||RawData(?)] */
	signedNormalBlobSize =
	    PLATFORM_HMAC_SIZE + DATA_CONTENT_SIZE + rawNormalBlobSize;

	if (NULL == (signedNormalBlob = sdoAlloc(signedNormalBlobSize))) {
		LOG(LOG_ERROR,
		    "Malloc Failed for sealed Normal Blob buffer!\n");
		goto err;
	}
#if defined(DEVICE_TPM20_ENABLED)
	if (0 != sdoComputeStorageHMAC(rawNormalBlob, rawNormalBlobSize,
				       signedNormalBlob, PLATFORM_HMAC_SIZE)) {
		goto err;
	}
#else
#if defined(USE_MBEDTLS)
	if (0 != mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
				 (const uint8_t *)hmac_key,
				 PLATFORM_HMAC_KEY_DEFAULT_LEN, rawNormalBlob,
				 rawNormalBlobSize, signedNormalBlob))
		goto err;
#else // USE_OPENSSL
	if (NULL == HMAC(EVP_sha256(), hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN,
			 rawNormalBlob, (int)rawNormalBlobSize,
			 signedNormalBlob, NULL)) {
		goto err;
	}
#endif
#endif
	// copy plain-text size
	signedNormalBlob[PLATFORM_HMAC_SIZE + 3] = rawNormalBlobSize >> 0;
	signedNormalBlob[PLATFORM_HMAC_SIZE + 2] = rawNormalBlobSize >> 8;
	signedNormalBlob[PLATFORM_HMAC_SIZE + 1] = rawNormalBlobSize >> 16;
	signedNormalBlob[PLATFORM_HMAC_SIZE + 0] = rawNormalBlobSize >> 24;

	// copy plain-text content
	if (memcpy_s(signedNormalBlob + PLATFORM_HMAC_SIZE + DATA_CONTENT_SIZE,
		     rawNormalBlobSize, rawNormalBlob,
		     rawNormalBlobSize) != 0) {
		LOG(LOG_ERROR,
		    "Copying data failed writing sealed normal blob!\n");
		goto err;
	}

	bytesWritten = sdoBlobWrite(SDO_CRED_NORMAL, SDO_SDK_RAW_DATA,
				    signedNormalBlob, signedNormalBlobSize);
	if (bytesWritten != signedNormalBlobSize) {
		LOG(LOG_ERROR,
		    "Sealed Normal blob not written successfully!\n");
		goto err;
	}
	ret = 0;
err:
	if (rawNormalBlob)
		sdoFree(rawNormalBlob);
	if (signedNormalBlob)
		sdoFree(signedNormalBlob);
	return ret;
}
