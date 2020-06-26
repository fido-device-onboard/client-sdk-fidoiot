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
 * configure_normal_blob call, new hmac generation is not tried on whole
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
#if defined(DEVICE_TPM20_ENABLED)
#include "tpm20_Utils.h"
#include "sdoCrypto.h"
#endif

#if !defined(DEVICE_TPM20_ENABLED)
/* platform level rand no generation reference */
static int32_t *gen_rdm_bytestream(uint8_t *random_buffer, size_t num_bytes)
{
	size_t i;

	for (i = 0; i < num_bytes; i++) {
		random_buffer[i] = (uint8_t)(rand() % 255);
	}
	return 0;
}
#endif

int32_t configure_normal_blob(void)
{
	/* From the platfrom, read unsealed Normal Blob for the very first time
	 * and
	 * write back
	 * sealed Normal blob for SDO.
	 */
	size_t bytes_written = 0;
	uint8_t *raw_normal_blob = NULL;
	size_t raw_normal_blob_size = 0;
	uint8_t *signed_normal_blob = NULL;
	size_t signed_normal_blob_size = 0;
	int32_t ret = -1;

#if defined(DEVICE_TPM20_ENABLED)
	if (0 == is_valid_tpm_data_protection_key_present()) {
		if (0 != sdo_generate_storage_hmac_key()) {
			LOG(LOG_ERROR, "Failed to generate TPM data protection"
				       " key.\n");
			goto err;
		}

		LOG(LOG_DEBUG,
		    "TPM data protection key generated successfully.\n");
	}
#else
	uint8_t hmac_key[PLATFORM_HMAC_KEY_DEFAULT_LEN] = {0};

	size_t key_size_stored =
	    sdo_blob_size((const char *)PLATFORM_HMAC_KEY, SDO_SDK_RAW_DATA);
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
		    sdo_blob_write((const char *)PLATFORM_HMAC_KEY,
				   SDO_SDK_RAW_DATA, hmac_key,
				   PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR, "Plaform HMAC Key file is not written"
				       " properly!\n");
			goto err;
		}
	}

	if (sdo_blob_read((const char *)PLATFORM_HMAC_KEY, SDO_SDK_RAW_DATA,
			  hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN) <= 0) {
		LOG(LOG_ERROR, "Failed to read plain Normal blob!\n");
		goto err;
	}
#endif

	raw_normal_blob_size =
	    sdo_blob_size((char *)SDO_CRED_NORMAL, SDO_SDK_RAW_DATA);

	if (raw_normal_blob_size <= 0) {
		LOG(LOG_ERROR, "Trouble getting plain Normal blob size!\n");
		goto err;
	} else if (raw_normal_blob_size >
		   PLATFORM_HMAC_KEY_DEFAULT_LEN + DATA_CONTENT_SIZE) {
		ret = 0;
		goto err;
	}

	raw_normal_blob = sdo_alloc(raw_normal_blob_size);

	if (!raw_normal_blob) {
		LOG(LOG_ERROR, "Buffer Allocation failed for plain "
			       "Normal blob!\n");
		goto err;
	}

	if (sdo_blob_read((char *)SDO_CRED_NORMAL, SDO_SDK_RAW_DATA,
			  (uint8_t *)raw_normal_blob,
			  raw_normal_blob_size) == -1) {
		LOG(LOG_ERROR, "Failed to read plain Normal blob!\n");
		goto err;
	}

	/* HMAC-256 is used to platform-sealing, format used to store
	 * sealed-data:
	 * [HMAC(32 bytes)||Sizeof_raw_data(4 bytes)||Raw_data(?)]
	 */
	signed_normal_blob_size =
	    PLATFORM_HMAC_SIZE + DATA_CONTENT_SIZE + raw_normal_blob_size;

	signed_normal_blob = sdo_alloc(signed_normal_blob_size);
	if (NULL == signed_normal_blob) {
		LOG(LOG_ERROR,
		    "Malloc Failed for sealed Normal Blob buffer!\n");
		goto err;
	}
#if defined(DEVICE_TPM20_ENABLED)
	if (0 != sdo_compute_storage_hmac(raw_normal_blob, raw_normal_blob_size,
					  signed_normal_blob,
					  PLATFORM_HMAC_SIZE)) {
		goto err;
	}
#else
#if defined(USE_MBEDTLS)
	if (0 != mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
				 (const uint8_t *)hmac_key,
				 PLATFORM_HMAC_KEY_DEFAULT_LEN, raw_normal_blob,
				 raw_normal_blob_size, signed_normal_blob))
		goto err;
#else // USE_OPENSSL
	if (NULL == HMAC(EVP_sha256(), hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN,
			 raw_normal_blob, (int)raw_normal_blob_size,
			 signed_normal_blob, NULL)) {
		goto err;
	}
#endif
#endif
	// copy plain-text size
	signed_normal_blob[PLATFORM_HMAC_SIZE + 3] = raw_normal_blob_size >> 0;
	signed_normal_blob[PLATFORM_HMAC_SIZE + 2] = raw_normal_blob_size >> 8;
	signed_normal_blob[PLATFORM_HMAC_SIZE + 1] = raw_normal_blob_size >> 16;
	signed_normal_blob[PLATFORM_HMAC_SIZE + 0] = raw_normal_blob_size >> 24;

	// copy plain-text content
	if (memcpy_s(signed_normal_blob + PLATFORM_HMAC_SIZE +
			 DATA_CONTENT_SIZE,
		     raw_normal_blob_size, raw_normal_blob,
		     raw_normal_blob_size) != 0) {
		LOG(LOG_ERROR,
		    "Copying data failed writing sealed normal blob!\n");
		goto err;
	}

	bytes_written =
	    sdo_blob_write(SDO_CRED_NORMAL, SDO_SDK_RAW_DATA,
			   signed_normal_blob, signed_normal_blob_size);
	if (bytes_written != signed_normal_blob_size) {
		LOG(LOG_ERROR,
		    "Sealed Normal blob not written successfully!\n");
		goto err;
	}
	ret = 0;
err:
	if (raw_normal_blob)
		sdo_free(raw_normal_blob);
	if (signed_normal_blob)
		sdo_free(signed_normal_blob);
	return ret;
}
