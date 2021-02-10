/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of m-string for Device Initialize protocol
 */

#include "sdotypes.h"
#include "sdoprot.h"
#include "util.h"
#include "safe_lib.h"
#include "sdoCrypto.h"
#include "snprintf_s.h"
#include "sdoCryptoHal.h"
#include "storage_al.h"

/*
 * Generate the "m" string value.
 * Syntax:
 * [<key type id>, <serial number>, <model number>, <CSR>]
 * @key type id  : ECDSA256 = 13 and ECDSA384 = 14
 * @serial number: Device serial number.
 * @model number : Device model number.
 * @csr          : CSR based on EC keys
 *
 * OA: Owner Attestation
 * DA: Device Attestation
 *
 * Referring to the table in the end, we see that <key type id> is a mix of
 * OA and DA, since, OA is never ECDSA384 based.
 *
 * o OA: ECDSA256
 *   - DA: ECDSA256/ECDSA384: In this case CSR data is being sent.
 *                            <key type id> = 13 or 14 based on DA choosen.
 */

/* All below sizes are excluding NULL termination */
#define DEVICE_MFG_STRING_ARRAY_SZ 4
#define MAX_DEV_SERIAL_SZ 32
#define MAX_MODEL_NO_SZ 32

/* TODO: Device serial number source need to be fixed */
#define DEF_SERIAL_NO "abcdef"
#define DEF_MODEL_NO "12345"
static char device_serial[MAX_DEV_SERIAL_SZ];
static char model_number[MAX_MODEL_NO_SZ];
static int key_id;

static int read_fill_modelserial(void)
{
	int ret = -1;
	uint8_t def_serial_sz = 0;
	uint8_t def_model_sz = 0;
	int32_t fsize = 0;

	fsize = sdo_blob_size((const char *)SERIAL_FILE, SDO_SDK_RAW_DATA);
	if ((fsize > 0) && (fsize <= MAX_DEV_SERIAL_SZ)) {

		if (sdo_blob_read((const char *)SERIAL_FILE, SDO_SDK_RAW_DATA,
				  (uint8_t *)device_serial, fsize) <= 0) {

			LOG(LOG_ERROR, "Failed to get serial no\n");
			goto err;
		}
	} else {
		LOG(LOG_INFO, "No serialno file present!\n");

		def_serial_sz = strnlen_s(DEF_SERIAL_NO, MAX_DEV_SERIAL_SZ);
		ret = strncpy_s(device_serial, MAX_DEV_SERIAL_SZ, DEF_SERIAL_NO,
				def_serial_sz);
		if (ret) {
			LOG(LOG_ERROR, "Failed to get serial no\n");
			goto err;
		}
	}

	fsize = sdo_blob_size((const char *)MODEL_FILE, SDO_SDK_RAW_DATA);
	if ((fsize > 0) && (fsize <= MAX_MODEL_NO_SZ)) {
		if (sdo_blob_read((const char *)MODEL_FILE, SDO_SDK_RAW_DATA,
				  (uint8_t *)model_number, fsize) <= 0) {
			LOG(LOG_ERROR, "Failed to get serial no\n");
			goto err;
		}
	} else {

		LOG(LOG_INFO, "No model number file present!\n");
		def_model_sz = strnlen_s(DEF_MODEL_NO, MAX_MODEL_NO_SZ);
		ret = strncpy_s(model_number, MAX_MODEL_NO_SZ, DEF_MODEL_NO,
				def_model_sz);
		if (ret) {
			LOG(LOG_ERROR, "Failed to get model no\n");
			goto err;
		}
	}
	ret = 0;
err:
	return ret;
}

/**
 * Internal API
 */
int ps_get_m_string(sdo_prot_t *ps)
{
	int ret = -1;
	sdo_byte_array_t *csr = NULL;

	/* Fill in the key id */
#if defined(ECDSA256_DA)
	key_id = SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256;
#else
	key_id = SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384;
#endif

	if (read_fill_modelserial()) {
		return ret;
	}

	size_t device_serial_len = strnlen_s(device_serial, MAX_DEV_SERIAL_SZ);
	size_t model_number_len = strnlen_s(model_number, MAX_MODEL_NO_SZ);

	/* Get the CSR data */
#if defined(DEVICE_TPM20_ENABLED)
	size_t m_string_sz = get_file_size(TPM_DEVICE_CSR);

	csr = sdo_byte_array_alloc(m_string_sz);
	if (!csr) {
		LOG(LOG_ERROR,
		    "Failed to allocate memory for device mstring.\n");
		goto err;
	}

	if (0 != read_buffer_from_file(TPM_DEVICE_CSR, csr->bytes,
				       csr->byte_sz)) {
		LOG(LOG_ERROR, "Failed to read %s file!\n", TPM_DEVICE_CSR);
		goto err;
	}

	// TO-DO - Update the TPM script to:
	// 1. Not store serial and model number in the file.
	// 2. Store only the CSR in DER format.
	// This does not work without the above changes.
#endif
	ret = sdo_get_device_csr(&csr);
	if (0 != ret) {
		LOG(LOG_ERROR, "Unable to get device CSR\n");
		goto err;
	}
	if (!sdow_start_array(&ps->sdow, DEVICE_MFG_STRING_ARRAY_SZ))
		goto err;
	if (!sdow_signed_int(&ps->sdow, key_id))
		goto err;
	if (!sdow_text_string(&ps->sdow, (char *) device_serial, device_serial_len))
		goto err;
	if (!sdow_text_string(&ps->sdow, (char *) model_number, model_number_len))
		goto err;
	if (!sdow_byte_string(&ps->sdow, csr->bytes, csr->byte_sz))
		goto err;
	if (!sdow_end_array(&ps->sdow))
		goto err;
	LOG(LOG_DEBUG, "Generated device CSR successfully\n");
err:
	if (csr)
		sdo_byte_array_free(csr);
	return ret;
}
