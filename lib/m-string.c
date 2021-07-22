/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of m-string for Device Initialize protocol
 */

#include "fdotypes.h"
#include "fdoprot.h"
#include "util.h"
#include "safe_lib.h"
#include "fdoCrypto.h"
#include "snprintf_s.h"
#include "fdoCryptoHal.h"
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
	size_t fsize = 0;

	fsize = fdo_blob_size((const char *)SERIAL_FILE, FDO_SDK_RAW_DATA);
	if ((fsize > 0) && (fsize <= MAX_DEV_SERIAL_SZ)) {

		if (fdo_blob_read((const char *)SERIAL_FILE, FDO_SDK_RAW_DATA,
				  (uint8_t *)device_serial, fsize) <= 0) {

			LOG(LOG_ERROR, "Failed to get serial no\n");
			goto err;
		}
	} else {
		LOG(LOG_INFO, "No serialno file present!\n");

		def_serial_sz = strnlen_s(DEF_SERIAL_NO, MAX_DEV_SERIAL_SZ);
		if (!def_serial_sz || def_serial_sz == MAX_DEV_SERIAL_SZ) {
			LOG(LOG_ERROR, "Default serial number string isn't "
					"NULL terminated\n");
			goto err;
		}
		
		ret = strncpy_s(device_serial, MAX_DEV_SERIAL_SZ, DEF_SERIAL_NO,
				def_serial_sz);
		if (ret) {
			LOG(LOG_ERROR, "Failed to get serial no\n");
			goto err;
		}
	}

	fsize = fdo_blob_size((const char *)MODEL_FILE, FDO_SDK_RAW_DATA);
	if ((fsize > 0) && (fsize <= MAX_MODEL_NO_SZ)) {
		if (fdo_blob_read((const char *)MODEL_FILE, FDO_SDK_RAW_DATA,
				  (uint8_t *)model_number, fsize) <= 0) {
			LOG(LOG_ERROR, "Failed to get serial no\n");
			goto err;
		}
	} else {

		LOG(LOG_INFO, "No model number file present!\n");
		def_model_sz = strnlen_s(DEF_MODEL_NO, MAX_MODEL_NO_SZ);
		if (!def_model_sz || def_model_sz == MAX_MODEL_NO_SZ) {
			LOG(LOG_ERROR, "Default model number string isn't "
					"NULL terminated\n");
			goto err;
		}

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
int ps_get_m_string(fdo_prot_t *ps)
{
	int ret = -1;
	fdo_byte_array_t *csr = NULL;

	/* Fill in the key id */
#if defined(ECDSA256_DA)
	key_id = FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256;
#else
	key_id = FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384;
#endif

	if (read_fill_modelserial()) {
		return ret;
	}

	size_t device_serial_len = strnlen_s(device_serial, MAX_DEV_SERIAL_SZ);
	if (!device_serial_len || device_serial_len == MAX_DEV_SERIAL_SZ) {
		LOG(LOG_ERROR, "device_serial isn't a NULL terminated.\n");
		goto err;
	}

	size_t model_number_len = strnlen_s(model_number, MAX_MODEL_NO_SZ);
	if (!model_number_len || model_number_len == MAX_MODEL_NO_SZ) {
		LOG(LOG_ERROR, "model_number isn't a NULL terminated.\n");
		goto err;
	}

	/* Get the CSR data */
#if defined(DEVICE_TPM20_ENABLED)
	size_t m_string_sz = get_file_size(TPM_DEVICE_CSR);

	csr = fdo_byte_array_alloc(m_string_sz);
	if (!csr) {
		LOG(LOG_ERROR,
		    "Failed to allocate memory for device mstring.\n");
		goto err;
	}

	ret = read_buffer_from_file(TPM_DEVICE_CSR, csr->bytes,
				       csr->byte_sz);
	if (0 != ret) {
		LOG(LOG_ERROR, "Failed to read %s file!\n", TPM_DEVICE_CSR);
		goto err;
	}

#else
	ret = fdo_get_device_csr(&csr);
	if (0 != ret) {
		LOG(LOG_ERROR, "Unable to get device CSR\n");
		goto err;
	}
#endif
	if (!fdow_start_array(&ps->fdow, DEVICE_MFG_STRING_ARRAY_SZ)) {
		goto err;
	}
	if (!fdow_signed_int(&ps->fdow, key_id)) {
		goto err;
	}
	if (!fdow_text_string(&ps->fdow, (char *) device_serial, device_serial_len)) {
		goto err;
	}
	if (!fdow_text_string(&ps->fdow, (char *) model_number, model_number_len)) {
		goto err;
	}
	if (!fdow_byte_string(&ps->fdow, csr->bytes, csr->byte_sz)) {
		goto err;
	}
	if (!fdow_end_array(&ps->fdow)) {
		goto err;
	}
	LOG(LOG_DEBUG, "Generated device CSR successfully\n");
err:
	if (csr) {
		fdo_byte_array_free(csr);
	}
	return ret;
}
