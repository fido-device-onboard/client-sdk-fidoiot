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
#if defined(DEVICE_CSE_ENABLED)
#include "cse_utils.h"
#include "cse_tools.h"
#endif

#include <inttypes.h>

/*
 * Generate the "m" string value.
 * Syntax:
 * [<key type id>, <serial number>, <model number>, <CSR>]
 * @key type id  : ECDSA256 = 10 and ECDSA384 = 11
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
 *                            <key type id> = 10 or 11 based on DA choosen.
 */

/* All below sizes are excluding NULL termination */
#if defined(DEVICE_CSE_ENABLED)
#define DEVICE_MFG_STRING_ARRAY_SZ 8
#else
#define DEVICE_MFG_STRING_ARRAY_SZ 5
#endif

#define MAX_DEV_SERIAL_SZ 255
#define MAX_MODEL_NO_SZ 32

/* TODO: Device serial number source need to be fixed */
#define DEF_SERIAL_NO "abcdef"
#define DEF_MODEL_NO "12345"
static char device_serial[MAX_DEV_SERIAL_SZ];
static char model_number[MAX_MODEL_NO_SZ];
static int key_id;
static int key_enc;
static int key_hashtype;

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
		if (fsize > MAX_DEV_SERIAL_SZ) {
			LOG(LOG_INFO, "Serialno exceeds 255 characters. Defaulting it to 'abcdef'\n");
		} else {
			LOG(LOG_INFO, "No serialno file present!\n");
		}

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
		if (fsize > MAX_MODEL_NO_SZ) {
			LOG(LOG_INFO, "Model number exceeds 32 characters. Defaulting it to '12345'\n");
		} else {
			LOG(LOG_INFO, "No model number file present!\n");
		}

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
 * Write custom MfgInfo as below:
 * MfgInfo.cbor = [
 *   pkType, // as per FDO spec
 *   pkEnc, // as per FDO spec
 *   serialNo, // tstr
 *   modelNo, // tstr
 *   CSR // bstr
 * 	 OnDie ECDSA cert chain // bstr
 *   test signature // bstr
 *   MAROE prefix // bstr
 * ]
 *
 * DeviceMfgInfo = bstr, MfgInfo.cbor (bstr-wrap MfgInfo CBOR bytes)
 */
int ps_get_m_string(fdo_prot_t *ps)
{
	int ret = -1;
	fdo_byte_array_t *csr = NULL;
	fdow_t temp_fdow = {0};
	size_t enc_device_mfginfo = 0;

#if defined(DEVICE_CSE_ENABLED)
	fdo_byte_array_t *cse_cert = NULL;
	fdo_byte_array_t *cse_maroeprefix = NULL;
	fdo_byte_array_t *cse_signature = NULL;
	fdo_byte_array_t *cose_sig_structure = NULL;
#endif

	/* Fill in the key id */
#if defined(ECDSA256_DA)
	key_id = FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256;
#else
	key_id = FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384;
#endif

	key_enc = FDO_OWNER_ATTEST_PK_ENC;
	key_hashtype = FDO_CRYPTO_HMAC_TYPE_USED;

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
#elif defined(DEVICE_CSE_ENABLED)
	// CSR will be NULL for CSE
	csr = fdo_byte_array_alloc(0);
	if (!csr) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Byte Array Alloc failed\n");
		goto err;
	}

	// Read OnDie ECDSA cert chain from CSE
	cse_cert = fdo_byte_array_alloc(FDO_MAX_CERT_CHAIN_SIZE);
	if (!cse_cert) {
		LOG(LOG_ERROR,"DeviceMfgInfo: Failed to allocate data for storing cert data\n");
		goto err;
	}

	ret = cse_get_cert_chain(&cse_cert);
	if (0 != ret) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Unable to get Cert chain from CSE\n");
		goto err;
	}

	// Get the Sig structure
	ret = cse_get_cose_sig_structure(&cose_sig_structure, (uint8_t *)device_serial, device_serial_len);
	if (0 != ret) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Unable to get Cose Sig structure\n");
		goto err;
	}

	// Read test signature and MAROE prefix fromm CSE
	cse_maroeprefix = fdo_byte_array_alloc(FDO_MAX_MAROE_PREFIX_SIZE);
	if (!cse_maroeprefix) {
		LOG(LOG_ERROR,"DeviceMfgInfo: Failed to allocate data for storing CSE maroeprefix\n");
		goto err;
	}

	cse_signature = fdo_byte_array_alloc(FDO_SIGNATURE_LENGTH);
	if (!cse_signature) {
		LOG(LOG_ERROR,"DeviceMfgInfo: Failed to allocate data for storing cse sig data\n");
		goto err;
	}

	ret = cse_get_test_sig(&cse_signature, &cse_maroeprefix, cose_sig_structure, (uint8_t *)device_serial, device_serial_len);
	if (0 != ret) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Unable to get test Signature\n");
		goto err;
	}
#else
	ret = fdo_get_device_csr(&csr);
	if (0 != ret) {
		LOG(LOG_ERROR, "Unable to get device CSR\n");
		goto err;
	}
#endif
	// use this temporary FDOW to write DeviceMfgInfo array
	// 4K bytes is probably sufficient, extend if required
	if (!fdow_init(&temp_fdow) ||
			!fdo_block_alloc_with_size(&temp_fdow.b, BUFF_SIZE_4K_BYTES) ||
			!fdow_encoder_init(&temp_fdow)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: FDOW Initialization/Allocation failed!\n");
		goto err;
	}
	if (!fdow_start_array(&temp_fdow, DEVICE_MFG_STRING_ARRAY_SZ)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to start array\n");
		goto err;
	}
	if (!fdow_signed_int(&temp_fdow, key_id)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to write keyType\n");
		goto err;
	}
	if (!fdow_signed_int(&temp_fdow, key_enc)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to write keyEnc\n");
		goto err;
	}
	if (!fdow_text_string(&temp_fdow, (char *) device_serial, device_serial_len)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to write serialNumber\n");
		goto err;
	}
	if (!fdow_text_string(&temp_fdow, (char *) model_number, model_number_len)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to write deviceInfo\n");
		goto err;
	}

#if defined(DEVICE_CSE_ENABLED)

	if (!fdow_byte_string(&temp_fdow, csr->bytes, csr->byte_sz)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to write CSR\n");
		goto err;
	}

	if (!fdow_byte_string(&temp_fdow, cse_cert->bytes, cse_cert->byte_sz)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to write CSE cert data\n");
		goto err;
	}

	if (!fdow_byte_string(&temp_fdow, cse_signature->bytes,
				cse_signature->byte_sz)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to write CSE signature\n");
		goto err;
	}

	if (!fdow_byte_string(&temp_fdow, cse_maroeprefix->bytes,
				cse_maroeprefix->byte_sz)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to write CSE maroeprefix\n");
		goto err;
	}
	ret = 0;
#else
	if (!fdow_byte_string(&temp_fdow, csr->bytes, csr->byte_sz)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to write CSR\n");
		goto err;
	}
#endif
	if (!fdow_end_array(&temp_fdow)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to end array\n");
		goto err;
	}

	if (!fdow_encoded_length(&temp_fdow, &enc_device_mfginfo) || enc_device_mfginfo == 0) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to find encoded length\n");
		goto err;
	}
	// now write the CBOR-encoded DeviceMfgInfo as bstr
	if (!fdow_byte_string(&ps->fdow, temp_fdow.b.block, enc_device_mfginfo)) {
		LOG(LOG_ERROR, "DeviceMfgInfo: Failed to write DeviceMfgInfo as bstr\n");
		goto err;
	}
	LOG(LOG_DEBUG, "Generated DeviceMfgInfo successfully\n");
err:
	if (csr) {
		fdo_byte_array_free(csr);
	}
#if defined(DEVICE_CSE_ENABLED)
	if (cose_sig_structure) {
		fdo_byte_array_free(cose_sig_structure);
		cose_sig_structure = NULL;
	}

	if (cse_cert) {
		fdo_byte_array_free(cse_cert);
	}

	if (cse_maroeprefix) {
		fdo_byte_array_free(cse_maroeprefix);
	}

	if (cse_signature) {
		fdo_byte_array_free(cse_signature);
	}
#endif
	if (temp_fdow.b.block || temp_fdow.current) {
		fdow_flush(&temp_fdow);
	}
	return ret;
}
