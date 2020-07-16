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
 * <key type id>\0<serial number>\0<model number>[\0<CSR>]
 * @key type id  : RSA = 1, ECDSA256 = 13 and ECDSA384 = 14
 * @serial number: TODO: What it should be
 * @model number : can be empty string
 * @csr          : Only for ECC
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
 *   - DA: EPID             : CSR data is not being sent.
 *                            <key type id> = 13 based on OA being ECDSA256
 *
 * o OA: RSA
 *   - DA: ECDSA256/ECDSA384: FIXME: What to send in m-string???
 *                            m-string is supposed to be OA based. In that case,
 *                            we will not send out CSR and DA will fail.
 *   - DA: EPID             : <key type id> = 1 for RSA
 *
 *   Refer: Spec v1.1.12o Section: 2.5.5.5
 *   ---------------------------------------
 *  |Device Attestation | Owner Attestation |
 *  |---------------------------------------|
 *  | EPID              | RSA2048RESTR      |
 *  | ECDSA NIST P-256  | RSA2048RESTR      |
 *  | ECDSA NIST P-384  | RSA2048RESTR      |
 *  | EPID              | RSA 3072-bit key  |
 *  | ECDSA NIST P-256  | RSA 3072-bit key  |
 *  | ECDSA NIST P-384  | RSA 3072-bit key  |
 *  | EPID              | ECDSA NIST P-256  |
 *   ---------------------------------------
 */

/* All below sizes are excluding NULL termination */
#define MAX_KEY_ID_SIZE 3
#define MAX_DEV_SERIAL_SZ 32
#define MAX_MODEL_NO_SZ 32

#if defined(MANUFACTURER_TOOLKIT)
/* TODO: Device serial number source need to be fixed */
#define DEF_SERIAL_NO "abcdef"
#define DEF_MODEL_NO "0"
static char device_serial[MAX_DEV_SERIAL_SZ];
static char model_number[MAX_MODEL_NO_SZ];
static char key_id[MAX_KEY_ID_SIZE];

static int read_fill_modelserial(void)
{
	int ret = -1;
	uint8_t def_serial_sz = 0;
	uint8_t def_model_sz = 0;
	int32_t fsize = 0;

	fsize = sdo_blob_size((const char *)SERIAL_FILE, SDO_SDK_RAW_DATA);
	if (fsize > 0) {

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
	if (fsize > 0) {
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
 * Returns the base common size of m_string;
 */
static uint32_t get_base_m_string_size(void)
{
	return strnlen_s(key_id, MAX_KEY_ID_SIZE) + 1 +
	       strnlen_s(device_serial, MAX_DEV_SERIAL_SZ) + 1 +
	       strnlen_s(model_number, MAX_MODEL_NO_SZ);
}

/**
 * Internal API
 * Fills in the base m-string
 */
static int fill_base_m_string(uint8_t *m_string_bytes, size_t m_string_sz,
			      uint32_t *ofs)
{
	int ret = -1;
	size_t key_id_len = strnlen_s(key_id, MAX_KEY_ID_SIZE);
	size_t device_serial_len = strnlen_s(device_serial, MAX_DEV_SERIAL_SZ);
	size_t model_number_len = strnlen_s(model_number, MAX_MODEL_NO_SZ);

	/* Fill in the key ID. First param of m-string */
	ret =
	    strncpy_s((char *)m_string_bytes, m_string_sz, key_id, key_id_len);
	if (ret) {
		LOG(LOG_ERROR, "Failed to copy key_id in m-string\n");
		goto err;
	}
	*ofs = key_id_len + 1;

	/* Fill in the device serial */
	ret = strncpy_s((char *)m_string_bytes + *ofs, m_string_sz - *ofs,
			device_serial, device_serial_len);
	if (ret) {
		LOG(LOG_ERROR, "Failed to copy device serial in m-string\n");
		goto err;
	}
	*ofs += device_serial_len + 1;

#if defined(PK_ENC_ECDSA) && (defined(ECDSA256_DA) || defined(ECDSA384_DA))
	/* Fill in the model number with NULL termination */
	ret = strncpy_s((char *)m_string_bytes + *ofs, m_string_sz - *ofs,
			model_number, model_number_len);
	if (ret) {
		LOG(LOG_ERROR, "Failed to copy model number in m-string\n");
		goto err;
	}
	*ofs += strnlen_s(model_number, MAX_MODEL_NO_SZ) + 1;
#else /* PK_ENC_RSA or DA = epid*/
	/* Fill in the model number without NULL termination, no space for it */

	ret = memcpy_s((char *)m_string_bytes + *ofs, m_string_sz - *ofs,
		       model_number, model_number_len);
	if (ret) {
		LOG(LOG_ERROR, "Failed to copy model number in m-string\n");
		goto err;
	}
	*ofs += strnlen_s(model_number, MAX_MODEL_NO_SZ);
#endif

err:
	return ret;
}

/**
 * Internal API
 * Fill in ps with non-CSR data. It is used for:
 * a. PK_ENC = rsa
 * b. PK_ENC = ecdsa DA = epid
 */
#if defined(EPID_DA) || defined(PK_ENC_RSA)
static int non_csr_m_string(sdo_prot_t *ps)
{
	int ret = -1;
	uint32_t ofs = 0;
	size_t m_string_sz = 0;
	sdo_byte_array_t *m_string = NULL;

	if (read_fill_modelserial()) {
		return ret;
	}

	/* Get the total size of m-string (includes NULL + CSR) */
	m_string_sz = get_base_m_string_size();
	m_string = sdo_byte_array_alloc(m_string_sz);
	if (!m_string) {
		LOG(LOG_ERROR, "Failed to allocate m-string buffer\n");
		goto err;
	}

	/* Fill the base part of m-string */
	ret = fill_base_m_string(m_string->bytes, m_string->byte_sz, &ofs);
	if (ret) {
		LOG(LOG_ERROR, "Failed to fill in base ecc m-string\n");
		goto err;
	}

	sdo_byte_array_write_chars(&ps->sdow, m_string);

err:
	if (m_string)
		sdo_byte_array_free(m_string);
	return ret;
}
#endif

/**
 * Internal API
 */
#if defined(PK_ENC_ECDSA)
#if defined(ECDSA256_DA) || defined(ECDSA384_DA)
int ps_get_m_string(sdo_prot_t *ps)
{
	int ret = -1;
	uint32_t ofs = 0;
	size_t m_string_sz = 0;
	sdo_byte_array_t *csr = NULL;
	sdo_byte_array_t *m_string = NULL;

	if (read_fill_modelserial()) {
		return ret;
	}

	/* Get the CSR data */
	ret = sdo_get_device_csr(&csr);
	if (0 != ret) {
		LOG(LOG_ERROR, "Unable to get device CSR\n");
		goto err;
	}

	/* Fill in the key id */
#if defined(ECDSA256_DA)
	if (snprintf_s_i(key_id, sizeof(key_id), "%u",
			 SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256) < 0) {
		LOG(LOG_ERROR, "failed to fill in key id for ecdsa256\n");
		goto err;
	}
#else
	if (snprintf_s_i(key_id, sizeof(key_id), "%u",
			 SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384) < 0) {
		LOG(LOG_ERROR, "failed to fill in key id for ecdsa384\n");
		goto err;
	}
#endif

	/* Get the total size of m-string (includes NULL + CSR) */
	m_string_sz = get_base_m_string_size() + (1 + csr->byte_sz);
	m_string = sdo_byte_array_alloc(m_string_sz);
	if (!m_string) {
		LOG(LOG_ERROR, "Failed to allocate m-string buffer\n");
		goto err;
	}

	/* Fill the base part of m-string */
	ret = fill_base_m_string(m_string->bytes, m_string->byte_sz, &ofs);
	if (ret) {
		LOG(LOG_ERROR, "Failed to fill in base ecc m-string\n");
		goto err;
	}

	/* Copy CSR */
	ret = memcpy_s(m_string->bytes + ofs, m_string_sz - ofs, csr->bytes,
		       csr->byte_sz);
	if (ret) {
		LOG(LOG_ERROR, "Failed to copy csr-data\n");
		goto err;
	}

	sdo_byte_array_write_chars(&ps->sdow, m_string);

err:
	if (m_string)
		sdo_byte_array_free(m_string);
	if (csr)
		sdo_byte_array_free(csr);
	return ret;
}
#elif defined(EPID_DA)
int ps_get_m_string(sdo_prot_t *ps)
{
	/* Fill in the key id based on owner attestation */
	if (snprintf_s_i(key_id, sizeof(key_id), "%u",
			 SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256) < 0) {
		LOG(LOG_ERROR, "failed to fill in key id for ecdsa256\n");
		return -1;
	}

	return non_csr_m_string(ps);
}
#endif /* #if defined (ECDSA256_DA) || defined (ECDSA384_DA) */

#elif defined(PK_ENC_RSA)
/**
 * Internal API
 */
int ps_get_m_string(sdo_prot_t *ps)
{
	/* Fill in the key id */
	if (snprintf_s_i(key_id, sizeof(key_id), "%u",
			 SDO_CRYPTO_PUB_KEY_ALGO_RSA) < 0) {
		LOG(LOG_ERROR, "failed to fill in key id for rsa\n");
		return -1;
	}

	return non_csr_m_string(ps);
}
#endif
#else /* If Manufacturer toolkit is not defined */
/**
 * Internal API
 * TODO: Delete this function once manufacturer toolkit is ON by default
 */
int ps_get_m_string(sdo_prot_t *ps)
{
	sdo_write_string(&ps->sdow, "device-serial");
	return 0;
}
#endif
