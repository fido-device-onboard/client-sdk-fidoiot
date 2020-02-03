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
#include "sdoCryptoApi.h"
#include "snprintf_s.h"

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
#define MAX_DEVICE_SERIAL_SIZE 32
#define MAX_MODEL_NUMBER_SIZE 2

#if defined(MANUFACTURER_TOOLKIT)
/* TODO: Device serial number source need to be fixed */
static const char *device_serial = "abcdef";
static const char *model_number = "0";
static char key_id[MAX_KEY_ID_SIZE];

/**
 * Internal API
 * Returns the base common size of m_string;
 */
static uint32_t get_base_m_string_size(void)
{
	return strnlen_s(key_id, MAX_KEY_ID_SIZE) + 1 +
	       strnlen_s(device_serial, MAX_DEVICE_SERIAL_SIZE) + 1 +
	       strnlen_s(model_number, MAX_MODEL_NUMBER_SIZE);
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
	size_t device_serial_len =
	    strnlen_s(device_serial, MAX_DEVICE_SERIAL_SIZE);
	size_t model_number_len =
	    strnlen_s(model_number, MAX_MODEL_NUMBER_SIZE);

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
	*ofs += strnlen_s(model_number, MAX_MODEL_NUMBER_SIZE) + 1;
#else /* PK_ENC_RSA or DA = epid*/
	/* Fill in the model number without NULL termination, no space for it */
	ret = memcpy_s((char *)m_string_bytes + *ofs, m_string_sz - *ofs,
		       model_number, model_number_len);
	if (ret) {
		LOG(LOG_ERROR, "Failed to copy model number in m-string\n");
		goto err;
	}
	*ofs += strnlen_s(model_number, MAX_MODEL_NUMBER_SIZE);
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
int non_csr_m_string(SDOProt_t *ps)
{
	int ret = -1;
	uint32_t ofs = 0;
	size_t m_string_sz = 0;
	SDOByteArray_t *m_string = NULL;

	/* Get the total size of m-string (includes NULL + CSR) */
	m_string_sz = get_base_m_string_size();
	m_string = sdoByteArrayAlloc(m_string_sz);
	if (!m_string) {
		LOG(LOG_ERROR, "Failed to allocate m-string buffer\n");
		goto err;
	}

	/* Fill the base part of m-string */
	ret = fill_base_m_string(m_string->bytes, m_string->byteSz, &ofs);
	if (ret) {
		LOG(LOG_ERROR, "Failed to fill in base ecc m-string\n");
		goto err;
	}

	sdoByteArrayWriteChars(&ps->sdow, m_string);

err:
	if (m_string)
		sdoByteArrayFree(m_string);
	return ret;
}

/**
 * Internal API
 */
#if defined(PK_ENC_ECDSA)
#if defined(ECDSA256_DA) || defined(ECDSA384_DA)
int ps_get_m_string(SDOProt_t *ps)
{
	int ret = -1;
	uint32_t ofs = 0;
	size_t m_string_sz = 0;
	SDOByteArray_t *csr = NULL;
	SDOByteArray_t *m_string = NULL;

	/* Get the CSR data */
	ret = sdoGetDeviceCsr(&csr);
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
	m_string_sz = get_base_m_string_size() + (1 + csr->byteSz);
	m_string = sdoByteArrayAlloc(m_string_sz);
	if (!m_string) {
		LOG(LOG_ERROR, "Failed to allocate m-string buffer\n");
		goto err;
	}

	/* Fill the base part of m-string */
	ret = fill_base_m_string(m_string->bytes, m_string->byteSz, &ofs);
	if (ret) {
		LOG(LOG_ERROR, "Failed to fill in base ecc m-string\n");
		goto err;
	}

	/* Copy CSR */
	ret = memcpy_s(m_string->bytes + ofs, m_string_sz - ofs, csr->bytes,
		       csr->byteSz);
	if (ret) {
		LOG(LOG_ERROR, "Failed to copy csr-data\n");
		goto err;
	}

	sdoByteArrayWriteChars(&ps->sdow, m_string);

err:
	if (m_string)
		sdoByteArrayFree(m_string);
	if (csr)
		sdoByteArrayFree(csr);
	return ret;
}
#elif defined(EPID_DA)
int ps_get_m_string(SDOProt_t *ps)
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
int ps_get_m_string(SDOProt_t *ps)
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
int ps_get_m_string(SDOProt_t *ps)
{
	sdoWriteString(&ps->sdow, "device-serial");
	return 0;
}
#endif
