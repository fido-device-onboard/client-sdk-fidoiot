/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "fdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"
#include "fdoCryptoCtx.h"
#include "fdoCrypto.h"
#include "fdoprot.h"
#include "storage_al.h"
#include "platform_utils.h"

#if defined(DEVICE_TPM20_ENABLED)
#include "tpm20_Utils.h"
#endif

#if defined(DEVICE_CSE_ENABLED)
#include "cse_utils.h"
#endif

/**
 * This function sets the Ownership Voucher hmac key in the structure.
 * Which will later be used by the OVHMAC function to get the hmac.
 * @param OVkey In Pointer to the Ownership Voucher hmac.
 * @param OVKey_len In Size of the Ownership Voucher hmac key
 * @return 0 on success and -1 on failure.
 */
int32_t set_ov_key(fdo_byte_array_t *OVkey, size_t OVKey_len)
{
	int ret = -1;
	fdo_byte_array_t **ovkeyctx = getOVKey();

	if ((NULL == OVkey) || !(OVkey->bytes) ||
	    !((BUFF_SIZE_32_BYTES == OVKey_len) ||
	      (BUFF_SIZE_64_BYTES == OVKey_len))) {
		return -1;
	}

	if (NULL == *ovkeyctx) {
		*ovkeyctx = fdo_byte_array_alloc(OVKey_len);
		if (!*ovkeyctx) {
			LOG(LOG_ERROR, "Alloc failed\n");
			return -1;
		}
	}
	if (!(*ovkeyctx) || !(*ovkeyctx)->bytes) {
		goto err;
	}

	ret = memcpy_s((*ovkeyctx)->bytes, OVKey_len, OVkey->bytes, OVKey_len);
	if (ret != 0) {
		ret = -1;
		goto err;
	}
	ret = 0;
err:
	if ((0 != ret) && (*ovkeyctx)) {
		fdo_byte_array_free(*ovkeyctx);
		*ovkeyctx = NULL;
	}

	return ret;
}

/**
 * This function sets the Ownership Voucher replacement hmac key in the structure.
 * Which will later be used to generate the replacement hmac.
 * @param OVkey In Pointer to the Ownership Voucher replacement hmac key.
 * @param OVKey_len In Size of the Ownership Voucher replacement hmac key
 * @return 0 on success and -1 on failure.
 */
int32_t set_ov_replacement_key(fdo_byte_array_t *OVkey, size_t OVKey_len)
{
	int ret = -1;
	fdo_byte_array_t **ovkeyctx = getreplacementOVKey();

	if ((NULL == OVkey) || !(OVkey->bytes) ||
	    !((BUFF_SIZE_32_BYTES == OVKey_len) ||
	      (BUFF_SIZE_64_BYTES == OVKey_len))) {
		return -1;
	}

	if (NULL == *ovkeyctx) {
		*ovkeyctx = fdo_byte_array_alloc(OVKey_len);
		if (!*ovkeyctx) {
			LOG(LOG_ERROR, "Alloc failed\n");
			return -1;
		}
	}
	if (!(*ovkeyctx) || !(*ovkeyctx)->bytes) {
		goto err;
	}

	ret = memcpy_s((*ovkeyctx)->bytes, OVKey_len, OVkey->bytes, OVKey_len);
	if (ret != 0) {
		ret = -1;
		goto err;
	}
	ret = 0;
err:
	if ((0 != ret) && (*ovkeyctx)) {
		fdo_byte_array_free(*ovkeyctx);
		*ovkeyctx = NULL;
	}

	return ret;
}

/**
 * This function computes the HMAC of OV Header using device secret as the key
 * in
 * fdo_to2Crypto_ctx. The Ownership Voucher header shall be pointed by OVHdr
 * with its length specified in OVHdr_length and generated HMAC shall be placed
 * in output buffer pointed by hmac, the size of which is specified by
 * hmac_length. The hmac buffer must be of size FDO_DEVICE_HMAC_LENGTH or
 * greater.
 * @param OVHdr In Pointer to the Ownership Voucher header
 * @param OVHdr_len In Size of the Ownership Voucher header
 * @param hmac Out Pointer to the buffer where the hmac is stored after the hmac
 * operation is completed. This buffer must be allocated before calling this API
 * @param hmac_len In/Out In: Size of the buffer pointed to by hmac
 * Out: Size of the message hmac
 * @param is_replacement_hmac In bool value that signifies whether the HMAC to
 * be computed is the orginal HMAC (for DI, using original HMAC key), or,
 * replacement HMAC (for TO2, using replacement HMAC key)
 * @return 0 on success and -1 on failure.
 */
int32_t fdo_device_ov_hmac(uint8_t *OVHdr, size_t OVHdr_len, uint8_t *hmac,
			   size_t hmac_len, bool is_replacement_hmac)
{
	if (!OVHdr || !hmac) {
		return -1;
	}

#if defined(DEVICE_CSE_ENABLED)
	(void)is_replacement_hmac;

	if (!OVHdr_len || !hmac_len) {
		goto error;
	}

	if (0 != crypto_hal_hmac_cse(OVHdr, OVHdr_len, hmac, hmac_len)) {
		LOG(LOG_ERROR, "Failed to perform HMAC\n");
		goto error;
	}
	return 0;
#else
	fdo_byte_array_t **keyset = NULL;
	if (is_replacement_hmac) {
#if defined(DEVICE_TPM20_ENABLED)
	return fdo_tpm_get_hmac(OVHdr, OVHdr_len, hmac, hmac_len,
				TPM_HMAC_REPLACEMENT_PUB_KEY, TPM_HMAC_REPLACEMENT_PRIV_KEY);
#else
		keyset = getreplacementOVKey();
#endif
	} else {
#if defined(DEVICE_TPM20_ENABLED)
	return fdo_tpm_get_hmac(OVHdr, OVHdr_len, hmac, hmac_len,
				TPM_HMAC_PUB_KEY, TPM_HMAC_PRIV_KEY);
#else
		keyset = getOVKey();
#endif
	}
	if (!keyset || !*keyset) {
		goto error;
	}

	uint8_t *hmac_key = (*keyset)->bytes;
	uint8_t hmac_key_len = (*keyset)->byte_sz;

	if (!hmac_key || !hmac_key_len || !OVHdr_len || !hmac_len) {
		goto error;
	}

	if (0 != crypto_hal_hmac(FDO_CRYPTO_HMAC_TYPE_USED, OVHdr, OVHdr_len,
				 hmac, hmac_len, hmac_key, hmac_key_len)) {
		LOG(LOG_ERROR, "Failed to perform HMAC\n");
		goto error;
	}
	return 0;
#endif
error:
	return -1;
}

/**
 * fdo_crypto_hash function calculate hash on input data
 *
 * @param message - pointer to input data buffer of uint8_t type.
 * @param message_length - input data buffer size
 * @param hash - pointer to output data buffer of uint8_t type.
 * @param hash_length - output data buffer size
 *
 * @return
 *        return 0 on success. -ve value on failure.
 */
int32_t fdo_crypto_hash(const uint8_t *message, size_t message_length,
			uint8_t *hash, size_t hash_length)
{

	if (!message || !message_length || !hash || !hash_length) {
		return -1;
	}

	if (0 != crypto_hal_hash(FDO_CRYPTO_HASH_TYPE_USED, message,
				  message_length, hash, hash_length)) {

		return -1;
	}
	return 0;
}

/**
 * fdo_generate_ov_hmac_key function generates OV HMAC key
 *
 * @return
 *        return 0 on success, -1 on failure.
 */

int32_t fdo_generate_ov_hmac_key(void)
{

	int32_t ret = -1;
#if defined(DEVICE_TPM20_ENABLED)
	if (0 !=
	    fdo_tpm_generate_hmac_key(TPM_HMAC_PUB_KEY, TPM_HMAC_PRIV_KEY)) {
		LOG(LOG_ERROR, "Failed to generate device HMAC key"
			       " from TPM.\n");
		return ret;
	}

	ret = 0;
	LOG(LOG_DEBUG, "Successfully generated device HMAC key"
		       " from TPM.\n");

#else
	fdo_byte_array_t *secret = fdo_byte_array_alloc(FDO_HMAC_KEY_LENGTH);

	if (!secret) {
		LOG(LOG_ERROR, "Out of memory for OV HMAC key\n");
		goto err;
	}

	/* Generate HMAC key for calcuating it over Ownership header */
	fdo_crypto_random_bytes(secret->bytes, FDO_HMAC_KEY_LENGTH);
	if (0 != set_ov_key(secret, FDO_HMAC_KEY_LENGTH)) {
		goto err;
	}

	ret = 0;
err:
	fdo_byte_array_free(secret);
#endif

	return ret;
}

/**
 * fdo_generate_ov_replacement_hmac_key function generates the new/replacement OV HMAC key
 *
 * @return
 *        return 0 on success, -1 on failure.
 */
int32_t fdo_generate_ov_replacement_hmac_key(void)
{

	int32_t ret = -1;
#if defined(DEVICE_TPM20_ENABLED)
	if (0 !=
	    fdo_tpm_generate_hmac_key(TPM_HMAC_REPLACEMENT_PUB_KEY,
			TPM_HMAC_REPLACEMENT_PRIV_KEY)) {
		LOG(LOG_ERROR, "Failed to generate device replacement HMAC key"
			       " from TPM.\n");
		return ret;
	}

	ret = 0;
	LOG(LOG_DEBUG, "Successfully generated device HMAC key"
		       " from TPM.\n");

#else
	fdo_byte_array_t *secret = fdo_byte_array_alloc(FDO_HMAC_KEY_LENGTH);

	if (!secret) {
		LOG(LOG_ERROR, "Out of memory for OV replacement HMAC key\n");
		goto err;
	}

	/* Generate replacement HMAC key for calcuating it over Ownership header */
	fdo_crypto_random_bytes(secret->bytes, FDO_HMAC_KEY_LENGTH);
	if (0 != set_ov_replacement_key(secret, FDO_HMAC_KEY_LENGTH)) {
		goto err;
	}

	ret = 0;
err:
	fdo_byte_array_free(secret);
#endif
	return ret;
}

/**
 * Commit the OV replacment key by replacing the original HMAC key
 * with the replacement HMAC key. This operation is final and the original HMAC key
 * is lost completely.
 *
 * @return
 *        return 0 on success, -1 on failure.
 */
int32_t fdo_commit_ov_replacement_hmac_key(void)
{

	int32_t ret = -1;
#if defined(DEVICE_TPM20_ENABLED)
	if (0 != fdo_tpm_commit_replacement_hmac_key()) {
		LOG(LOG_ERROR, "Failed to commit device replacement HMAC key"
			       " for TPM.\n");
		return ret;
	}

	ret = 0;
#else
	fdo_byte_array_t **secret = getreplacementOVKey();

	if (!secret || !(*secret) || !(*secret)->bytes) {
		LOG(LOG_ERROR, "Failed to read OV replacement HMAC key\n");
		return false;
	}

	if (0 != set_ov_key(*secret, FDO_HMAC_KEY_LENGTH)) {
		LOG(LOG_ERROR, "Failed to commit OV replacement HMAC key\n");
		return false;
	}

	ret = 0;
#endif
	return ret;
}

/**
 * fdo_compute_storage_hmac function generates OV HMAC key
 * @param data: pointer to the input data
 * @param data_length: length of the input data
 * @param computed_hmac: pointer to the computed HMAC
 * @param computed_hmac_size: size of the computed HMAC buffer
 *
 * @return
 *        return 0 on success, -1 on failure.
 */
#ifndef TARGET_OS_OPTEE
int32_t fdo_compute_storage_hmac(const uint8_t *data, uint32_t data_length,
				 uint8_t *computed_hmac, int computed_hmac_size)
{

	int32_t ret = -1;

	if (!data || !data_length || !computed_hmac ||
	    (computed_hmac_size != PLATFORM_HMAC_SIZE)) {
		LOG(LOG_ERROR, "Failed to generate HMAC, invalid"
			       " parameter received.\n");
		goto error;
	}

#if defined(DEVICE_TPM20_ENABLED)
	if (0 != fdo_tpm_get_hmac(data, data_length, computed_hmac,
				  computed_hmac_size, TPM_HMAC_DATA_PUB_KEY,
				  TPM_HMAC_DATA_PRIV_KEY)) {
		LOG(LOG_ERROR, "TPM HMAC Computation failed!\n");
		goto error;
	}

	LOG(LOG_DEBUG, "TPM HMAC computed successfully!\n");

#else
	uint8_t hmac_key[PLATFORM_HMAC_KEY_DEFAULT_LEN] = {0};

	if (!get_platform_hmac_key(hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
		LOG(LOG_ERROR, "Could not get platform IV!\n");
		goto error;
	}

	// compute HMAC
	if (0 != crypto_hal_hmac(FDO_CRYPTO_HMAC_TYPE_SHA_256, data,
				 data_length, computed_hmac, computed_hmac_size,
				 hmac_key, HMACSHA256_KEY_SIZE)) {
		LOG(LOG_ERROR, "HMAC computation dailed during"
			       " fdo_blob_read()!\n");
		goto error;
	}
	LOG(LOG_DEBUG, "HMAC computed successfully!\n");
#endif
	ret = 0;
error:
#if !defined(DEVICE_TPM20_ENABLED)
	if (memset_s(hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN, 0)) {
		LOG(LOG_ERROR, "Failed to clear HMAC key\n");
		goto error;
	}
#endif
	return ret;
}
#endif

/**
 * fdo_generate_storage_hmac_key function generates Storage HMAC key
 *
 * @return
 *        return 0 on success, -1 on failure.
 */
int32_t fdo_generate_storage_hmac_key(void)
{

	int32_t ret = -1;

#if defined(TARGET_OS_OPTEE)
	return 0;

#elif defined(DEVICE_TPM20_ENABLED)
	if (0 != fdo_tpm_generate_hmac_key(TPM_HMAC_DATA_PUB_KEY,
					   TPM_HMAC_DATA_PRIV_KEY)) {
		LOG(LOG_ERROR, "Failed to generate TPM data protection "
			       "key.\n");
		return ret;
	}

	ret = 0;
	LOG(LOG_DEBUG, "TPM data protection key generated successfully.\n");

#else
	uint8_t hmac_key[PLATFORM_HMAC_KEY_DEFAULT_LEN] = {0};

	if (0 !=
	    fdo_crypto_random_bytes(hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
		LOG(LOG_ERROR, "Unable to generate hmac key.\n");
		return ret;
	}

	if (PLATFORM_HMAC_KEY_DEFAULT_LEN !=
	    fdo_blob_write((const char *)PLATFORM_HMAC_KEY, FDO_SDK_RAW_DATA,
			   hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
		LOG(LOG_ERROR, "Plaform HMAC Key file is not written"
			       " properly!\n");
		return ret;
	}

	ret = 0;

#endif
	return ret;
}
