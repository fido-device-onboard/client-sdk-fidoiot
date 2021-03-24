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

/**
 * This function computes the HMAC of encrypted TO2 messages using SVK as its
 * key. fdo_to2Crypto_context specifies the hmac_type to be used to generate
 * the HMAC of the data contained in to2Msg of size to2Msg_length and places
 * the output in hmac, the size of which is specified by hmac_length.
 * The hmac buffer must be of size FDO_MSG_HMAC_LENGTH or greater.
 * @param to2Msg In Pointer to the message
 * @param to2Msg_len In Size of the message
 * @param hmac Out Pointer to the buffer where the hmac is stored after the HMAC
 * operation is completed. This buffer must be allocated before calling this API
 * @param hmac_len In Size of the buffer pointed to by hmac
 * @return 0 on success and -1 on failure.
 */
int32_t fdo_to2_hmac(uint8_t *to2Msg, size_t to2Msg_len, uint8_t *hmac,
		     size_t hmac_len)
{
	fdo_aes_keyset_t *keyset = get_keyset();
	uint8_t *svk;
	uint8_t svk_len;

	if (NULL == keyset || (NULL == keyset->svk) || (NULL == to2Msg)) {
		return -1;
	}
	svk = keyset->svk->bytes;
	svk_len = keyset->svk->byte_sz;

	if (!svk || !svk_len || !to2Msg_len || !hmac_len)
		goto error;

	if (0 != crypto_hal_hmac(FDO_CRYPTO_HMAC_TYPE_USED, to2Msg, to2Msg_len,
				 hmac, hmac_len, svk, svk_len)) {
		LOG(LOG_ERROR, "Failed to perform HMAC\n");
		goto error;
	}
	return 0;
error:
	return -1;
}

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
	      (BUFF_SIZE_48_BYTES == OVKey_len))) {
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
 * @return 0 on success and -1 on failure.
 */
int32_t fdo_device_ov_hmac(uint8_t *OVHdr, size_t OVHdr_len, uint8_t *hmac,
			   size_t hmac_len)
{
#if defined(DEVICE_TPM20_ENABLED)
	return fdo_tpm_get_hmac(OVHdr, OVHdr_len, hmac, hmac_len,
				TPM_HMAC_PUB_KEY, TPM_HMAC_PRIV_KEY);
#else
	fdo_byte_array_t **keyset = getOVKey();

	if (!keyset || !*keyset || !OVHdr || !hmac) {
		return -1;
	}
	uint8_t *hmac_key = (*keyset)->bytes;
	uint8_t hmac_key_len = (*keyset)->byte_sz;

	if (!hmac_key || !hmac_key_len || !OVHdr_len || !hmac_len)
		goto error;

	if (0 != crypto_hal_hmac(FDO_CRYPTO_HMAC_TYPE_USED, OVHdr, OVHdr_len,
				 hmac, hmac_len, hmac_key, hmac_key_len)) {
		LOG(LOG_ERROR, "Failed to perform HMAC\n");
		goto error;
	}
	return 0;
error:
	return -1;
#endif
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
	fdo_byte_array_t *secret = fdo_byte_array_alloc(INITIAL_SECRET_BYTES);

	if (!secret) {
		LOG(LOG_ERROR, "Out of memory for OV HMAC key\n");
		goto err;
	}

	/* Generate HMAC key for calcuating it over Ownership header */
	fdo_crypto_random_bytes(secret->bytes, INITIAL_SECRET_BYTES);
	if (0 != set_ov_key(secret, INITIAL_SECRET_BYTES)) {
		goto err;
	}

	ret = 0;
err:
	fdo_byte_array_free(secret);
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
