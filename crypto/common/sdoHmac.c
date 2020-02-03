/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "sdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"
#include "sdoCryptoCtx.h"
#include "sdoCryptoApi.h"
#include "sdoprot.h"
#include "storage_al.h"
#include "platform_utils.h"

#if defined(DEVICE_TPM20_ENABLED)
#include "tpm20_Utils.h"
#endif

/**
 * This function computes the HMAC of encrypted TO2 messages using SVK as its
 * key. sdoTo2CryptoContext specifies the hmacType to be used to generate
 * the HMAC of the data contained in to2Msg of size to2MsgLength and places
 * the output in hmac, the size of which is specified by hmacLength.
 * The hmac buffer must be of size SDO_MSG_HMAC_LENGTH or greater.
 * @param to2Msg In Pointer to the message
 * @param to2MsgLen In Size of the message
 * @param hmac Out Pointer to the buffer where the hmac is stored after the HMAC
 * operation is completed. This buffer must be allocated before calling this API
 * @param hmacLen In Size of the buffer pointed to by hmac
 * @return 0 on success and -1 on failure.
 */
int32_t sdoTo2HMAC(uint8_t *to2Msg, size_t to2MsgLen, uint8_t *hmac,
		   size_t hmacLen)
{
	SDOAESKeyset_t *keyset = getKeyset();
	uint8_t *svk;
	uint8_t svkLen;

	if (NULL == keyset || (NULL == keyset->svk) || (NULL == to2Msg)) {
		return -1;
	}
	svk = keyset->svk->bytes;
	svkLen = keyset->svk->byteSz;

	if (!svk || !svkLen || !to2MsgLen || !hmacLen)
		goto error;

	if (0 != sdoCryptoHMAC(SDO_CRYPTO_HMAC_TYPE_USED, to2Msg, to2MsgLen,
			       hmac, hmacLen, svk, svkLen)) {
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
 * @param OVKeyLen In Size of the Ownership Voucher hmac key
 * @return 0 on success and -1 on failure.
 */
int32_t setOVKey(SDOByteArray_t *OVkey, size_t OVKeyLen)
{
	int ret = -1;
	SDOByteArray_t **ovkeyctx = getOVKey();

	if ((NULL == OVkey) || !(OVkey->bytes) ||
	    !((BUFF_SIZE_32_BYTES == OVKeyLen) ||
	      (BUFF_SIZE_48_BYTES == OVKeyLen))) {
		return -1;
	}

	if (NULL == *ovkeyctx) {
		*ovkeyctx = sdoByteArrayAlloc(OVKeyLen);
		if (!*ovkeyctx) {
			LOG(LOG_ERROR, "Alloc failed \n");
			return -1;
		}
	}
	if (!(*ovkeyctx) || !(*ovkeyctx)->bytes) {
		goto err;
	}

	ret = memcpy_s((*ovkeyctx)->bytes, OVKeyLen, OVkey->bytes, OVKeyLen);
	if (ret != 0) {
		ret = -1;
		goto err;
	}
	ret = 0;
err:
	if ((0 != ret) && (*ovkeyctx)) {
		sdoByteArrayFree(*ovkeyctx);
		*ovkeyctx = NULL;
	}

	return ret;
}

/**
 * This function computes the HMAC of OV Header using device secret as the key
 * in
 * sdoTo2CryptoCtx. The Ownership Voucher header shall be pointed by OVHdr with
 * its length specified in OVHdrLength and generated HMAC shall be placed in
 * output buffer pointed by hmac, the size of which is specified by hmacLength.
 * The hmac buffer must be of size SDO_DEVICE_HMAC_LENGTH or greater.
 * @param OVHdr In Pointer to the Ownership Voucher header
 * @param OVHdrLen In Size of the Ownership Voucher header
 * @param hmac Out Pointer to the buffer where the hmac is stored after the hmac
 * operation is completed. This buffer must be allocated before calling this API
 * @param hmacLen In/Out In: Size of the buffer pointed to by hmac
 * Out: Size of the message hmac
 * @return 0 on success and -1 on failure.
 */
int32_t sdoDeviceOVHMAC(uint8_t *OVHdr, size_t OVHdrLen, uint8_t *hmac,
			size_t hmacLen)
{
#if defined(DEVICE_TPM20_ENABLED)
	return sdoTPMGetHMAC(OVHdr, OVHdrLen, hmac, hmacLen, TPM_HMAC_PUB_KEY,
			     TPM_HMAC_PRIV_KEY);
#else
	SDOByteArray_t **keyset = getOVKey();
	if (!keyset || !*keyset || !OVHdr || !hmac) {
		return -1;
	}
	uint8_t *hmacKey = (*keyset)->bytes;
	uint8_t hmacKeyLen = (*keyset)->byteSz;

	if (!hmacKey || !hmacKeyLen || !OVHdrLen || !hmacLen)
		goto error;

	if (0 != sdoCryptoHMAC(SDO_CRYPTO_HMAC_TYPE_USED, OVHdr, OVHdrLen, hmac,
			       hmacLen, hmacKey, hmacKeyLen)) {
		LOG(LOG_ERROR, "Failed to perform HMAC\n");
		goto error;
	}
	return 0;
error:
	return -1;
#endif
}

/**
 * sdoCryptoHash function calculate hash on input data
 *
 * @param message - pointer to input data buffer of uint8_t type.
 * @param messageLength - input data buffer size
 * @param hash - pointer to output data buffer of uint8_t type.
 * @param hashLength - output data buffer size
 *
 * @return
 *        return 0 on success. -ve value on failure.
 */
int32_t sdoCryptoHash(uint8_t *message, size_t messageLength, uint8_t *hash,
		      size_t hashLength)
{

	if (!message || !messageLength || !hash || !hashLength) {
		return -1;
	}

	if (0 != _sdoCryptoHash(SDO_CRYPTO_HASH_TYPE_USED, message,
				messageLength, hash, hashLength)) {

		return -1;
	}
	return 0;
}

/**
 * sdoGenerateOVHMACKey function generates OV HMAC key
 *
 * @return
 *        return 0 on success, -1 on failure.
 */

int32_t sdoGenerateOVHMACKey(void)
{

	int32_t ret = -1;
#if defined(DEVICE_TPM20_ENABLED)
	if (0 != sdoTPMGenerateHMACKey(TPM_HMAC_PUB_KEY, TPM_HMAC_PRIV_KEY)) {
		LOG(LOG_ERROR, "Failed to generate device HMAC key"
			       " from TPM.\n");
		return ret;
	}

	ret = 0;
	LOG(LOG_DEBUG, "Successfully generated device HMAC key"
		       " from TPM.\n");

#else
	SDOByteArray_t *secret = sdoByteArrayAlloc(INITIAL_SECRET_BYTES);

	/* Generate HMAC key for calcuating it over Ownership header */
	sdoCryptoRandomBytes(secret->bytes, INITIAL_SECRET_BYTES);
	if (0 != setOVKey(secret, INITIAL_SECRET_BYTES)) {
		goto err;
	}

	ret = 0;
err:
	sdoByteArrayFree(secret);
#endif

	return ret;
}

/**
 * sdoComputeStorageHMAC function generates OV HMAC key
 * @param data: pointer to the input data
 * @param dataLength: length of the input data
 * @param computedHmac: pointer to the computed HMAC
 * @param computedHmacSize: size of the computed HMAC buffer
 *
 * @return
 *        return 0 on success, -1 on failure.
 */

int32_t sdoComputeStorageHMAC(const uint8_t *data, uint32_t dataLength,
			      uint8_t *computedHmac, int computedHmacSize)
{

	int32_t ret = -1;

	if (!data || !dataLength || !computedHmac ||
	    (computedHmacSize != PLATFORM_HMAC_SIZE)) {
		LOG(LOG_ERROR, "Failed to generate HMAC, invalid"
			       " parameter received.\n");
		goto error;
	}

#if defined(DEVICE_TPM20_ENABLED)
	if (0 != sdoTPMGetHMAC(data, dataLength, computedHmac, computedHmacSize,
			       TPM_HMAC_DATA_PUB_KEY, TPM_HMAC_DATA_PRIV_KEY)) {
		LOG(LOG_ERROR, "TPM HMAC Computation failed!\n");
		goto error;
	}

	LOG(LOG_DEBUG, "TPM HMAC computed successfully!\n");

#else
	uint8_t hmac_key[PLATFORM_HMAC_KEY_DEFAULT_LEN] = {0};
	if (!getPlatformHMACKey(hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
		LOG(LOG_ERROR, "Could not get platform IV!\n");
		goto error;
	}

	// compute HMAC
	if (0 != sdoCryptoHMAC(SDO_CRYPTO_HMAC_TYPE_SHA_256, data, dataLength,
			       computedHmac, computedHmacSize, hmac_key,
			       HMACSHA256_KEY_SIZE)) {
		LOG(LOG_ERROR, "HMAC computation dailed during"
			       " sdoBlobRead()!\n");
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

/**
 * sdoGenerateStorageHMACKey function generates Storage HMAC key
 *
 * @return
 *        return 0 on success, -1 on failure.
 */

int32_t sdoGenerateStorageHMACKey(void)
{

	int32_t ret = -1;

#if defined(DEVICE_TPM20_ENABLED)
	if (0 != sdoTPMGenerateHMACKey(TPM_HMAC_DATA_PUB_KEY,
				       TPM_HMAC_DATA_PRIV_KEY)) {
		LOG(LOG_ERROR, "Failed to generate TPM data protection"
			       "key.\n");
		return ret;
	}

	ret = 0;
	LOG(LOG_DEBUG, "TPM data protection key generated successfully.\n");

#else
	uint8_t hmac_key[PLATFORM_HMAC_KEY_DEFAULT_LEN] = {0};

	if (0 !=
	    sdoCryptoRandomBytes(hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
		LOG(LOG_ERROR, "Unable to generate hmac key.\n");
		return ret;
	}

	if (PLATFORM_HMAC_KEY_DEFAULT_LEN !=
	    sdoBlobWrite((const char *)PLATFORM_HMAC_KEY, SDO_SDK_RAW_DATA,
			 hmac_key, PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
		LOG(LOG_ERROR, "Plaform HMAC Key file is not written"
			       " properly!\n");
		return ret;
	}

	ret = 0;

#endif
	return ret;
}
