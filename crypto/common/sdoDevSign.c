/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "sdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "stdlib.h"
#if defined(EPID_DA)
#include "epid.h"
#endif
#include "sdoCryptoCtx.h"
#include "sdoCrypto.h"

#define ECDSA_SIGNATURE_MAX_LEN BUFF_SIZE_256_BYTES

/* This function signs a message passed in message of size message_length.
 * The generated signature will be available in signature of size
 * signature_length. This API shall use the default device private key
 *  which has been either generated or provisioned into the device.
 * The decision to use either generated or provisioned key will be
 * made at the time of platform build.
 * @param  message In Pointer to the message
 * @param  message_length In Size of the message
 * @param  signature In/Out_pointer to the buffer where the signature is
 *                   stored after the signing operation is completed.
 *                   This buffer is allocated inside the API
 * @param  signature_length_in/Out_in: Size of the buffer pointed to by
 signature
 * @param Out: Size of the message signature
 * @return 0 on success and -1 on failure

 */
int32_t sdo_device_sign(const uint8_t *message, size_t message_length,
			sdo_byte_array_t **signature)
{
	int ret = -1;

	if (!signature) {
		return ret;
	}
#if defined(EPID_DA)
	sdo_dev_key_ctx_t *device_ctx = getsdo_dev_key_ctx();
	sdo_epid_info_eb_t *eB;

	if (!device_ctx || !device_ctx->eB || !device_ctx->eB->pubkey ||
	    !device_ctx->eB->sig_rl) {
		goto end;
	}
	eB = device_ctx->eB;

	*signature = epid_sign((uint8_t *)message, message_length,
			       eB->pubkey->bytes, eB->pubkey->byte_sz,
			       eB->sig_rl->bytes, eB->sig_rl->byte_sz);

	if (NULL == *signature) {
		LOG(LOG_ERROR, "EPID signing failed!\n");
		goto end;
	}
	ret = 0;
#elif defined(ECDSA256_DA) || defined(ECDSA384_DA)
	*signature = sdo_byte_array_alloc(ECDSA_SIGNATURE_MAX_LEN);
	if (NULL == *signature) {
		LOG(LOG_ERROR, "Alloc failed!\n");
		goto end;
	}

	if (0 != crypto_hal_ecdsa_sign(message, message_length, (*signature)->bytes,
				&(*signature)->byte_sz)) {
		LOG(LOG_ERROR, "ECDSA signing failed!\n");
		sdo_byte_array_free(*signature);
		*signature = NULL;
		goto end;
	}
	ret = 0;
#endif

end:
	return ret;
}

/* This function sets the eB parameter that is sent from the
 * Owner to the Device in response to eA parameter
 * @param eB pointer to EPID eB param
 * @return 0 on success and -1 on failure.
 */
int32_t sdo_set_device_sig_infoeB(sdo_byte_array_t *sig_rl,
				  sdo_byte_array_t *pubkey)
{

	sdo_dev_key_ctx_t *device_ctx = getsdo_dev_key_ctx();

	if (NULL == device_ctx || !sig_rl || !pubkey) {
		return -1;
	}
	if (NULL != device_ctx->eB) {
		/* eB is sent twice once in msg 31 and msg 41.
		 * when we receive  in 41 we clear the eB received
		 * before.
		 */
		sdo_epid_info_eb_free(device_ctx->eB);
		device_ctx->eB = NULL;
	}
	device_ctx->eB = sdo_alloc(sizeof(sdo_epid_info_eb_t));
	if (NULL == device_ctx->eB) {
		return -1;
	}
	device_ctx->eB->sig_rl = sig_rl;
	device_ctx->eB->pubkey = pubkey;
	device_ctx->eB->epid_type = SDOEPID_VERSION;
	return 0;
}

/* This function sets the eA parameter. In case of EPID it
 * will allocate the public key structs and loads it with
 * input value. For other cases public key algorithm is populated
 * and public key is not allocated.
 * @param In eA The pointer to eA.
 * @param In eALen the size of the eA.
 * @return 0 on success and -1 on failure.
 */
int32_t sdo_set_device_sig_infoeA(uint8_t *eA, size_t *eALen)
{
	int32_t ret = 0;
	sdo_dev_key_ctx_t *device_ctx = getsdo_dev_key_ctx();

	if (NULL == device_ctx || !eA || !eALen) {
		return -1;
	}

	device_ctx->eA = sdo_alloc(sizeof(sdo_sig_info_t));

	if (!device_ctx->eA) {
		LOG(LOG_ERROR, "Malloc failed\n");
		return -1;
	}

	device_ctx->eA->sig_type = SDO_PK_ALGO;

#ifdef EPID_DA
	device_ctx->eA->pubkey = sdo_alloc(sizeof(sdo_public_key_t));
	if (!device_ctx->eA->pubkey) {
		LOG(LOG_ERROR, "Malloc failed\n");
		ret = -1;
		goto err;
	}
	device_ctx->eA->pubkey->key1 = sdo_byte_array_alloc(SDO_PK_EA_SIZE);
	if (!device_ctx->eA->pubkey->key1) {
		LOG(LOG_ERROR, "Malloc failed\n");
		ret = -1;
		goto err;
	}
	device_ctx->eA->pubkey->pkalg = SDO_PK_ALGO;
	device_ctx->eA->pubkey->pkenc = SDO_PK_ENC;

	/* First GID_SIZE bytes in a private key are gid. */
	if (*eALen < SDO_PK_EA_SIZE) {
		ret = -1;
		goto err;
	}
	if (memcpy_s(device_ctx->eA->pubkey->key1->bytes, SDO_PK_EA_SIZE, eA,
		     SDO_PK_EA_SIZE) != 0) {
		LOG(LOG_ERROR, "Memcpy of eA failed\n");
		ret = -1;
		goto err;
	}
err:
	if (ret) {
		if(device_ctx->eA->pubkey) {
			sdo_byte_array_free(device_ctx->eA->pubkey->key1);
			device_ctx->eA->pubkey->key1 = NULL;
			sdo_free(device_ctx->eA->pubkey);
			device_ctx->eA->pubkey = NULL;
		}

	}
#endif
	return ret;
}

/* This function returns the eA parameter that is sent from the Device
 *  to the Owner. This parameter provides initial device key specific
 *  information to the signature verifier
 * @return returns the sdo_sig_info_t which holds the eA param.
 */
sdo_sig_info_t *sdo_get_device_sig_infoeA(void)
{
	sdo_dev_key_ctx_t *device_ctx = getsdo_dev_key_ctx();

	if (NULL == device_ctx) {
		return NULL;
	}

	return (device_ctx->eA);
}
