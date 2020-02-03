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
#include "sdoCryptoApi.h"

#define ECDSA_SIGNATURE_MAX_LEN BUFF_SIZE_256_BYTES

/* This function signs a message passed in message of size messageLength.
 * The generated signature will be available in signature of size
 * signatureLength. This API shall use the default device private key
 *  which has been either generated or provisioned into the device.
 * The decision to use either generated or provisioned key will be
 * made at the time of platform build.
 * @param  message In Pointer to the message
 * @param  messageLength In Size of the message
 * @param  signature In/OutPointer to the buffer where the signature is
 *                   stored after the signing operation is completed.
 *                   This buffer is allocated inside the API
 * @param  signatureLengthIn/OutIn: Size of the buffer pointed to by signature
 * @param Out: Size of the message signature
 * @return 0 on success and -1 on failure

 */
int32_t sdoDeviceSign(const uint8_t *message, size_t messageLength,
		      SDOByteArray_t **signature)
{
	if (!signature) {
		return -1;
	}
#if defined(EPID_DA)
	sdoDevKeyCtx_t *deviceCtx = getsdoDevKeyCtx();
	SDOEPIDInfoeB_t *eB;

	if (!deviceCtx || !deviceCtx->eB || !deviceCtx->eB->pubkey ||
	    !deviceCtx->eB->sigRL) {
		return -1;
	}
	eB = deviceCtx->eB;

	*signature =
	    EPID_Sign((uint8_t *)message, messageLength, eB->pubkey->bytes,
		      eB->pubkey->byteSz, eB->sigRL->bytes, eB->sigRL->byteSz);

	if (NULL == *signature) {
		LOG(LOG_ERROR, "EPID signing failed!\n");
		return -1;
	}

#elif defined(ECDSA256_DA) || defined(ECDSA384_DA)
	*signature = sdoByteArrayAlloc(ECDSA_SIGNATURE_MAX_LEN);
	if (NULL == *signature) {
		LOG(LOG_ERROR, "Alloc failed!\n");
		return -1;
	}

	if (0 != sdoECDSASign(message, messageLength, (*signature)->bytes,
			      &(*signature)->byteSz)) {
		LOG(LOG_ERROR, "ECDSA signing failed!\n");
		sdoByteArrayFree(*signature);
		*signature = NULL;
		return -1;
	}
#endif

	return 0;
}

/* This function sets the eB parameter that is sent from the
 * Owner to the Device in response to eA parameter
 * @param eB pointer to EPID eB param
 * @return 0 on success and -1 on failure.
 */
int32_t sdoSetDeviceSigInfoeB(SDOByteArray_t *sigRL, SDOByteArray_t *pubkey)
{

	sdoDevKeyCtx_t *deviceCtx = getsdoDevKeyCtx();

	if (NULL == deviceCtx || !sigRL || !pubkey) {
		return -1;
	}
	if (NULL != deviceCtx->eB) {
		/* eB is sent twice once in msg 31 and msg 41.
		 * when we receive  in 41 we clear the eB received
		 * before. */
		sdoEPIDInfoEBFree(deviceCtx->eB);
	}
	deviceCtx->eB = sdoAlloc(sizeof(SDOEPIDInfoeB_t));
	if (NULL == deviceCtx->eB) {
		return -1;
	}
	deviceCtx->eB->sigRL = sigRL;
	deviceCtx->eB->pubkey = pubkey;
	deviceCtx->eB->EPIDType = SDOEPID_VERSION;
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
int32_t sdoSetDeviceSigInfoeA(uint8_t *eA, size_t *eALen)
{
	int32_t ret = 0;
	sdoDevKeyCtx_t *deviceCtx = getsdoDevKeyCtx();

	if (NULL == deviceCtx || !eA || !eALen) {
		return -1;
	}

	deviceCtx->eA = sdoAlloc(sizeof(SDOSigInfo_t));

	if (!deviceCtx->eA) {
		LOG(LOG_ERROR, "Malloc failed \n");
		return -1;
	}

	deviceCtx->eA->sigType = SDO_PK_ALGO;

#ifdef EPID_DA
	deviceCtx->eA->pubkey = sdoAlloc(sizeof(SDOPublicKey_t));
	if (!deviceCtx->eA->pubkey) {
		LOG(LOG_ERROR, "Malloc failed \n");
		ret = -1;
		goto err;
	}
	deviceCtx->eA->pubkey->key1 = sdoByteArrayAlloc(SDO_PK_EA_SIZE);
	if (!deviceCtx->eA->pubkey->key1) {
		LOG(LOG_ERROR, "Malloc failed \n");
		ret = -1;
		goto err;
	}
	deviceCtx->eA->pubkey->pkalg = SDO_PK_ALGO;
	deviceCtx->eA->pubkey->pkenc = SDO_PK_ENC;

	/* First GID_SIZE bytes in a private key are gid. */
	if (*eALen < SDO_PK_EA_SIZE) {
		ret = -1;
		goto err;
	}
	if (memcpy_s(deviceCtx->eA->pubkey->key1->bytes, SDO_PK_EA_SIZE, eA,
		     SDO_PK_EA_SIZE) != 0) {
		LOG(LOG_ERROR, "Memcpy of eA failed \n");
		ret = -1;
		goto err;
	}
err:
	if (ret && (deviceCtx->eA->pubkey || deviceCtx->eA->pubkey->key1)) {
		sdoFree(deviceCtx->eA->pubkey);
		sdoByteArrayFree(deviceCtx->eA->pubkey->key1);
	}
#endif
	return ret;
}

/* This function returns the eA parameter that is sent from the Device
 *  to the Owner. This parameter provides initial device key specific
 *  information to the signature verifier
 * @return returns the SDOSigInfo_t which holds the eA param.
 */
SDOSigInfo_t *sdoGetDeviceSigInfoeA(void)
{
	sdoDevKeyCtx_t *deviceCtx = getsdoDevKeyCtx();
	if (NULL == deviceCtx) {
		return NULL;
	}

	return (deviceCtx->eA);
}
