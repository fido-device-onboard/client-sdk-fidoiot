/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "util.h"
#include "safe_lib.h"
#include "load_credentials.h"
#include "storage_al.h"
#include <unistd.h>
#include <stdlib.h>
#include "util.h"
#include "safe_lib.h"
#include "sdoCryptoHal.h"
#include "sdoCryptoApi.h"
#ifdef EPID_DA
#include "epid.h"
#define EPIDKEYLEN 144 // Value will change as per EPID version

/**
 * Load EPID data from credentials data store.
 *
 * @return ret
 *        return 0 on success. -1 on failure.
 */
int32_t dev_attestation_init(void)
{
	uint8_t *privateKey = NULL;
	size_t privateKeyLen = EPIDKEYLEN;
	size_t rawBlobSize = 0;
	int ret = -1;
	SDOR_t sdoreader = {0};
	SDOR_t *sdor = NULL;
	SDOBlock_t *sdob = NULL;

	sdor = &sdoreader;
	sdob = &(sdor->b);
	SDOByteArray_t *cacert_data = sdoByteArrayAlloc(0);
	SDOByteArray_t *signed_sig_rl = sdoByteArrayAlloc(0);
	SDOByteArray_t *signedGroupPublicKey = sdoByteArrayAlloc(0);

	if (!cacert_data || !signed_sig_rl || !signedGroupPublicKey) {
		LOG(LOG_ERROR,
		    "Allocation for storing Raw block content failed\n");
		goto end;
	}

	if (!sdoRInit(sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdoRInit() failed!\n");
		goto end;
	}

	/*
	 * Read in the EPID group public key, private key, SigRl, and cacert.
	 * In a real product the private key and cacert data would be in the
	 * TEE, the Public key would come from the OProxy and the sigrl we
	 * would load it from a network resource for our group.
	 */

	// Raw Blob
	if ((rawBlobSize = sdoBlobSize((char *)RAW_BLOB, SDO_SDK_RAW_DATA)) >
	    0) {
		sdoResizeBlock(sdob, rawBlobSize);
	} else {
		LOG(LOG_DEBUG, "%s cacert!\n",
		    rawBlobSize ? "Error reading" : "Missing");
		goto end;
	}

	if (sdoBlobRead((char *)RAW_BLOB, SDO_SDK_RAW_DATA, sdob->block,
			rawBlobSize) == -1) {
		LOG(LOG_ERROR, "Could not read the cacert blob\n");
		goto end;
	}

	sdor->b.blockSize = rawBlobSize;
	sdor->haveBlock = true;

	LOG(LOG_DEBUG, "Raw blob has been processed\n");

	if (!sdoRBeginObject(sdor)) {
		LOG(LOG_ERROR, "Begin object not found \n");
		goto end;
	}

	if (!sdoReadExpectedTag(sdor, "cacert")) {
		LOG(LOG_ERROR, "tag=cacert not found \n");
		goto end;
	}

	if (!sdoRBeginSequence(sdor)) {
		LOG(LOG_ERROR, "Beginning sequence not found.\n");
		goto end;
	}

	/* It may be possible that CA certificate doesn't have any data */
	if (!sdoByteArrayReadChars(sdor, cacert_data)) {
		LOG(LOG_DEBUG, "cacert not available.\n");
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	if (cacert_data->byteSz) {
		hexdump("cacert", cacert_data->bytes, cacert_data->byteSz);
	}
#endif

	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		goto end;
	}

	/* SigRl */
	if (!sdoReadExpectedTag(sdor, "sigrl")) {
		LOG(LOG_ERROR, "tag=sigrl not found \n");
		goto end;
	}

	if (!sdoRBeginSequence(sdor)) {
		LOG(LOG_ERROR, "Beginning sequence not found.\n");
		goto end;
	}

	/* It may be possible that sig revocation list is not available */
	if (!sdoByteArrayReadChars(sdor, signed_sig_rl)) {
		LOG(LOG_DEBUG, "Sigrl not available.\n");
	}

	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		goto end;
	}

	/* Group public key blob */
	if (!sdoReadExpectedTag(sdor, "pubkey")) {
		LOG(LOG_ERROR, "tag=pubkey not found \n");
		goto end;
	}

	if (!sdoRBeginSequence(sdor)) {
		LOG(LOG_ERROR, "Beginning sequence not found.\n");
		goto end;
	}

	/* It may be possible that public key is not available */
	if (!sdoByteArrayReadChars(sdor, signedGroupPublicKey)) {
		LOG(LOG_DEBUG, "pubkey not available.\n");
	}

	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		goto end;
	}

	/* Member private key */
	privateKey = sdoAlloc(privateKeyLen);
	if (!privateKey) {
		LOG(LOG_ERROR, "Malloc Failed for privateKey!\n");
		goto end;
	}

	// When EPID is read from platform, error code will be introduced
	if (sdoReadEPIDKey(privateKey, (uint32_t *)&privateKeyLen) == -1) {
		LOG(LOG_DEBUG, "ReadprivateKey Failed!\n");
		goto end;
	}

	if (sdoSetDeviceSigInfoeA(privateKey, &privateKeyLen) != 0) {
		LOG(LOG_ERROR, "Memcpy failed\n");
		goto end;
	}

	ret = EPID_Init(signedGroupPublicKey->bytes,
			signedGroupPublicKey->byteSz, privateKey, privateKeyLen,
			cacert_data->bytes, cacert_data->byteSz,
			signed_sig_rl->bytes, signed_sig_rl->byteSz, NULL, 0);
	if (ret != 0) {
		LOG(LOG_ERROR, "EPID Could not be initialized !!\n");
		goto end;
	}

	ret = 0; /* Mark as success */

end:
	if (privateKey) {
		if (memset_s(privateKey, privateKeyLen, 0)) {
			LOG(LOG_ERROR, "Failed to clear private key\n");
			ret = -1;
		}
		sdoFree(privateKey);
	}
	if (signed_sig_rl) {
		sdoByteArrayFree(signed_sig_rl);
	}
	if (signedGroupPublicKey) {
		sdoByteArrayFree(signedGroupPublicKey);
	}
	if (cacert_data) {
		sdoByteArrayFree(cacert_data);
	}
	if (sdob->block) {
		sdoFree(sdob->block);
		sdob->block = NULL;
	}
	return ret;
}

/* Calls EPID close.
 */
void dev_attestation_close(void)
{
	EPID_Close();
}

#else

/* Do nothing for ECDSA based attestation */
int32_t dev_attestation_init(void)
{
	return 0;
}

void dev_attestation_close(void)
{
	return;
}
#endif
