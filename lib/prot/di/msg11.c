/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of msg number 11. The device received response of msg10
 */

#include "load_credentials.h"
#include "sdoCryptoApi.h"
#include "sdoprot.h"
#include "util.h"

/**
 * msg11() - DI.SetCredentials
 * The device gets credentials from the manufacturer.
 *
 * {
 *       "oh":{# Ownership header
 *           "pv": UInt16,    # Protocol version
 *           "pe": UInt8,     # Public Key Encoding (RSA, ECDSA)
 *           "r": Rendezvous, # Whom to connect to next in customer
 *                            # premises (Rendezvous Server)
 *           "g": GUID,       # Securely generated random number
 *           "d": String,     # Device info
 *           "pk": PublicKey, # Manufacturer Public Key (First owner)
 *           "hdc": Hash      # Absent if EPID
 *       },
 *       "cu": String,        # URL of manufacturer’s permanent certificate
 *       "ch": Hash           # Hash of manufacturer’s permanent certificate
 * }
 */
int32_t msg11(SDOProt_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtDI";
	SDOOwnershipVoucher_t *ov = NULL;
	SDODevCred_t *devCred = app_get_credentials();

	/* Is device credentials memory allocated */
	if (!devCred) {
		LOG(LOG_ERROR, "No device credentials available\n");
		goto err;
	}

	/*
	 * Receive the message from the internal buffer, if no msg is there,
	 * break out from here for now. Mark the state as true, but don't set
	 * the state to next msg (msg12)
	 */
	if (!sdoProtRcvMsg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0;
		goto err;
	}

	/* Prepare for writing device credentials */
	if (!sdoRBeginObject(&ps->sdor)) {
		goto err;
	}

	if (NULL == ps->devCred->mfgBlk) {
		ps->devCred->mfgBlk = sdoCredMfgAlloc();
	}

	if (NULL == ps->devCred->ownerBlk) {
		ps->devCred->ownerBlk = SDOCredOwnerAlloc();
		if (!ps->devCred->ownerBlk) {
			LOG(LOG_ERROR, "Alloc failed\n");
			goto err;
		}
	}

	if (!devCred->mfgBlk || !devCred->ownerBlk) {
		LOG(LOG_ERROR, "devCred's ownerBlk and/or "
			       "mfgBlk allocation failed\n");
		goto err;
	}

	if (0 != sdoGenerateOVHMACKey()) {
		LOG(LOG_ERROR, "OV HMAC key generation failed.\n");
		goto err;
	}

	/* Parse the complete Ownership header and calcuate HMAC over it */
	ov = sdoOvHdrRead(&ps->sdor, &ps->newOVHdrHMAC, false);
	if (!ov) {
		LOG(LOG_ERROR, "sdoOvHdrRead Failed\n");
		goto err;
	}

	if (ov->protVersion != SDO_PROT_SPEC_VERSION) {
		sdoOvFree(ov);
		LOG(LOG_ERROR, "Wrong protocol version\n");
		goto err;
	}

	if (ov->keyEncoding != SDO_CRYPTO_PUB_KEY_ENCODING_X509 &&
	    ov->keyEncoding != SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP) {
		sdoOvFree(ov);
		LOG(LOG_ERROR, "Wrong key encoding\n");
		goto err;
	}

	devCred->ownerBlk->pv = ov->protVersion;
	devCred->ownerBlk->pe = ov->keyEncoding;
	devCred->ownerBlk->rvlst = ov->rvlst2;
	devCred->ownerBlk->guid = ov->g2;
	devCred->mfgBlk->d = ov->devInfo;
	ps->devCred->ownerBlk->pk = ov->mfgPubKey;

	if (ov->hdc) {
		sdoHashFree(ov->hdc);
	}
	sdoFree(ov);

	if (!sdoREndObject(&ps->sdor)) {
		goto err;
	}
	sdoRFlush(&ps->sdor);

	/* All good, move to msg12 */
	ps->state = SDO_STATE_DI_SET_HMAC;
	ret = 0;

err:
	return ret;
}
