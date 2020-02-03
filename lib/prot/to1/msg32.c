/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 32.
 */

#include "util.h"
#include "sdoprot.h"
#include "sdoCryptoApi.h"

/**
 * msg32() - TO1.ProveToSDO
 * The device responds with the data which potentially proves to RV that it is
 * the authorized device requesting the owner information
 *
 * --- Message Format Begins ---
 * {
 *      "bo": {
 *	    "ai": AppId,     # AppId of SDO
 *   	"n4": Nonce,     # Nonce which was received in msg31
 *      "g2": GUID,      # GUID sent to RV in msg30
 *      },
 *      "pk": PublicKey, # EPID Public key if DA = epid, else PKNull
 *      "sg": Signature  # Signature calculated over nonce
 * }
 * --- Message Format Ends---
 *
 */
int32_t msg32(SDOProt_t *ps)
{
	int ret = -1;
	SDOSig_t sig = {0};
	SDOSigInfo_t *eA;
	SDOPublicKey_t *publickey;

	LOG(LOG_DEBUG, "Starting SDO_STATE_TO1_SND_PROVE_TO_SDO\n");

	/* Start writing the block for msg31 */
	sdoWNextBlock(&ps->sdow, SDO_TO1_TYPE_PROVE_TO_SDO);

	/* Start Body/Begin Object "bo" tag */
	eA = sdoGetDeviceSigInfoeA();
	publickey = eA ? eA->pubkey : NULL;

	if (!sdoBeginWriteSignature(&ps->sdow, &sig, publickey)) {
		LOG(LOG_ERROR, "Failed in writing the signature\n");
		goto err;
	}

	sdoWBeginObject(&ps->sdow);

	/* Write the "ai" tag */
	sdoWriteTag(&ps->sdow, "ai");
	sdoAppIDWrite(&ps->sdow);

	/* Write back the same nonce which was received in msg31 */
	sdoWriteTag(&ps->sdow, "n4");
	if (!ps->n4) {
		LOG(LOG_ERROR, "ps->n4 is empty MSG#32\n");
		goto err;
	}

	/* FIXME: Move to error handling. If TO1 restarts, we will leak memory
	 */
	sdoByteArrayWriteChars(&ps->sdow, ps->n4);
	sdoByteArrayFree(ps->n4);
	ps->n4 = NULL;

	/* Write the GUID received during DI */
	sdoWriteTag(&ps->sdow, "g2");
	sdoByteArrayWriteChars(&ps->sdow, ps->devCred->ownerBlk->guid);
	/* TODO: Add support for epk defined in spec 0.8 */
	sdoWEndObject(&ps->sdow);

	/* Fill in the pk and sg based on Device Attestation selected */
	if (sdoEndWriteSignature(&ps->sdow, &sig) != true) {
		LOG(LOG_ERROR, "Failed in writing the signature\n");
		goto err;
	}

	/* Mark as success and move to msg 33 */
	ps->state = SDO_STATE_TO1_RCV_SDO_REDIRECT;
	ret = 0;

	LOG(LOG_DEBUG, "Complete SDO_STATE_TO1_SND_PROVE_TO_SDO\n");

err:
	return ret;
}
