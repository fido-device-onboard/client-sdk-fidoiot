/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg44 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"
#include "sdoCryptoApi.h"

/**
 * msg44() - TO2.ProveDevice
 * The device sends out data proving that it is authentic device.
 * --- Message Format Begins ---
 * { # Signature
 *     "bo": {
 *         "ai": AppId,        # proves App provenance within TEE
 *         "n6: Nonce,         # proves signature freshness
 *         "n7: Nonce,         # used in TO2.SetupDevice
 *         "g2": GUID,         # proves the GUID matches with g2 in
 *                             # TO2.HelloDevice
 *         "nn": UInt8,        # number of device service info messages to come
 *         "xB": DHKeyExchange # Key Exchange, 2nd Step
 *     },
 *     "pk": PublicKey,        # EPID key for EPID device attestation;
 *                             # PKNull if ECDSA
 *     "sg": Signature         # Signature from device
 * }
 * --- Message Format Ends ---
 */
int32_t msg44(SDOProt_t *ps)
{
	int modMesCount = 0;
	int modRetVal = 0;
	int ret = -1;
	SDOSig_t sig = {0};
	SDOByteArray_t *xB = NULL;
	char buf[DEBUGBUFSZ] = {0};
	SDOSigInfo_t *eA;
	SDOPublicKey_t *publickey;

	LOG(LOG_DEBUG, "SDO_STATE_TO2_SND_PROVE_DEVICE: Starting\n");

	sdoWNextBlock(&ps->sdow, SDO_TO2_PROVE_DEVICE);

	eA = sdoGetDeviceSigInfoeA();
	publickey = eA ? eA->pubkey : NULL;

	LOG(LOG_DEBUG, "EPID key is: %s\n",
	    sdoPublicKeyToString(publickey, buf, sizeof(buf)) ? buf : "");

	/* Store the pointer to opening "{" for signing */
	if (sdoBeginWriteSignature(&ps->sdow, &sig, publickey) != true) {
		LOG(LOG_ERROR, "Failed in writing the signature\n");
		goto err;
	}

	/* Get the second part of Key Exchange */
	ret = sdoGetKexParamB(&xB);
	if (0 != ret && !xB) {
		LOG(LOG_ERROR, "Device has no publicB\n");
		goto err;
	}

	/* Write "ai" (application id) in the body */
	sdoWBeginObject(&ps->sdow);
	sdoWriteTag(&ps->sdow, "ai");
	sdoAppIDWrite(&ps->sdow);

	/* Write "n6" (nonce) received in msg41 */
	sdoWriteTag(&ps->sdow, "n6");
	sdoByteArrayWriteChars(&ps->sdow, ps->n6);
	LOG(LOG_DEBUG, "Sending n6: %s\n",
	    sdoNonceToString(ps->n6->bytes, buf, sizeof buf) ? buf : "");

	/* Write "n7" (nonce) to be used in msg47 */
	sdoWriteTag(&ps->sdow, "n7");
	ps->n7 = sdoByteArrayAlloc(SDO_NONCE_BYTES);
	if (!ps->n7) {
		LOG(LOG_ERROR, "Alloc failed \n");
		goto err;
	}
	sdoNonceInitRand(ps->n7);
	sdoByteArrayWriteChars(&ps->sdow, ps->n7);
	LOG(LOG_DEBUG, "Sending n7: %s\n",
	    sdoNonceToString(ps->n7->bytes, buf, sizeof buf) ? buf : "");

	/* Write the guid sent in msg40 (same as received in msg 11) */
	sdoWriteTag(&ps->sdow, "g2");
	sdoByteArrayWriteChars(&ps->sdow, ps->g2);

	/* Get Device Service Info (DSI) count from modules (GET_DSI_COUNT) */
	if (!sdoGetDSICount(ps->SvInfoModListHead, &modMesCount, &modRetVal)) {
		if (modRetVal == SDO_SI_INTERNAL_ERROR)
			goto err;
	}

	/* +1 for all platform DSI's */
	ps->totalDsiRounds = 1 + modMesCount;
	sdoWriteTag(&ps->sdow, "nn");
	/* If we have any device service info, then not 0 */
	if (ps->serviceInfo) /* FIXME: Where is 0 written?? */
		sdoWriteUInt(&ps->sdow, ps->totalDsiRounds);

	/* Write down the "xB" (key exchange) info */
	sdoWriteTag(&ps->sdow, "xB");
	SDOByteArrayWrite(&ps->sdow, xB);
	sdoWEndObject(&ps->sdow);

	/* Sign the body */
	if (sdoEndWriteSignature(&ps->sdow, &sig) != true) {
		LOG(LOG_ERROR, "Failed in writing the signature\n");
		goto err;
	}

	if (ps->serviceInfo && ps->serviceInfo->numKV) {
		/* Goto msg45 */
		ps->state = SDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO;
		LOG(LOG_DEBUG, "Device Service Info messages to come: %d\n",
		    ps->totalDsiRounds);
	} else {
		ps->state = SDO_STATE_TO2_RCV_SETUP_DEVICE; /* msg47 */
	}

	ret = 0; /* Mark as success */
	LOG(LOG_DEBUG, "SDO_STATE_TO2_SND_PROVE_DEVICE: Complete\n");
err:
	return ret;
}
