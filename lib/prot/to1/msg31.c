/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 31.
 */

#include "util.h"
#include "sdoprot.h"

/**
 * msg31() - TO1.HelloSDOAck
 * The device receives information which it needs to use to prove to
 * Rendezvous(RV) Server, that it is the device which it claims it to
 * be.
 *
 * --- Message Format Begins ---
 * {
 *      "n4": Nonce,  # Calcuate sign on Nonce for sigature freshness
 *      "eB": SigInfo # Information to use for signing
 * }
 * --- Message Format Ends
 *
 * --- eB for EPID 2.0 ---
 * {
 *     sigRLSize: UInt16 # Size of data in sigRL field
 * 	   sigRL	: Signature Revocation List
 * 	   publicKeySize: UInt16 Size of data in publicKey field
 * 	   publicKey: Group public key
 * }
 *
 * --- eB for ECDSA ---
 * {
 *     -- TODO --
 * }
 *
 */
int32_t msg31(SDOProt_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO1";
	char buf[DEBUGBUFSZ] = {0};

	/* Read network data from internal buffer */
	if (!sdoProtRcvMsg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Mark for retry */
		goto err;
	}

	if (!sdoRBeginObject(&ps->sdor)) {
		goto err;
	}

	/* Read "n4" tag, and it's data */
	if (!sdoReadExpectedTag(&ps->sdor, "n4")) {
		goto err;
	}

	ps->n4 = sdoByteArrayAlloc(SDO_NONCE_BYTES);
	if (!ps->n4 || !sdoByteArrayReadChars(&ps->sdor, ps->n4)) {
		goto err;
	}

	LOG(LOG_DEBUG, "Received n4: %s\n",
	    sdoNonceToString(ps->n4->bytes, buf, sizeof buf) ? buf : "");

	/* Read eB data: EPID or ECDSA */
	if (!sdoReadExpectedTag(&ps->sdor, "eB")) {
		goto err;
	}

	/* Handle both EPID and ECDSA cases */
	if (0 != sdoEBRead(&ps->sdor)) {
		LOG(LOG_ERROR, "EB read in message 31 failed\n");
		goto err;
	}

	if (!sdoREndObject(&ps->sdor)) {
		goto err;
	}

	sdoRFlush(&ps->sdor);

	/* Updated state to move to msg32 */
	ps->state = SDO_STATE_TO1_SND_PROVE_TO_SDO;
	ret = 0;

err:
	return ret;
}
