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
 *      "eB": Sig_info # Information to use for signing
 * }
 * --- Message Format Ends
 *
 * --- eB for EPID 2.0 ---
 * {
 *     sig_rlSize: UInt16 # Size of data in sig_rl field
 * 	   sig_rl	: Signature Revocation List
 * 	   public_key_size: UInt16 Size of data in public_key field
 * 	   public_key: Group public key
 * }
 *
 * --- eB for ECDSA ---
 * {
 *     -- TODO --
 * }
 *
 */
int32_t msg31(sdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO1";
	char buf[DEBUGBUFSZ] = {0};

	/* Read network data from internal buffer */
	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Mark for retry */
		goto err;
	}

	if (!sdor_begin_object(&ps->sdor)) {
		goto err;
	}

	/* Read "n4" tag, and it's data */
	if (!sdo_read_expected_tag(&ps->sdor, "n4")) {
		goto err;
	}

	ps->n4 = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n4 || !sdo_byte_array_read_chars(&ps->sdor, ps->n4)) {
		goto err;
	}

	LOG(LOG_DEBUG, "Received n4: %s\n",
	    sdo_nonce_to_string(ps->n4->bytes, buf, sizeof buf) ? buf : "");

	/* Read eB data: ECDSA */
	if (!sdo_read_expected_tag(&ps->sdor, "eB")) {
		goto err;
	}

	/* Handle ECDSA cases */
	if (0 != sdo_eb_read(&ps->sdor)) {
		LOG(LOG_ERROR, "EB read in message 31 failed\n");
		goto err;
	}

	if (!sdor_end_object(&ps->sdor)) {
		goto err;
	}

	sdor_flush(&ps->sdor);

	/* Updated state to move to msg32 */
	ps->state = SDO_STATE_TO1_SND_PROVE_TO_SDO;
	ret = 0;

err:
	return ret;
}
