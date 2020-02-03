/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg51 of TO2 state machine.
 */

#include "sdoprot.h"
#include "util.h"
#include "sdokeyexchange.h"

/**
 * msg51() - TO2.Done2
 * This message provides an opportunity for a final ACK after the Owner
 * has invoked the System Info block to establish agent-to-server
 * communications between the Device and its final Owner.
 * --- Message Format Begins ---
 * {
 *     "n6:": Nonce
 * }
 * --- Message Format Ends ---
 */
int32_t msg51(SDOProt_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
	char buf[DEBUGBUFSZ] = {0};
	SDOEncryptedPacket_t *pkt = NULL;

	LOG(LOG_DEBUG, "SDO_STATE_TO2_RCV_DONE_2: Starting\n");

	if (!sdoCheckTO2RoundTrips(ps)) {
		goto err;
	}

	if (!sdoProtRcvMsg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	pkt = sdoEncryptedPacketRead(&ps->sdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "Trouble reading encrypted packet\n");
		goto err;
	}

	if (!sdoEncryptedPacketUnwind(&ps->sdor, pkt, ps->iv)) {
		LOG(LOG_ERROR, "Failed to decrypt packet!\n");
		goto err;
	}

	if (!sdoRBeginObject(&ps->sdor)) {
		goto err;
	}

	if (!sdoReadExpectedTag(&ps->sdor, "n7")) {
		goto err;
	}

	/* already allocated  n7r*/
	if (!ps->n7r || !sdoByteArrayReadChars(&ps->sdor, ps->n7r)) {
		goto err;
	}
	LOG(LOG_DEBUG, "Receiving n7: %s\n",
	    sdoNonceToString(ps->n7r->bytes, buf, sizeof buf) ? buf : "");

	if (!sdoREndObject(&ps->sdor)) {
		goto err;
	}

	/* verify the nonce received is correct. */
	if (!sdoNonceEqual(ps->n7r, ps->n7)) {
		LOG(LOG_ERROR, "Invalid Nonce send by owner\n");
		goto err;
	}

	sdoRFlush(&ps->sdor);
	ps->state = SDO_STATE_DONE;
	ps->success = true;

	/* Execute SvInfo type=END, before TO2 exits */
	if (!sdoModExecSvInfotype(ps->SvInfoModListHead, SDO_SI_END)) {
		LOG(LOG_DEBUG, "SvInfo: One or more Module did "
			       "not finish well\n");
	}

	ret = 0; /* Mark as success */

err:
	return ret;
}
