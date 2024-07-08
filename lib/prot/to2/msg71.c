/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg71 of TO2 state machine.
 */

#include "fdoprot.h"
#include "util.h"
#include "fdokeyexchange.h"

/**
 * msg71() - TO2.Done2
 * This message provides an opportunity for a final ACK after the Owner
 * has invoked the System Info block to establish agent-to-server
 * communications between the Device and its final Owner.
 * TO2.Done2 = [
 *   NonceTO2SetupDv
 * ]
 */
int32_t msg71(fdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "FDOProtTO2";
	fdo_encrypted_packet_t *pkt = NULL;

	if (!ps) {
		LOG(LOG_ERROR, "Invalid protocol state\n");
		return ret;
	}

	LOG(LOG_DEBUG, "TO2.Done2 started\n");

	if (!fdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!fdo_prot_rcv_msg(&ps->fdor, &ps->fdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	pkt = fdo_encrypted_packet_read(&ps->fdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "TO2.Done2: Failed to parse encrypted packet\n");
		goto err;
	}

	if (!fdo_encrypted_packet_unwind(&ps->fdor, pkt)) {
		LOG(LOG_ERROR, "TO2.Done2: Failed to decrypt packet!\n");
		goto err;
	}

	if (!fdor_start_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.Done2: Failed to read start array\n");
		goto err;
	}

	/* already allocated  nonce_to2setupdv_rcv*/
	if (!ps->nonce_to2setupdv_rcv ||
	    !fdor_byte_string(&ps->fdor, ps->nonce_to2setupdv_rcv->bytes,
			      ps->nonce_to2setupdv_rcv->byte_sz)) {
		LOG(LOG_ERROR,
		    "TO2.Done2: Failed to alloc/read NonceTO2SetupDv array\n");
		goto err;
	}

	if (!fdor_end_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.Done2: Failed to read end array\n");
		goto err;
	}

	/* verify the nonce received is correct. */
	if (!fdo_nonce_equal(ps->nonce_to2setupdv_rcv, ps->nonce_to2setupdv)) {
		LOG(LOG_ERROR, "TO2.Done2: Received NonceTO2SetupDv does not "
			       "match with the"
			       "stored NonceTO2SetupDv\n");
		goto err;
	}

	ps->state = FDO_STATE_DONE;
	ps->success = true;

	/* Execute Sv_info type=END, before TO2 exits */
	// TO-DO : Update during serviceinfo implementation
	if (!fdo_mod_exec_sv_infotype(ps->sv_info_mod_list_head, FDO_SI_END)) {
		LOG(LOG_DEBUG, "TO2.Done2: (Sv_info) One or more Module did "
			       "not finish well\n");
	}

	LOG(LOG_DEBUG, "TO2.Done2 completed successfully\n");
	ret = 0; /* Mark as success */

err:
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.have_block = false;
	return ret;
}
