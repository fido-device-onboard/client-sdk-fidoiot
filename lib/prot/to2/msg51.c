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
 * msg71() - TO2.Done2
 * This message provides an opportunity for a final ACK after the Owner
 * has invoked the System Info block to establish agent-to-server
 * communications between the Device and its final Owner.
 * TO2.Done2 = [
 *   Nonce7
 * ]
 */
int32_t msg71(sdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
	sdo_encrypted_packet_t *pkt = NULL;

	LOG(LOG_DEBUG, "TO2.Done2 started\n");

	if (!sdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	pkt = sdo_encrypted_packet_read(&ps->sdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "TO2.Done2: Failed to parse encrypted packet\n");
		goto err;
	}

	if (!sdo_encrypted_packet_unwind(&ps->sdor, pkt, ps->iv)) {
		LOG(LOG_ERROR, "TO2.Done2: Failed to decrypt packet!\n");
		goto err;
	}

	if (!sdor_start_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.Done2: Failed to read start array\n");
		goto err;
	}

	/* already allocated  n7r*/
	if (!ps->n7r || !sdor_byte_string(&ps->sdor, ps->n7r->bytes, ps->n7r->byte_sz)) {
		LOG(LOG_ERROR, "TO2.Done2: Failed to alloc/read Nonce7 array\n");
		goto err;
	}

	if (!sdor_end_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.Done2: Failed to read end array\n");
		goto err;
	}

	/* verify the nonce received is correct. */
	if (!sdo_nonce_equal(ps->n7r, ps->n7)) {
		LOG(LOG_ERROR, "TO2.Done2: Received Nonce7 does not match with the stored Nonce7\n");
		goto err;
	}

	ps->state = SDO_STATE_DONE;
	ps->success = true;

	/* Execute Sv_info type=END, before TO2 exits */
	// TO-DO : Update during serviceinfo implementation
	if (!sdo_mod_exec_sv_infotype(ps->sv_info_mod_list_head, SDO_SI_END)) {
		LOG(LOG_DEBUG, "TO2.Done2: (Sv_info) One or more Module did "
			       "not finish well\n");
	}

	LOG(LOG_DEBUG, "TO2.Done2 completed successfully\n");
	ret = 0; /* Mark as success */

err:
	sdo_block_reset(&ps->sdor.b);
	ps->sdor.have_block = false;
	return ret;
}
