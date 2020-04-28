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
int32_t msg51(sdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
	char buf[DEBUGBUFSZ] = {0};
	sdo_encrypted_packet_t *pkt = NULL;

	LOG(LOG_DEBUG, "SDO_STATE_TO2_RCV_DONE_2: Starting\n");

	if (!sdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	pkt = sdo_encrypted_packet_read(&ps->sdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "Trouble reading encrypted packet\n");
		goto err;
	}

	if (!sdo_encrypted_packet_unwind(&ps->sdor, pkt, ps->iv)) {
		LOG(LOG_ERROR, "Failed to decrypt packet!\n");
		goto err;
	}

	if (!sdor_begin_object(&ps->sdor)) {
		goto err;
	}

	if (!sdo_read_expected_tag(&ps->sdor, "n7")) {
		goto err;
	}

	/* already allocated  n7r*/
	if (!ps->n7r || !sdo_byte_array_read_chars(&ps->sdor, ps->n7r)) {
		goto err;
	}
	LOG(LOG_DEBUG, "Receiving n7: %s\n",
	    sdo_nonce_to_string(ps->n7r->bytes, buf, sizeof buf) ? buf : "");

	if (!sdor_end_object(&ps->sdor)) {
		goto err;
	}

	/* verify the nonce received is correct. */
	if (!sdo_nonce_equal(ps->n7r, ps->n7)) {
		LOG(LOG_ERROR, "Invalid Nonce send by owner\n");
		goto err;
	}

	sdor_flush(&ps->sdor);
	ps->state = SDO_STATE_DONE;
	ps->success = true;

	/* Execute Sv_info type=END, before TO2 exits */
	if (!sdo_mod_exec_sv_infotype(ps->sv_info_mod_list_head, SDO_SI_END)) {
		LOG(LOG_DEBUG, "Sv_info: One or more Module did "
			       "not finish well\n");
	}

	ret = 0; /* Mark as success */

err:
	return ret;
}
