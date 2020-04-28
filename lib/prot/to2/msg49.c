/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg49 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg49() - TO2.Owner_service_info
 * --- Message Format Begins ---
 * {
 *    "nn": UInt8, # index of this message, from zero upwards
 *    "sv": Service_info
 * }
 * --- Message Format Ends ---
 */
int32_t msg49(sdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
	uint32_t mtype = 0;
	sdo_encrypted_packet_t *pkt = NULL;

	if (!sdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	/* If the packet is encrypted, decrypt it */
	pkt = sdo_encrypted_packet_read(&ps->sdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "Trouble reading "
			       "encrypted packet\n");
		goto err;
	}
	if (!sdo_encrypted_packet_unwind(&ps->sdor, pkt, ps->iv)) {
		goto err;
	}
	/* Get past any header */
	if (!sdor_next_block(&ps->sdor, &mtype)) {
		LOG(LOG_DEBUG, "SDOR doesn't seems to "
			       "have "
			       "next block !!\n");
		goto err;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	/* Print the service information received from the owner
	 * in plain text. */
	LOG(LOG_DEBUG, "Owner service info: ");
	print_buffer(LOG_DEBUG, ps->sdor.b.block, ps->sdor.b.block_size);
#endif

	if (!sdor_begin_object(&ps->sdor)) {
		goto err;
	}

	/* Read the index of the Owner service info */
	if (!sdo_read_expected_tag(&ps->sdor, "nn")) {
		goto err;
	}
	ps->owner_supplied_service_info_rcv = sdo_read_uint(&ps->sdor);

	if (ps->owner_supplied_service_info_num ==
	    ps->owner_supplied_service_info_rcv) {
		int mod_ret_val = 0;

		if (!sdo_read_expected_tag(&ps->sdor, "sv")) {
			goto err;
		}

		if (!sdor_begin_object(&ps->sdor)) {
			goto err;
		}

		/*
		 * ===============OSI=================
		 * 1. Fill OSI KV data structure
		 * 2. Make appropriate module callback's
		 */
		sdo_sdk_si_key_value osiKV;

		if (!sdo_osi_parsing(&ps->sdor, ps->sv_info_mod_list_head,
				     &osiKV, &mod_ret_val)) {
			LOG(LOG_ERROR, "Sv_info: OSI did not "
				       "finished "
				       "gracefully!\n");
			goto err;
		}
		/*===============OSI=================*/

		if (!sdor_end_object(&ps->sdor)) {
			goto err;
		}
	}

	if (!sdor_end_object(&ps->sdor)) {
		goto err;
	}

	sdor_flush(&ps->sdor);

	/* Loop until all have been requested */
	ps->owner_supplied_service_info_num++;
	if (ps->owner_supplied_service_info_num >=
	    ps->owner_supplied_service_info_count) {
		ps->state = SDO_STATE_TO2_SND_DONE;
	} else {
		ps->state = SDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO;
	}

	ret = 0; /*Mark as success */

err:
	return ret;
}
