/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg46 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg46() - TO2.Next_device_service_info
 * --- Message Format Begins ---
 * {
 *   "nn" : UInt8,      # index of this message, from zero upwards.
 *   "dsi": Service_info # service info entries to add or
 *                      # append to previous ones.
 * }
 * --- Message Format Ends ---
 */
int32_t msg46(sdo_prot_t *ps)
{
	int ret = -1;

	/* Send all the key value sets in the Service Info list */
	sdow_next_block(&ps->sdow, SDO_TO2_NEXT_DEVICE_SERVICE_INFO);
	sdow_begin_object(&ps->sdow);

	/* Write the index of this message ("nn") */
	sdo_write_tag(&ps->sdow, "nn");
	sdo_writeUInt(&ps->sdow, ps->serv_req_info_num);

	/* Write the Device Service Info ("dsi") */
	sdo_write_tag(&ps->sdow, "dsi");
	sdow_begin_object(&ps->sdow);

	if (!ps->service_info)
		goto err;

	/*
	 * DSI's that need to be sent:
	 * 1. Platform DSI's (1st iteration, when nn=0)
	 * 2. Sv_info external module(s) DSI's (remaining iterations)
	 */

	if (ps->serv_req_info_num == 0) {
		/* Construct and write platform DSI's into a single json msg */
		if (!sdo_combine_platform_dsis(&ps->sdow, ps->service_info)) {
			LOG(LOG_ERROR, "Error in combining platform DSI's!\n");
			goto err;
		}
	} else {
		int mod_ret_val = 0;

		/* Sv_info external module(s) DSI's */
		sdo_sdk_si_key_value *sv_kv =
		    sdo_alloc(sizeof(sdo_sdk_si_key_value));
		if (!sv_kv)
			goto err;

		if (!sdo_construct_module_dsi(ps->dsi_info, sv_kv,
					      &mod_ret_val)) {
			LOG(LOG_DEBUG, "Sv_info: module DSI "
				       "Construction Failed\n");
			sdo_sv_key_value_free(sv_kv);
			goto err;
		}

		if (!sdo_mod_kv_write(&ps->sdow, sv_kv)) {
			sdo_sv_key_value_free(sv_kv);
			goto err;
		}
		/* Free allocated memory */
		sdo_sv_key_value_free(sv_kv);
	}

	sdow_end_object(&ps->sdow);
	sdow_end_object(&ps->sdow);

	/* Encrypt the packet */
	if (!sdo_encrypted_packet_windup(
		&ps->sdow, SDO_TO2_NEXT_DEVICE_SERVICE_INFO, ps->iv)) {
		goto err;
	}

	/* Check for DSI rounds */
	if (ps->serv_req_info_num < ps->total_dsi_rounds - 1) {
		/* Back to msg45 */
		ps->state = SDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO;
	} else {
		/* Move to msg47 */
		ps->state = SDO_STATE_TO2_RCV_SETUP_DEVICE;
	}

	ret = 0; /* Mark as success */

err:
	return ret;
}
