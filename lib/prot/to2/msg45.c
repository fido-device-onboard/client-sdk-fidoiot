/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg45 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg45() - TO2.Get_next_device_service_info
 * So, the owner has verified that it is talking to right device and
 * sending in the service info data
 * --- Message Format Begins ---
 * {
 *   "nn": UInt8,  #Index of device service info message expected
 *   "psi": String # extra for this version of protocol only
 * }
 * --- Message Format Ends ---
 */

int32_t msg45(sdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
	sdo_string_t *psi = NULL;
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
		LOG(LOG_ERROR, "Trouble reading encrypted packet\n");
		goto err;
	}

	if (!sdo_encrypted_packet_unwind(&ps->sdor, pkt, ps->iv)) {
		LOG(LOG_ERROR, "Failed to decrypt packet!\n");
		goto err;
	}

	/* Get past any header */
	if (!sdor_next_block(&ps->sdor, &mtype)) {
		LOG(LOG_DEBUG, "SDOR doesn't seems to have next block !!\n");
		goto err;
	}

	if (!sdor_begin_object(&ps->sdor)) {
		goto err;
	}

	/* The device needs to send the Service Info corresponding to "nn" */
	if (!sdo_read_expected_tag(&ps->sdor, "nn")) {
		goto err;
	}
	ps->serv_req_info_num = sdo_read_uint(&ps->sdor);

	/*
	 * It is optional and can only contain value if "nn" = 0. For non-NULL
	 * "psi", it is indicating to device, to prepare itself for Service
	 * Info. (PSI: Pre Service Info
	 */
	if (!sdo_read_expected_tag(&ps->sdor, "psi")) {
		goto err;
	}

	psi = sdo_string_alloc();
	if (psi == NULL) {
		goto err;
	}
	if (!sdo_string_read(&ps->sdor, psi)) {
		LOG(LOG_ERROR, "Parsing psi String\n");
		goto err;
	}

	/*
	 * TODO:Support for preference module message, it is not needed for now
	 * as we have defined modules, but may be require at later point of
	 * time when  modules are completely dynamic.
	 */
	LOG(LOG_DEBUG, "psi string: %s, nn = %d\n\n", psi->bytes,
	    ps->serv_req_info_num);

	/* For "nn" == 0 */
	if (ps->serv_req_info_num == 0) {
		/* Parse PSI only when psi->bytes is not an empty string */
		if (psi->byte_sz > EMPTY_STRING_LEN) {
			int mod_ret_val = 0;
			if (!sdo_psi_parsing(ps->sv_info_mod_list_head,
					     psi->bytes, psi->byte_sz,
					     &mod_ret_val)) {
				LOG(LOG_ERROR, "Sv_info: PSI did not "
					       "finished gracefully!\n");

				/*
				 * TODO: See if there's benefit to handle
				 * multiple SI errors.
				 */
				goto err;
			}
		} else {
			LOG(LOG_INFO, "Sv_info: Empty PSI string for nn=0\n");
		}
	} else if (ps->serv_req_info_num > 0 &&
		   (ps->serv_req_info_num < ps->total_dsi_rounds)) {
		if (psi->byte_sz != EMPTY_STRING_LEN) {
			LOG(LOG_ERROR, "Sv_info: For non-zero nn, "
				       "psi string must be empty!\n");
			goto err;
		}
	} else {
		LOG(LOG_ERROR, "Sv_info: nn value is out of range!");
		goto err;
	}

	if (!sdor_end_object(&ps->sdor)) {
		goto err;
	}

	sdor_flush(&ps->sdor);
	ps->state = SDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO;
	LOG(LOG_DEBUG, "SDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO "
		       ": 45 Completed\n");
	ret = 0; /* Marks as success */

err:
	if (psi) {
		sdo_string_free(psi);
	}
	return ret;
}
