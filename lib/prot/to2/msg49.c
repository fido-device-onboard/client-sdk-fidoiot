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
 * msg49() - TO2.OwnerServiceInfo
 * Device receives the Owner ServiceInfo.
 *
 * TO2.OwnerServiceInfo = [
 *   IsMoreServiceInfo,		// bool
 *   IsDone,				// bool
 *   ServiceInfo
 * ]
 * where,
 * ServiceInfo = [
 *   *ServiceInfoKeyVal
 * ]
 * ServiceInfoKeyVal = [
 *   *ServiceInfoKV
 * ]
 * ServiceInfoKV = [
 *   ServiceInfoKey: tstr,
 *   ServiceInfoVal: cborSimpleType
 * ]
 */
int32_t msg69(sdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
	sdo_encrypted_packet_t *pkt = NULL;
	bool IsMoreServiceInfo;
	bool isDone;

	if (!sdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	LOG(LOG_DEBUG, "TO2.OwnerServiceInfo started\n");

	/* If the packet is encrypted, decrypt it */
	pkt = sdo_encrypted_packet_read(&ps->sdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfo: Failed to parse encrypted packet\n");
		goto err;
	}
	if (!sdo_encrypted_packet_unwind(&ps->sdor, pkt, ps->iv)) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfo: Failed to decrypt packet!\n");
		goto err;
	}

	sdo_log_block(&ps->sdor.b);

	if (!sdor_start_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfo: Failed to start array\n");
		goto err;
	}

	if (!sdor_boolean(&ps->sdor, &IsMoreServiceInfo)) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfo: Failed to read IsMoreServiceInfo\n");
		goto err;
	}

	if (!sdor_boolean(&ps->sdor, &isDone)) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfo: Failed to read IsDone\n");
		goto err;
	}

	if (!IsMoreServiceInfo && isDone) {
		// Expecting ServiceInfo to be an empty array [].
		// However, PRI currently sends [[]], so parsing as such.
		// TO-DO : Update when PRI is updated.
		if (!sdor_start_array(&ps->sdor)) {
			LOG(LOG_ERROR, "TO2.OwnerServiceInfo: Failed to start empty ServiceInfo array\n");
			goto err;
		}
		if (!sdor_start_array(&ps->sdor)) {
			LOG(LOG_ERROR,
				"TO2.OwnerServiceInfo: Failed to start empty ServiceInfo.ServiceInfoKeyVal array\n");
			goto err;
		}
		if (!sdor_end_array(&ps->sdor)) {
			LOG(LOG_ERROR,
				"TO2.OwnerServiceInfo: Failed to end empty ServiceInfo.ServiceInfoKeyVal array\n");
			goto err;
		}
		if (!sdor_end_array(&ps->sdor)) {
			LOG(LOG_ERROR, "TO2.OwnerServiceInfo: Failed to end empty ServiceInfo array\n");
			goto err;
		}
	} else {
		// Expecting ServiceInfo. TO-DO : Test ater
		if (!fdo_serviceinfo_read(&ps->sdor)) {
			LOG(LOG_ERROR, "TO2.OwnerServiceInfo: Failed to read ServiceInfo\n");
			goto err;
		}
	}

	if (!sdor_end_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfo: Failed to end array\n");
		goto err;
	}
/*
		sdo_sdk_si_key_value osiKV;

		if (!sdo_osi_parsing(&ps->sdor, ps->sv_info_mod_list_head,
				     &osiKV, &mod_ret_val)) {
			LOG(LOG_ERROR, "Sv_info: OSI did not "
				       "finished "
				       "gracefully!\n");
			goto err;
		}
*/	

	if (isDone) {
		ps->state = SDO_STATE_TO2_SND_DONE;
	} else {
		ps->state = SDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO;
	}

	LOG(LOG_DEBUG, "TO2.OwnerServiceInfo completed successfully\n");
	ret = 0; /*Mark as success */

err:
	sdor_flush(&ps->sdor);
	ps->sdor.have_block = false;
	return ret;
}
