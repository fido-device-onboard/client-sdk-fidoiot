/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg48 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg68() - TO2.DeviceServiceInfo
 * Device sends the Device ServiceInfo to the owner.
 * 
 * TO2.DeviceServiceInfo = [
 *   IsMoreServiceInfo,   ;; more ServiceInfo to come, bool
 *   ServiceInfo          ;; service info entries
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
int32_t msg68(sdo_prot_t *ps)
{
	int ret = -1;

	LOG(LOG_DEBUG, "TO2.DeviceServiceInfo started\n");

	/* send entry number to load */
	sdow_next_block(&ps->sdow, SDO_TO2_GET_NEXT_OWNER_SERVICE_INFO);

	if (!sdow_start_array(&ps->sdow, 2)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to start array\n");
		return false;
	}

	// DeviceServiceInfo's that need to be sent:
	// 1. 'devmod' module (1st iteration)
	// 2. External module(s) (remaining iterations) TO-DO later
	// when multiple modules support will be added
	// The current implementation only sends the 'devmod' module

	// 1 for 'devmod' Device ServiceInfo
	// however, it should contain total number of Device ServiceInfo rounds
	ps->total_dsi_rounds = 1;

	if (ps->service_info && ps->serv_req_info_num == 0) {

		if (!sdow_boolean(&ps->sdow, true)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to write IsMoreServiceInfo\n");
			return false;
		}

		// Construct and write platform DSI's into a single msg
		if (!fdo_serviceinfo_write(&ps->sdow, ps->service_info)) {
			LOG(LOG_ERROR, "Error in combining platform DSI's!\n");
			goto err;
		}
		// increment the internal counter that keeps track for Device ServiceInfo round-trips
		// currently, only a single round-trip is done
		ps->serv_req_info_num++;

	} else {

		// Empty ServiceInfo. send [false, []]
		if (!sdow_boolean(&ps->sdow, false)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to write IsMoreServiceInfo\n");
			return false;
		}

		if (!sdow_start_array(&ps->sdow, 0)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to start empty ServiceInfo array\n");
			return false;
		}
		if (!sdow_end_array(&ps->sdow)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to end empty ServiceInfo array\n");
			return false;
		}
	}

	if (!sdow_end_array(&ps->sdow)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to end array\n");
		return false;
	}

	if (!sdo_encrypted_packet_windup(
		&ps->sdow, SDO_TO2_GET_NEXT_OWNER_SERVICE_INFO, ps->iv)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to create Encrypted Message\n");
		goto err;
	}

	ps->state = SDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO;
	ret = 0; /* Mark as success */
	LOG(LOG_DEBUG, "TO2.DeviceServiceInfo completed successfully\n");
err:
	return ret;
}
