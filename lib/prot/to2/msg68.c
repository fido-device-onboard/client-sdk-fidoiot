/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg68 of TO2 state machine.
 */

#include "fdoprot.h"
#include "fdokeyexchange.h"
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
int32_t msg68(fdo_prot_t *ps)
{
	int ret = -1;
	fdo_service_info_t *serviceinfo_itr = NULL;

	if (!ps) {
		LOG(LOG_ERROR, "Invalid protocol state\n");
		return ret;
	}

	LOG(LOG_DEBUG, "TO2.DeviceServiceInfo started\n");

	/* send entry number to load */
	fdow_next_block(&ps->fdow, FDO_TO2_GET_NEXT_OWNER_SERVICE_INFO);

	if (!fdow_start_array(&ps->fdow, 2)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to start array\n");
		return false;
	}

	// DeviceServiceInfo's that need to be sent:
	// 1. 'devmod' module (1st iteration)
	// 2. Response [modname:active,false] when an unsupported module is being accessed.
	// 3. External module(s) (remaining iterations) TO-DO later
	// when multiple modules support will be added
	// The current implementation only sends the 'devmod' module

	// 1 for 'devmod' Device ServiceInfo
	// however, it should contain total number of Device ServiceInfo rounds
	ps->total_dsi_rounds = 1;
	// since there is only 1 round-trip, isMoreServiceInfo is always false
	ps->device_serviceinfo_ismore = false;

	if (ps->service_info && ps->serv_req_info_num == 0) {

		// for a single module and MIN_SERVICEINFO_SZ, only a single round-trip suffices
		// TO-DO : To be updated when support for multiple Device ServiceInfo is added
		if (!fdow_boolean(&ps->fdow, ps->device_serviceinfo_ismore)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to write IsMoreServiceInfo\n");
			return false;
		}

		serviceinfo_itr = ps->service_info;
		// Construct and write platform DSI's into a single msg
		if (!fdo_serviceinfo_write(&ps->fdow, serviceinfo_itr, true)) {
			LOG(LOG_ERROR, "Error in combining platform DSI's!\n");
			goto err;
		}
		// increment the internal counter that keeps track for Device ServiceInfo round-trips
		// currently, only a single round-trip is done
		ps->serv_req_info_num++;
		serviceinfo_itr = NULL;

	} else if (ps->serviceinfo_invalid_modname) {
		// 2. Response for unsuppprted modname
		if (!fdow_boolean(&ps->fdow, ps->device_serviceinfo_ismore)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to write IsMoreServiceInfo\n");
			return false;
		}

		serviceinfo_itr = fdo_service_info_alloc();
		if(!serviceinfo_itr) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to alloc ServiceInfo\n");
			return false;
		}
		if (!fdo_service_info_add_kv_bool(serviceinfo_itr,
			ps->serviceinfo_invalid_modname->bytes, false)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to create ServiceInfo\n");
			goto err;
		}
		if (!fdo_serviceinfo_write(&ps->fdow, serviceinfo_itr, false)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to write ServiceInfo\n");
			goto err;
		}
	} else {

		// Empty ServiceInfo. send [false, []]
		if (!fdow_boolean(&ps->fdow, ps->device_serviceinfo_ismore)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to write IsMoreServiceInfo\n");
			return false;
		}

		if (!fdow_start_array(&ps->fdow, 0)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to start empty ServiceInfo array\n");
			return false;
		}
		if (!fdow_end_array(&ps->fdow)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to end empty ServiceInfo array\n");
			return false;
		}
	}

	if (!fdow_end_array(&ps->fdow)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to end array\n");
		return false;
	}

	if (!fdo_encrypted_packet_windup(
		&ps->fdow, FDO_TO2_GET_NEXT_OWNER_SERVICE_INFO)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to create Encrypted Message\n");
		goto err;
	}

	ps->state = FDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO;
	ret = 0; /* Mark as success */
	LOG(LOG_DEBUG, "TO2.DeviceServiceInfo completed successfully\n");
err:
	if (serviceinfo_itr) {
		fdo_service_info_free(serviceinfo_itr);
		serviceinfo_itr = NULL;
	}
	if (ps->serviceinfo_invalid_modname) {
		fdo_string_free(ps->serviceinfo_invalid_modname);
		ps->serviceinfo_invalid_modname = NULL;
	}
	return ret;
}
