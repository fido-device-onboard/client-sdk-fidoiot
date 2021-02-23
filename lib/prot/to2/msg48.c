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

	// To be updated when serviceinfo is hooked.
	// For now, send [false, []]
	if (!sdow_boolean(&ps->sdow, false)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to write IsMoreServiceInfo\n");
		return false;
	}

	if (!sdow_start_array(&ps->sdow, 0)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to write ServiceInfo start array\n");
		return false;
	}

	if (!sdow_end_array(&ps->sdow)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to write ServiceInfo end array\n");
		return false;
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
