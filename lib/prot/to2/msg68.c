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
#include "safe_lib.h"

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
	fdo_sv_invalid_modnames_t *serviceinfo_invalid_modnames_it = NULL;
	char sv_modname_key[FDO_MODULE_NAME_LEN + FDO_MODULE_MSG_LEN + 1] = "";
	size_t serviceinfo_invalid_modnames_count = 0;

	if (!ps) {
		LOG(LOG_ERROR, "Invalid protocol state\n");
		return ret;
	}

	LOG(LOG_DEBUG, "TO2.DeviceServiceInfo started\n");

	// DeviceServiceInfo's that need to be sent:
	// 1. 'devmod' module (1st iteration)
	// 2. Response [modname:active,false] when an unsupported module is being accessed.
	// 3. External module(s) (remaining iterations) TO-DO later
	// when multiple modules support will be added
	// The current implementation only handle (1) and (2).

	// either ther is something to send (calulate ismore), or nothing to send (ismore=false)
	if (!ps->service_info && !ps->serviceinfo_invalid_modnames) {
		ps->device_serviceinfo_ismore = false;
	} else {
		// There is a list of unsupported module names that need to be sent, AND,
		// it has not been added to the serviceinfo list, AND,
		// Owner has nothing more to send (for now), so that we only add once
		if (!ps->service_info && ps->serviceinfo_invalid_modnames &&
			!ps->owner_serviceinfo_ismore) {
			ps->service_info = fdo_service_info_alloc();
			if(!ps->service_info) {
				LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to alloc ServiceInfo\n");
				return false;
			}

			serviceinfo_invalid_modnames_it = ps->serviceinfo_invalid_modnames;
			while (serviceinfo_invalid_modnames_it) {

				// The message to be sent contains a list of unsupported module names
				// with key/message 'active' and value 'false', something of the form
				// [[modname1:active, false], [modname2:active, false]]...

				// create 'modname:active'
				if (0 != strncpy_s(sv_modname_key, FDO_MODULE_NAME_LEN,
					serviceinfo_invalid_modnames_it->bytes, FDO_MODULE_NAME_LEN)) {
					LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to concatenate module name\n");
					goto err;
				}
				if (0 != strcat_s(sv_modname_key, FDO_MODULE_MSG_LEN,
					FDO_MODULE_SEPARATOR)) {
					LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to concatenate module name\n");
					goto err;
				}
				if (0 != strcat_s(sv_modname_key, FDO_MODULE_MSG_LEN,
					FDO_MODULE_MESSAGE_ACTIVE)) {
					LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to concatenate module name\n");
					goto err;
				}

				// add 'modname:active=false' into the serviceinfo list
				if (!fdo_service_info_add_kv_bool(ps->service_info,
					sv_modname_key, false)) {
					LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to create ServiceInfo\n");
					goto err;
				}
				serviceinfo_invalid_modnames_it = serviceinfo_invalid_modnames_it->next;
				serviceinfo_invalid_modnames_count++;
			}
			ps->service_info->numKV = serviceinfo_invalid_modnames_count;

			// clear it here immediately, so we don't use it back
			fdo_serviceinfo_invalid_modname_free(ps->serviceinfo_invalid_modnames);
			ps->serviceinfo_invalid_modnames = NULL;
		}

		// The splitting is done by considering an additional margin for CBOR encoding.
		// The data is CBOR encoded twice. First time to find the what can be fit, and
		// and second time to actually transmit the ServiceInfo.
		// This is done in this way, since the underlying
		// TinyCBOR library doesn't allow us to change the total number of entries
		// in an array (ServiceInfoKeyVal, in this case), once it's set.
		if (!fdo_serviceinfo_fit_mtu(&ps->fdow, ps->service_info,
			ps->maxDeviceServiceInfoSz - SERVICEINFO_MTU_FIT_MARGIN)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to fit within MTU\n");
			goto err;
		}

		if (ps->service_info->sv_index_end == ps->service_info->numKV &&
			ps->service_info->sv_val_index == 0) {
			ps->device_serviceinfo_ismore = false;
		} else if (ps->service_info->sv_index_end < ps->service_info->numKV) {
			ps->device_serviceinfo_ismore = true;
		} else {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Invalid state reached while processing "
				"Device ServiceInfo\n");
			goto err;			
		}
	}

	// reset FDOW because it was used in this method, out of place
	fdo_block_reset(&ps->fdow.b);
	ps->fdor.b.block_size = ps->prot_buff_sz;
	if (!fdow_encoder_init(&ps->fdow)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to initialize FDOW encoder\n");
		goto err;
	}

	/* send entry number to load */
	fdow_next_block(&ps->fdow, FDO_TO2_GET_NEXT_OWNER_SERVICE_INFO);

	if (!fdow_start_array(&ps->fdow, 2)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to start array\n");
		return false;
	}

	// Send ServiceInfo only if:
	// 1. We have ServiceInfo to send, AND
	// 2. Owner has nothing more to send (for now atleast)
	if (ps->service_info && !ps->owner_serviceinfo_ismore) {

		if (!fdow_boolean(&ps->fdow, ps->device_serviceinfo_ismore)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfo: Failed to write IsMoreServiceInfo\n");
			return false;
		}

		serviceinfo_itr = ps->service_info;
		// Construct and write Device ServiceInfo
		if (!fdo_serviceinfo_write(&ps->fdow, serviceinfo_itr)) {
			LOG(LOG_ERROR, "Error in combining platform DSI's!\n");
			goto err;
		}

		serviceinfo_itr = NULL;
		// there is nothing to send, so clear it immediately
		// so that we don't use it in the next iteration
		if (!ps->device_serviceinfo_ismore) {
			fdo_service_info_free(ps->service_info);
			ps->service_info = NULL;
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
	return ret;
}
