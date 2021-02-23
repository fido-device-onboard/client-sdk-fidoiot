/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg47 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg67() - TO2.OwnerServiceInfoReady
 * 
 * TO2.OwnerServiceInfoReady  = [
 *   maxDeviceServiceInfoSz    ;; maximum size service info that Owner can receive, uint/NULL
 * ]
 */
int32_t msg67(sdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
	sdo_encrypted_packet_t *pkt = NULL;
	int rec_maxDeviceServiceInfoSz = 0;
	sdo_byte_array_t *null_bytes = NULL;

	if (!sdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	LOG(LOG_DEBUG, "TO2.OwnerServiceInfoReady started\n");

	pkt = sdo_encrypted_packet_read(&ps->sdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfoReady: Failed to parse encrypted packet\n");
		goto err;
	}

	if (!sdo_encrypted_packet_unwind(&ps->sdor, pkt, ps->iv)) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfoReady: Failed to decrypt packet!\n");
		goto err;
	}

	sdo_log_block(&ps->sdor.b);

	if (!sdor_start_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfoReady: Failed to start array\n");
		goto err;
	}

	// maxDeviceServiceInfoSz = CBOR NULL implies that MAXDEVICESERVICEINFOSZ should be accepted
	// maxDeviceServiceInfoSz = Unsigned Integer implies that the given value should be processed
	if (sdor_is_value_signed_int(&ps->sdor)) {
		if (!sdor_signed_int(&ps->sdor, &rec_maxDeviceServiceInfoSz)) {
			LOG(LOG_ERROR,
				"TO2.OwnerServiceInfoReady: Failed to read maxDeviceServiceInfoSz as number\n");
			goto err;
		}
	} else if (sdor_is_value_null(&ps->sdor)) {
		if (!sdor_next(&ps->sdor)) {
			LOG(LOG_ERROR,
				"TO2.OwnerServiceInfoReady: Failed to read maxDeviceServiceInfoSz as null\n");
			goto err;
		}
	} else {
		// buffer to store CBOR NULL wrapped in bstr, as sent by PRI.
		// To be removed once PRI is updated to send CBOR NULL directly.
		null_bytes = sdo_byte_array_alloc(1);
		if (!null_bytes) {
			LOG(LOG_ERROR,
				"TO2.OwnerServiceInfoReady: Failed to read maxDeviceServiceInfoSz as null\n");
			goto err;
		}
		if (!sdor_byte_string(&ps->sdor, null_bytes->bytes, null_bytes->byte_sz)) {
			LOG(LOG_ERROR,
				"TO2.OwnerServiceInfoReady: Failed to read maxDeviceServiceInfoSz as null\n");
			goto err;
		}

	/*	Throw an error if not int/NULL. This is the way. TO-DO
		LOG(LOG_ERROR,
			"TO2.OwnerServiceInfoReady: Invalid value type for maxDeviceServiceInfoSz\n");
		goto err;
	*/
	}

	if (rec_maxDeviceServiceInfoSz > 0 &&
		rec_maxDeviceServiceInfoSz < MAXDEVICESERVICEINFOSZ) {
		ps->maxDeviceServiceInfoSz = rec_maxDeviceServiceInfoSz;
	} else {
		ps->maxDeviceServiceInfoSz = MAXDEVICESERVICEINFOSZ;
	}

	if (!sdor_end_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfoReady: Failed to end array\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TO2.OwnerServiceInfoReady: Expected Maximum Device ServiceInfo size is %d \n",
	    ps->maxDeviceServiceInfoSz);
	ps->state = SDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO;
	LOG(LOG_DEBUG, "TO2.OwnerServiceInfoReady completed successfully\n");
	ret = 0; /* Mark as success */

err:
	sdor_flush(&ps->sdor);
	ps->sdor.have_block = false;
	if (null_bytes) {
		sdo_byte_array_free(null_bytes);
	}
	return ret;
}
