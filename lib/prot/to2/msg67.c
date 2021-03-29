/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg47 of TO2 state machine.
 */

#include "fdoprot.h"
#include "fdokeyexchange.h"
#include "util.h"

/**
 * msg67() - TO2.OwnerServiceInfoReady
 * 
 * TO2.OwnerServiceInfoReady  = [
 *   maxDeviceServiceInfoSz    ;; maximum size service info that Owner can receive, uint/NULL
 * ]
 */
int32_t msg67(fdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "FDOProtTO2";
	fdo_encrypted_packet_t *pkt = NULL;
	int rec_maxDeviceServiceInfoSz = 0;

	if (!fdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!fdo_prot_rcv_msg(&ps->fdor, &ps->fdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	LOG(LOG_DEBUG, "TO2.OwnerServiceInfoReady started\n");

	pkt = fdo_encrypted_packet_read(&ps->fdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfoReady: Failed to parse encrypted packet\n");
		goto err;
	}

	if (!fdo_encrypted_packet_unwind(&ps->fdor, pkt, ps->iv)) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfoReady: Failed to decrypt packet!\n");
		goto err;
	}

	if (!fdor_start_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfoReady: Failed to start array\n");
		goto err;
	}

	// maxDeviceServiceInfoSz = CBOR NULL implies that MIN_SERVICEINFO_SZ should be accepted
	// maxDeviceServiceInfoSz = Unsigned Integer implies that the given value should be processed
	if (fdor_is_value_signed_int(&ps->fdor)) {
		if (!fdor_signed_int(&ps->fdor, &rec_maxDeviceServiceInfoSz)) {
			LOG(LOG_ERROR,
				"TO2.OwnerServiceInfoReady: Failed to read maxDeviceServiceInfoSz as number\n");
			goto err;
		}
	} else if (fdor_is_value_null(&ps->fdor)) {
		if (!fdor_next(&ps->fdor)) {
			LOG(LOG_ERROR,
				"TO2.OwnerServiceInfoReady: Failed to read maxDeviceServiceInfoSz as null\n");
			goto err;
		}
	} else {
		// Throw an error if not int/NULL.
		LOG(LOG_ERROR,
			"TO2.OwnerServiceInfoReady: Invalid value type for maxDeviceServiceInfoSz\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TO2.OwnerServiceInfoReady: Received maxDeviceServiceInfoSz = %d\n",
		rec_maxDeviceServiceInfoSz);
	if (rec_maxDeviceServiceInfoSz <= MIN_SERVICEINFO_SZ) {
		// default to minimum and log it
		ps->maxDeviceServiceInfoSz = MIN_SERVICEINFO_SZ;
		LOG(LOG_DEBUG,
			"TO2.OwnerServiceInfoReady: Received maxDeviceServiceInfoSz is less than "
			"the minimum size supported. Defaulting to %d\n",
			ps->maxDeviceServiceInfoSz);
	}
	else if	(rec_maxDeviceServiceInfoSz >= ps->maxDeviceServiceInfoSz) {
		// nothing to do, just log it
		LOG(LOG_DEBUG,
			"TO2.OwnerServiceInfoReady: Received maxDeviceServiceInfoSz is more than "
			"the maximum size supported. Defaulting to %d\n",
			ps->maxDeviceServiceInfoSz);
	}

	if (!fdor_end_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.OwnerServiceInfoReady: Failed to end array\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TO2.OwnerServiceInfoReady: Expected Maximum Device ServiceInfo size is %d \n",
	    ps->maxDeviceServiceInfoSz);
	ps->state = FDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO;
	LOG(LOG_DEBUG, "TO2.OwnerServiceInfoReady completed successfully\n");
	ret = 0; /* Mark as success */

err:
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.have_block = false;
	return ret;
}
