/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 30.
 */

#include "util.h"
#include "sdoprot.h"

/**
 * msg30() - TO1.HelloRV, Type 30
 * The device is powered ON again in customer premises and the process of
 * finding rightful owner begins with this message. The device will
 * prepare itself to talk to Rendezvous(RV) Server and establish the trust
 * to get the credentials of next owner
 *
 * [
 *   Guid,
 *   eASigInfo
 * ]
 */
int32_t msg30(sdo_prot_t *ps)
{
	LOG(LOG_DEBUG, "TO1.HelloRV started\n");
	sdow_next_block(&ps->sdow, SDO_TO1_TYPE_HELLO_SDO);
	if (!sdow_start_array(&ps->sdow, 2)) {
		LOG(LOG_ERROR, "TO1.HelloRV: Failed to start array\n");
		return false;
	}

	/* Write GUID received during DI */
	if (!sdow_byte_string(&ps->sdow, ps->dev_cred->owner_blk->guid->bytes,
		ps->dev_cred->owner_blk->guid->byte_sz)) {
		LOG(LOG_ERROR, "TO1.HelloRV: Failed to write Guid\n");
		return false;
	}

	/* Write the siginfo for RV to use and prepare next msg */
	if (!sdo_siginfo_write(&ps->sdow)) {
		LOG(LOG_ERROR, "TO1.HelloRV: Failed to write eASigInfo\n");
		return false;
	}

	if (!sdow_end_array(&ps->sdow)) {
		LOG(LOG_ERROR, "TO1.HelloRV: Failed to end array\n");
		return false;
	}

	/* Move to next state (msg31) */
	ps->state = SDO_STATE_TO1_RCV_HELLO_SDOACK;
	LOG(LOG_DEBUG, "TO1.HelloRV completed successfully\n");

	return 0;
}
