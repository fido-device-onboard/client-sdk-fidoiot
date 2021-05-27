/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 30.
 */

#include "util.h"
#include "fdoprot.h"

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
int32_t msg30(fdo_prot_t *ps)
{
	int ret = -1;
	if (!ps) {
		LOG(LOG_ERROR, "Invalid protocol state\n");
		return ret;
	}

	LOG(LOG_DEBUG, "TO1.HelloRV started\n");
	fdow_next_block(&ps->fdow, FDO_TO1_TYPE_HELLO_FDO);
	if (!fdow_start_array(&ps->fdow, 2)) {
		LOG(LOG_ERROR, "TO1.HelloRV: Failed to start array\n");
		return false;
	}

	/* Write GUID received during DI */
	if (!fdow_byte_string(&ps->fdow, ps->dev_cred->owner_blk->guid->bytes,
		ps->dev_cred->owner_blk->guid->byte_sz)) {
		LOG(LOG_ERROR, "TO1.HelloRV: Failed to write Guid\n");
		return false;
	}

	/* Write the siginfo for RV to use and prepare next msg */
	if (!fdo_siginfo_write(&ps->fdow)) {
		LOG(LOG_ERROR, "TO1.HelloRV: Failed to write eASigInfo\n");
		return false;
	}

	if (!fdow_end_array(&ps->fdow)) {
		LOG(LOG_ERROR, "TO1.HelloRV: Failed to end array\n");
		return false;
	}

	/* Move to next state (msg31) */
	ps->state = FDO_STATE_TO1_RCV_HELLO_FDOACK;
	LOG(LOG_DEBUG, "TO1.HelloRV completed successfully\n");

	return 0;
}
