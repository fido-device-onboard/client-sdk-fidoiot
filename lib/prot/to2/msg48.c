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
 * msg48() - TO2.GetNextOwnerServiceInfo
 * --- Message Format Begins ---
 * {
 *   "nn":Uint8
 * }
 * --- Message Format Ends ---
 */
int32_t msg48(SDOProt_t *ps)
{
	int ret = -1;

	/* send entry number to load */
	sdoWNextBlock(&ps->sdow, SDO_TO2_GET_NEXT_OWNER_SERVICE_INFO);
	sdoWBeginObject(&ps->sdow);

	/* Write the "nn" - next Owner Service Info Index */
	sdoWriteTag(&ps->sdow, "nn");
	sdoWriteUInt(&ps->sdow, ps->ownerSuppliedServiceInfoNum);
	sdoWEndObject(&ps->sdow);

	if (!sdoEncryptedPacketWindup(
		&ps->sdow, SDO_TO2_GET_NEXT_OWNER_SERVICE_INFO, ps->iv)) {
		goto err;
	}

	ps->state = SDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO;
	ret = 0; /* Mark as success */

err:
	return ret;
}
