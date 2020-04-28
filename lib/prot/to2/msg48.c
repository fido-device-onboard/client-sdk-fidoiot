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
 * msg48() - TO2.Get_next_owner_service_info
 * --- Message Format Begins ---
 * {
 *   "nn":Uint8
 * }
 * --- Message Format Ends ---
 */
int32_t msg48(sdo_prot_t *ps)
{
	int ret = -1;

	/* send entry number to load */
	sdow_next_block(&ps->sdow, SDO_TO2_GET_NEXT_OWNER_SERVICE_INFO);
	sdow_begin_object(&ps->sdow);

	/* Write the "nn" - next Owner Service Info Index */
	sdo_write_tag(&ps->sdow, "nn");
	sdo_writeUInt(&ps->sdow, ps->owner_supplied_service_info_num);
	sdow_end_object(&ps->sdow);

	if (!sdo_encrypted_packet_windup(
		&ps->sdow, SDO_TO2_GET_NEXT_OWNER_SERVICE_INFO, ps->iv)) {
		goto err;
	}

	ps->state = SDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO;
	ret = 0; /* Mark as success */

err:
	return ret;
}
