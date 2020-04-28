/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg42 of TO2 state machine.
 */

#include "sdoprot.h"
#include "util.h"

/**
 * msg42() - TO2.GetOPNext_entry
 *
 * --- Message Format Begins ---
 * {
 *     "enn": UInt8 # Requests for entry with index "enn"
 * }
 * --- Message Format Ends ---
 */
int32_t msg42(sdo_prot_t *ps)
{
	LOG(LOG_DEBUG, "SDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY: Starting\n");
	sdow_next_block(&ps->sdow, SDO_TO2_GET_OP_NEXT_ENTRY);
	sdow_begin_object(&ps->sdow);

	/* Write "enn" value in the block */
	sdo_write_tag(&ps->sdow, "enn");
	sdo_writeUInt(&ps->sdow, ps->ov_entry_num);

	sdow_end_object(&ps->sdow);

	/* Move to msg43 */
	ps->state = SDO_STATE_T02_RCV_OP_NEXT_ENTRY;
	return 0;
}
