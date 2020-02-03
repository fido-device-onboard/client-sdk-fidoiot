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
 * msg42() - TO2.GetOPNextEntry
 *
 * --- Message Format Begins ---
 * {
 *     "enn": UInt8 # Requests for entry with index "enn"
 * }
 * --- Message Format Ends ---
 */
int32_t msg42(SDOProt_t *ps)
{
	LOG(LOG_DEBUG, "SDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY: Starting\n");
	sdoWNextBlock(&ps->sdow, SDO_TO2_GET_OP_NEXT_ENTRY);
	sdoWBeginObject(&ps->sdow);

	/* Write "enn" value in the block */
	sdoWriteTag(&ps->sdow, "enn");
	sdoWriteUInt(&ps->sdow, ps->ovEntryNum);

	sdoWEndObject(&ps->sdow);

	/* Move to msg43 */
	ps->state = SDO_STATE_T02_RCV_OP_NEXT_ENTRY;
	return 0;
}
