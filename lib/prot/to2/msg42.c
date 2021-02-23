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
 * msg62() - TO2.GetOVNextEntry
 *
 * TO2.GetOVNextEntry = [
 *   OPEntryNum;	int
 * ]
 */
int32_t msg62(sdo_prot_t *ps)
{
	LOG(LOG_DEBUG, "TO2.GetOVNextEntry started\n");

	sdow_next_block(&ps->sdow, SDO_TO2_GET_OP_NEXT_ENTRY);
	if (!sdow_start_array(&ps->sdow, 1)) {
		LOG(LOG_ERROR, "TO2.GetOVNextEntry: Failed to read start array\n");
		return -1;
	}

	/* Write "enn" value in the block */
	if (!sdow_signed_int(&ps->sdow, ps->ov_entry_num)) {
		LOG(LOG_ERROR, "TO2.GetOVNextEntry: Failed to read OPEntryNum\n");
		return -1;
	}

	if (!sdow_end_array(&ps->sdow)) {
		LOG(LOG_ERROR, "TO2.GetOVNextEntry: Failed to read end array\n");
		return -1;
	}
	/* Move to msg43 */
	ps->state = SDO_STATE_T02_RCV_OP_NEXT_ENTRY;
	LOG(LOG_DEBUG, "TO2.GetOVNextEntry completed successfully\n");
	return 0;
}
