/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg62 of TO2 state machine.
 */

#include "fdoprot.h"
#include "util.h"

/**
 * msg62() - TO2.GetOVNextEntry
 *
 * TO2.GetOVNextEntry = [
 *   OPEntryNum;	int
 * ]
 */
int32_t msg62(fdo_prot_t *ps)
{
	LOG(LOG_DEBUG, "TO2.GetOVNextEntry started\n");

	fdow_next_block(&ps->fdow, FDO_TO2_GET_OP_NEXT_ENTRY);
	if (!fdow_start_array(&ps->fdow, 1)) {
		LOG(LOG_ERROR, "TO2.GetOVNextEntry: Failed to read start array\n");
		return -1;
	}

	/* Write OVEntryNum value in the block */
	if (!fdow_signed_int(&ps->fdow, ps->ov_entry_num)) {
		LOG(LOG_ERROR, "TO2.GetOVNextEntry: Failed to read OPEntryNum\n");
		return -1;
	}

	if (!fdow_end_array(&ps->fdow)) {
		LOG(LOG_ERROR, "TO2.GetOVNextEntry: Failed to read end array\n");
		return -1;
	}
	/* Move to msg63 */
	ps->state = FDO_STATE_T02_RCV_OP_NEXT_ENTRY;
	LOG(LOG_DEBUG, "TO2.GetOVNextEntry completed successfully\n");
	return 0;
}
