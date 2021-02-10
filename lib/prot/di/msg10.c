/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of msg number 10; first step of Device Initialize
 * Protocol
 */

#include "util.h"
#include "sdoprot.h"

/* TODO: Move m-string generation here */

/**
 * msg10() - DIAppStart, Type 10
 * This is the beginning of state machine for ownership transfer of device.The
 * device prepares the "m" string to communicate with the manufacturer, so, it
 * gets the first ownership voucher after Device Initialize (DI) stage is
 * complete.
 *
 * Message format
 * ---------------------------------------------------------------------------
 * DI.AppStart = [
 *   DeviceMfgInfo
 * ]
 */
int32_t msg10(sdo_prot_t *ps)
{
	int ret = -1;

	sdow_next_block(&ps->sdow, SDO_DI_APP_START);
	if (!sdow_start_array(&ps->sdow, 1))
		goto err;

	/* Get the DeviceMfgInfo in the ps object */
	ret = ps_get_m_string(ps);
	if (ret) {
		LOG(LOG_ERROR, "Failed to get DeviceMfgInfo\n");
		goto err;
	}
	/* End the object */
	if (!sdow_end_array(&ps->sdow))
		goto err;

	/* This state manages the transition to the next protocol message */
	ps->state = SDO_STATE_DI_SET_CREDENTIALS;
	LOG(LOG_DEBUG, "DIAppStart completed\n");
	ret = 0;

err:
	return ret;
}
