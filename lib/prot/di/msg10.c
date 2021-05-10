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
#include "fdoprot.h"

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
int32_t msg10(fdo_prot_t *ps)
{
	int ret = -1;

	fdow_next_block(&ps->fdow, FDO_DI_APP_START);
	if (!fdow_start_array(&ps->fdow, 1))
		goto err;

	/* Get the DeviceMfgInfo in the ps object */
	ret = ps_get_m_string(ps);
	if (ret) {
		LOG(LOG_ERROR, "Failed to get DeviceMfgInfo\n");
		goto err;
	}
	/* End the object */
	if (!fdow_end_array(&ps->fdow))
		goto err;

	/* This state manages the transition to the next protocol message */
	ps->state = FDO_STATE_DI_SET_CREDENTIALS;
	LOG(LOG_DEBUG, "DIAppStart completed\n");
	ret = 0;

err:
	return ret;
}
