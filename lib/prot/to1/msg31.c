/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 31.
 */

#include "util.h"
#include "fdoprot.h"

/**
 * msg31() - TO1.HelloRVAck, Type 31
 * The device receives information which it needs to use to prove to
 * Rendezvous(RV) Server, that it is the device which it claims it to
 * be.
 *
 * [
 *   Nonce4,
 *   eBSigInfo
 * ]
 */
int32_t msg31(fdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "FDOProtTO1";

	/* Read network data from internal buffer */
	if (!fdo_prot_rcv_msg(&ps->fdor, &ps->fdow, prot, &ps->state)) {
		ret = 0; /* Mark for retry */
		goto err;
	}

	LOG(LOG_DEBUG, "TO1.HelloRVAck started\n");

	if (!fdor_start_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO1.HelloRVAck: Failed to start array\n");
		goto err;
	}

	ps->n4 = fdo_byte_array_alloc(FDO_NONCE_BYTES);
	if (!ps->n4 || !fdor_byte_string(&ps->fdor, ps->n4->bytes, ps->n4->byte_sz)) {
		LOG(LOG_ERROR, "TO1.HelloRVAck: Failed to read Nonce4\n");
		goto err;
	}

	if (!fdo_siginfo_read(&ps->fdor)) {
		LOG(LOG_ERROR, "TO1.HelloRVAck: Failed to read eBSigInfo\n");
		goto err;
	}

	if (!fdor_end_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO1.HelloRVAck: Failed to end array\n");
		goto err;
	}

	/* Updated state to move to msg32 */
	ps->state = FDO_STATE_TO1_SND_PROVE_TO_FDO;
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.have_block = false;
	ret = 0;
	LOG(LOG_DEBUG, "TO1.HelloRVAck completed successfully\n");

err:
	return ret;
}
