/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 31.
 */

#include "util.h"
#include "sdoprot.h"

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
int32_t msg31(sdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO1";

	/* Read network data from internal buffer */
	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Mark for retry */
		goto err;
	}

	LOG(LOG_DEBUG, "TO1.HelloRVAck started\n");

	if (!sdor_start_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO1.HelloRVAck: Failed to start array\n");
		goto err;
	}

	ps->n4 = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n4 || !sdor_byte_string(&ps->sdor, ps->n4->bytes, ps->n4->byte_sz)) {
		LOG(LOG_ERROR, "TO1.HelloRVAck: Failed to read Nonce4\n");
		goto err;
	}

	if (!sdo_eb_read(&ps->sdor)) {
		LOG(LOG_ERROR, "TO1.HelloRVAck: Failed to read eBSigInfo\n");
		goto err;
	}

	if (!sdor_end_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO1.HelloRVAck: Failed to end array\n");
		goto err;
	}

	/* Updated state to move to msg32 */
	ps->state = SDO_STATE_TO1_SND_PROVE_TO_SDO;
	sdo_block_reset(&ps->sdor.b);
	ps->sdor.have_block = false;
	ret = 0;
	LOG(LOG_DEBUG, "TO1.HelloRVAck completed successfully\n");

err:
	return ret;
}
