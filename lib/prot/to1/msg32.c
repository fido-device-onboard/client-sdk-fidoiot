/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 32.
 */

#include "util.h"
#include "sdoprot.h"
#include "sdoCrypto.h"

/**
 * msg32() - TO1.Prove_toSDO
 * The device responds with the data which potentially proves to RV that it is
 * the authorized device requesting the owner information
 *
 * --- Message Format Begins ---
 * {
 *      "bo": {
 *	    "ai": App_id,     # App_id of SDO
 *   	"n4": Nonce,     # Nonce which was received in msg31
 *      "g2": GUID,      # GUID sent to RV in msg30
 *      },
 *      "pk": Public_key, # EPID Public key if DA = epid, else PKNull
 *      "sg": Signature  # Signature calculated over nonce
 * }
 * --- Message Format Ends---
 *
 */
int32_t msg32(sdo_prot_t *ps)
{
	int ret = -1;
	sdo_sig_t sig = {0};
	sdo_public_key_t *publickey;

	LOG(LOG_DEBUG, "Starting SDO_STATE_TO1_SND_PROVE_TO_SDO\n");

	/* Start writing the block for msg31 */
	sdow_next_block(&ps->sdow, SDO_TO1_TYPE_PROVE_TO_SDO);

	/* Start Body/Begin Object "bo" tag */
	publickey = NULL;

	if (!sdo_begin_write_signature(&ps->sdow, &sig, publickey)) {
		LOG(LOG_ERROR, "Failed in writing the signature\n");
		goto err;
	}

	sdow_begin_object(&ps->sdow);

	/* Write the "ai" tag */
	sdo_write_tag(&ps->sdow, "ai");
	sdo_app_id_write(&ps->sdow);

	/* Write back the same nonce which was received in msg31 */
	sdo_write_tag(&ps->sdow, "n4");
	if (!ps->n4) {
		LOG(LOG_ERROR, "ps->n4 is empty MSG#32\n");
		goto err;
	}

	/* FIXME: Move to error handling. If TO1 restarts, we will leak memory
	 */
	sdo_byte_array_write_chars(&ps->sdow, ps->n4);
	sdo_byte_array_free(ps->n4);
	ps->n4 = NULL;

	/* Write the GUID received during DI */
	sdo_write_tag(&ps->sdow, "g2");
	sdo_byte_array_write_chars(&ps->sdow, ps->dev_cred->owner_blk->guid);
	/* TODO: Add support for epk defined in spec 0.8 */
	sdow_end_object(&ps->sdow);

	/* Fill in the pk and sg based on Device Attestation selected */
	if (sdo_end_write_signature(&ps->sdow, &sig) != true) {
		LOG(LOG_ERROR, "Failed in writing the signature\n");
		goto err;
	}

	/* Mark as success and move to msg 33 */
	ps->state = SDO_STATE_TO1_RCV_SDO_REDIRECT;
	ret = 0;

	LOG(LOG_DEBUG, "Complete SDO_STATE_TO1_SND_PROVE_TO_SDO\n");

err:
	return ret;
}
