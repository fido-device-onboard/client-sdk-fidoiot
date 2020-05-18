/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg44 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"
#include "sdoCrypto.h"

/**
 * msg44() - TO2.Prove_device
 * The device sends out data proving that it is authentic device.
 * --- Message Format Begins ---
 * { # Signature
 *     "bo": {
 *         "ai": App_id,        # proves App provenance within TEE
 *         "n6: Nonce,         # proves signature freshness
 *         "n7: Nonce,         # used in TO2.Setup_device
 *         "g2": GUID,         # proves the GUID matches with g2 in
 *                             # TO2.Hello_device
 *         "nn": UInt8,        # number of device service info messages to come
 *         "xB": DHKey_exchange # Key Exchange, 2nd Step
 *     },
 *     "pk": Public_key,        # EPID key for EPID device attestation;
 *                             # PKNull if ECDSA
 *     "sg": Signature         # Signature from device
 * }
 * --- Message Format Ends ---
 */
int32_t msg44(sdo_prot_t *ps)
{
	int mod_mes_count = 0;
	int mod_ret_val = 0;
	int ret = -1;
	sdo_sig_t sig = {0};
	sdo_byte_array_t *xB = NULL;
	char buf[DEBUGBUFSZ] = {0};
	sdo_public_key_t *publickey;

	LOG(LOG_DEBUG, "SDO_STATE_TO2_SND_PROVE_DEVICE: Starting\n");

	sdow_next_block(&ps->sdow, SDO_TO2_PROVE_DEVICE);

	publickey = NULL;

	/* Store the pointer to opening "{" for signing */
	if (sdo_begin_write_signature(&ps->sdow, &sig, publickey) != true) {
		LOG(LOG_ERROR, "Failed in writing the signature\n");
		goto err;
	}

	/* Get the second part of Key Exchange */
	ret = sdo_get_kex_paramB(&xB);
	if (0 != ret && !xB) {
		LOG(LOG_ERROR, "Device has no publicB\n");
		goto err;
	}

	/* Write "ai" (application id) in the body */
	sdow_begin_object(&ps->sdow);
	sdo_write_tag(&ps->sdow, "ai");
	sdo_app_id_write(&ps->sdow);

	/* Write "n6" (nonce) received in msg41 */
	sdo_write_tag(&ps->sdow, "n6");
	sdo_byte_array_write_chars(&ps->sdow, ps->n6);
	LOG(LOG_DEBUG, "Sending n6: %s\n",
	    sdo_nonce_to_string(ps->n6->bytes, buf, sizeof buf) ? buf : "");

	/* Write "n7" (nonce) to be used in msg47 */
	sdo_write_tag(&ps->sdow, "n7");
	ps->n7 = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n7) {
		LOG(LOG_ERROR, "Alloc failed \n");
		goto err;
	}
	sdo_nonce_init_rand(ps->n7);
	sdo_byte_array_write_chars(&ps->sdow, ps->n7);
	LOG(LOG_DEBUG, "Sending n7: %s\n",
	    sdo_nonce_to_string(ps->n7->bytes, buf, sizeof buf) ? buf : "");

	/* Write the guid sent in msg40 (same as received in msg 11) */
	sdo_write_tag(&ps->sdow, "g2");
	sdo_byte_array_write_chars(&ps->sdow, ps->g2);

	/* Get Device Service Info (DSI) count from modules (GET_DSI_COUNT) */
	if (!sdo_get_dsi_count(ps->sv_info_mod_list_head, &mod_mes_count,
			       &mod_ret_val)) {
		if (mod_ret_val == SDO_SI_INTERNAL_ERROR)
			goto err;
	}

	/* +1 for all platform DSI's */
	ps->total_dsi_rounds = 1 + mod_mes_count;
	sdo_write_tag(&ps->sdow, "nn");
	/* If we have any device service info, then not 0 */
	if (ps->service_info) /* FIXME: Where is 0 written?? */
		sdo_writeUInt(&ps->sdow, ps->total_dsi_rounds);

	/* Write down the "xB" (key exchange) info */
	sdo_write_tag(&ps->sdow, "xB");
	sdo_byte_array_write(&ps->sdow, xB);
	sdow_end_object(&ps->sdow);

	/* Sign the body */
	if (sdo_end_write_signature(&ps->sdow, &sig) != true) {
		LOG(LOG_ERROR, "Failed in writing the signature\n");
		goto err;
	}

	if (ps->service_info && ps->service_info->numKV) {
		/* Goto msg45 */
		ps->state = SDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO;
		LOG(LOG_DEBUG, "Device Service Info messages to come: %d\n",
		    ps->total_dsi_rounds);
	} else {
		ps->state = SDO_STATE_TO2_RCV_SETUP_DEVICE; /* msg47 */
	}

	ret = 0; /* Mark as success */
	LOG(LOG_DEBUG, "SDO_STATE_TO2_SND_PROVE_DEVICE: Complete\n");
err:
	return ret;
}
