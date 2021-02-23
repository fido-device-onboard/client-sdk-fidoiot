/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg46 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"
#include "sdoCrypto.h"

/**
 * msg66() - TO2.DeviceServiceInfoReady
 * The device calculates HMAC over the new Ownership voucher which may be used
 * later on to resale the device. However, the device may not support resale.
 *
 * TO2.DeviceServiceInfoReady = [
 *   ReplacementHMac, ;; Replacement for DI.SetHMac.HMac or equivalent
 *   maxOwnerServiceInfoSz    ;; maximum size service info that Device can receive
 * ]
 */
int32_t msg66(sdo_prot_t *ps)
{
	int ret = -1;
	sdo_hash_t *hmac = NULL;

	LOG(LOG_DEBUG, "TO2.DeviceServiceInfoReady started\n");

	/* Send all the key value sets in the Service Info list */
	sdow_next_block(&ps->sdow, SDO_TO2_NEXT_DEVICE_SERVICE_INFO);

	if (!sdow_start_array(&ps->sdow, 2)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to start array\n");
		goto err;
	}

	/* Check if REUSE is ON */
	if (sdo_compare_public_keys(ps->owner_public_key, ps->osc->pubkey) &&
	    sdo_compare_byte_arrays(ps->dev_cred->owner_blk->guid, ps->osc->guid) &&
	    sdo_compare_rv_lists(ps->dev_cred->owner_blk->rvlst, ps->osc->rvlst)) {
		LOG(LOG_DEBUG, "\n***** REUSE feature enabled *****\n");
		ps->reuse_enabled = true;
	}

	if (ps->reuse_enabled && reuse_supported) {
		LOG(LOG_DEBUG, "TO2.DeviceServiceInfoReady: *****Reuse triggered.*****\n");
		// write CBOR NULL
		if (!sdow_null(&ps->sdow)) {
			LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to write ReplacementHMac\n");
			goto err;
		}

	} else {
		/* Resale Case or Reuse not supported case*/
		if (ps->reuse_enabled) {
			LOG(LOG_DEBUG,
			    "TO2.DeviceServiceInfoReady: *****Reuse triggered but not supported.*****\n");
			// throw error now as per FDO sec
			goto err;
		}

		if (resale_supported) {
			LOG(LOG_DEBUG, "TO2.DeviceServiceInfoReady: *****Resale triggered.*****\n");
			/* Generate new HMAC secret for OV header validation */
			if (0 != sdo_generate_ov_hmac_key()) {
				LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to refresh OV HMAC Key\n");
				goto err;
			}
			hmac = sdo_new_ov_hdr_sign(ps->dev_cred, ps->osc,
						   ps->ovoucher->hdc);
			if (!hmac) {
				LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to generate ReplacementHMac\n");
				goto err;
			}

			if (!sdo_hash_write(&ps->sdow, hmac)) {
				LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to write ReplacementHMac\n");
				goto err;
			}
			// Update the pkh to the new values and store hash of the new owner public key
			sdo_hash_free(ps->dev_cred->owner_blk->pkh);
			ps->dev_cred->owner_blk->pkh =
			    sdo_pub_key_hash(ps->osc->pubkey);

		} else {
			LOG(LOG_DEBUG,
			    "TO2.DeviceServiceInfoReady: *****Resale triggered but not supported.*****\n");
			// TO-DO: This case is no more, update the flags
			goto err;
		}
	}

	if (!sdow_signed_int(&ps->sdow, MAXOWNERSERVICEINFOSZ)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to write maxOwnerServiceInfoSz\n");
		goto err;
	}

	if (!sdow_end_array(&ps->sdow)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to end array\n");
		goto err;
	}

	/* Encrypt the packet */
	if (!sdo_encrypted_packet_windup(
		&ps->sdow, SDO_TO2_NEXT_DEVICE_SERVICE_INFO, ps->iv)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to create Encrypted Message\n");
		goto err;
	}

	ps->state = SDO_STATE_TO2_RCV_SETUP_DEVICE;
	LOG(LOG_DEBUG, "TO2.DeviceServiceInfoReady completed successfully\n");
	ret = 0; /* Mark as success */

err:
	return ret;
}
