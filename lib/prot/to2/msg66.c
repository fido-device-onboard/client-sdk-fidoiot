/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg66 of TO2 state machine.
 */

#include "fdoprot.h"
#include "fdokeyexchange.h"
#include "util.h"
#include "fdoCrypto.h"

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
int32_t msg66(fdo_prot_t *ps)
{
	int ret = -1;
	fdo_hash_t *hmac = NULL;

	if (!ps) {
		LOG(LOG_ERROR, "Invalid protocol state\n");
		return ret;
	}

	LOG(LOG_DEBUG, "TO2.DeviceServiceInfoReady started\n");

	/* Send all the key value sets in the Service Info list */
	fdow_next_block(&ps->fdow, FDO_TO2_NEXT_DEVICE_SERVICE_INFO);

	if (!fdow_start_array(&ps->fdow, 2)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to start array\n");
		goto err;
	}

	/* Check if REUSE is ON */
	if (fdo_compare_public_keys(ps->owner_public_key, ps->osc->pubkey) &&
	    fdo_compare_byte_arrays(ps->dev_cred->owner_blk->guid, ps->osc->guid) &&
	    fdo_compare_rv_lists(ps->dev_cred->owner_blk->rvlst, ps->osc->rvlst)) {
		LOG(LOG_DEBUG, "\n***** REUSE feature enabled *****\n");
		ps->reuse_enabled = true;
	}

	if (ps->reuse_enabled && reuse_supported) {
		LOG(LOG_DEBUG, "TO2.DeviceServiceInfoReady: *****Reuse triggered.*****\n");
		// write CBOR NULL
		if (!fdow_null(&ps->fdow)) {
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
			if (0 != fdo_generate_ov_replacement_hmac_key()) {
				LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to refresh OV HMAC Key\n");
				goto err;
			}
			hmac = fdo_new_ov_hdr_sign(ps->dev_cred, ps->osc,
						   ps->ovoucher->hdc);
			if (!hmac) {
				LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to generate ReplacementHMac\n");
				goto err;
			}

			if (!fdo_hash_write(&ps->fdow, hmac)) {
				LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to write ReplacementHMac\n");
				goto err;
			}
		} else {
			LOG(LOG_DEBUG,
			    "TO2.DeviceServiceInfoReady: *****Resale triggered but not supported.*****\n");
			// write CBOR NULL
			if (!fdow_null(&ps->fdow)) {
				LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to write ReplacementHMac\n");
				goto err;
			}
			goto err;
		}
	}

	if (!fdow_unsigned_int(&ps->fdow, ps->maxOwnerServiceInfoSz)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to write maxOwnerServiceInfoSz\n");
		goto err;
	}

	if (ps->maxOwnerServiceInfoSz > MAX_NEGO_MSG_SIZE) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: maxOwnerServiceInfoSz can not be greater than 65535\n");
		goto err;
	}
	LOG(LOG_DEBUG, "TO2.DeviceServiceInfoReady: Sent maxOwnerServiceInfoSz = %"PRIu64"\n", ps->maxOwnerServiceInfoSz);

	if (!fdow_end_array(&ps->fdow)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to end array\n");
		goto err;
	}

	/* Encrypt the packet */
	if (!fdo_encrypted_packet_windup(
		&ps->fdow, FDO_TO2_NEXT_DEVICE_SERVICE_INFO)) {
		LOG(LOG_ERROR, "TO2.DeviceServiceInfoReady: Failed to create Encrypted Message\n");
		goto err;
	}

	ps->state = FDO_STATE_TO2_RCV_SETUP_DEVICE;
	LOG(LOG_DEBUG, "TO2.DeviceServiceInfoReady completed successfully\n");
	ret = 0; /* Mark as success */

err:
	if (hmac) {
		fdo_hash_free(hmac);
	}
	return ret;
}
