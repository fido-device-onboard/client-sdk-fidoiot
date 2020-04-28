/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg50 of TO2 state machine.
 */

#include "sdoCrypto.h"
#include "load_credentials.h"
#include "sdoprot.h"
#include "util.h"

#define REUSE_HMAC_MAX_LEN 1

/**
 * msg50() - TO2.Done
 * The device calculates HMAC over the new Ownership voucher which may be used
 * later on to resale the device. However, the device may not support resale.
 * --- Message Format Begins ---
 * {
 *     "hmac:": Hash
 * }
 * --- Message Format Ends ---
 */
int32_t msg50(sdo_prot_t *ps)
{
	int ret = -1;
	sdo_byte_array_t *new_guid = ps->osc->guid;
	sdo_rendezvous_list_t *new_rvlist = ps->osc->rvlst;
	sdo_hash_t *hmac = NULL;

	LOG(LOG_DEBUG, "SDO_STATE_TO2_SND_DONE: Starting\n");

	/* Check if REUSE is ON */
	if (sdo_compare_public_keys(ps->owner_public_key, ps->new_pk) &&
	    sdo_compare_byte_arrays(ps->dev_cred->owner_blk->guid, new_guid) &&
	    sdo_compare_rv_lists(ps->dev_cred->owner_blk->rvlst, new_rvlist)) {
		LOG(LOG_DEBUG, "\n***** REUSE feature enabled *****\n");
		ps->reuse_enabled = true;
	}

	/*
	 * TODO: Writing credentials to TEE!
	 * This GUID came as g3 - "the new transaction GUID"
	 * which will overwrite GUID in initial credential data.
	 * A new transaction will start fresh, taking the latest
	 * credential (among them this, new GUID). That's why
	 * simple memorizing GUID in RAM is not needed.
	 */
	sdo_byte_array_free(ps->dev_cred->owner_blk->guid);
	ps->dev_cred->owner_blk->guid = new_guid;

	sdo_rendezvous_list_free(ps->dev_cred->owner_blk->rvlst);
	ps->dev_cred->owner_blk->rvlst = new_rvlist;

	sdo_public_key_free(ps->owner_public_key);
	ps->owner_public_key = NULL;

	if (ps->reuse_enabled && reuse_supported) {
		LOG(LOG_DEBUG, "*****Reuse triggered.*****\n");

		/* Send Invalid HMAC of "=" as data */
		const char *plain_text = "=";
		size_t plain_text_len =
		    strnlen_s(plain_text, REUSE_HMAC_MAX_LEN);

		/* For reuse hastype = 0 and length = 1 */
		hmac = sdo_hash_alloc(0, plain_text_len);
		if (!hmac) {
			LOG(LOG_ERROR, "Hash allocation failed.\n");
			goto err;
		}
		if (memcpy_s(hmac->hash->bytes, plain_text_len, plain_text,
			     plain_text_len) != 0) {
			LOG(LOG_ERROR, "Hash copy failed.\n");
			goto err;
		}

		/* Moving to post DI state  for Reuse case */
		ps->dev_cred->ST = SDO_DEVICE_STATE_READY1;
	} else {
		/* Resale Case or Reuse not supported case*/
		if (ps->reuse_enabled) {
			LOG(LOG_DEBUG,
			    "*****Reuse triggered but not supported.*****\n");
		}

		/* Generate new HMAC secret for OV header validation */
		if (0 != sdo_generate_ov_hmac_key()) {
			LOG(LOG_ERROR, "OV HMAC Key refresh failed.\n");
			goto err;
		}

		if (resale_supported) {
			LOG(LOG_DEBUG, "*****Resale triggered.*****\n");
			hmac = sdo_new_ov_hdr_sign(ps->dev_cred, ps->new_pk,
						   ps->ovoucher->hdc);
			if (!hmac) {
				LOG(LOG_ERROR, "Failed to get new HMAC\n");
				goto err;
			}

			/* Update the pkh to the new
			 * values
			 * Store hash of the new owner public key */
			sdo_hash_free(ps->dev_cred->owner_blk->pkh);
			ps->dev_cred->owner_blk->pkh =
			    sdo_pub_key_hash(ps->new_pk);

		} else {
			LOG(LOG_DEBUG,
			    "*****Resale triggered but not supported.*****\n");
			/*
			 * Device inability to perform resale by transmitting
			 * zero length HMAC
			 * */
			hmac = sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_USED,
					      SDO_SHA_DIGEST_SIZE_USED);

			if (hmac == NULL) {
				LOG(LOG_ERROR,
				    "HMAC buffer allocation failed.\n");
				goto err;
			}

			if (memset_s(hmac->hash->bytes, hmac->hash->byte_sz,
				     0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				goto err;
			}

			hmac->hash->byte_sz = 0;
		}
		/*  Done with Secure Device Onboard.*/
		/*  As of now moving to done state for resale*/
		ps->dev_cred->ST = SDO_DEVICE_STATE_IDLE;
	}
	sdo_public_key_free(ps->new_pk);
	ps->new_pk = NULL;

	/* Rotate Data Protection Key */
	if (0 != sdo_generate_storage_hmac_key()) {
		LOG(LOG_ERROR, "Failed to rotate data protection key.\n");
	}
	LOG(LOG_DEBUG, "Data protection key rotated successfully!!\n");

	/* Write new device credentials */
	if (store_credential(ps->dev_cred) != 0) {
		LOG(LOG_ERROR, "Failed to store new device creds\n");
		goto err;
	}
	LOG(LOG_DEBUG, "Updated device with new credentials\n");

	/* Create message and send "hmac" */
	sdow_next_block(&ps->sdow, SDO_TO2_DONE);
	sdow_begin_object(&ps->sdow);

	sdo_write_tag(&ps->sdow, "hmac");
	sdo_hash_write(&ps->sdow, hmac);
	sdo_write_tag(&ps->sdow, "n6");
	sdo_byte_array_write_chars(&ps->sdow, ps->n6);

	sdow_end_object(&ps->sdow);

	if (!sdo_encrypted_packet_windup(&ps->sdow, SDO_TO2_DONE, ps->iv)) {
		goto err;
	}

	ps->success = true;
	ps->state = SDO_STATE_TO2_RCV_DONE_2;
	ret = 0; /*Mark as success */

err:
	if (hmac)
		sdo_hash_free(hmac);
	return ret;
}
