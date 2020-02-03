/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg50 of TO2 state machine.
 */

#include "sdoCryptoApi.h"
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
int32_t msg50(SDOProt_t *ps)
{
	int ret = -1;
	SDOByteArray_t *new_guid = ps->osc->guid;
	SDORendezvousList_t *new_rvlist = ps->osc->rvlst;
	SDOHash_t *hmac = NULL;

	LOG(LOG_DEBUG, "SDO_STATE_TO2_SND_DONE: Starting\n");

	/* Check if REUSE is ON */
	if (sdoComparePublicKeys(ps->ownerPublicKey, ps->new_pk) &&
	    sdoCompareByteArrays(ps->devCred->ownerBlk->guid, new_guid) &&
	    sdoCompareRvLists(ps->devCred->ownerBlk->rvlst, new_rvlist)) {
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
	sdoByteArrayFree(ps->devCred->ownerBlk->guid);
	ps->devCred->ownerBlk->guid = new_guid;

	sdoRendezvousListFree(ps->devCred->ownerBlk->rvlst);
	ps->devCred->ownerBlk->rvlst = new_rvlist;

	sdoPublicKeyFree(ps->ownerPublicKey);
	ps->ownerPublicKey = NULL;

	if (ps->reuse_enabled && reuse_supported) {
		LOG(LOG_DEBUG, "*****Reuse triggered.*****\n");

		/* Send Invalid HMAC of "=" as data */
		const char *plainText = "=";
		size_t plainTextLen = strnlen_s(plainText, REUSE_HMAC_MAX_LEN);

		/* For reuse hastype = 0 and length = 1 */
		hmac = sdoHashAlloc(0, plainTextLen);
		if (!hmac) {
			LOG(LOG_ERROR, "Hash allocation failed.\n");
			goto err;
		}
		if (memcpy_s(hmac->hash->bytes, plainTextLen, plainText,
			     plainTextLen) != 0) {
			LOG(LOG_ERROR, "Hash copy failed.\n");
			goto err;
		}

		/* Moving to post DI state  for Reuse case */
		ps->devCred->ST = SDO_DEVICE_STATE_READY1;
	} else {
		/* Resale Case or Reuse not supported case*/
		if (ps->reuse_enabled) {
			LOG(LOG_DEBUG,
			    "*****Reuse triggered but not supported.*****\n");
		}

		/* Generate new HMAC secret for OV header validation */
		if (0 != sdoGenerateOVHMACKey()) {
			LOG(LOG_ERROR, "OV HMAC Key refresh failed.\n");
			goto err;
		}

		if (resale_supported) {
			LOG(LOG_DEBUG, "*****Resale triggered.*****\n");
			hmac = sdoNewOVHdrSign(ps->devCred, ps->new_pk);

			/* Update the pkh to the new
			 * values
			 * Store hash of the new owner public key */
			sdoHashFree(ps->devCred->ownerBlk->pkh);
			ps->devCred->ownerBlk->pkh = sdoPubKeyHash(ps->new_pk);

		} else {
			LOG(LOG_DEBUG,
			    "*****Resale triggered but not supported.*****\n");
			/*
			 * Device inability to perform resale by transmitting
			 * zero length HMAC
			 * */
			hmac = sdoHashAlloc(SDO_CRYPTO_HMAC_TYPE_USED,
					    SDO_SHA_DIGEST_SIZE_USED);

			if (hmac == NULL) {
				LOG(LOG_ERROR,
				    "HMAC buffer allocation failed.\n");
				goto err;
			}

			if (memset_s(hmac->hash->bytes, hmac->hash->byteSz,
				     0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				goto err;
			}

			hmac->hash->byteSz = 0;
		}
		/*  Done with Secure Device Onboard.*/
		/*  As of now moving to done state for resale*/
		ps->devCred->ST = SDO_DEVICE_STATE_IDLE;
	}
	sdoPublicKeyFree(ps->new_pk);
	ps->new_pk = NULL;

	if (hmac == NULL) {
		goto err;
	}

	/* Rotate Data Protection Key */
	if (0 != sdoGenerateStorageHMACKey()) {
		LOG(LOG_ERROR, "Failed to rotate data protection key.\n");
	}
	LOG(LOG_DEBUG, "Data protection key rotated successfully!!\n");

	/* Write new device credentials */
	if (store_credential(ps->devCred) != 0) {
		LOG(LOG_ERROR, "Failed to store new device creds\n");
		goto err;
	}
	LOG(LOG_DEBUG, "Updated device with new credentials\n");

	/* Create message and send "hmac" */
	sdoWNextBlock(&ps->sdow, SDO_TO2_DONE);
	sdoWBeginObject(&ps->sdow);

	sdoWriteTag(&ps->sdow, "hmac");
	sdoHashWrite(&ps->sdow, hmac);
	sdoWriteTag(&ps->sdow, "n6");
	sdoByteArrayWriteChars(&ps->sdow, ps->n6);

	sdoWEndObject(&ps->sdow);

	if (!sdoEncryptedPacketWindup(&ps->sdow, SDO_TO2_DONE, ps->iv)) {
		sdoHashFree(hmac);
		goto err;
	}

	sdoHashFree(hmac);
	ps->success = true;
	ps->state = SDO_STATE_TO2_RCV_DONE_2;
	ret = 0; /*Mark as success */

err:
	return ret;
}
