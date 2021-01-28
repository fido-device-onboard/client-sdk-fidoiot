/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of msg number 11. The device received response of msg10
 */

#include "load_credentials.h"
#include "sdoCrypto.h"
#include "sdoprot.h"
#include "util.h"

/**
 * msg11() - DISetCredentials, Type 11
 * The device gets credentials from the manufacturer.
 *
 * OVHeader = [
 *   OVProtVer:         protver,        ;; protocol version
 *   OVGuid:            Guid,           ;; guid
 *   OVRVInfo:          RendezvousInfo, ;; rendezvous instructions
 *   OVDeviceInfo:      tstr,           ;; DeviceInfo
 *   OVPubKey:          PublicKey,      ;; mfg public key
 *   OVDevCertChainHash:OVDevCertChainHashOrNull
 * ]
 */
int32_t msg11(sdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtDI";
	sdo_ownership_voucher_t *ov = NULL;
	sdo_dev_cred_t *dev_cred = app_get_credentials();

	/* Is device credentials memory allocated */
	if (!dev_cred) {
		LOG(LOG_ERROR, "No device credentials available\n");
		goto err;
	}

	/*
	 * Receive the message from the internal buffer, if no msg is there,
	 * break out from here for now. Mark the state as true, but don't set
	 * the state to next msg (msg12)
	 */
	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0;
		goto err;
	}

	/* Prepare for writing device credentials */
	if (!sdor_start_array(&ps->sdor)) {
		goto err;
	}

	if (NULL == ps->dev_cred->mfg_blk) {
		ps->dev_cred->mfg_blk = sdo_cred_mfg_alloc();
	}

	if (NULL == ps->dev_cred->owner_blk) {
		ps->dev_cred->owner_blk = sdo_cred_owner_alloc();
		if (!ps->dev_cred->owner_blk) {
			LOG(LOG_ERROR, "Alloc failed\n");
			goto err;
		}
	}

	if (!dev_cred->mfg_blk || !dev_cred->owner_blk) {
		LOG(LOG_ERROR, "dev_cred's owner_blk and/or "
			       "mfg_blk allocation failed\n");
		goto err;
	}

	if (0 != sdo_generate_ov_hmac_key()) {
		LOG(LOG_ERROR, "OV HMAC key generation failed.\n");
		goto err;
	}

	/* Parse the complete Ownership header and calcuate HMAC over it */
	ov = sdo_ov_hdr_read(&ps->sdor, &ps->new_ov_hdr_hmac, false);
	if (!ov) {
		LOG(LOG_ERROR, "Failed to read OVHeader\n");
		goto err;
	}

	if (ov->prot_version != SDO_PROT_SPEC_VERSION) {
		sdo_ov_free(ov);
		LOG(LOG_ERROR, "Invalid OVProtVer\n");
		goto err;
	}

	dev_cred->owner_blk->pv = ov->prot_version;
	dev_cred->owner_blk->rvlst = ov->rvlst2;
	dev_cred->owner_blk->guid = ov->g2;
	dev_cred->mfg_blk->d = ov->dev_info;
	dev_cred->owner_blk->pk = ov->mfg_pub_key;

	ps->dev_cred = dev_cred;

	if (ov->hdc) {
		sdo_hash_free(ov->hdc);
	}
	sdo_free(ov);

	if (!sdor_end_array(&ps->sdor)) {
		goto err;
	}

	/* All good, move to msg12 */
	ps->state = SDO_STATE_DI_SET_HMAC;
	ps->sdor.have_block = false;
	sdor_flush(&ps->sdor);
	LOG(LOG_DEBUG, "DISetCredentials completed\n");
	ret = 0;

err:
	return ret;
}
