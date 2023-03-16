/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of msg number 11. The device received response of msg10
 */

#include "load_credentials.h"
#include "fdoCrypto.h"
#include "fdoprot.h"
#include "util.h"

/**
 * msg11() - DISetCredentials, Type 11
 * The device gets credentials from the manufacturer.
 *
 * bstr. cbor bytes OVHeader = [
 *   OVProtVer:         protver,        ;; protocol version
 *   OVGuid:            Guid,           ;; guid
 *   OVRVInfo:          RendezvousInfo, ;; rendezvous instructions
 *   OVDeviceInfo:      tstr,           ;; DeviceInfo
 *   OVPubKey:          PublicKey,      ;; mfg public key
 *   OVDevCertChainHash:OVDevCertChainHashOrNull
 * ]
 */
int32_t msg11(fdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "FDOProtDI";
	fdo_ownership_voucher_t *ov = NULL;
	fdo_dev_cred_t *dev_cred = app_get_credentials();
	fdo_byte_array_t *ovheader = NULL;
	size_t ovheader_sz = 0;

	if (!ps) {
		LOG(LOG_ERROR, "Invalid protocol state\n");
		return ret;
	}

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
	if (!fdo_prot_rcv_msg(&ps->fdor, &ps->fdow, prot, &ps->state)) {
		ret = 0;
		goto err;
	}

	if (NULL == ps->dev_cred->mfg_blk) {
		ps->dev_cred->mfg_blk = fdo_cred_mfg_alloc();
	}

	if (NULL == ps->dev_cred->owner_blk) {
		ps->dev_cred->owner_blk = fdo_cred_owner_alloc();
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

	if (0 != fdo_generate_ov_hmac_key()) {
		LOG(LOG_ERROR, "OV HMAC key generation failed.\n");
		goto err;
	}

	// read msg 11
	if (!fdor_start_array(&ps->fdor)) {
		LOG(LOG_ERROR, "DISetCredentials: Failed to start array\n");
		goto err;
	}

	if (!fdor_string_length(&ps->fdor, &ovheader_sz) || ovheader_sz == 0) {
		LOG(LOG_ERROR,
		    "DISetCredentials: Failed to read OVeader as bstr length\n");
		goto err;
	}

	ovheader = fdo_byte_array_alloc(ovheader_sz);
	if (!ovheader) {
		LOG(LOG_ERROR, "DISetCredentials: Failed to alloc for OVHeader as bstr\n");
		goto err;
	}
	if (!fdor_byte_string(&ps->fdor, ovheader->bytes, ovheader->byte_sz)) {
		LOG(LOG_ERROR, "DISetCredentials: Failed to read OVHeader as bstr\n");
		goto err;
	}

	if (!fdor_end_array(&ps->fdor)) {
		LOG(LOG_ERROR, "DISetCredentials: Failed to end array\n");
		goto err;
	}

	/* Parse the complete Ownership header and calcuate HMAC over it */
	ov = fdo_ov_hdr_read(ovheader);
	if (!ov) {
		LOG(LOG_ERROR, "DISetCredentials: Failed to read OVHeader\n");
		goto err;
	}

	if (!fdo_ov_hdr_hmac(ovheader, &ps->new_ov_hdr_hmac)) {
		LOG(LOG_ERROR, "DISetCredentials: Failed to get HMAC\n");
		goto err;
	}

	if (ov->prot_version != FDO_PROT_SPEC_VERSION) {
		fdo_ov_free(ov);
		LOG(LOG_ERROR, "DISetCredentials: Invalid OVProtVer\n");
		goto err;
	}

	dev_cred->owner_blk->pv = ov->prot_version;
	dev_cred->owner_blk->rvlst = ov->rvlst2;
	dev_cred->owner_blk->guid = ov->g2;
	dev_cred->mfg_blk->d = ov->dev_info;
	dev_cred->owner_blk->pk = ov->mfg_pub_key;

	ps->dev_cred = dev_cred;

	if (ov->hdc) {
		fdo_hash_free(ov->hdc);
	}
	fdo_free(ov);

	/* All good, move to msg12 */
	ps->state = FDO_STATE_DI_SET_HMAC;
	ps->fdor.have_block = false;
	fdo_block_reset(&ps->fdor.b);
	LOG(LOG_DEBUG, "DISetCredentials completed\n");
	ret = 0;

err:
	if (ovheader) {
		fdo_byte_array_free(ovheader);
		ovheader = NULL;
	}
	return ret;
}
