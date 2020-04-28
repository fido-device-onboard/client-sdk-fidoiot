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
 * msg11() - DI.Set_credentials
 * The device gets credentials from the manufacturer.
 *
 * {
 *       "oh":{# Ownership header
 *           "pv": UInt16,    # Protocol version
 *           "pe": UInt8,     # Public Key Encoding (RSA, ECDSA)
 *           "r": Rendezvous, # Whom to connect to next in customer
 *                            # premises (Rendezvous Server)
 *           "g": GUID,       # Securely generated random number
 *           "d": String,     # Device info
 *           "pk": Public_key, # Manufacturer Public Key (First owner)
 *           "hdc": Hash      # Absent if EPID
 *       },
 *       "cu": String,        # URL of manufacturer’s permanent certificate
 *       "ch": Hash           # Hash of manufacturer’s permanent certificate
 * }
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
	if (!sdor_begin_object(&ps->sdor)) {
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
		LOG(LOG_ERROR, "sdo_ov_hdr_read Failed\n");
		goto err;
	}

	if (ov->prot_version != SDO_PROT_SPEC_VERSION) {
		sdo_ov_free(ov);
		LOG(LOG_ERROR, "Wrong protocol version\n");
		goto err;
	}

	if (ov->key_encoding != SDO_CRYPTO_PUB_KEY_ENCODING_X509 &&
	    ov->key_encoding != SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP) {
		sdo_ov_free(ov);
		LOG(LOG_ERROR, "Wrong key encoding\n");
		goto err;
	}

	dev_cred->owner_blk->pv = ov->prot_version;
	dev_cred->owner_blk->pe = ov->key_encoding;
	dev_cred->owner_blk->rvlst = ov->rvlst2;
	dev_cred->owner_blk->guid = ov->g2;
	dev_cred->mfg_blk->d = ov->dev_info;
	ps->dev_cred->owner_blk->pk = ov->mfg_pub_key;

	if (ov->hdc) {
		sdo_hash_free(ov->hdc);
	}
	sdo_free(ov);

	if (!sdor_end_object(&ps->sdor)) {
		goto err;
	}
	sdor_flush(&ps->sdor);

	/* All good, move to msg12 */
	ps->state = SDO_STATE_DI_SET_HMAC;
	ret = 0;

err:
	return ret;
}
