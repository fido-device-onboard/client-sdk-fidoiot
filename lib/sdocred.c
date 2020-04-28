/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of Creating device credentials database in SDO spec
 * defined format.
 */

#include "sdoCrypto.h"
#include "util.h"
#include "sdoprot.h"
#include "sdocred.h"
#include <stdlib.h>
#include "safe_lib.h"

#define OCBUF_SIZE 256
#define PUBLIC_KEY_OFFSET 12

/*------------------------------------------------------------------------------
 * PM.Cred_ownwer routines
 */

/**
 * Allocate a Cred_owner object and allocate its members
 * @return and allocated sdo_cred_owner_t object
 */
sdo_cred_owner_t *sdo_cred_owner_alloc(void)
{
	return sdo_alloc(sizeof(sdo_cred_owner_t));
}

/**
 * Free an allocated Cred_owner object
 * @param ocred - the object to sdo_free
 * @return none
 */
void sdo_cred_owner_free(sdo_cred_owner_t *ocred)
{
	if (!ocred)
		return;
	if (ocred->rvlst) {
		sdo_rendezvous_list_free(ocred->rvlst);
		ocred->rvlst = NULL;
	}
	if (ocred->pkh)
		sdo_hash_free(ocred->pkh);
	if (ocred->guid)
		sdo_byte_array_free(ocred->guid);
	if (ocred->pk)
		sdo_public_key_free(ocred->pk);

	sdo_free(ocred);
}

#if LOG_LEVEL == LOG_MAX_LEVEL
/**
 * Print the Ocred as decoded
 * @param ocred - the Owner Credential object
 * @return none
 */
void sdo_cred_owner_print(sdo_cred_owner_t *ocred)
{
	char pbuf[1024] = {0};
	char *p_pbuf = NULL;

	LOG(LOG_DEBUG, "========================================\n");
	LOG(LOG_DEBUG, "PM.Cred_owner\n");
	LOG(LOG_DEBUG, " pv : %d\n", ocred->pv);
	p_pbuf = sdo_pk_enc_to_string(ocred->pe);
	LOG(LOG_DEBUG, " pe : %s\n", p_pbuf ? p_pbuf : "");
	p_pbuf = sdo_guid_to_string(ocred->guid, pbuf, sizeof(pbuf));
	LOG(LOG_DEBUG, " g  : %s\n", p_pbuf ? p_pbuf : "");
	p_pbuf = sdo_rendezvous_to_string(ocred->rvlst->rv_entries, pbuf,
					  sizeof(pbuf));
	LOG(LOG_DEBUG, " r  : %s\n", p_pbuf ? p_pbuf : "");
	p_pbuf = sdo_hash_to_string(ocred->pkh, pbuf, sizeof(pbuf));
	LOG(LOG_DEBUG, " pkh: %s\n", p_pbuf ? p_pbuf : "");
}
#endif

/*------------------------------------------------------------------------------
 * PM.Cred_mfg Manufacturer's Block routines
 */

/**
 * Allocate a Owner Credential Manufacturer object
 * return an allocated sdo_cred_mfg_t object
 */
sdo_cred_mfg_t *sdo_cred_mfg_alloc(void)
{
	return sdo_alloc(sizeof(sdo_cred_mfg_t));
}

/**
 * Free the memory contained in a sdo_cred_mfg_t object
 * including any allocated attached objects
 * @param ocred_mfg - the object to clear and sdo_free
 * @return none
 */
void sdo_cred_mfg_free(sdo_cred_mfg_t *ocred_mfg)
{
	if (ocred_mfg->d)
		sdo_string_free(ocred_mfg->d);

	if (ocred_mfg->cu)
		sdo_string_free(ocred_mfg->cu);

	if (ocred_mfg->ch)
		sdo_hash_free(ocred_mfg->ch);

	sdo_free(ocred_mfg);
	ocred_mfg = NULL;
}

#if LOG_LEVEL == LOG_MAX_LEVEL
/**
 * Print the values in the Manufacturer's Block to stdout
 * @param ocred_mfg - The object to print
 * @return none
 */
void sdo_cred_mfg_print(sdo_cred_mfg_t *ocred_mfg)
{
	char ocbuf[OCBUF_SIZE] = {0};
	char *ocbufp = NULL;

	LOG(LOG_DEBUG, "========================================\n");
	LOG(LOG_DEBUG, "PM.Cred_mfg\n");
	ocbufp = sdo_string_to_string(ocred_mfg->d, ocbuf, OCBUF_SIZE);
	if (ocbufp)
		LOG(LOG_DEBUG, "d  : %s\n", ocbufp);
	ocbufp = sdo_string_to_string(ocred_mfg->cu, ocbuf, OCBUF_SIZE);
	if (ocbufp)
		LOG(LOG_DEBUG, "cu : %s\n", ocbufp);
	ocbufp = sdo_hash_to_string(ocred_mfg->ch, ocbuf, OCBUF_SIZE);
	if (ocbufp)
		LOG(LOG_DEBUG, "ch : %s\n", ocbufp);
}
#endif

/*------------------------------------------------------------------------------
 * PMDevice_credentials routines
 */

/**
 * Allocate a sdo_dev_cred_t object
 * @return pointer to an allocated empty object
 */
sdo_dev_cred_t *sdo_dev_cred_alloc(void)
{
	return sdo_alloc(sizeof(sdo_dev_cred_t));
}

/**
 * Clear a devcred object
 * @param dev_cred - object to be cleared
 * @return none
 */
void sdo_dev_cred_init(sdo_dev_cred_t *dev_cred)
{
	if (dev_cred) {
		dev_cred->ST = 0;
		dev_cred->mfg_blk = NULL;
		dev_cred->owner_blk = NULL;
	}
}

/**
 * Free the memory contained in a sdo_dev_cred_t object
 * including any allocated attached objects
 * @param dev_cred - the object to clear and sdo_free
 * @return none
 */
void sdo_dev_cred_free(sdo_dev_cred_t *dev_cred)
{
	if (!dev_cred)
		return;

	if (dev_cred->owner_blk) {
		sdo_cred_owner_free(dev_cred->owner_blk);
		dev_cred->owner_blk = NULL;
	}

	if (dev_cred->mfg_blk) {
		sdo_cred_mfg_free(dev_cred->mfg_blk);
		dev_cred->mfg_blk = NULL;
	}
}

/**
 * Make a hash of the passed public key
 * @param pub_key - pointer to the public key object
 * @return a hash of the JSON representation of the key
 */
sdo_hash_t *sdo_pub_key_hash(sdo_public_key_t *pub_key)
{
	// Calculate the hash of the mfg_pub_key
	sdo_hash_t *hash = NULL;

	hash =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
	if (!hash)
		return NULL;

	sdow_t sdowriter, *sdow = &sdowriter;

	// Prepare the data structure
	if (!sdow_init(sdow)) {
		sdo_hash_free(hash);
		LOG(LOG_ERROR, "sdow_init() failed!\n");
		return NULL;
	}
	sdow_next_block(sdow, SDO_TYPE_HMAC);
	sdo_public_key_write(sdow, pub_key);

	if (hash && (sdow->b.block_size < PUBLIC_KEY_OFFSET)) {
		sdo_hash_free(hash);
		return NULL;
	}

	// buffer sdow now contains the key to sign offset 12

	if (hash &&
	    (0 != sdo_crypto_hash(&sdow->b.block[PUBLIC_KEY_OFFSET],
				  sdow->b.block_size - PUBLIC_KEY_OFFSET,
				  hash->hash->bytes, hash->hash->byte_sz))) {

		sdo_hash_free(hash);
		return NULL;
	}

	if (sdow->b.block) {
		sdo_free(sdow->b.block);
		sdow->b.block = NULL;
	}
	return hash;
}

/*------------------------------------------------------------------------------
 * Owner Proxy Entry Routines
 */

/**
 * Allocate an empty Owner Proxy Entry
 * @param - none
 * @return e - an newly allocated, cleared, Owner Proxy Entry
 */
sdo_ov_entry_t *sdo_ov_entry_alloc_empty(void)
{
	// SDOOVEntry_init(e);
	return sdo_alloc(sizeof(sdo_ov_entry_t));
}

/**
 * Release and sdo_free an Ownership Voucher entry
 * @param e - the entry to sdo_free
 * @return - the entry pointed to by the next value
 */
sdo_ov_entry_t *sdo_ov_entry_free(sdo_ov_entry_t *e)
{
	if (e->pk)
		sdo_public_key_free(e->pk);
	if (e->hp_hash)
		sdo_hash_free(e->hp_hash);
	if (e->hc_hash)
		sdo_hash_free(e->hc_hash);
	sdo_ov_entry_t *next = e->next;

	sdo_free(e);
	return next;
}
/*------------------------------------------------------------------------------
 * Ownership Voucher Routines
 */

/**
 * Allocate an Owner Proxy Base object
 * @return The newly allocated Owner Proxy
 */
sdo_ownership_voucher_t *sdo_ov_alloc(void)
{
	sdo_ownership_voucher_t *ov =
	    sdo_alloc(sizeof(sdo_ownership_voucher_t));
	if (ov) {
		ov->key_encoding = SDO_OWNER_ATTEST_PK_ENC;
	}
	return ov;
}

/**
 * Free and Ownership Voucher Oject
 * @param ov - Ownership Voucher to sdo_free
 * @return none
 */
void sdo_ov_free(sdo_ownership_voucher_t *ov)
{
	sdo_ov_entry_t *e;

	if (ov->rvlst2 != NULL)
		sdo_rendezvous_list_free(ov->rvlst2);
	if (ov->dev_info != NULL)
		sdo_string_free(ov->dev_info);
	if (ov->mfg_pub_key != NULL)
		sdo_public_key_free(ov->mfg_pub_key);
	if (ov->ovoucher_hdr_hash != NULL)
		sdo_hash_free(ov->ovoucher_hdr_hash);
	if (ov->g2)
		sdo_byte_array_free(ov->g2);
	if (ov->hdc)
		sdo_hash_free(ov->hdc);

	// Free all listed Owner Proxy Entries
	while ((e = ov->ov_entries) != NULL) {
		ov->ov_entries = e->next;
		sdo_ov_entry_free(e);
	}
	sdo_free(ov);
}

/**
 * Read the Ownership Voucher header passed in TO2 Prove Ov_header
 * @param sdor - the received context from the server
 * @param hmac a place top store the resulting HMAC
 * @param cal_hp_hc - calculate hp, hc if true.
 * @return A newly allocated Ownership Voucher with the header completed
 */
sdo_ownership_voucher_t *sdo_ov_hdr_read(sdor_t *sdor, sdo_hash_t **hmac,
					 bool cal_hp_hc)
{

	if (!sdor || !hmac)
		return NULL;

	sdo_ownership_voucher_t *ov = sdo_ov_alloc();
	int gstart = -1;
	int gend = -1;
	int dstart = -1;
	int dend = -1;
	int sig_block_start = -1;
	int ret = -1;
	uint8_t *hp_text = NULL;
	uint8_t *hc_text = NULL;

	if (ov == NULL) {
		LOG(LOG_ERROR, "Ownership Voucher allocation failed!");
		return NULL;
	}

	if (!sdo_begin_readHMAC(sdor, &sig_block_start))
		goto exit;

	if (!sdor_begin_object(sdor))
		goto exit;

	if (!sdo_read_expected_tag(sdor, "pv")) // Protocol Version
		goto exit;
	ov->prot_version = sdo_read_uint(sdor);

	if (!sdo_read_expected_tag(sdor, "pe")) // Public key encoding
		goto exit;
	ov->key_encoding = sdo_read_uint(sdor);

	if (!sdo_read_expected_tag(sdor, "r")) // Rendezvous
		goto exit;
	ov->rvlst2 = sdo_rendezvous_list_alloc();

	if (!ov->rvlst2 || !sdo_rendezvous_list_read(sdor, ov->rvlst2)) {
		LOG(LOG_ERROR, "%s Rendezvous Error\n", __func__);
		goto exit;
	}

	/* There must be at-least 1 valid rv entry, if not its a error-case */
	if (ov->rvlst2->num_entries == 0) {
		LOG(LOG_ERROR,
		    "All rendezvous entries are invalid for the device!\n");
		goto exit;
	}

	if (!sdo_read_expected_tag(sdor, "g"))
		goto exit;
	gstart = sdor->b.cursor;
	ov->g2 = sdo_byte_array_alloc(0);
	if (!ov->g2 || !sdo_byte_array_read_chars(sdor, ov->g2)) {
		LOG(LOG_ERROR, "%s GUID Error\n", __func__);
		goto exit;
	}
	gend = sdor->b.cursor;
	uint8_t *g_text = sdor_get_block_ptr(sdor, gstart);

	if (g_text == NULL)
		goto exit;

	if (!sdo_read_expected_tag(sdor, "d")) // Device_info String
		goto exit;

	dstart = sdor->b.cursor;
	ov->dev_info = sdo_string_alloc();

	if (!ov->dev_info || !sdo_string_read(sdor, ov->dev_info)) {
		LOG(LOG_ERROR, "%s Dev_info Error\n", __func__);
		goto exit;
	}

	dend = sdor->b.cursor;

	uint8_t *d_text = sdor_get_block_ptr(sdor, dstart);

	if (d_text == NULL)
		goto exit;

	if (!sdo_read_expected_tag(sdor, "pk")) // Mfg Public key
		goto exit;

	if (ov->mfg_pub_key != NULL)
		sdo_public_key_free(ov->mfg_pub_key);
	ov->mfg_pub_key =
	    sdo_public_key_read(sdor); // Creates a Public key and fills it in

#if defined(ECDSA256_DA) || defined(ECDSA384_DA)
	if (!sdo_read_expected_tag(sdor, "hdc")) { // device cert-chain hash
		LOG(LOG_ERROR, "hdc tag not found!\n");
		goto exit;
	}

	ov->hdc = sdo_hash_alloc_empty();
	if (!ov->hdc) {
		LOG(LOG_ERROR, "Hash alloc failed!\n");
		goto exit;
	}

	if (!sdo_hash_read(sdor, ov->hdc)) {
		LOG(LOG_ERROR, "device cert-chain hash reading failed!\n");
		goto exit;
	}
#endif
	if (!sdo_end_readHMAC(sdor, hmac, sig_block_start)) {
		LOG(LOG_ERROR, "Error making OVHdr HMAC!\n");
		goto exit;
	}

	if (cal_hp_hc) {
		int oh_end = sdor->b.cursor;
		int oh_sz = oh_end - sig_block_start;
		uint8_t *oh_text = sdor_get_block_ptr(sdor, sig_block_start);
		int hmac_start = 0;
		int hmac_end = 0;
		uint8_t *hmac_text = NULL;

		if (oh_text == NULL)
			goto exit;

		// Now get the HMAC of the OV Header from the DI
		// phase
		if (!sdo_read_expected_tag(sdor, "hmac"))
			goto exit;
		hmac_start = sdor->b.cursor;
		ov->ovoucher_hdr_hash = sdo_hash_alloc_empty();
		if (!ov->ovoucher_hdr_hash ||
		    !sdo_hash_read(sdor, ov->ovoucher_hdr_hash))
			goto exit;
		hmac_end = sdor->b.cursor;
		hmac_text = sdor_get_block_ptr(sdor, hmac_start);

		if (hmac_text == NULL)
			goto exit;

		// hp = SHA256[TO2.ProveOVHdr.bo.oh||TO2.Prove_ov_hdr.bo.hmac] )

		hp_text = sdo_alloc(oh_sz + (hmac_end - hmac_start));
		if (hp_text == NULL) {
			LOG(LOG_ERROR, "Memset Failed\n");
			goto exit;
		}

		if (memcpy_s(hp_text, oh_sz + (hmac_end - hmac_start), oh_text,
			     oh_sz) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			goto exit;
		}

		if (memcpy_s(hp_text + oh_sz, hmac_end - hmac_start, hmac_text,
			     hmac_end - hmac_start) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			goto exit;
		}

		ov->ov_entries = sdo_ov_entry_alloc_empty();

		if (ov->ov_entries)
			ov->ov_entries->hp_hash =
			    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_USED,
					   SDO_SHA_DIGEST_SIZE_USED);
		if (!ov->ov_entries || !ov->ov_entries->hp_hash) {
			LOG(LOG_ERROR,
			    "Ownership Voucher allocation failed!\n");
			goto exit;
		}

		if (0 !=
		    sdo_crypto_hash(hp_text, oh_sz + (hmac_end - hmac_start),
				    ov->ov_entries->hp_hash->hash->bytes,
				    ov->ov_entries->hp_hash->hash->byte_sz)) {
			goto exit;
		}

		// hc = SHA256[TO2.ProveOVHdr.bo.oh.g||TO2.ProveOVHdr.bo.oh.d]
		// g size + d size
		hc_text = sdo_alloc((gend - gstart) + (dend - dstart));
		if (hc_text == NULL) {
			LOG(LOG_ERROR, "Memset Failed\n");
			goto exit;
		}

		if (memcpy_s(hc_text, ((gend - gstart) + (dend - dstart)),
			     g_text, (gend - gstart)) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			goto exit;
		}

		if (memcpy_s(hc_text + (gend - gstart), (dend - dstart), d_text,
			     (dend - dstart)) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			goto exit;
		}

		ov->ov_entries->hc_hash = sdo_hash_alloc(
		    SDO_CRYPTO_HASH_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
		if (!ov->ov_entries->hc_hash)
			goto exit;

		if (0 !=
		    sdo_crypto_hash(hc_text, (gend - gstart) + (dend - dstart),
				    ov->ov_entries->hc_hash->hash->bytes,
				    ov->ov_entries->hc_hash->hash->byte_sz)) {
			LOG(LOG_ERROR, "Hash generation failed\n");
			goto exit;
		}

		// To verify the next entry in the ownership voucher
		ov->ov_entries->pk = sdo_public_key_clone(ov->mfg_pub_key);
	}
	ret = 0;
exit:
	if (hp_text)
		sdo_free(hp_text);
	if (hc_text)
		sdo_free(hc_text);
	if (ret) {
		LOG(LOG_ERROR, "Ov_hdr Error\n");
		sdo_ov_free(ov);
		return NULL;
	}
	return ov;
}

/**
 * Take the the values in the "oh" and create a new HMAC
 * @param dev_cred - pointer to the Device_credential to source
 * @param new_pub_key - the public key to use in the signature
 * @param hdc - device cert-chain hash
 * @return pointer to a new sdo_hash_t object containing the HMAC
 */
sdo_hash_t *sdo_new_ov_hdr_sign(sdo_dev_cred_t *dev_cred,
				sdo_public_key_t *new_pub_key, sdo_hash_t *hdc)
{
	sdow_t sdowriter, *sdow = &sdowriter;

	// Prepare the data structure
	if (!sdow_init(sdow)) {
		LOG(LOG_ERROR, "sdow_init() failed!\n");
		return false;
	}
	sdow_next_block(sdow, SDO_TYPE_HMAC);

	// build the "oh" structure in the buffer
	// Get the pointers ready for the signature
	int sig_block_start = sdow->b.cursor;

	sdow->need_comma = false;
	sdow_begin_object(sdow);

	sdo_write_tag(sdow, "pv");
	sdo_writeUInt(sdow, dev_cred->owner_blk->pv);

	sdo_write_tag(sdow, "pe");
	sdo_writeUInt(sdow, dev_cred->owner_blk->pe);

	sdo_write_tag(sdow, "r");
	sdo_rendezvous_list_write(sdow, dev_cred->owner_blk->rvlst);

	sdo_write_tag(sdow, "g");
	sdo_byte_array_write_chars(sdow, dev_cred->owner_blk->guid);

	sdo_write_tag(sdow, "d");
	sdo_write_string_len(sdow, dev_cred->mfg_blk->d->bytes,
			     dev_cred->mfg_blk->d->byte_sz);

	sdo_write_tag(sdow, "pk");
	sdo_public_key_write(sdow, new_pub_key);

	if (hdc) {
		sdo_write_tag(sdow, "hdc");
		sdo_hash_write(sdow, hdc);
	}

	sdow_end_object(sdow);

	int sig_block_end = sdow->b.cursor;
	int sig_block_sz = sig_block_end - sig_block_start;
	uint8_t *plain_text = sdow_get_block_ptr(sdow, sig_block_start);

	if (plain_text == NULL) {
		LOG(LOG_ERROR,
		    "sdow_get_block_ptr() returned NULL, "
		    "%s failed !!",
		    __func__);
		return NULL;
	}

	sdo_hash_t *hmac =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);

	if (hmac &&
	    (0 != sdo_device_ov_hmac(plain_text, sig_block_sz,
				     hmac->hash->bytes, hmac->hash->byte_sz))) {
		sdo_hash_free(hmac);
		return NULL;
	}

	if (sdow->b.block) {
		sdo_free(sdow->b.block);
		sdow->b.block = NULL;
	}
	return hmac;
}

/**
 * Allocate a new Owner Supplied Credentials object
 * @return an sdo_owner_supplied_credentials_t object with all setting cleared
 */
sdo_owner_supplied_credentials_t *sdo_owner_supplied_credentials_alloc(void)
{
	return sdo_alloc(sizeof(sdo_owner_supplied_credentials_t));
}

/**
 * Free the Owner Supplied Credential object
 * @param osc - The owner supplied credential object
 * @return none.
 */
void sdo_owner_supplied_credentials_free(sdo_owner_supplied_credentials_t *osc)
{
	if (osc != NULL) {
		sdo_rendezvous_list_free(osc->rvlst);
		osc->rvlst = NULL;
		sdo_service_info_free(osc->si);
		sdo_free(osc);
	}
}

/**
 * Free the IV object
 * @param iv - The iv store object
 * @return none.
 */
void sdo_iv_free(sdo_iv_t *iv)
{
	if (iv != NULL)
		sdo_free(iv);
}
