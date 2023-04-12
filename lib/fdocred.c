/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of Creating device credentials database in FDO spec
 * defined format.
 */

#include "fdoCrypto.h"
#include "util.h"
#include "fdoprot.h"
#include "fdocred.h"
#include <stdlib.h>
#include "safe_lib.h"
#if defined(DEVICE_CSE_ENABLED)
#include "cse_utils.h"
#include "cse_tools.h"
#endif

/*------------------------------------------------------------------------------
 * DeviceCredential's Owner Credential (fdo_cred_owner_t) routines
 */

/**
 * Allocate a fdo_cred_owner_t object
 * @return and allocated fdo_cred_owner_t object
 */
fdo_cred_owner_t *fdo_cred_owner_alloc(void)
{
	return fdo_alloc(sizeof(fdo_cred_owner_t));
}

/**
 * Free an allocated fdo_cred_owner_t object
 * @param ocred - the object to fdo_free
 * @return none
 */
void fdo_cred_owner_free(fdo_cred_owner_t *ocred)
{
	if (!ocred)
		return;
	if (ocred->rvlst) {
		fdo_rendezvous_list_free(ocred->rvlst);
		ocred->rvlst = NULL;
	}
	if (ocred->pkh) {
		fdo_hash_free(ocred->pkh);
	}
	if (ocred->guid) {
		fdo_byte_array_free(ocred->guid);
	}
	if (ocred->pk) {
		fdo_public_key_free(ocred->pk);
	}

	fdo_free(ocred);
}

/*------------------------------------------------------------------------------
 * DeviceCredential's Manufacturer's Block (fdo_cred_mfg_t) routines
 */

/**
 * Allocate a fdo_cred_mfg_t object
 * return an allocated fdo_cred_mfg_t object
 */
fdo_cred_mfg_t *fdo_cred_mfg_alloc(void)
{
	return fdo_alloc(sizeof(fdo_cred_mfg_t));
}

/**
 * Free the memory contained in a fdo_cred_mfg_t object
 * including any allocated attached objects
 * @param ocred_mfg - the object to clear and fdo_free
 * @return none
 */
void fdo_cred_mfg_free(fdo_cred_mfg_t *ocred_mfg)
{
	if (ocred_mfg->d) {
		fdo_string_free(ocred_mfg->d);
	}

	fdo_free(ocred_mfg);
	ocred_mfg = NULL;
}

/*------------------------------------------------------------------------------
 * DeviceCredential routines
 */

/**
 * Allocate a fdo_dev_cred_t object
 * @return pointer to an allocated empty object
 */
fdo_dev_cred_t *fdo_dev_cred_alloc(void)
{
	return fdo_alloc(sizeof(fdo_dev_cred_t));
}

/**
 * Clear a fdo_dev_cred_t object
 * @param dev_cred - object to be cleared
 * @return none
 */
void fdo_dev_cred_init(fdo_dev_cred_t *dev_cred)
{
	if (dev_cred) {
		dev_cred->ST = 0;
		dev_cred->dc_active = false;
		dev_cred->mfg_blk = NULL;
		dev_cred->owner_blk = NULL;
	}
}

/**
 * Free the memory contained in a fdo_dev_cred_t object
 * including any allocated attached objects
 * @param dev_cred - the object to clear and fdo_free
 * @return none
 */
void fdo_dev_cred_free(fdo_dev_cred_t *dev_cred)
{
	if (!dev_cred) {
		return;
	}

	if (dev_cred->owner_blk) {
		fdo_cred_owner_free(dev_cred->owner_blk);
		dev_cred->owner_blk = NULL;
	}

	if (dev_cred->mfg_blk) {
		fdo_cred_mfg_free(dev_cred->mfg_blk);
		dev_cred->mfg_blk = NULL;
	}
}

/**
 * Make a hash of the passed public key
 * @param pub_key - pointer to the public key object
 * @return a hash of the CBOR representation of the key
 */
fdo_hash_t *fdo_pub_key_hash(fdo_public_key_t *pub_key)
{
	if (!pub_key) {
		return NULL;
	}
	// Calculate the hash of the mfg_pub_key
	fdow_t *fdow = fdo_alloc(sizeof(fdow_t));
	if (!fdow_init(fdow) ||
		!fdo_block_alloc_with_size(&fdow->b, pub_key->key1->byte_sz + BUFF_SIZE_128_BYTES) ||
		!fdow_encoder_init(fdow)) {
		LOG(LOG_ERROR, "Failed to initialize FDOW\n");
		return NULL;
	}

	fdo_hash_t *hash = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_USED, FDO_SHA_DIGEST_SIZE_USED);
	if (!hash) {
		return NULL;
	}
	fdo_public_key_write(fdow, pub_key);
	size_t encoded_pk_length = 0;
	if (!fdow_encoded_length(fdow, &encoded_pk_length) || encoded_pk_length == 0) {
		LOG(LOG_ERROR, "Failed to get PubKey encoded length\n");
		fdo_hash_free(hash);
		return NULL;
	}
	fdow->b.block_size = encoded_pk_length;

	if ((0 != fdo_crypto_hash(fdow->b.block,
				  fdow->b.block_size,
				  hash->hash->bytes, hash->hash->byte_sz))) {
		fdo_hash_free(hash);
		return NULL;
	}

	fdow_flush(fdow);
	fdo_free(fdow);
	return hash;
}

/*------------------------------------------------------------------------------
 * OwnershipVoucher.OVEntries Routines
 */

/**
 * Allocate an empty fdo_ov_entry_t
 * @param - none
 * @return e - an newly allocated, cleared, fdo_ov_entry_t
 */
fdo_ov_entry_t *fdo_ov_entry_alloc_empty(void)
{
	// FDOOVEntry_init(e);
	return fdo_alloc(sizeof(fdo_ov_entry_t));
}

/**
 * Release and fdo_free an fdo_ov_entry_t
 * @param e - the entry to fdo_free
 * @return - the entry pointed to by the next value
 */
fdo_ov_entry_t *fdo_ov_entry_free(fdo_ov_entry_t *e)
{
	if (e->pk) {
		fdo_public_key_free(e->pk);
	}
	if (e->hp_hash) {
		fdo_hash_free(e->hp_hash);
	}
	if (e->hc_hash) {
		fdo_hash_free(e->hc_hash);
	}
	fdo_ov_entry_t *next = e->next;

	fdo_free(e);
	return next;
}
/*------------------------------------------------------------------------------
 * OwnershipVoucher Routines
 */

/**
 * Allocate an fdo_ownership_voucher_t object
 * @return The newly allocated fdo_ownership_voucher_t
 */
fdo_ownership_voucher_t *fdo_ov_alloc(void)
{
	fdo_ownership_voucher_t *ov =
	    fdo_alloc(sizeof(fdo_ownership_voucher_t));
	if (!ov) {
		LOG(LOG_ERROR, "OwnershipVoucher allocation failed!");
		return NULL;
	}
	return ov;
}

/**
 * Free an fdo_ownership_voucher_t object
 * @param ov - fdo_ownership_voucher_t to fdo_free
 * @return none
 */
void fdo_ov_free(fdo_ownership_voucher_t *ov)
{
	fdo_ov_entry_t *e;

	if (ov->rvlst2 != NULL) {
		fdo_rendezvous_list_free(ov->rvlst2);
	}
	if (ov->dev_info != NULL) {
		fdo_string_free(ov->dev_info);
	}
	if (ov->mfg_pub_key != NULL) {
		fdo_public_key_free(ov->mfg_pub_key);
	}
	if (ov->ovoucher_hdr_hash != NULL) {
		fdo_hash_free(ov->ovoucher_hdr_hash);
	}
	if (ov->g2) {
		fdo_byte_array_free(ov->g2);
	}
	if (ov->hdc) {
		fdo_hash_free(ov->hdc);
	}

	// Free all listed OVEntries
	while ((e = ov->ov_entries) != NULL) {
		ov->ov_entries = e->next;
		fdo_ov_entry_free(e);
	}
	fdo_free(ov);
}

/**
 * Read the OwnershipVoucher header passed in TO2.ProveOVHeader
 * @param ovheader - the received CBOR-encoded OVHeader
 * @return A newly allocated OwnershipVoucher with the header completed
 */
fdo_ownership_voucher_t *fdo_ov_hdr_read(fdo_byte_array_t *ovheader)
{

	if (!ovheader) {
		return NULL;
	}

	fdor_t fdor = {0};
	fdo_ownership_voucher_t *ov = fdo_ov_alloc();
	size_t num_ov_items = 0;
	int ret = -1;

	if (ov == NULL) {
		LOG(LOG_ERROR, "OwnershipVoucher allocation failed!");
		return NULL;
	}

	if (memset_s(&fdor, sizeof(fdor_t), 0) != 0) {
		LOG(LOG_ERROR, "OVheader: Failed to intialize temporary FDOR\n");
		return NULL;
	}
	if (!fdor_init(&fdor) ||
		!fdo_block_alloc_with_size(&fdor.b, ovheader->byte_sz)) {
		LOG(LOG_ERROR,
			"OVHeader: Failed to setup temporary FDOR\n");
		goto exit;
	}

	if (0 != memcpy_s(fdor.b.block, fdor.b.block_size,
		ovheader->bytes, ovheader->byte_sz)) {
		LOG(LOG_ERROR,
			"OVHeader: Failed to copy temporary data\n");
		goto exit;
	}

	if (!fdor_parser_init(&fdor)) {
		LOG(LOG_ERROR,
			"OVHeader: Failed to init temporary FDOR parser\n");
		goto exit;
	}

	// OVHeader is of size 6 always.
	if (!fdor_array_length(&fdor, &num_ov_items) || num_ov_items != 6) {
		LOG(LOG_ERROR, "%s Invalid OVHeader: Invalid OVHeader array length\n", __func__);
		goto exit;
	}

	LOG(LOG_DEBUG, "%s OVHeader read started!\n", __func__);
	if (!fdor_start_array(&fdor)) {
		goto exit;
	}

	if (!fdor_signed_int(&fdor, &ov->prot_version) || ov->prot_version != FDO_PROT_SPEC_VERSION) {
		// Protocol Version
		LOG(LOG_ERROR, "%s Invalid OVHeader: Invalid OVProtVer\n", __func__);
		goto exit;
	}

	size_t ov_guid_length;
	if (!fdor_string_length(&fdor, &ov_guid_length) || ov_guid_length != FDO_GUID_BYTES) {
		LOG(LOG_ERROR, "%s Invalid OVHeader: Invalid OVGuid Length\n", __func__);
		goto exit;
	}
	ov->g2 = fdo_byte_array_alloc(ov_guid_length);
	if (!ov->g2) {
		goto exit;
	}
	ov->g2->byte_sz = ov_guid_length;
	if (!fdor_byte_string(&fdor, ov->g2->bytes, ov->g2->byte_sz)) {
		LOG(LOG_ERROR, "%s Invalid OVHeader: Unable to decode OVGuid\n", __func__);
		goto exit;
	}

	// Rendezvous
	ov->rvlst2 = fdo_rendezvous_list_alloc();

	if (!ov->rvlst2 || !fdo_rendezvous_list_read(&fdor, ov->rvlst2)) {
		LOG(LOG_ERROR, "%s Invalid OVHeader: Unable to decode OVRvInfo\n", __func__);
		goto exit;
	}

	/* There must be at-least 1 valid rv entry, if not its a error-case */
	if (ov->rvlst2->num_rv_directives == 0) {
		LOG(LOG_ERROR,
		    "Invalid OVHeader: All rendezvous entries are invalid for the device!\n");
		goto exit;
	}

	// Device_info String
	size_t dev_info_length;
	if (!fdor_string_length(&fdor, &dev_info_length)) {
		LOG(LOG_ERROR, "%s Invalid OVHeader: Unable to decode OVDeviceInfo length\n", __func__);
		goto exit;
	}
	ov->dev_info = fdo_string_alloc_size(dev_info_length);
	if (!ov->dev_info ||
			!fdor_text_string(&fdor, ov->dev_info->bytes, dev_info_length)) {
		LOG(LOG_ERROR, "%s Invalid OVHeader: Unable to decode OVDeviceInfo\n", __func__);
		goto exit;
	}
	ov->dev_info->bytes[dev_info_length] = '\0';

	// Mfg Public key
	if (ov->mfg_pub_key != NULL) {
		fdo_public_key_free(ov->mfg_pub_key);
	}
	ov->mfg_pub_key =
	    fdo_public_key_read(&fdor); // Creates a Public key and fills it in
	if (ov->mfg_pub_key == NULL) {
		LOG(LOG_ERROR, "%s Invalid OVHeader: Unable to decode PubKey\n", __func__);
		goto exit;
	}

	// device cert-chain hash
	ov->hdc = fdo_hash_alloc_empty();
	if (!ov->hdc) {
		LOG(LOG_ERROR, "Hash alloc failed!\n");
		goto exit;
	}

	if (!fdo_hash_read(&fdor, ov->hdc)) {
		LOG(LOG_ERROR, "Invalid OVHeader: Unable to decode OVDevCertChainHash\n");
		goto exit;
	}

	fdor_end_array(&fdor);
	LOG(LOG_DEBUG, "%s OVHeader read completed!\n", __func__);
	ret = 0;
exit:
	if (ret) {
		LOG(LOG_ERROR, "Ov_hdr Error\n");
		fdo_ov_free(ov);
		return NULL;
	}
	if (fdor.b.block || fdor.current) {
		fdor_flush(&fdor);
	}
	return ov;
}

#if defined(DEVICE_CSE_ENABLED)
/**
 * Given an OwnershipVoucher header (OVHeader), proceed to load and compares with
 * stored OVHeader from CSE. If verfication succeed it returns the stored HMAC.
 * @param ovheader - the received CBOR-encoded OVHeader
 * @param hmac a place top store the resulting HMAC
 * @return true if hmac was successfully load and verified, false otherwise.
 */
bool fdo_ov_hdr_cse_load_hmac(fdo_byte_array_t *ovheader, fdo_hash_t **hmac)
{

	if (!ovheader || !hmac) {
		return false;
	}

	bool ret = false;
	uint32_t ovh_len = 0;
	int result_memcmp = 0;
	fdo_byte_array_t *ovh_data = NULL;

	*hmac = fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_USED, FDO_SHA_DIGEST_SIZE_USED);
	if (!*hmac) {
		LOG(LOG_ERROR, "Failed to alloc for OVHeaderHmac\n");
		goto exit;
	}

	ovh_data = fdo_byte_array_alloc(FDO_MAX_FILE_SIZE);
	if (!ovh_data) {
		LOG(LOG_ERROR,"Invalid OVHeader read: Failed to allocate data for storing OVH data\n");
		goto exit;
	}

	if (0 != cse_load_file(OVH_FILE_ID, ovh_data->bytes, &ovh_len,
			(*hmac)->hash->bytes, (*hmac)->hash->byte_sz)) {
		LOG(LOG_ERROR, "Invalid OVHeader read: Unable to load file form CSE\n");
		goto exit;
	}
	ovh_data->byte_sz = ovh_len;

	ret = memcmp_s(ovh_data->bytes,
		       ovh_data->byte_sz,
		       ovheader->bytes,
		       ovheader->byte_sz, &result_memcmp);
	if (ret || result_memcmp != 0) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Invalid OVH received over OVHeader\n");
		ret = false;
		goto exit;
	}
	LOG(LOG_DEBUG, "TO2.ProveOVHdr: Valid Ownership Header received\n");
	ret = true;
exit:

	if (ovh_data) {
		fdo_byte_array_free(ovh_data);
		ovh_data = NULL;
	}

	return ret;

}
#endif
/**
 * Given an OwnershipVoucher header (OVHeader), proceed to generate hmac.
 * @param ovheader - the received CBOR-encoded OVHeader
 * @param hmac a place top store the resulting HMAC
 * @return true if hmac was successfully generated, false otherwise.
 */
bool fdo_ov_hdr_hmac(fdo_byte_array_t *ovheader, fdo_hash_t **hmac) {

	if (!ovheader || !hmac) {
		return false;
	}

	bool ret = false;
	// Create the HMAC
	*hmac =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_USED, FDO_SHA_DIGEST_SIZE_USED);
	if (!*hmac) {
		LOG(LOG_ERROR, "Failed to alloc for OVHeaderHmac\n");
		goto exit;
	}

	if (0 != fdo_device_ov_hmac(ovheader->bytes, ovheader->byte_sz,
				    (*hmac)->hash->bytes,
				    (*hmac)->hash->byte_sz, false)) {
		fdo_hash_free(*hmac);
		LOG(LOG_ERROR, "Failed to generate OVHeaderHmac\n");
		goto exit;
	}
	ret = true;

exit :
	return ret;
}

/**
 * Given an OwnershipVoucher header (OVHeader), CBOR encode it.
 * OVHeader = [
 *   OVProtVer:         protver,        ;; protocol version
 *   OVGuid:            Guid,           ;; guid
 *   OVRVInfo:          RendezvousInfo, ;; rendezvous instructions
 *   OVDeviceInfo:      tstr,           ;; DeviceInfo
 *   OVPubKey:          PublicKey,      ;; mfg public key
 *   OVDevCertChainHash:OVDevCertChainHashOrNull
 * ]
 * @param ov - the received ownership voucher from the server
 * @param hmac a place top store the resulting HMAC
 * @param num_ov_items - number of items in ownership voucher header
 * @return true if hmac was successfully generated, false otherwise.
 */
bool fdo_ovheader_write(fdow_t *fdow, int protver, fdo_byte_array_t *guid, fdo_rendezvous_list_t *rvlst,
	fdo_string_t *dev_info, fdo_public_key_t *pubkey, fdo_hash_t *hdc) {

	if (!fdow_start_array(fdow, 6)) {
		LOG(LOG_ERROR, "OVHeader: Failed to start array\n");
		return false;
	}
	if (!fdow_signed_int(fdow, protver)) {
		LOG(LOG_ERROR, "OVHeader: Failed to write OVProtVer\n");
		return false;
	}
	if (!fdow_byte_string(fdow, guid->bytes, guid->byte_sz)) {
		LOG(LOG_ERROR, "OVHeader: Failed to write OVGuid\n");
		return false;
	}
	if (!fdo_rendezvous_list_write(fdow, rvlst)) {
		LOG(LOG_ERROR, "OVHeader: Failed to write OVRVInfo\n");
		return false;
	}
	if (!fdow_text_string(fdow, dev_info->bytes, dev_info->byte_sz)) {
		LOG(LOG_ERROR, "OVHeader: Failed to write OVDeviceInfo\n");
		return false;
	}
	if (!fdo_public_key_write(fdow, pubkey)) {
		LOG(LOG_ERROR, "OVHeader: Failed to write OVPubKey\n");
		return false;
	}
	if (!fdo_hash_write(fdow, hdc)) {
		LOG(LOG_ERROR, "OVHeader: Failed to write OVDevCertChainHash\n");
		return false;
	}
	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "OVHeader: Failed to end array\n");
		return false;
	}
	if (!fdow_encoded_length(fdow, &fdow->b.block_size)) {
		return false;
	}
	return true;
}

/**
 * Given an OwnershipVoucher, calculate and save the OVEHashHdrInfo.
 * @param ov - pointer to the fdo_ownership_voucher_t object
 * @return true if operation is a success, false otherwise
 */
bool fdo_ove_hash_hdr_info_save(fdo_ownership_voucher_t *ov) {

	bool ret = false;
	// calculate and save OVEHashHdrInfo (hash[GUID||DeviceInfo])
	// Header Hash Info is of length OVGuid length + OVDeviceInfo length
	uint8_t *hash_hdr_info = fdo_alloc(ov->g2->byte_sz + ov->dev_info->byte_sz);
	if (!hash_hdr_info) {
		LOG(LOG_ERROR, "OVEHashHdrInfo: Failed to alloc for OVEHashHdrInfo\n");
		goto exit;
	}
	if (0 != memcpy_s(hash_hdr_info, ov->g2->byte_sz,
		ov->g2->bytes, ov->g2->byte_sz)) {
		LOG(LOG_ERROR, "OVEHashHdrInfo: Failed to copy GUID\n");
		goto exit;
	}
	if (0 != memcpy_s(hash_hdr_info + ov->g2->byte_sz, ov->dev_info->byte_sz,
		ov->dev_info->bytes, ov->dev_info->byte_sz)) {
		LOG(LOG_ERROR, "OVEHashHdrInfo: Failed to copy DeviceInfo\n");
		goto exit;
	}

	ov->ov_entries->hc_hash = fdo_hash_alloc(
	    FDO_CRYPTO_HASH_TYPE_USED, FDO_SHA_DIGEST_SIZE_USED);
	if (!ov->ov_entries->hc_hash){
		LOG(LOG_ERROR, "OVEHashHdrInfo: Failed to alloc OVEHashHdrInfo in storage\n");
		goto exit;
	}
	if (0 != fdo_crypto_hash(hash_hdr_info, ov->g2->byte_sz + ov->dev_info->byte_sz,
		ov->ov_entries->hc_hash->hash->bytes,
		ov->ov_entries->hc_hash->hash->byte_sz)) {
		LOG(LOG_ERROR, "OVEHashHdrInfo: Failed to generate hash\n");
		goto exit;
	}
	ret = true;
exit:
	if (hash_hdr_info) {
		fdo_free(hash_hdr_info);
	}
	if (!ret && ov->ov_entries->hc_hash) {
		fdo_hash_free(ov->ov_entries->hc_hash);
	}
	return ret;
}

/**
 * Given an OwnershipVoucher and hmac, calculate and save the OVEHashPrevEntry.
 * @param fdow - fdow_t object to use for encoding data into CBOR
 * @param ov - pointer to the fdo_ownership_voucher_t object
 * @param hmac - OVHeaderHMac.OVHeaderHMac object
 * @return true if operation is a success, false otherwise
 */
bool fdo_ove_hash_prev_entry_save(fdow_t *fdow, fdo_ownership_voucher_t *ov,
	fdo_hash_t *hmac) {

	bool ret = false;
	fdo_byte_array_t *enc_ovheader = NULL;
	fdo_byte_array_t *enc_hmac = NULL;
	uint8_t *hash_prev_entry = NULL;
	// save the default buffer size, set it back at the end
	size_t fdow_buff_default_sz = fdow->b.block_size;

	// reset the block to write OVHeader
	fdo_block_reset(&fdow->b);
	fdow->b.block_size = fdow_buff_default_sz;
	if (!fdow_encoder_init(fdow)) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to initialize FDOW encoder\n");
		goto exit;
	}

	// write OVHeader
	if (!fdo_ovheader_write(fdow, ov->prot_version, ov->g2, ov->rvlst2,
		ov->dev_info, ov->mfg_pub_key, ov->hdc)) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to write OVHeader\n");
		goto exit;
	}
	enc_ovheader = fdo_byte_array_alloc_with_byte_array(fdow->b.block, fdow->b.block_size);
	if (!enc_ovheader) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to copy encoded OVHeader\n");
		goto exit;
	}

	// reset the FDOW block to write HMac
	fdo_block_reset(&fdow->b);
	fdow->b.block_size = fdow_buff_default_sz;
	if (!fdow_encoder_init(fdow)) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to initialize FDOW encoder\n");
		goto exit;
	}

	// write HMac
	if (!fdo_hash_write(fdow, hmac)) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to write HMac\n");
		goto exit;
	}
	if (!fdow_encoded_length(fdow, &fdow->b.block_size)) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to get HMac length\n");
		goto exit;
	}
	enc_hmac = fdo_byte_array_alloc_with_byte_array(fdow->b.block, fdow->b.block_size);
	if (!enc_hmac) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to copy encoded HMac\n");
		goto exit;
	}
	// calculate and save OVEHashPrevEntry (hash[OVHeader||HMac])
	// Prev Entry Hash is of length OVHeader length + HMac length
	hash_prev_entry = fdo_alloc(enc_ovheader->byte_sz + enc_hmac->byte_sz);
	if (!hash_prev_entry) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to alloc for OVEHashPrevEntry\n");
		goto exit;
	}
	if (0 != memcpy_s(hash_prev_entry, enc_ovheader->byte_sz,
		enc_ovheader->bytes, enc_ovheader->byte_sz)) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to copy OVHeader\n");
		goto exit;
	}
	if (0 != memcpy_s(hash_prev_entry + enc_ovheader->byte_sz, enc_hmac->byte_sz,
		enc_hmac->bytes, enc_hmac->byte_sz)) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to copy HMac\n");
		goto exit;
	}

	ov->ov_entries->hp_hash = fdo_hash_alloc(
	    FDO_CRYPTO_HASH_TYPE_USED, FDO_SHA_DIGEST_SIZE_USED);
	if (!ov->ov_entries->hp_hash) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to alloc for OVEHashPrevEntry in storage\n");
		goto exit;
	}
	if (0 != fdo_crypto_hash(hash_prev_entry, enc_ovheader->byte_sz + enc_hmac->byte_sz,
		ov->ov_entries->hp_hash->hash->bytes,
		ov->ov_entries->hp_hash->hash->byte_sz)) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to generate hash\n");
		goto exit;
	}
	ret = true;

	// reset the given FDOW for the next encoding
	fdo_block_reset(&fdow->b);
	fdow->b.block_size = fdow_buff_default_sz;
	if (!fdow_encoder_init(fdow)) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to initialize FDOW encoder\n");
		goto exit;
	}
exit:
	if (enc_ovheader) {
		fdo_byte_array_free(enc_ovheader);
	}
	if (enc_hmac) {
		fdo_byte_array_free(enc_hmac);
	}
	if (hash_prev_entry) {
		fdo_free(hash_prev_entry);
	}
	if (!ret && ov->ov_entries->hp_hash) {
		fdo_hash_free(ov->ov_entries->hp_hash);
	}
	return ret;
}

/**
 * Take the the values of old OVHeader contents and newly supplied replacement credentials
 * and create a new HMAC.
 * @param dev_cred - pointer to the Device_credential to source
 * @param new_pub_key - the public key to use in the signature
 * @param hdc - device cert-chain hash
 * @return pointer to a new fdo_hash_t object containing the HMAC
 */
fdo_hash_t *fdo_new_ov_hdr_sign(fdo_dev_cred_t *dev_cred,
			fdo_owner_supplied_credentials_t *osc, fdo_hash_t *hdc)
{

	bool ret = false;

	// fdow_t to generate CBOR encoded OVHeader. Used to generate HMAC.
	fdow_t *fdow = fdo_alloc(sizeof(fdow_t));
	if (!fdow_init(fdow) ||
		!fdo_block_alloc_with_size(&fdow->b, BUFF_SIZE_8K_BYTES) ||
		!fdow_encoder_init(fdow)) {
		LOG(LOG_ERROR, "Failed to initialize FDOW\n");
		goto exit;
	}

	if (!fdo_ovheader_write(fdow, dev_cred->owner_blk->pv, osc->guid, osc->rvlst,
		dev_cred->mfg_blk->d, osc->pubkey, hdc)) {
		goto exit;
	}

	fdo_hash_t *hmac =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_USED, FDO_SHA_DIGEST_SIZE_USED);

	if (hmac &&
	    (0 != fdo_device_ov_hmac(fdow->b.block, fdow->b.block_size,
				     hmac->hash->bytes, hmac->hash->byte_sz, true))) {
		fdo_hash_free(hmac);
		goto exit;
	}
	ret = true;
exit:
	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
	if (ret) {
		return hmac;
	} else {
		return NULL;
	}
}

/**
 * Allocate a new Owner Supplied Credentials object
 * @return an fdo_owner_supplied_credentials_t object with all setting cleared
 */
fdo_owner_supplied_credentials_t *fdo_owner_supplied_credentials_alloc(void)
{
	return fdo_alloc(sizeof(fdo_owner_supplied_credentials_t));
}

/**
 * Free the Owner Supplied Credential object
 * @param osc - The owner supplied credential object
 * @return none.
 */
void fdo_owner_supplied_credentials_free(fdo_owner_supplied_credentials_t *osc)
{
	if (osc != NULL) {
		fdo_rendezvous_list_free(osc->rvlst);
		osc->rvlst = NULL;
		fdo_free(osc);
	}
}