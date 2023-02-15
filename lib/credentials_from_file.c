/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Reading & Writing Device credentials in JSON format as described by
 * spec.
 */

#include "util.h"
#include "safe_lib.h"
#include "load_credentials.h"
#include "storage_al.h"
#include <unistd.h>
#include <stdlib.h>
#include "util.h"
#include "fdoCrypto.h"
#if defined(DEVICE_CSE_ENABLED)
#include "cse_utils.h"
#include "cse_tools.h"
#endif

static bool validate_state(fdo_sdk_device_status current_status);

#if !defined(DEVICE_CSE_ENABLED)
/**
 * Write the Device Credentials blob, contains our state
 * @param dev_cred_file - pointer of type const char to which credentails are
 * to be written.
 * @param flags ///TO BE ADDED
 *
 *
 * @param ocred - pointer of type fdo_dev_cred_t, holds the credentials for
 * writing to dev_cred_file.
 * @return true if write and parsed correctly, otherwise false
 */

bool write_normal_device_credentials(const char *dev_cred_file,
		fdo_sdk_blob_flags flags,
		fdo_dev_cred_t *ocred)
{
	bool ret = true;

	if (!ocred || !dev_cred_file) {
		return false;
	}
#ifndef NO_PERSISTENT_STORAGE

	fdow_t *fdow = fdo_alloc(sizeof(fdow_t));
	if (!fdow || !fdow_init(fdow) ||
			!fdo_block_alloc_with_size(&fdow->b, BUFF_SIZE_4K_BYTES) ||
			!fdow_encoder_init(fdow)) {
		LOG(LOG_ERROR, "FDOW Initialization/Allocation failed!\n");
		ret = false;
		goto end;
	}

	/**
	 * Blob format: Complete DeviceCredential as per Section 3.4.1 of FDO Specification,
	 * except the DeviceCredential.DCHmacSecret, and addition of 'State'.
	 * DeviceCredential = [
	 * 		State,
	 * 		DCActive,
	 *		DCProtVer,
	 * 		DCDeviceInfo,
	 * 		DCGuid,
	 * 		DCRVInfo,
	 * 		DCPubKeyHash
	 * ]
	 */
	fdow_next_block(fdow, FDO_DI_SET_CREDENTIALS);
	if (!fdow_start_array(fdow, 7)) {
		ret = false;
		goto end;
	}
	if (!fdow_signed_int(fdow, ocred->ST)) {
		ret = false;
		goto end;
	}
	if (!fdow_boolean(fdow, true)) {
		ret = false;
		goto end;
	}
	if (!fdow_signed_int(fdow, ocred->owner_blk->pv)) {
		ret = false;
		goto end;
	}

	if (!fdow_text_string(fdow, ocred->mfg_blk->d->bytes, ocred->mfg_blk->d->byte_sz)) {
		ret = false;
		goto end;
	}
	if (!fdow_byte_string(fdow, ocred->owner_blk->guid->bytes, ocred->owner_blk->guid->byte_sz)) {
		ret = false;
		goto end;
	}
	if (!fdo_rendezvous_list_write(fdow, ocred->owner_blk->rvlst)) {
		ret = false;
		goto end;
	}
	if (!fdo_hash_write(fdow, ocred->owner_blk->pkh)) {
		ret = false;
		goto end;
	}
	if (!fdow_end_array(fdow)) {
		ret = false;
		goto end;
	}
	size_t encoded_cred_length = 0;
	if (!fdow_encoded_length(fdow, &encoded_cred_length) || encoded_cred_length == 0) {
		LOG(LOG_ERROR, "Failed to get DeviceCredential encoded length\n");
		ret = false;
		goto end;
	}
	fdow->b.block_size = encoded_cred_length;

	if (fdo_blob_write((char *)dev_cred_file, flags, fdow->b.block,
				fdow->b.block_size) == -1) {
		LOG(LOG_ERROR, "Failed to write DeviceCredential blob\n");
		ret = false;
		goto end;
	}

end:
	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
#endif
	return ret;
}

/**
 * Write the Device Credentials blob, contains our Secret
 * @param dev_cred_file - pointer of type const char to which credentails are
 * to be written.
 * @param flags - descriptor telling type of file
 * @param ocred - pointer of type fdo_dev_cred_t, holds the credentials for
 * writing to dev_cred_file.
 * @return true if write and parsed correctly, otherwise false
 */

bool write_secure_device_credentials(const char *dev_cred_file,
		fdo_sdk_blob_flags flags, fdo_dev_cred_t *ocred)
{
	bool ret = true;
	(void) *ocred;

	if (!dev_cred_file) {
		return false;
	}

#ifndef NO_PERSISTENT_STORAGE

	fdow_t *fdow = fdo_alloc(sizeof(fdow_t));
	if (!fdow || !fdow_init(fdow) ||
			!fdo_block_alloc_with_size(&fdow->b, BUFF_SIZE_128_BYTES) ||
			!fdow_encoder_init(fdow)) {
		LOG(LOG_ERROR, "FDOW Initialization/Allocation failed!\n");
		ret = false;
		goto end;
	}
	fdo_byte_array_t **ovkey = getOVKey();
	if (!ovkey || !*ovkey) {
		ret = false;
		goto end;
	}
	/**
	 * Blob format: DeviceCredential.DCHmacSecret as bstr.
	 */
	fdow_byte_string(fdow, (*ovkey)->bytes, (*ovkey)->byte_sz);
	size_t encoded_secret_length = 0;
	if (!fdow_encoded_length(fdow, &encoded_secret_length) || encoded_secret_length == 0) {
		LOG(LOG_ERROR, "Failed to get encoded DeviceCredential.DCHmacSecret length\n");
		ret = false;
		goto end;
	}
	fdow->b.block_size = encoded_secret_length;

	if (fdo_blob_write((char *)dev_cred_file, flags, fdow->b.block,
				fdow->b.block_size) == -1) {
		LOG(LOG_ERROR, "Failed to write DeviceCredential.DCHmacSecret blob\n");
		ret = false;
		goto end;
	}
end:
	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
#endif
	return ret;
}

/**
 * Read the Device Credentials blob, contains our state & owner_blk
 * @param dev_cred_file - the blob the credentials are saved in
 * @param flags - descriptor telling type of file
 * @param our_dev_cred - pointer to the device credentials block,
 * @return true if read and parsed correctly, otherwise false.
 */
bool read_normal_device_credentials(const char *dev_cred_file,
		fdo_sdk_blob_flags flags,
		fdo_dev_cred_t *our_dev_cred)
{
	bool ret = false;
	size_t dev_cred_len = 0;
	fdor_t *fdor = NULL;
	int dev_state = -1;

	if (!dev_cred_file || !our_dev_cred) {
		LOG(LOG_ERROR, "Invalid params\n");
		return false;
	}

	if (our_dev_cred->owner_blk != NULL) {
		fdo_cred_owner_free(our_dev_cred->owner_blk);
		our_dev_cred->owner_blk = NULL;
	}

	/* Memory allocating data.inside dev_cred. */
	our_dev_cred->owner_blk = fdo_cred_owner_alloc();
	if (!our_dev_cred->owner_blk) {
		LOG(LOG_ERROR, "dev_cred's owner_blk allocation failed\n");
		goto end;
	}

	dev_cred_len = fdo_blob_size((char *)dev_cred_file, flags);
	// Device has not yet been initialized.
	// Since, Normal.blob is empty, the file size will be 0
	if (dev_cred_len == 0) {
		LOG(LOG_DEBUG, "DeviceCredential not found. Proceeding with DI\n");
		our_dev_cred->ST = FDO_DEVICE_STATE_PC;
		return true;
	}

	LOG(LOG_DEBUG, "Reading DeviceCredential blob of length %"PRIu64"\n", dev_cred_len);

	fdor = fdo_alloc(sizeof(fdor_t));
	if (!fdor || !fdor_init(fdor) || !fdo_block_alloc_with_size(&fdor->b, dev_cred_len)) {
		LOG(LOG_ERROR, "FDOR Initialization/Allocation failed!\n");
		goto end;
	}

	if (fdo_blob_read((char *)dev_cred_file, flags, fdor->b.block,
				fdor->b.block_size) == -1) {
		LOG(LOG_ERROR, "Failed to read DeviceCredential blob : Normal.blob\n");
		goto end;
	}

	if (!fdor_parser_init(fdor)) {
		LOG(LOG_ERROR, "FDOR Parser Initialization failed!\n");
		goto end;
	}

	if (!fdor_start_array(fdor)) {
		LOG(LOG_ERROR, "DeviceCredential read: Begin Array not found\n");
		goto end;
	}

	if (!fdor_signed_int(fdor, &dev_state)) {
		LOG(LOG_ERROR, "DeviceCredential read: ST not found\n");
		goto end;
	}
	our_dev_cred->ST = dev_state;

	if (!validate_state(our_dev_cred->ST)) {
		LOG(LOG_ERROR, "DeviceCredential read: Invalid ST\n");
		goto end;
	}

	if (!fdor_boolean(fdor, &our_dev_cred->dc_active)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCActive not found\n");
		goto end;
	}

	if (!fdor_signed_int(fdor, &our_dev_cred->owner_blk->pv)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCProtVer not found\n");
		goto end;
	}

	size_t device_info_length = 0;
	if (!fdor_string_length(fdor, &device_info_length) || device_info_length == 0) {
		LOG(LOG_ERROR, "DeviceCredential read: Invalid DCDeviceInfo length\n");
		goto end;
	}

	our_dev_cred->mfg_blk = fdo_cred_mfg_alloc();
	if (!our_dev_cred->mfg_blk) {
		LOG(LOG_ERROR, "DeviceCredential read: Malloc for DCDeviceInfo failed");
		goto end;
	}

	our_dev_cred->mfg_blk->d = fdo_string_alloc_size(device_info_length);
	if (!our_dev_cred->mfg_blk->d ||
			!fdor_text_string(fdor, our_dev_cred->mfg_blk->d->bytes,
				our_dev_cred->mfg_blk->d->byte_sz)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCDeviceInfo not found\n");
		goto end;
	}
	our_dev_cred->mfg_blk->d->bytes[device_info_length] = '\0';

	size_t guid_length = 0;
	if (!fdor_string_length(fdor, &guid_length) || guid_length == 0) {
		LOG(LOG_ERROR, "DeviceCredential read: Invalid DCGuid length\n");
		goto end;
	}
	our_dev_cred->owner_blk->guid = fdo_byte_array_alloc(guid_length);
	if (!our_dev_cred->owner_blk->guid ||
			!fdor_byte_string(fdor, our_dev_cred->owner_blk->guid->bytes,
				our_dev_cred->owner_blk->guid->byte_sz)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCGuid not found\n");
		goto end;
	}

	our_dev_cred->owner_blk->rvlst = fdo_rendezvous_list_alloc();
	if (!our_dev_cred->owner_blk->rvlst ||
			!fdo_rendezvous_list_read(fdor, our_dev_cred->owner_blk->rvlst)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCRVInfo not found\n");
		goto end;
	}

	our_dev_cred->owner_blk->pkh =
		fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_USED, FDO_SHA_DIGEST_SIZE_USED);
	if (!our_dev_cred->owner_blk->pkh ||
			!fdo_hash_read(fdor, our_dev_cred->owner_blk->pkh)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCPubKeyHash not found\n");
		goto end;
	}

	if (!fdor_end_array(fdor)) {
		LOG(LOG_ERROR, "DeviceCredential read: End Array not found\n");
		goto end;
	}
	ret = true;
end:
	if (fdor) {
		fdor_flush(fdor);
		fdo_free(fdor);
	}
	return ret;
}

/**
 * Read the Secure Device Credentials blob, contains our Secret
 * @param dev_cred_file - the blob the credentials are saved in
 * @param flags - descriptor telling type of file
 * @param our_dev_cred - pointer to the device credentials block,
 * @return true if read and parsed correctly, otherwise false.
 */
bool read_secure_device_credentials(const char *dev_cred_file,
		fdo_sdk_blob_flags flags,
		fdo_dev_cred_t *our_dev_cred)
{
	bool ret = false;
	size_t dev_cred_len = 0;
	fdo_byte_array_t *secret = NULL;

	if (!dev_cred_file) {
		LOG(LOG_DEBUG, "Invalid params\n");
		return false;
	}

	(void)our_dev_cred; /* Unused Warning */

	dev_cred_len = fdo_blob_size((char *)dev_cred_file, flags);
	if (dev_cred_len == 0) {
		LOG(LOG_DEBUG, "DeviceCredential.DCHmacSecret not found. Proceeding with DI\n");
		return true;
	}

	fdor_t *fdor = fdo_alloc(sizeof(fdor_t));
	if (!fdor || !fdor_init(fdor) || !fdo_block_alloc_with_size(&fdor->b, dev_cred_len)) {
		LOG(LOG_ERROR, "FDOR Initialization/Allocation failed!\n");
		goto end;
	}

	if (fdo_blob_read((char *)dev_cred_file, flags, fdor->b.block,
				fdor->b.block_size) == -1) {
		LOG(LOG_ERROR, "Failed to read DeviceCredential blob: Secure.blob\n");
		goto end;
	}

	if (!fdor_parser_init(fdor)) {
		LOG(LOG_ERROR, "FDOR Parser Initialization failed!\n");
		goto end;
	}

	secret = fdo_byte_array_alloc(FDO_HMAC_KEY_LENGTH);
	if (!secret) {
		LOG(LOG_ERROR, "Dev_cred Secret malloc Failed.\n");
		goto end;
	}

	if (!fdor_byte_string(fdor, secret->bytes, secret->byte_sz)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCHmacSecret not found\n");
		goto end;
	}

	if (0 != set_ov_key(secret, FDO_HMAC_KEY_LENGTH)) {
		LOG(LOG_ERROR, "Failed to set HMAC secret.\n");
		goto end;
	}
	ret = true;

end:
	fdo_byte_array_free(secret);
	if (fdor) {
		fdor_flush(fdor);
		fdo_free(fdor);
	}
	return ret;
}

/**
 * Write and save the device credentials passed as an parameter ocred of type
 * fdo_dev_cred_t.
 * @param ocred - Pointer of type fdo_dev_cred_t, credentials to be copied
 * @return 0 if success, else -1 on failure.
 */
int store_credential(fdo_dev_cred_t *ocred)
{
	/* Write in the file and save the Normal device credentials */
	LOG(LOG_DEBUG, "Writing to %s blob\n", "Normal.blob");
	if (!write_normal_device_credentials((char *)FDO_CRED_NORMAL,
				FDO_SDK_NORMAL_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not write to Normal Credentials blob\n");
		return -1;
	}

#if !defined(DEVICE_TPM20_ENABLED)
	/* Write in the file and save the Secure device credentials */
	LOG(LOG_DEBUG, "Writing to %s blob\n", "Secure.blob");
	if (!write_secure_device_credentials((char *)FDO_CRED_SECURE,
				FDO_SDK_SECURE_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not write to Secure Credentials blob\n");
		return -1;
	}
#endif

	return 0;
}
#endif

#if defined(DEVICE_CSE_ENABLED)
/**
 * Populates the dev_cred structure by loading the OVH and DS file data from CSE flash.
 * @param our_dev_cred - pointer to the device credentials block,
 * @return true if read and parsed correctly, otherwise false.
 */
bool read_cse_device_credentials(fdo_dev_cred_t *our_dev_cred)
{
	bool ret = false;
	uint32_t dev_cred_len = 0;
	uint32_t dev_state_len = 0;
	uint8_t dev_state[1] = {-1};
	uint8_t *ds_ptr = (uint8_t*)&dev_state;
	fdo_ownership_voucher_t *ov = NULL;
	fdo_byte_array_t *ovheader = NULL;
	fdo_byte_array_t *hmac_ptr = NULL;

	if (!our_dev_cred) {
		LOG(LOG_ERROR, "Invalid params\n");
		goto end;
	}

	if (our_dev_cred->owner_blk != NULL) {
		fdo_cred_owner_free(our_dev_cred->owner_blk);
		our_dev_cred->owner_blk = NULL;
	}

	/* Memory allocating data.inside dev_cred. */
	our_dev_cred->owner_blk = fdo_cred_owner_alloc();
	if (!our_dev_cred->owner_blk) {
		LOG(LOG_ERROR, "dev_cred's owner_blk allocation failed\n");
		goto end;
	}

	if (our_dev_cred->mfg_blk != NULL) {
		fdo_cred_mfg_free(our_dev_cred->mfg_blk);
		our_dev_cred->mfg_blk = NULL;
	}

	our_dev_cred->mfg_blk = fdo_cred_mfg_alloc();
	if (!our_dev_cred->mfg_blk) {
		LOG(LOG_ERROR, "dev_cred's mfg_blk allocation failed\n");
		goto end;
	}

	ovheader = fdo_byte_array_alloc(FDO_MAX_FILE_SIZE);
	if (!ovheader) {
		LOG(LOG_ERROR,"DeviceCredential read: Failed to allocate data for storing OVH data\n");
		goto end;
	}

	hmac_ptr = fdo_byte_array_alloc(FDO_HMAC_384_SIZE);
	if (!hmac_ptr) {
		LOG(LOG_ERROR, "DeviceCredential read: Failed to allocate data for storing HMAC data \n");
		goto end;
	}

	if (0 != cse_load_file(OVH_FILE_ID, ovheader->bytes, &dev_cred_len,
				hmac_ptr->bytes, hmac_ptr->byte_sz)) {
		LOG(LOG_ERROR, "DeviceCredential read: Unable to load file form CSE\n");
		goto end;
	}

	// Device has not yet been initialized.
	if (dev_cred_len == 0) {
		LOG(LOG_DEBUG, "DeviceCredential not found. Proceeding with DI\n");
		our_dev_cred->ST = FDO_DEVICE_STATE_PC;
		ret = true;
		goto end;
	}

	LOG(LOG_DEBUG, "Reading DeviceCredential blob of length %u\n", dev_cred_len);
	ovheader->byte_sz = dev_cred_len;

	ov = fdo_ov_hdr_read(ovheader);
	if (!ov) {
		LOG(LOG_ERROR, "DeviceCredential read: Failed to read OVHeader\n");
		goto end;
	}

	if (ov->prot_version != FDO_PROT_SPEC_VERSION) {
		fdo_ov_free(ov);
		LOG(LOG_ERROR, "DeviceCredential read: Invalid OVProtVer\n");
		goto end;
	}

	if (0 != cse_load_file(DS_FILE_ID, ds_ptr, &dev_state_len, NULL, 0)) {
		LOG(LOG_ERROR, "DeviceCredential read: Unable to load file form CSE\n");
		goto end;
	}

	our_dev_cred->ST = dev_state[0];
	our_dev_cred->dc_active = false;
	our_dev_cred->owner_blk->pv = ov->prot_version;
	our_dev_cred->owner_blk->rvlst = ov->rvlst2;
	our_dev_cred->owner_blk->guid = ov->g2;
	our_dev_cred->mfg_blk->d = ov->dev_info;
	our_dev_cred->owner_blk->pk = ov->mfg_pub_key;
	our_dev_cred->owner_blk->pkh = fdo_pub_key_hash(our_dev_cred->owner_blk->pk);

	if (ov->hdc) {
		fdo_hash_free(ov->hdc);
	}
	fdo_free(ov);

	if (!our_dev_cred->owner_blk->pkh) {
		LOG(LOG_ERROR, "Hash creation of manufacturer pk failed\n");
		goto end;
	}

	if (!validate_state(our_dev_cred->ST)) {
		LOG(LOG_ERROR, "DeviceCredential read: Invalid ST\n");
		goto end;
	}

	ret = true;
end:
	if (ovheader) {
		fdo_byte_array_free(ovheader);
		ovheader = NULL;
	}

	if (hmac_ptr) {
		fdo_byte_array_free(hmac_ptr);
		hmac_ptr = NULL;
	}
	return ret;
}
#endif

/**
 * load_credentials function loads the State, Owner and Manufacturer credentials from
 * storage
 *
 * @return
 *        return 0 on success. -1 on failure.
 */
int load_credential(fdo_dev_cred_t *ocred)
{
	if (!ocred) {
		return -1;
	}

#if defined(DEVICE_CSE_ENABLED)
	/* Read the device credentials from CSE*/
	if (!read_cse_device_credentials(ocred)) {
		LOG(LOG_ERROR, "Could not parse the Device Credentials form CSE\n");
		return -1;
	}
#else
	/* Read in the blob and save the device credentials */
	if (!read_normal_device_credentials((char *)FDO_CRED_NORMAL,
				FDO_SDK_NORMAL_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not parse the Device Credentials blob\n");
		return -1;
	}
#endif
	return 0;
}

#if !defined(DEVICE_CSE_ENABLED)
/**
 * load_device_secret function loads the Secure & credentials from storage
 *
 * @return
 *        return 0 on success. -1 on failure.
 */

int load_device_secret(void)
{

#if !defined(DEVICE_TPM20_ENABLED)
	// ReadHMAC Credentials
	if (!read_secure_device_credentials((char *)FDO_CRED_SECURE,
				FDO_SDK_SECURE_DATA, NULL)) {
		LOG(LOG_ERROR, "Could not parse the Device Credentials blob\n");
		return -1;
	}
#endif
	return 0;
}
#endif

/**
 * Read the Device status and store it in the out variable 'state'.
 *
 * @return
 *        return true on success. false on failure.
 */
bool load_device_status(fdo_sdk_device_status *state) {

	if (!state) {
		return false;
	}

#if defined(DEVICE_CSE_ENABLED)
	uint32_t dev_cred_len;
	uint8_t dev_state[1] = {-1};
	uint8_t *ds_ptr = (uint8_t*)&dev_state;

	if (0 != cse_load_file(DS_FILE_ID, ds_ptr, &dev_cred_len, NULL, 0)) {
		LOG(LOG_ERROR, "DeviceCredential read: Unable to load file form CSE\n");
		return false;
	}
#else
	size_t dev_cred_len = fdo_blob_size((char *)FDO_CRED_NORMAL, FDO_SDK_NORMAL_DATA);
#endif
	// Device has not yet been initialized.
	// Since, Normal.blob is empty, the file size will be 0
	if (dev_cred_len == 0) {
		LOG(LOG_DEBUG, "DeviceCredential is empty. Set state to run DI\n");
		*state = FDO_DEVICE_STATE_PC;
	} else {
		LOG(LOG_DEBUG, "DeviceCredential is non-empty. Set state to run TO1/TO2\n");
		// No Device state is being set currently
	}
	return true;
}

/**
 * Store the Device status given by the variable 'state'.
 * @return return true on success. false on failure.
 */
bool store_device_status(fdo_sdk_device_status *state) {
#if defined(DEVICE_CSE_ENABLED)
	FDO_STATUS fdo_status;

	if (TEE_SUCCESS != fdo_heci_load_file(&fdo_cse_handle, DS_FILE_ID,
				&fdo_status) || FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO HECI LOAD DS failed!! %u\n", fdo_status);
		return false;
	}
	LOG(LOG_DEBUG, "FDO HECI LOAD DS succeeded %u\n", fdo_status);

	if (TEE_SUCCESS != fdo_heci_update_file(&fdo_cse_handle, DS_FILE_ID,
				(uint8_t *)state, 1, NULL, 0, &fdo_status) || FDO_STATUS_SUCCESS !=
			fdo_status) {
		LOG(LOG_ERROR, "FDO HECI UPDATE DS failed!! %u\n", fdo_status);
		return false;
	}
	LOG(LOG_DEBUG, "FDO HECI UPDATE DS succeeded %u\n", fdo_status);

	if (TEE_SUCCESS != fdo_heci_commit_file(&fdo_cse_handle, DS_FILE_ID,
				&fdo_status) || FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO DS COMMIT failed!! %u\n", fdo_status);
		return false;
	}
	LOG(LOG_DEBUG, "FDO DS COMMIT succeeded %u\n", fdo_status);
#else
	/** NOTE: Currently, it does nothing. This is a provision to store status separately
	 * and is unused in this specific implementation.
	 */
	(void)state;
#endif
	return true;
}

/**
 * Validate the current status of the device.
 */
static bool validate_state(fdo_sdk_device_status current_status) {

	if (current_status == FDO_DEVICE_STATE_READY1 ||
			current_status == FDO_DEVICE_STATE_D1 ||
			current_status == FDO_DEVICE_STATE_IDLE ||
			current_status == FDO_DEVICE_STATE_READYN ||
			current_status == FDO_DEVICE_STATE_DN) {
		return true;
	}
	return false;
}
