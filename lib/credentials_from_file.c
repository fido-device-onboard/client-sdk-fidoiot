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

	if (!fdor_signed_int(fdor, &our_dev_cred->ST)) {
		LOG(LOG_ERROR, "DeviceCredential read: ST not found\n");
		goto end;
	}

	if (our_dev_cred->ST < FDO_DEVICE_STATE_READY1) {
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

	if (!dev_cred_file || !our_dev_cred) {
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

/**
 * load_credentials function loads the State & Owner_blk credentials from
 * storage
 *
 * @return
 *        return 0 on success. -1 on failure.
 */
int load_credential(void)
{
	fdo_dev_cred_t *ocred = app_alloc_credentials();

	if (!ocred) {
		return -1;
	}

	fdo_dev_cred_init(ocred);

	/* Read in the blob and save the device credentials */
	if (!read_normal_device_credentials((char *)FDO_CRED_NORMAL,
					    FDO_SDK_NORMAL_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not parse the Device Credentials blob\n");
		return -1;
	}
	return 0;
}

/**
 * load_mfg_secret function loads the Secure & MFG credentials from storage
 *
 * @return
 *        return 0 on success. -1 on failure.
 */

int load_mfg_secret(void)
{
	fdo_dev_cred_t *ocred = app_get_credentials();

	if (!ocred) {
		return -1;
	}

#if !defined(DEVICE_TPM20_ENABLED)
	// ReadHMAC Credentials
	if (!read_secure_device_credentials((char *)FDO_CRED_SECURE,
					    FDO_SDK_SECURE_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not parse the Device Credentials blob\n");
		return -1;
	}
#endif
	return 0;
}
