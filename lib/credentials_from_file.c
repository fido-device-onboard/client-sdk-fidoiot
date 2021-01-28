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
#include "sdoCrypto.h"
#define verbose_dump_packets 0

/**
 * Write the Device Credentials blob, contains our state
 * @param dev_cred_file - pointer of type const char to which credentails are
 * to be written.
 * @param flags ///TO BE ADDED
 *
 *
 * @param ocred - pointer of type sdo_dev_cred_t, holds the credentials for
 * writing to dev_cred_file.
 * @return true if write and parsed correctly, otherwise false
 */

bool write_normal_device_credentials(const char *dev_cred_file,
				     sdo_sdk_blob_flags flags,
				     sdo_dev_cred_t *ocred)
{
	bool ret = true;

	if (!ocred || !dev_cred_file) {
		return false;
	}
#ifndef NO_PERSISTENT_STORAGE

	sdow_t *sdow = sdo_alloc(sizeof(sdow_t));
	if (!sdow_init(sdow) || !sdo_block_alloc(&sdow->b) || !sdow_encoder_init(sdow)) {
		LOG(LOG_ERROR, "sdow_init() failed!\n");
		ret = false;
		goto end;
	}

	sdow_next_block(sdow, SDO_DI_SET_CREDENTIALS);
	if (!sdow_start_array(sdow, 7)) {
		ret = false;
		goto end;
	}
	if (!sdow_signed_int(sdow, ocred->ST)) {
		ret = false;
		goto end;
	}
	if (!sdow_boolean(sdow, true)) {
		ret = false;
		goto end;
	}
	if (!sdow_signed_int(sdow, ocred->owner_blk->pv)) {
		ret = false;
		goto end;
	}
	if (!sdow_text_string(sdow, ocred->mfg_blk->d->bytes, ocred->mfg_blk->d->byte_sz)) {
		ret = false;
		goto end;
	}
	if (!sdow_byte_string(sdow, ocred->owner_blk->guid->bytes, ocred->owner_blk->guid->byte_sz)) {
		ret = false;
		goto end;
	}
	if (!sdo_rendezvous_list_write(sdow, ocred->owner_blk->rvlst)) {
		ret = false;
		goto end;
	}
	if (!sdo_hash_write(sdow, ocred->owner_blk->pkh)) {
		ret = false;
		goto end;
	}
	if (!sdow_end_array(sdow)) {
		ret = false;
		goto end;
	}
	size_t encoded_cred_length = 0;
	if (!sdow_encoded_length(sdow, &encoded_cred_length) || encoded_cred_length <= 0) {
		LOG(LOG_ERROR, "Failed to get DeviceCredential encoded length\n");
		ret = false;
		goto end;
	}
	sdow->b.block_size = encoded_cred_length;

	if (sdo_blob_write((char *)dev_cred_file, flags, sdow->b.block,
			   sdow->b.block_size) == -1) {
		LOG(LOG_ERROR, "Failed to write DeviceCredential blob\n");
		ret = false;
		goto end;
	}

end:
	sdow_flush(sdow);
	sdo_free(sdow);
#endif
	return ret;
}

/**
 * Write the Device Credentials blob, contains our Secret
 * @param dev_cred_file - pointer of type const char to which credentails are
 * to be written.
 * @param flags - descriptor telling type of file
 * @param ocred - pointer of type sdo_dev_cred_t, holds the credentials for
 * writing to dev_cred_file.
 * @return true if write and parsed correctly, otherwise false
 */

bool write_secure_device_credentials(const char *dev_cred_file,
				     sdo_sdk_blob_flags flags, sdo_dev_cred_t *ocred)
{
	bool ret = true;
	(void) *ocred;

	if (!dev_cred_file) {
		return false;
	}

#ifndef NO_PERSISTENT_STORAGE

	sdow_t *sdow = sdo_alloc(sizeof(sdow_t));
	if (!sdow_init(sdow) || !sdo_block_alloc(&sdow->b) || !sdow_encoder_init(sdow)) {
		LOG(LOG_ERROR, "sdow_init() failed!\n");
		ret = false;
		goto end;
	}
	sdo_byte_array_t **ovkey = getOVKey();
	if (!ovkey || !*ovkey) {
		ret = false;
		goto end;
	}
	sdow_byte_string(sdow, (*ovkey)->bytes, INITIAL_SECRET_BYTES);
	size_t encoded_secret_length = 0;
	if (!sdow_encoded_length(sdow, &encoded_secret_length) || encoded_secret_length <= 0) {
		LOG(LOG_ERROR, "Failed to get encoded DeviceCredential.DCHmacSecret length\n");
		ret = false;
		goto end;
	}
	sdow->b.block_size = encoded_secret_length;

	if (sdo_blob_write((char *)dev_cred_file, flags, sdow->b.block,
			   sdow->b.block_size) == -1) {
		LOG(LOG_ERROR, "Failed to write DeviceCredential.DCHmacSecret blob\n");
		ret = false;
		goto end;
	}
end:
	sdow_flush(sdow);
	sdo_free(sdow);
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
				    sdo_sdk_blob_flags flags,
				    sdo_dev_cred_t *our_dev_cred)
{
	bool ret = false;
	int32_t dev_cred_len = 0;
	sdor_t *sdor = NULL;

	if (!our_dev_cred) {
		goto end;
	}

	if (our_dev_cred->owner_blk != NULL) {
		sdo_cred_owner_free(our_dev_cred->owner_blk);
		our_dev_cred->owner_blk = NULL;
	}

	/* Memory allocating data.inside dev_cred. */
	our_dev_cred->owner_blk = sdo_cred_owner_alloc();
	if (!our_dev_cred->owner_blk) {
		LOG(LOG_ERROR, "dev_cred's owner_blk allocation failed\n");
		goto end;
	}

	dev_cred_len = sdo_blob_size((char *)dev_cred_file, flags);
	// Device has not yet been initialized.
	// Since, Normal.blob is empty, the file size will be 0
	if (dev_cred_len == 0) {
		LOG(LOG_DEBUG, "DeviceCredential not found. Proceeding with DI\n");
		our_dev_cred->ST = SDO_DEVICE_STATE_PC;
		return true;
	}

	LOG(LOG_DEBUG, "Reading DeviceCredential blob of length %"PRId32"\n", dev_cred_len);

	sdor = sdo_alloc(sizeof(sdor_t));
	if (!sdor_init(sdor) || !sdo_block_alloc_with_size(&sdor->b, dev_cred_len)) {
		LOG(LOG_ERROR, "SDOR Initialization/Allocation failed!\n");
		goto end;
	}

	if (sdo_blob_read((char *)dev_cred_file, flags, sdor->b.block,
			  sdor->b.block_size) == -1) {
		LOG(LOG_ERROR, "Failed to read DeviceCredential blob : Normal.blob\n");
		goto end;
	}

	if (!sdor_parser_init(sdor)) {
		LOG(LOG_ERROR, "SDOR Parser Initialization failed!\n");
		goto end;
	}

	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR, "DeviceCredential read: Begin Array not found\n");
		goto end;
	}

	if (!sdor_signed_int(sdor, &our_dev_cred->ST)) {
		LOG(LOG_ERROR, "DeviceCredential read: ST not found\n");
		goto end;
	}

	if (our_dev_cred->ST < SDO_DEVICE_STATE_READY1) {
		goto end;
	}

	if (!sdor_boolean(sdor, &our_dev_cred->dc_active)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCActive not found\n");
		goto end;
	}

	if (!sdor_signed_int(sdor, &our_dev_cred->owner_blk->pv)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCProtVer not found\n");
		goto end;
	}

	size_t device_info_length = 0;
	if (!sdor_string_length(sdor, &device_info_length) || device_info_length <= 0) {
		LOG(LOG_ERROR, "DeviceCredential read: Invalid DCDeviceInfo length\n");
		goto end;
	}

	our_dev_cred->mfg_blk = sdo_cred_mfg_alloc();
	if (!our_dev_cred->mfg_blk) {
		LOG(LOG_ERROR, "DeviceCredential read: Malloc for DCDeviceInfo failed");
		goto end;
	}

	our_dev_cred->mfg_blk->d = sdo_string_alloc_size(device_info_length);
	if (!our_dev_cred->mfg_blk->d ||
		!sdor_text_string(sdor, our_dev_cred->mfg_blk->d->bytes,
		our_dev_cred->mfg_blk->d->byte_sz)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCDeviceInfo not found\n");
		goto end;
	}

	size_t guid_length = 0;
	if (!sdor_string_length(sdor, &guid_length) || guid_length <= 0) {
		LOG(LOG_ERROR, "DeviceCredential read: Invalid DCGuid length\n");
		goto end;
	}
	our_dev_cred->owner_blk->guid = sdo_byte_array_alloc(guid_length);
	if (!our_dev_cred->owner_blk->guid ||
		!sdor_byte_string(sdor, our_dev_cred->owner_blk->guid->bytes,
		our_dev_cred->owner_blk->guid->byte_sz)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCGuid not found\n");
		goto end;
	}

	our_dev_cred->owner_blk->rvlst = sdo_rendezvous_list_alloc();
	if (!our_dev_cred->owner_blk->rvlst || 
		!sdo_rendezvous_list_read(sdor, our_dev_cred->owner_blk->rvlst)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCRVInfo not found\n");
		goto end;
	}

	our_dev_cred->owner_blk->pkh =
		sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
	if (!our_dev_cred->owner_blk->pkh ||
		!sdo_hash_read(sdor, our_dev_cred->owner_blk->pkh)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCPubKeyHash not found\n");
		goto end;
	}

	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR, "DeviceCredential read: End Array not found\n");
		goto end;
	}
	ret = true;
end:
	sdor_flush(sdor);
	sdo_free(sdor);
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
				    sdo_sdk_blob_flags flags,
				    sdo_dev_cred_t *our_dev_cred)
{
	bool ret = false;
	size_t dev_cred_len = 0;
	sdo_byte_array_t *secret = NULL;

	(void)our_dev_cred; /* Unused Warning */

	dev_cred_len = sdo_blob_size((char *)dev_cred_file, flags);
	if (dev_cred_len == 0) {
		LOG(LOG_DEBUG, "DeviceCredential.DCHmacSecret not found. Proceeding with DI\n");
		return true;
	}

	sdor_t *sdor = sdo_alloc(sizeof(sdor_t));
	if (!sdor_init(sdor) || !sdo_block_alloc_with_size(&sdor->b, dev_cred_len)) {
		LOG(LOG_ERROR, "SDOR Initialization/Allocation failed!\n");
		goto end;
	}

	if (sdo_blob_read((char *)dev_cred_file, flags, sdor->b.block,
			  sdor->b.block_size) == -1) {
		LOG(LOG_ERROR, "Failed to read DeviceCredential blob: Secure.blob\n");
		goto end;
	}

	if (!sdor_parser_init(sdor)) {
		LOG(LOG_ERROR, "SDOR Parser Initialization failed!\n");
		goto end;
	}

	// TO-DO : Is it always 32 bytes? Could it be 48 bytes as well? Compare length.
	secret = sdo_byte_array_alloc(INITIAL_SECRET_BYTES);
	if (!secret) {
		LOG(LOG_ERROR, "Dev_cred Secret malloc Failed.\n");
		goto end;
	}

	if (!sdor_byte_string(sdor, secret->bytes, secret->byte_sz)) {
		LOG(LOG_ERROR, "DeviceCredential read: DCHmacSecret not found\n");
		goto end;
	}

	if (0 != set_ov_key(secret, INITIAL_SECRET_BYTES)) {
		LOG(LOG_ERROR, "Failed to set HMAC secret.\n");
		goto end;
	}
	ret = true;

end:
	sdo_byte_array_free(secret);
	sdor_flush(sdor);
	sdo_free(sdor);
	return ret;
}

#if 0
/**
 * Internal API
 */
static int sdoRFile_recv(sdor_t *sdor, int nbytes)
{
	sdo_block_t *sdob = &sdor->b;
	FILE *f = sdor->receive_data;
	int nread, limit;

	limit = sdob->cursor + nbytes;
	sdo_resize_block(sdob, limit + 1);
	nread = fread(&sdob->block[sdob->cursor], 1, nbytes, f);

	if (verbose_dump_packets)
		LOG(LOG_DEBUG,
		    "SDOR Read_file, cursor %u block_size:%u block_max:%u\n",
		    sdob->cursor, sdob->block_size, sdob->block_max);
	limit = sdob->cursor + nread;
	sdob->block[limit] = 0;
	if (verbose_dump_packets)
		LOG(LOG_DEBUG, "%s\n", sdob->block);

	return nread;
}
#endif
/**
 * Write and save the device credentials passed as an parameter ocred of type
 * sdo_dev_cred_t.
 * @param ocred - Pointer of type sdo_dev_cred_t, credentials to be copied
 * @return 0 if success, else -1 on failure.
 */
int store_credential(sdo_dev_cred_t *ocred)
{
	/* Write in the file and save the Normal device credentials */
	LOG(LOG_DEBUG, "Writing to %s blob\n", "Normal.blob");
	if (!write_normal_device_credentials((char *)SDO_CRED_NORMAL,
					     SDO_SDK_NORMAL_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not write to Normal Credentials blob\n");
		return -1;
	}

#if !defined(DEVICE_TPM20_ENABLED)
	/* Write in the file and save the Secure device credentials */
	LOG(LOG_DEBUG, "Writing to %s blob\n", "Secure.blob");
	if (!write_secure_device_credentials((char *)SDO_CRED_SECURE,
					     SDO_SDK_SECURE_DATA, ocred)) {
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
	sdo_dev_cred_t *ocred = app_alloc_credentials();

	if (!ocred)
		return -1;

	sdo_dev_cred_init(ocred);

	/* Read in the blob and save the device credentials */
	if (!read_normal_device_credentials((char *)SDO_CRED_NORMAL,
					    SDO_SDK_NORMAL_DATA, ocred)) {
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
	sdo_dev_cred_t *ocred = app_get_credentials();

	if (!ocred)
		return -1;

#if !defined(DEVICE_TPM20_ENABLED)
	// ReadHMAC Credentials
	if (!read_secure_device_credentials((char *)SDO_CRED_SECURE,
					    SDO_SDK_SECURE_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not parse the Device Credentials blob\n");
		return -1;
	}
#endif
	return 0;
}
