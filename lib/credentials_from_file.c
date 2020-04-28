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
#include "safe_lib.h"
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
	sdow_t sdowriter, *sdow = &sdowriter;

	if (!sdow_init(sdow)) {
		LOG(LOG_ERROR, "sdow_init() failed!\n");
		return false;
	}

	sdow_next_block(sdow, SDO_DI_SET_CREDENTIALS);
	sdow_begin_object(sdow);
	sdo_write_tag(sdow, "ST");
	sdo_writeUInt(sdow, ocred->ST);

	sdo_write_tag(sdow, "O");
	sdow_begin_object(sdow);

	sdo_write_tag(sdow, "pv");
	sdo_writeUInt(sdow, ocred->owner_blk->pv);

	sdo_write_tag(sdow, "pe");
	sdo_writeUInt(sdow, ocred->owner_blk->pe);

	sdo_write_tag(sdow, "g");
	sdo_byte_array_write_chars(sdow, ocred->owner_blk->guid);

	sdo_write_tag(sdow, "r");
	sdo_rendezvous_list_write(sdow, ocred->owner_blk->rvlst);

	sdo_write_tag(sdow, "pkh");
	sdo_hash_write(sdow, ocred->owner_blk->pkh);

	sdow_end_object(sdow);
	sdow_end_object(sdow);

	/* Fill sdow buffer */

	if (sdo_blob_write((char *)dev_cred_file, flags, &sdow->b.block[0],
			   sdow->b.block_size) == -1) {
		LOG(LOG_ERROR, "Issue while writing Devcred blob\n");
		ret = false;
		goto end;
	}

end:
	if (sdow->b.block) {
		sdo_free(sdow->b.block);
		sdow->b.block = NULL;
	}
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
				     sdo_sdk_blob_flags flags,
				     sdo_dev_cred_t *ocred)
{
	bool ret = true;

	(void)ocred; /* Unused warning */

	if (!dev_cred_file) {
		return false;
	}

#ifndef NO_PERSISTENT_STORAGE
	sdow_t sdowriter, *sdow = &sdowriter;

	if (!sdow_init(sdow)) {
		LOG(LOG_ERROR, "sdow_init() failed!\n");
		return false;
	}

	sdow_begin_object(sdow);
	sdo_write_tag(sdow, "Secret");
	sdow_begin_sequence(sdow);
	sdo_byte_array_t **ovkey = getOVKey();

	if (!ovkey || !*ovkey) {
		ret = false;
		goto end;
	}
	sdo_write_byte_array_field(sdow, (*ovkey)->bytes, INITIAL_SECRET_BYTES);
	sdow_end_sequence(sdow);
	sdow_end_object(sdow);

	/* Fill sdow buffer */

	if (sdo_blob_write((char *)dev_cred_file, flags, &sdow->b.block[0],
			   sdow->b.block_size) == -1) {
		LOG(LOG_ERROR, "Issue while writing Devcred blob\n");
		ret = false;
		goto end;
	}

end:
	if (sdow->b.block) {
		if (memset_s(sdow->b.block, sdow->b.block_size, 0)) {
			LOG(LOG_ERROR, "Failed to clear device credentials\n");
			ret = false;
		}
		sdo_free(sdow->b.block);
	}
#endif
	return ret;
}

/**
 * Write the Device Credentials blob, contains our MFG Blk
 * @param dev_cred_file - pointer of type const char to which credentails are
 * to be written.
 * @param flags - descriptor telling type of file
 * @param ocred - pointer of type sdo_dev_cred_t, holds the credentials for
 * writing to dev_cred_file.
 * @return true if write and parsed correctly, otherwise false
 */
bool write_mfg_device_credentials(const char *dev_cred_file,
				  sdo_sdk_blob_flags flags,
				  sdo_dev_cred_t *ocred)
{
	bool ret = true;

	if (!ocred || !dev_cred_file) {
		return false;
	}

#ifndef NO_PERSISTENT_STORAGE
	sdow_t sdowriter, *sdow = &sdowriter;

	if (!sdow_init(sdow)) {
		LOG(LOG_ERROR, "sdow_init() failed!\n");
		return false;
	}

	sdow_begin_object(sdow);
	sdo_write_tag(sdow, "M");
	sdow_begin_object(sdow);

	sdo_write_tag(sdow, "d");
	sdo_write_string(sdow, ocred->mfg_blk->d->bytes);

	sdow_end_object(sdow);
	sdow_end_object(sdow);

	/* Fill sdow buffer */
	if (sdo_blob_write((char *)dev_cred_file, flags, &sdow->b.block[0],
			   sdow->b.block_size) == -1) {
		LOG(LOG_ERROR, "Issue while writing Devcred blob\n");
		ret = false;
		goto end;
	}

end:
	if (sdow->b.block) {
		sdo_free(sdow->b.block);
		sdow->b.block = NULL;
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
				    sdo_sdk_blob_flags flags,
				    sdo_dev_cred_t *our_dev_cred)
{
	sdor_t sdoreader = {0};
	sdor_t *sdor = NULL;
	sdo_block_t *sdob = NULL;

	bool ret = false;
	int32_t dev_cred_len = 0;

	sdor = &sdoreader;
	sdob = &(sdor->b);

	if (!our_dev_cred) {
		goto end;
	}

	if (!sdor_init(sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdor_init() failed!\n");
		ret = false;
		goto end;
	}

	dev_cred_len = sdo_blob_size((char *)dev_cred_file, flags);
	if (dev_cred_len > 0) {
		// Resize sdob block size
		sdo_resize_block(sdob, dev_cred_len);
	} else {
		ret = false;
		LOG(LOG_ERROR, "Failed: sdo_blob_size is %lu!\n",
		    (unsigned long)dev_cred_len);
		goto end;
	}

	if (sdo_blob_read((char *)dev_cred_file, flags, sdob->block,
			  dev_cred_len) == -1) {
		LOG(LOG_ERROR, "Could not read the device credentials blob\n");
		ret = false;
		goto end;
	}

	LOG(LOG_DEBUG, "Reading Ownership Credential from blob: Normal.blob\n");

	sdor->b.block_size = dev_cred_len;
	sdor->have_block = true;

	// LOG(LOG_ERROR, "Normal Blob reading\n");
	if (!sdor_begin_object(sdor)) {
		LOG(LOG_ERROR, "Begin object not found\n");
		goto end;
	}

	if (!sdo_read_expected_tag(sdor, "ST")) {
		LOG(LOG_ERROR, "tag=ST not found\n");
		goto end;
	}

	our_dev_cred->ST = sdo_read_uint(sdor);

	if (our_dev_cred->ST < SDO_DEVICE_STATE_READY1) {
		ret = true;
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

	if (!sdo_read_expected_tag(sdor, "O")) {
		LOG(LOG_ERROR, "tag=0 not found\n");
		goto end;
	}

	if (!sdor_begin_object(sdor)) {
		LOG(LOG_ERROR, "Begin object not found\n");
		goto end;
	}

	if (!sdo_read_expected_tag(sdor, "pv")) {
		LOG(LOG_ERROR, "tag=pv not found\n");
		goto end;
	}

	our_dev_cred->owner_blk->pv = sdo_read_uint(sdor);
	if (!our_dev_cred->owner_blk->pv) {
		LOG(LOG_ERROR, "Own's pv read Error\n");
		goto end;
	}

	if (!sdo_read_expected_tag(sdor, "pe")) {
		LOG(LOG_ERROR, "tag=pe not found\n");
		goto end;
	}

	our_dev_cred->owner_blk->pe = sdo_read_uint(sdor);
	if (!our_dev_cred->owner_blk->pe) {
		LOG(LOG_ERROR, "Own's pe read Error\n");
		goto end;
	}

	if (!sdo_read_expected_tag(sdor, "g")) {
		LOG(LOG_ERROR, "tag=g not found\n");
		goto end;
	}

	our_dev_cred->owner_blk->guid = sdo_byte_array_alloc(0);
	if (!our_dev_cred->owner_blk->guid) {
		LOG(LOG_ERROR, "Alloc failed\n");
		goto end;
	}

	if (!sdo_byte_array_read_chars(sdor, our_dev_cred->owner_blk->guid)) {
		LOG(LOG_ERROR, "parsing guid: %s\n",
		    our_dev_cred->owner_blk->guid->bytes);
		goto end;
	}

	if (!sdo_read_expected_tag(sdor, "r")) {
		LOG(LOG_ERROR, "tag=r not found\n");
		goto end;
	}

	our_dev_cred->owner_blk->rvlst = sdo_rendezvous_list_alloc();
	if (!our_dev_cred->owner_blk->rvlst ||
	    !sdo_rendezvous_list_read(sdor, our_dev_cred->owner_blk->rvlst)) {
		LOG(LOG_ERROR, "Own's rvlist read Error\n");
		goto end;
	}

	if (!sdo_read_expected_tag(sdor, "pkh")) {
		LOG(LOG_ERROR, "tag=pkh not found\n");
		goto end;
	}

	our_dev_cred->owner_blk->pkh =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
	if (!our_dev_cred->owner_blk->pkh ||
	    !sdo_hash_read(sdor, our_dev_cred->owner_blk->pkh)) {
		LOG(LOG_ERROR, "Own's pkh read Error\n");
		goto end;
	}

	if (!sdor_end_object(sdor)) {
		LOG(LOG_ERROR, "End object not found\n");
		goto end;
	}

	if (!sdor_end_object(sdor)) {
		LOG(LOG_ERROR, "End object not found\n");
		goto end;
	}

	ret = true;

end:
	if (sdob->block) {
		sdo_free(sdob->block);
		sdob->block = NULL;
	}
	return ret;
}

/**
 * Read the Device Credentials blob, contains our MFG Blk
 * @param dev_cred_file - the blob the credentials are saved in
 * @param flags - descriptor telling type of file
 * @param our_dev_cred - pointer to the device credentials block,
 * @return true if read and parsed correctly, otherwise false.
 */
bool read_mfg_device_credentials(const char *dev_cred_file,
				 sdo_sdk_blob_flags flags,
				 sdo_dev_cred_t *our_dev_cred)
{
	bool ret = false;
	size_t dev_cred_len = 0;
	sdor_t sdoreader = {0};
	sdor_t *sdor = NULL;
	sdo_block_t *sdob = NULL;

	sdor = &sdoreader;
	sdob = &(sdor->b);

	if (!our_dev_cred) {
		goto end;
	}

	if (!sdor_init(sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdor_init() failed!\n");
		goto end;
	}

	dev_cred_len = sdo_blob_size((char *)dev_cred_file, flags);
	if (dev_cred_len > 0) {
		// Resize sdob block size
		sdo_resize_block(sdob, dev_cred_len);
	} else {
		LOG(LOG_ERROR, "Could not get %s!\n", (char *)dev_cred_file);
		goto end;
	}

	if (sdo_blob_read((char *)dev_cred_file, flags, sdob->block,
			  dev_cred_len) == -1) {
		LOG(LOG_ERROR, "Could not read the device credentials blob\n");
		goto end;
	}

	LOG(LOG_DEBUG, "Reading Mfg block\n");

	sdor->b.block_size = dev_cred_len;
	sdor->have_block = true;

	// LOG(LOG_ERROR, "Mfg Blk reading\n");
	if (!sdor_begin_object(sdor)) {
		LOG(LOG_ERROR, "Begin object not found\n");
		goto end;
	}

	if (!sdo_read_expected_tag(sdor, "M")) {
		LOG(LOG_ERROR, "tag=M not found\n");
		goto end;
	}

	if (!sdor_begin_object(sdor)) {
		LOG(LOG_ERROR, "Begin object not found\n");
		goto end;
	}

	if (!sdo_read_expected_tag(sdor, "d")) {
		LOG(LOG_ERROR, "tag=d not found\n");
		goto end;
	}

	our_dev_cred->mfg_blk = sdo_cred_mfg_alloc();
	if (!our_dev_cred->mfg_blk) {
		LOG(LOG_ERROR, "Malloc for mfgblk failed");
		goto end;
	}

	our_dev_cred->mfg_blk->d = sdo_string_alloc();

	if (!our_dev_cred->mfg_blk->d ||
	    !sdo_string_read(sdor, our_dev_cred->mfg_blk->d)) {
		LOG(LOG_ERROR, "Mfg's Dev_info read Error\n");
		goto end;
	}

	if (!sdor_end_object(sdor)) {
		LOG(LOG_ERROR, "End object not found\n");
		goto end;
	}

	if (!sdor_end_object(sdor)) {
		LOG(LOG_ERROR, "End object not found\n");
		goto end;
	}
	ret = true;

end:
	if (sdob->block) {
		sdo_free(sdob->block);
		sdob->block = NULL;
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
				    sdo_sdk_blob_flags flags,
				    sdo_dev_cred_t *our_dev_cred)
{
	bool ret = false;
	size_t dev_cred_len = 0;
	sdor_t sdoreader = {0};
	sdor_t *sdor = NULL;
	sdo_block_t *sdob = NULL;
	sdo_byte_array_t *secret = NULL;

	(void)our_dev_cred; /* Unused Warning */

	sdor = &sdoreader;
	sdob = &(sdor->b);

	if (!sdor_init(sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdor_init() failed!\n");
		goto end;
	}

	dev_cred_len = sdo_blob_size((char *)dev_cred_file, flags);
	if (dev_cred_len > 0) {
		// Resize sdob block size
		sdo_resize_block(sdob, dev_cred_len);
	} else {
		LOG(LOG_ERROR, "Could not get %s!\n", (char *)dev_cred_file);
		goto end;
	}
	if (sdo_blob_read((char *)dev_cred_file, flags, sdob->block,
			  dev_cred_len) == -1) {
		LOG(LOG_ERROR, "Could not read the device credentials blob\n");
		goto end;
	}

	sdor->b.block_size = dev_cred_len;
	sdor->have_block = true;

	if (!sdor_begin_object(sdor)) {
		LOG(LOG_ERROR, "Begin object not found\n");
		goto end;
	}

	if (!sdo_read_expected_tag(sdor, "Secret")) {
		LOG(LOG_ERROR, "tag=Secret not found\n");
		goto end;
	}

	if (!sdor_begin_sequence(sdor)) {
		LOG(LOG_ERROR, "Beginning sequence not found.\n");
		goto end;
	}

	secret = sdo_byte_array_alloc(INITIAL_SECRET_BYTES);
	if (!secret) {
		LOG(LOG_ERROR, "Dev_cred Secret malloc Failed.\n");
		goto end;
	}

	if (!sdo_byte_array_read_chars(sdor, secret)) {
		LOG(LOG_ERROR, "Secret Read failure.\n");
		goto end;
	}

	if (0 != set_ov_key(secret, INITIAL_SECRET_BYTES)) {
		LOG(LOG_ERROR, "Set HMAC secret failure.\n");
		goto end;
	}

	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		goto end;
	}

	if (!sdor_end_object(sdor)) {
		LOG(LOG_ERROR, "End object not found\n");
		goto end;
	}
	ret = true;

end:
	sdo_byte_array_free(secret);

	if (sdob->block) {
		if (memset_s(sdob->block, sdob->block_size, 0)) {
			LOG(LOG_ERROR, "Failed to clear device credentials\n");
			ret = false;
		}
		sdo_free(sdob->block);
	}
	sdor_flush(sdor);
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

	/* Write in the file and save the MFG device credentials */
	LOG(LOG_DEBUG, "Writing to %s blob\n", "Mfg.blob");
	if (!write_mfg_device_credentials((char *)SDO_CRED_MFG,
					  SDO_SDK_NORMAL_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not write to MFG Credentials blob\n");
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

	// ReadMFG block(MFG block will be used in message 47)
	if (!read_mfg_device_credentials((char *)SDO_CRED_MFG,
					 SDO_SDK_NORMAL_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not parse the Device Credentials blob\n");
		return -1;
	}

	return 0;
}
