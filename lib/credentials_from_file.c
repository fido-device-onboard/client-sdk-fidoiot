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
#include "sdoCryptoApi.h"
#define verboseDumpPackets 0

/**
 * Write the Device Credentials blob, contains our state
 * @param devCredFile - pointer of type const char to which credentails are
 * to be written.
 * @param flags ///TO BE ADDED
 *
 *
 * @param ocred - pointer of type SDODevCred_t, holds the credentials for
 * writing to devCredFile.
 * @return true if write and parsed correctly, otherwise false
 */

bool WriteNormalDeviceCredentials(const char *devCredFile,
				  sdoSdkBlobFlags flags, SDODevCred_t *ocred)
{
	bool ret = true;
#ifndef NO_PERSISTENT_STORAGE
	SDOW_t sdowriter, *sdow = &sdowriter;
	if (!sdoWInit(sdow)) {
		LOG(LOG_ERROR, "sdoWInit() failed!\n");
		return false;
	}

	sdoWNextBlock(sdow, SDO_DI_SET_CREDENTIALS);
	sdoWBeginObject(sdow);
	sdoWriteTag(sdow, "ST");
	sdoWriteUInt(sdow, ocred->ST);

	sdoWriteTag(sdow, "O");
	sdoWBeginObject(sdow);

	sdoWriteTag(sdow, "pv");
	sdoWriteUInt(sdow, ocred->ownerBlk->pv);

	sdoWriteTag(sdow, "pe");
	sdoWriteUInt(sdow, ocred->ownerBlk->pe);

	sdoWriteTag(sdow, "g");
	sdoByteArrayWriteChars(sdow, ocred->ownerBlk->guid);

	sdoWriteTag(sdow, "r");
	sdoRendezvousListWrite(sdow, ocred->ownerBlk->rvlst);

	sdoWriteTag(sdow, "pkh");
	sdoHashWrite(sdow, ocred->ownerBlk->pkh);

	sdoWEndObject(sdow);
	sdoWEndObject(sdow);

	/* Fill sdow buffer */

	if (sdoBlobWrite((char *)devCredFile, flags, &sdow->b.block[0],
			 sdow->b.blockSize) == -1) {
		LOG(LOG_ERROR, "Issue while writing Devcred blob\n");
		ret = false;
		goto end;
	}

end:
	if (sdow->b.block) {
		sdoFree(sdow->b.block);
		sdow->b.block = NULL;
	}
#endif
	return ret;
}

/**
 * Write the Device Credentials blob, contains our Secret
 * @param devCredFile - pointer of type const char to which credentails are
 * to be written.
 * @param flags - descriptor telling type of file
 * @param ocred - pointer of type SDODevCred_t, holds the credentials for
 * writing to devCredFile.
 * @return true if write and parsed correctly, otherwise false
 */

bool WriteSecureDeviceCredentials(const char *devCredFile,
				  sdoSdkBlobFlags flags, SDODevCred_t *ocred)
{
	bool ret = true;
#ifndef NO_PERSISTENT_STORAGE
	SDOW_t sdowriter, *sdow = &sdowriter;
	if (!sdoWInit(sdow)) {
		LOG(LOG_ERROR, "sdoWInit() failed!\n");
		return false;
	}

	sdoWBeginObject(sdow);
	sdoWriteTag(sdow, "Secret");
	sdoWBeginSequence(sdow);
	SDOByteArray_t **ovkey = getOVKey();
	if (!ovkey || !*ovkey) {
		ret = false;
		goto end;
	}
	sdoWriteByteArrayField(sdow, (*ovkey)->bytes, INITIAL_SECRET_BYTES);
	sdoWEndSequence(sdow);
	sdoWEndObject(sdow);

	/* Fill sdow buffer */

	if (sdoBlobWrite((char *)devCredFile, flags, &sdow->b.block[0],
			 sdow->b.blockSize) == -1) {
		LOG(LOG_ERROR, "Issue while writing Devcred blob\n");
		ret = false;
		goto end;
	}

end:
	if (sdow->b.block) {
		if (memset_s(sdow->b.block, sdow->b.blockSize, 0)) {
			LOG(LOG_ERROR, "Failed to clear device credentials\n");
			ret = false;
		}
		sdoFree(sdow->b.block);
	}
#endif
	return ret;
}

/**
 * Write the Device Credentials blob, contains our MFG Blk
 * @param devCredFile - pointer of type const char to which credentails are
 * to be written.
 * @param flags - descriptor telling type of file
 * @param ocred - pointer of type SDODevCred_t, holds the credentials for
 * writing to devCredFile.
 * @return true if write and parsed correctly, otherwise false
 */
bool WriteMfgDeviceCredentials(const char *devCredFile, sdoSdkBlobFlags flags,
			       SDODevCred_t *ocred)
{
	bool ret = true;
#ifndef NO_PERSISTENT_STORAGE
	SDOW_t sdowriter, *sdow = &sdowriter;
	if (!sdoWInit(sdow)) {
		LOG(LOG_ERROR, "sdoWInit() failed!\n");
		return false;
	}

	sdoWBeginObject(sdow);
	sdoWriteTag(sdow, "M");
	sdoWBeginObject(sdow);

	sdoWriteTag(sdow, "d");
	sdoWriteString(sdow, ocred->mfgBlk->d->bytes);

	sdoWEndObject(sdow);
	sdoWEndObject(sdow);

	/* Fill sdow buffer */
	if (sdoBlobWrite((char *)devCredFile, flags, &sdow->b.block[0],
			 sdow->b.blockSize) == -1) {
		LOG(LOG_ERROR, "Issue while writing Devcred blob\n");
		ret = false;
		goto end;
	}

end:
	if (sdow->b.block) {
		sdoFree(sdow->b.block);
		sdow->b.block = NULL;
	}
#endif
	return ret;
}

/**
 * Read the Device Credentials blob, contains our state & ownerBlk
 * @param devCredFile - the blob the credentials are saved in
 * @param flags - descriptor telling type of file
 * @param ourDevCred - pointer to the device credentials block,
 * @return true if read and parsed correctly, otherwise false.
 */
bool ReadNormalDeviceCredentials(const char *devCredFile, sdoSdkBlobFlags flags,
				 SDODevCred_t *ourDevCred)
{
	SDOR_t sdoreader = {0};
	SDOR_t *sdor = NULL;
	SDOBlock_t *sdob = NULL;

	bool ret = false;
	int32_t devCredLen = 0;

	sdor = &sdoreader;
	sdob = &(sdor->b);

	if (!sdoRInit(sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdoRInit() failed!\n");
		ret = false;
		goto end;
	}

	if ((devCredLen = sdoBlobSize((char *)devCredFile, flags)) > 0) {
		// Resize sdob block size
		sdoResizeBlock(sdob, devCredLen);
	} else {
		ret = false;
		LOG(LOG_ERROR, "Failed: sdoBlobSize is %lu!\n",
		    (unsigned long)devCredLen);
		goto end;
	}

	if (sdoBlobRead((char *)devCredFile, flags, sdob->block, devCredLen) ==
	    -1) {
		LOG(LOG_ERROR, "Could not read the device credentials blob\n");
		ret = false;
		goto end;
	}

	LOG(LOG_DEBUG, "Reading Ownership Credential from blob: Normal.blob\n");

	sdor->b.blockSize = devCredLen;
	sdor->haveBlock = true;

	// LOG(LOG_ERROR, "Normal Blob reading\n");
	if (!sdoRBeginObject(sdor)) {
		LOG(LOG_ERROR, "Begin object not found \n");
		goto end;
	}

	if (!sdoReadExpectedTag(sdor, "ST")) {
		LOG(LOG_ERROR, "tag=ST not found \n");
		goto end;
	}

	ourDevCred->ST = sdoReadUInt(sdor);

	if (ourDevCred->ST < SDO_DEVICE_STATE_READY1) {
		ret = true;
		goto end;
	}

	if (ourDevCred->ownerBlk != NULL) {
		sdoCredOwnerFree(ourDevCred->ownerBlk);
		ourDevCred->ownerBlk = NULL;
	}

	/* Memory allocating data.inside devCred. */
	ourDevCred->ownerBlk = SDOCredOwnerAlloc();
	if (!ourDevCred->ownerBlk) {
		LOG(LOG_ERROR, "devCred's ownerBlk allocation failed\n");
		goto end;
	}

	if (!sdoReadExpectedTag(sdor, "O")) {
		LOG(LOG_ERROR, "tag=0 not found \n");
		goto end;
	}

	if (!sdoRBeginObject(sdor)) {
		LOG(LOG_ERROR, "Begin object not found \n");
		goto end;
	}

	if (!sdoReadExpectedTag(sdor, "pv")) {
		LOG(LOG_ERROR, "tag=pv not found \n");
		goto end;
	}

	ourDevCred->ownerBlk->pv = sdoReadUInt(sdor);
	if (!ourDevCred->ownerBlk->pv) {
		LOG(LOG_ERROR, "Own's pv read Error\n");
		goto end;
	}

	if (!sdoReadExpectedTag(sdor, "pe")) {
		LOG(LOG_ERROR, "tag=pe not found \n");
		goto end;
	}

	ourDevCred->ownerBlk->pe = sdoReadUInt(sdor);
	if (!ourDevCred->ownerBlk->pe) {
		LOG(LOG_ERROR, "Own's pe read Error\n");
		goto end;
	}

	if (!sdoReadExpectedTag(sdor, "g")) {
		LOG(LOG_ERROR, "tag=g not found \n");
		goto end;
	}

	ourDevCred->ownerBlk->guid = sdoByteArrayAlloc(0);
	if (!ourDevCred->ownerBlk->guid) {
		LOG(LOG_ERROR, "Alloc failed \n");
		goto end;
	}

	if (!sdoByteArrayReadChars(sdor, ourDevCred->ownerBlk->guid)) {
		LOG(LOG_ERROR, "parsing guid: %s\n",
		    ourDevCred->ownerBlk->guid->bytes);
		goto end;
	}

	if (!sdoReadExpectedTag(sdor, "r")) {
		LOG(LOG_ERROR, "tag=r not found \n");
		goto end;
	}

	ourDevCred->ownerBlk->rvlst = sdoRendezvousListAlloc();
	if (!ourDevCred->ownerBlk->rvlst ||
	    !sdoRendezvousListRead(sdor, ourDevCred->ownerBlk->rvlst)) {
		LOG(LOG_ERROR, "Own's rvlist read Error\n");
		goto end;
	}

	if (!sdoReadExpectedTag(sdor, "pkh")) {
		LOG(LOG_ERROR, "tag=pkh not found \n");
		goto end;
	}

	ourDevCred->ownerBlk->pkh =
	    sdoHashAlloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
	if (!ourDevCred->ownerBlk->pkh ||
	    !sdoHashRead(sdor, ourDevCred->ownerBlk->pkh)) {
		LOG(LOG_ERROR, "Own's pkh read Error\n");
		goto end;
	}

	if (!sdoREndObject(sdor)) {
		LOG(LOG_ERROR, "End object not found \n");
		goto end;
	}

	if (!sdoREndObject(sdor)) {
		LOG(LOG_ERROR, "End object not found \n");
		goto end;
	}

	ret = true;

end:
	if (sdob->block) {
		sdoFree(sdob->block);
		sdob->block = NULL;
	}
	return ret;
}

/**
 * Read the Device Credentials blob, contains our MFG Blk
 * @param devCredFile - the blob the credentials are saved in
 * @param flags - descriptor telling type of file
 * @param ourDevCred - pointer to the device credentials block,
 * @return true if read and parsed correctly, otherwise false.
 */
bool ReadMfgDeviceCredentials(const char *devCredFile, sdoSdkBlobFlags flags,
			      SDODevCred_t *ourDevCred)
{
	bool ret = true;
	size_t devCredLen = 0;
	SDOR_t sdoreader = {0};
	SDOR_t *sdor = NULL;
	SDOBlock_t *sdob = NULL;

	sdor = &sdoreader;
	sdob = &(sdor->b);

	if (!sdoRInit(sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdoRInit() failed!\n");
		ret = false;
		goto end;
	}

	if ((devCredLen = sdoBlobSize((char *)devCredFile, flags)) > 0) {
		// Resize sdob block size
		sdoResizeBlock(sdob, devCredLen);
	} else {
		LOG(LOG_ERROR, "Could not get %s!\n", (char *)devCredFile);
		ret = false;
		goto end;
	}

	if (sdoBlobRead((char *)devCredFile, flags, sdob->block, devCredLen) ==
	    -1) {
		LOG(LOG_ERROR, "Could not read the device credentials blob\n");
		ret = false;
		goto end;
	}

	LOG(LOG_DEBUG, "Reading Mfg block\n");

	sdor->b.blockSize = devCredLen;
	sdor->haveBlock = true;

	// LOG(LOG_ERROR, "Mfg Blk reading\n");
	if (!sdoRBeginObject(sdor)) {
		LOG(LOG_ERROR, "Begin object not found \n");
		goto end;
	}

	if (!sdoReadExpectedTag(sdor, "M")) {
		LOG(LOG_ERROR, "tag=M not found \n");
		goto end;
	}

	if (!sdoRBeginObject(sdor)) {
		LOG(LOG_ERROR, "Begin object not found \n");
		goto end;
	}

	if (!sdoReadExpectedTag(sdor, "d")) {
		LOG(LOG_ERROR, "tag=d not found \n");
		goto end;
	}

	ourDevCred->mfgBlk = sdoCredMfgAlloc();
	if (!ourDevCred->mfgBlk) {
		LOG(LOG_ERROR, "Malloc for mfgblk failed");
		goto end;
	}

	ourDevCred->mfgBlk->d = sdoStringAlloc();

	if (!ourDevCred->mfgBlk->d ||
	    !sdoStringRead(sdor, ourDevCred->mfgBlk->d)) {
		LOG(LOG_ERROR, "Mfg's DevInfo read Error\n");
		goto end;
	}

	if (!sdoREndObject(sdor)) {
		LOG(LOG_ERROR, "End object not found \n");
		goto end;
	}

	if (!sdoREndObject(sdor)) {
		LOG(LOG_ERROR, "End object not found \n");
		goto end;
	}
end:
	if (sdob->block) {
		sdoFree(sdob->block);
		sdob->block = NULL;
	}
	return ret;
}

/**
 * Read the Secure Device Credentials blob, contains our Secret
 * @param devCredFile - the blob the credentials are saved in
 * @param flags - descriptor telling type of file
 * @param ourDevCred - pointer to the device credentials block,
 * @return true if read and parsed correctly, otherwise false.
 */
bool ReadSecureDeviceCredentials(const char *devCredFile, sdoSdkBlobFlags flags,
				 SDODevCred_t *ourDevCred)
{
	bool ret = true;
	size_t devCredLen = 0;
	SDOR_t sdoreader = {0};
	SDOR_t *sdor = NULL;
	SDOBlock_t *sdob = NULL;
	SDOByteArray_t *secret = NULL;

	sdor = &sdoreader;
	sdob = &(sdor->b);

	if (!sdoRInit(sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdoRInit() failed!\n");
		ret = false;
		goto end;
	}

	if ((devCredLen = sdoBlobSize((char *)devCredFile, flags)) > 0) {
		// Resize sdob block size
		sdoResizeBlock(sdob, devCredLen);
	} else {
		LOG(LOG_ERROR, "Could not get %s!\n", (char *)devCredFile);
		ret = false;
		goto end;
	}
	if (sdoBlobRead((char *)devCredFile, flags, sdob->block, devCredLen) ==
	    -1) {
		LOG(LOG_ERROR, "Could not read the device credentials blob\n");
		ret = false;
		goto end;
	}

	sdor->b.blockSize = devCredLen;
	sdor->haveBlock = true;

	if (!sdoRBeginObject(sdor)) {
		LOG(LOG_ERROR, "Begin object not found \n");
		goto end;
	}

	if (!sdoReadExpectedTag(sdor, "Secret")) {
		LOG(LOG_ERROR, "tag=Secret not found \n");
		goto end;
	}

	if (!sdoRBeginSequence(sdor)) {
		LOG(LOG_ERROR, "Beginning sequence not found.\n");
		goto end;
	}

	secret = sdoByteArrayAlloc(INITIAL_SECRET_BYTES);
	if (!secret) {
		LOG(LOG_ERROR, "DevCred Secret malloc Failed.\n");
		goto end;
	}

	if (!sdoByteArrayReadChars(sdor, secret)) {
		LOG(LOG_ERROR, "Secret Read failure.\n");
		goto end;
	}

	if (0 != setOVKey(secret, INITIAL_SECRET_BYTES)) {
		LOG(LOG_ERROR, "Set HMAC secret failure.\n");
		goto end;
	}

	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		goto end;
	}

	if (!sdoREndObject(sdor)) {
		LOG(LOG_ERROR, "End object not found \n");
		goto end;
	}

end:
	sdoByteArrayFree(secret);

	if (sdob->block) {
		if (memset_s(sdob->block, sdob->blockSize, 0)) {
			LOG(LOG_ERROR, "Failed to clear device credentials\n");
			ret = false;
		}
		sdoFree(sdob->block);
	}
	sdoRFlush(sdor);
	return ret;
}

#if 0
/**
 * Internal API
 */
static int sdoRFileRecv(SDOR_t *sdor, int nbytes)
{
	SDOBlock_t *sdob = &sdor->b;
	FILE *f = sdor->receiveData;
	int nread, limit;

	limit = sdob->cursor + nbytes;
	sdoResizeBlock(sdob, limit + 1);
	nread = fread(&sdob->block[sdob->cursor], 1, nbytes, f);

	if (verboseDumpPackets)
		LOG(LOG_DEBUG,
		    "SDOR ReadFile, cursor %u blockSize:%u blockMax:%u\n",
		    sdob->cursor, sdob->blockSize, sdob->blockMax);
	limit = sdob->cursor + nread;
	sdob->block[limit] = 0;
	if (verboseDumpPackets)
		LOG(LOG_DEBUG, "%s\n", sdob->block);

	return nread;
}
#endif
/**
 * Write and save the device credentials passed as an parameter ocred of type
 * SDODevCred_t.
 * @param ocred - Pointer of type SDODevCred_t, credentials to be copied
 * @return 0 if success, else -1 on failure.
 */
int store_credential(SDODevCred_t *ocred)
{
	/* Write in the file and save the Normal device credentials */
	LOG(LOG_DEBUG, "Writing to %s blob\n", "Normal.blob");
	if (!WriteNormalDeviceCredentials((char *)SDO_CRED_NORMAL,
					  SDO_SDK_NORMAL_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not write to Normal Credentials blob\n");
		return -1;
	}

	/* Write in the file and save the MFG device credentials */
	LOG(LOG_DEBUG, "Writing to %s blob\n", "Mfg.blob");
	if (!WriteMfgDeviceCredentials((char *)SDO_CRED_MFG,
				       SDO_SDK_NORMAL_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not write to MFG Credentials blob\n");
		return -1;
	}

#if !defined(DEVICE_TPM20_ENABLED)
	/* Write in the file and save the Secure device credentials */
	LOG(LOG_DEBUG, "Writing to %s blob\n", "Secure.blob");
	if (!WriteSecureDeviceCredentials((char *)SDO_CRED_SECURE,
					  SDO_SDK_SECURE_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not write to Secure Credentials blob\n");
		return -1;
	}
#endif

	return 0;
}

/**
 * load_credentials function loads the State & OwnerBlk credentials from storage
 *
 * @return
 *        return 0 on success. -1 on failure.
 */
int load_credential(void)
{
	SDODevCred_t *ocred = app_alloc_credentials();

	if (!ocred)
		return -1;

	sdoDevCredInit(ocred);

	/* Read in the blob and save the device credentials */
	if (!ReadNormalDeviceCredentials((char *)SDO_CRED_NORMAL,
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
	SDODevCred_t *ocred = app_get_credentials();

	if (!ocred)
		return -1;

#if !defined(DEVICE_TPM20_ENABLED)
	// ReadHMAC Credentials
	if (!ReadSecureDeviceCredentials((char *)SDO_CRED_SECURE,
					 SDO_SDK_SECURE_DATA, ocred)) {
		LOG(LOG_ERROR, "Could not parse the Device Credentials blob\n");
		return -1;
	}
#endif

	// ReadMFG block(MFG block will be used in message 47)
	if (!ReadMfgDeviceCredentials((char *)SDO_CRED_MFG, SDO_SDK_NORMAL_DATA,
				      ocred)) {
		LOG(LOG_ERROR, "Could not parse the Device Credentials blob\n");
		return -1;
	}

	return 0;
}
