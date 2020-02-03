/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of Creating device credentials database in SDO spec
 * defined format.
 */

#include "sdoCryptoApi.h"
#include "util.h"
#include "sdoprot.h"
#include "sdocred.h"
#include <stdlib.h>
#include "safe_lib.h"

#define OCBUF_SIZE 256
#define PUBLIC_KEY_OFFSET 12

/*------------------------------------------------------------------------------
 * PM.CredOwnwer routines
 */

/**
 * Allocate a CredOwner object and allocate its members
 * @return and allocated SDOCredOwner_t object
 */
SDOCredOwner_t *SDOCredOwnerAlloc(void)
{
	return sdoAlloc(sizeof(SDOCredOwner_t));
}

/**
 * Free an allocated CredOwner object
 * @param ocred - the object to sdoFree
 * @return none
 */
void sdoCredOwnerFree(SDOCredOwner_t *ocred)
{
	if (!ocred)
		return;
	if (ocred->rvlst) {
		sdoRendezvousListFree(ocred->rvlst);
		ocred->rvlst = NULL;
	}
	if (ocred->pkh)
		sdoHashFree(ocred->pkh);
	if (ocred->guid)
		sdoByteArrayFree(ocred->guid);
	if (ocred->pk)
		sdoPublicKeyFree(ocred->pk);

	sdoFree(ocred);
}

#if LOG_LEVEL == LOG_MAX_LEVEL
/**
 * Print the Ocred as decoded
 * @param ocred - the Owner Credential object
 * @return none
 */
void sdoCredOwnerPrint(SDOCredOwner_t *ocred)
{
	char pbuf[1024] = {0};
	char *p_pbuf = NULL;

	LOG(LOG_DEBUG, "========================================\n");
	LOG(LOG_DEBUG, "PM.CredOwner\n");
	LOG(LOG_DEBUG, " pv : %d\n", ocred->pv);
	p_pbuf = sdoPKEncToString(ocred->pe);
	LOG(LOG_DEBUG, " pe : %s\n", p_pbuf ? p_pbuf : "");
	p_pbuf = sdoGuidToString(ocred->guid, pbuf, sizeof pbuf);
	LOG(LOG_DEBUG, " g  : %s\n", p_pbuf ? p_pbuf : "");
	p_pbuf =
	    sdoRendezvousToString(ocred->rvlst->rvEntries, pbuf, sizeof pbuf);
	LOG(LOG_DEBUG, " r  : %s\n", p_pbuf ? p_pbuf : "");
	p_pbuf = sdoHashToString(ocred->pkh, pbuf, sizeof pbuf);
	LOG(LOG_DEBUG, " pkh: %s\n", p_pbuf ? p_pbuf : "");
}
#endif

/*------------------------------------------------------------------------------
 * PM.CredMfg Manufacturer's Block routines
 */

/**
 * Allocate a Owner Credential Manufacturer object
 * return an allocated SDOCredMfg_t object
 */
SDOCredMfg_t *sdoCredMfgAlloc(void)
{
	return sdoAlloc(sizeof(SDOCredMfg_t));
}

/**
 * Free the memory contained in a SDOCredMfg_t object
 * including any allocated attached objects
 * @param ocredMfg - the object to clear and sdoFree
 * @return none
 */
void sdoCredMfgFree(SDOCredMfg_t *ocredMfg)
{
	if (ocredMfg->d)
		sdoStringFree(ocredMfg->d);

	if (ocredMfg->cu)
		sdoStringFree(ocredMfg->cu);

	if (ocredMfg->ch)
		sdoHashFree(ocredMfg->ch);

	sdoFree(ocredMfg);
	ocredMfg = NULL;
}

#if LOG_LEVEL == LOG_MAX_LEVEL
/**
 * Print the values in the Manufacturer's Block to stdout
 * @param ocredMfg - The object to print
 * @return none
 */
void sdoCredMfgPrint(SDOCredMfg_t *ocredMfg)
{
	char ocbuf[OCBUF_SIZE] = {0};
	char *ocbufp = NULL;

	LOG(LOG_DEBUG, "========================================\n");
	LOG(LOG_DEBUG, "PM.CredMfg\n");
	ocbufp = sdoStringToString(ocredMfg->d, ocbuf, OCBUF_SIZE);
	if (ocbufp)
		LOG(LOG_DEBUG, "d  : %s\n", ocbufp);
	ocbufp = sdoStringToString(ocredMfg->cu, ocbuf, OCBUF_SIZE);
	if (ocbufp)
		LOG(LOG_DEBUG, "cu : %s\n", ocbufp);
	ocbufp = sdoHashToString(ocredMfg->ch, ocbuf, OCBUF_SIZE);
	if (ocbufp)
		LOG(LOG_DEBUG, "ch : %s\n", ocbufp);
}
#endif

/*------------------------------------------------------------------------------
 * PMDeviceCredentials routines
 */

/**
 * Allocate a SDODevCred_t object
 * @return pointer to an allocated empty object
 */
SDODevCred_t *sdoDevCredAlloc(void)
{
	return sdoAlloc(sizeof(SDODevCred_t));
}

/**
 * Clear a devcred object
 * @param devCred - object to be cleared
 * @return none
 */
void sdoDevCredInit(SDODevCred_t *devCred)
{
	if (devCred) {
		devCred->ST = 0;
		devCred->mfgBlk = NULL;
		devCred->ownerBlk = NULL;
	}
}

/**
 * Free the memory contained in a SDODevCred_t object
 * including any allocated attached objects
 * @param devCred - the object to clear and sdoFree
 * @return none
 */
void sdoDevCredFree(SDODevCred_t *devCred)
{
	if (!devCred)
		return;

	if (devCred->ownerBlk) {
		sdoCredOwnerFree(devCred->ownerBlk);
		devCred->ownerBlk = NULL;
	}

	if (devCred->mfgBlk) {
		sdoCredMfgFree(devCred->mfgBlk);
		devCred->mfgBlk = NULL;
	}
}

/**
 * Make a hash of the passed public key
 * @param pubKey - pointer to the public key object
 * @return a hash of the JSON representation of the key
 */
SDOHash_t *sdoPubKeyHash(SDOPublicKey_t *pubKey)
{
	// Calculate the hash of the mfgPubKey
	SDOHash_t *hash = NULL;
	hash =
	    sdoHashAlloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
	if (!hash)
		return NULL;

	SDOW_t sdowriter, *sdow = &sdowriter;

	// Prepare the data structure
	if (!sdoWInit(sdow)) {
		sdoHashFree(hash);
		LOG(LOG_ERROR, "sdoWInit() failed!\n");
		return NULL;
	}
	sdoWNextBlock(sdow, SDO_TYPE_HMAC);
	sdoPublicKeyWrite(sdow, pubKey);

	if (hash && (sdow->b.blockSize < PUBLIC_KEY_OFFSET)) {
		sdoHashFree(hash);
		return NULL;
	}

	// buffer sdow now contains the key to sign offset 12

	if (hash &&
	    (0 != sdoCryptoHash(&sdow->b.block[PUBLIC_KEY_OFFSET],
				sdow->b.blockSize - PUBLIC_KEY_OFFSET,
				hash->hash->bytes, hash->hash->byteSz))) {

		sdoHashFree(hash);
		return NULL;
	}

	if (sdow->b.block) {
		sdoFree(sdow->b.block);
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
SDOOvEntry_t *sdoOvEntryAllocEmpty(void)
{
	// SDOOVEntryInit(e);
	return sdoAlloc(sizeof(SDOOvEntry_t));
}

/**
 * Release and sdoFree an Ownership Voucher entry
 * @param e - the entry to sdoFree
 * @return - the entry pointed to by the next value
 */
SDOOvEntry_t *sdoOvEntryFree(SDOOvEntry_t *e)
{
	if (e->pk)
		sdoPublicKeyFree(e->pk);
	if (e->hpHash)
		sdoHashFree(e->hpHash);
	if (e->hcHash)
		sdoHashFree(e->hcHash);
	SDOOvEntry_t *next = e->next;
	sdoFree(e);
	return next;
}
/*------------------------------------------------------------------------------
 * Ownership Voucher Routines
 */

/**
 * Allocate an Owner Proxy Base object
 * @return The newly allocated Owner Proxy
 */
SDOOwnershipVoucher_t *sdoOvAlloc(void)
{
	SDOOwnershipVoucher_t *ov = sdoAlloc(sizeof(SDOOwnershipVoucher_t));
	if (ov) {
		ov->keyEncoding = SDO_OWNER_ATTEST_PK_ENC;
	}
	return ov;
}

/**
 * Free and Ownership Voucher Oject
 * @param ov - Ownership Voucher to sdoFree
 * @return none
 */
void sdoOvFree(SDOOwnershipVoucher_t *ov)
{
	SDOOvEntry_t *e;

	if (ov->rvlst2 != NULL)
		sdoRendezvousListFree(ov->rvlst2);
	if (ov->devInfo != NULL)
		sdoStringFree(ov->devInfo);
	if (ov->mfgPubKey != NULL)
		sdoPublicKeyFree(ov->mfgPubKey);
	if (ov->ovoucherHdrHash != NULL)
		sdoHashFree(ov->ovoucherHdrHash);
	if (ov->g2)
		sdoByteArrayFree(ov->g2);
	if (ov->hdc)
		sdoHashFree(ov->hdc);

	// Free all listed Owner Proxy Entries
	while ((e = ov->OVEntries) != NULL) {
		ov->OVEntries = e->next;
		sdoOvEntryFree(e);
	}
	sdoFree(ov);
}

/**
 * Read the Ownership Voucher header passed in TO2 Prove OvHeader
 * @param sdor - the received context from the server
 * @param hmac a place top store the resulting HMAC
 * @param calHpHc - calculate hp, hc if true.
 * @return A newly allocated Ownership Voucher with the header completed
 */
SDOOwnershipVoucher_t *sdoOvHdrRead(SDOR_t *sdor, SDOHash_t **hmac,
				    bool calHpHc)
{

	if (!sdor || !hmac)
		return NULL;

	SDOOwnershipVoucher_t *ov = sdoOvAlloc();
	int gstart = -1;
	int gend = -1;
	int dstart = -1;
	int dend = -1;
	int sigBlockStart = -1;
	int ret = -1;
	uint8_t *hpText = NULL;
	uint8_t *hcText = NULL;

	if (ov == NULL) {
		LOG(LOG_ERROR, "Ownership Voucher allocation failed!");
		return NULL;
	}

	if (!sdoBeginReadHMAC(sdor, &sigBlockStart))
		goto exit;

	if (!sdoRBeginObject(sdor))
		goto exit;

	if (!sdoReadExpectedTag(sdor, "pv")) // Protocol Version
		goto exit;
	ov->protVersion = sdoReadUInt(sdor);

	if (!sdoReadExpectedTag(sdor, "pe")) // Public key encoding
		goto exit;
	ov->keyEncoding = sdoReadUInt(sdor);

	if (!sdoReadExpectedTag(sdor, "r")) // Rendezvous
		goto exit;
	ov->rvlst2 = sdoRendezvousListAlloc();

	if (!ov->rvlst2 || !sdoRendezvousListRead(sdor, ov->rvlst2)) {
		LOG(LOG_ERROR, "sdoOvHdrRead Rendezvous Error\n");
		goto exit;
	}

	/* There must be at-least 1 valid rv entry, if not its a error-case */
	if (ov->rvlst2->numEntries == 0) {
		LOG(LOG_ERROR,
		    "All rendezvous entries are invalid for the device!\n");
		goto exit;
	}

	if (!sdoReadExpectedTag(sdor, "g"))
		goto exit;
	gstart = sdor->b.cursor;
	ov->g2 = sdoByteArrayAlloc(0);
	if (!ov->g2 || !sdoByteArrayReadChars(sdor, ov->g2)) {
		LOG(LOG_ERROR, "sdoOvHdrRead GUID Error\n");
		goto exit;
	}
	gend = sdor->b.cursor;
	uint8_t *gText = sdoRGetBlockPtr(sdor, gstart);

	if (gText == NULL)
		goto exit;

	if (!sdoReadExpectedTag(sdor, "d")) // DeviceInfo String
		goto exit;

	dstart = sdor->b.cursor;
	ov->devInfo = sdoStringAlloc();

	if (!ov->devInfo || !sdoStringRead(sdor, ov->devInfo)) {
		LOG(LOG_ERROR, "sdoOvHdrRead DevInfo Error\n");
		goto exit;
	}

	dend = sdor->b.cursor;

	uint8_t *dText = sdoRGetBlockPtr(sdor, dstart);
	if (dText == NULL)
		goto exit;

	if (!sdoReadExpectedTag(sdor, "pk")) // Mfg Public key
		goto exit;

	if (ov->mfgPubKey != NULL)
		sdoPublicKeyFree(ov->mfgPubKey);
	ov->mfgPubKey =
	    sdoPublicKeyRead(sdor); // Creates a Public key and fills it in

#if defined(ECDSA256_DA) || defined(ECDSA384_DA)
	if (!sdoReadExpectedTag(sdor, "hdc")) { // device cert-chain hash
		LOG(LOG_ERROR, "hdc tag not found!\n");
		goto exit;
	}

	ov->hdc = sdoHashAllocEmpty();
	if (!ov->hdc) {
		LOG(LOG_ERROR, "Hash alloc failed!\n");
		goto exit;
	}

	if (!sdoHashRead(sdor, ov->hdc)) {
		LOG(LOG_ERROR, "device cert-chain hash reading failed!\n");
		goto exit;
	}
#endif
	if (!sdoEndReadHMAC(sdor, hmac, sigBlockStart)) {
		LOG(LOG_ERROR, "Error making OVHdr HMAC!\n");
		goto exit;
	}

	if (calHpHc) {
		int ohEnd = sdor->b.cursor;
		int ohSz = ohEnd - sigBlockStart;
		uint8_t *ohText = sdoRGetBlockPtr(sdor, sigBlockStart);
		int hmacStart = 0;
		int hmacEnd = 0;
		uint8_t *hmacText = NULL;

		if (ohText == NULL)
			goto exit;

		// Now get the HMAC of the OV Header from the DI
		// phase
		if (!sdoReadExpectedTag(sdor, "hmac"))
			goto exit;
		hmacStart = sdor->b.cursor;
		ov->ovoucherHdrHash = sdoHashAllocEmpty();
		if (!ov->ovoucherHdrHash ||
		    !sdoHashRead(sdor, ov->ovoucherHdrHash))
			goto exit;
		hmacEnd = sdor->b.cursor;
		hmacText = sdoRGetBlockPtr(sdor, hmacStart);

		if (hmacText == NULL)
			goto exit;

		// hp = SHA256[TO2.ProveOVHdr.bo.oh||TO2.ProveOvHdr.bo.hmac] )

		hpText = sdoAlloc(ohSz + (hmacEnd - hmacStart));
		if (hpText == NULL) {
			LOG(LOG_ERROR, "Memset Failed\n");
			goto exit;
		}

		if (memcpy_s(hpText, ohSz + (hmacEnd - hmacStart), ohText,
			     ohSz) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			goto exit;
		}

		if (memcpy_s(hpText + ohSz, hmacEnd - hmacStart, hmacText,
			     hmacEnd - hmacStart) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			goto exit;
		}

		ov->OVEntries = sdoOvEntryAllocEmpty();

		if (ov->OVEntries)
			ov->OVEntries->hpHash =
			    sdoHashAlloc(SDO_CRYPTO_HASH_TYPE_USED,
					 SDO_SHA_DIGEST_SIZE_USED);
		if (!ov->OVEntries || !ov->OVEntries->hpHash) {
			LOG(LOG_ERROR,
			    "Ownership Voucher allocation failed!\n");
			goto exit;
		}

		if (0 != sdoCryptoHash(hpText, ohSz + (hmacEnd - hmacStart),
				       ov->OVEntries->hpHash->hash->bytes,
				       ov->OVEntries->hpHash->hash->byteSz)) {
			goto exit;
		}

		// hc = SHA256[TO2.ProveOVHdr.bo.oh.g||TO2.ProveOVHdr.bo.oh.d]
		// g size + d size
		hcText = sdoAlloc((gend - gstart) + (dend - dstart));
		if (hcText == NULL) {
			LOG(LOG_ERROR, "Memset Failed\n");
			goto exit;
		}

		if (memcpy_s(hcText, ((gend - gstart) + (dend - dstart)), gText,
			     (gend - gstart)) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			goto exit;
		}

		if (memcpy_s(hcText + (gend - gstart), (dend - dstart), dText,
			     (dend - dstart)) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			goto exit;
		}

		ov->OVEntries->hcHash = sdoHashAlloc(SDO_CRYPTO_HASH_TYPE_USED,
						     SDO_SHA_DIGEST_SIZE_USED);
		if (!ov->OVEntries->hcHash)
			goto exit;

		if (0 != sdoCryptoHash(hcText,
				       (gend - gstart) + (dend - dstart),
				       ov->OVEntries->hcHash->hash->bytes,
				       ov->OVEntries->hcHash->hash->byteSz)) {
			LOG(LOG_ERROR, "Hash generation failed\n");
			goto exit;
		}

		// To verify the next entry in the ownership voucher
		ov->OVEntries->pk = sdoPublicKeyClone(ov->mfgPubKey);
	}
	ret = 0;
exit:
	if (hpText)
		sdoFree(hpText);
	if (hcText)
		sdoFree(hcText);
	if (ret) {
		LOG(LOG_ERROR, "OvHdr Error\n");
		sdoOvFree(ov);
		return NULL;
	}
	return ov;
}

/**
 * Take the the values in the "oh" and create a new HMAC
 * @param devCred - pointer to the DeviceCredential to source
 * @param newPubKey - the public key to use in the signature
 * @return pointer to a new SDOHash_t object containing the HMAC
 */
SDOHash_t *sdoNewOVHdrSign(SDODevCred_t *devCred, SDOPublicKey_t *newPubKey)
{
	SDOW_t sdowriter, *sdow = &sdowriter;

	// Prepare the data structure
	if (!sdoWInit(sdow)) {
		LOG(LOG_ERROR, "sdoWInit() failed!\n");
		return false;
	}
	sdoWNextBlock(sdow, SDO_TYPE_HMAC);

	// build the "oh" structure in the buffer
	// Get the pointers ready for the signature
	int sigBlockStart = sdow->b.cursor;

	sdow->needComma = false;
	sdoWBeginObject(sdow);

	sdoWriteTag(sdow, "pv");
	sdoWriteUInt(sdow, devCred->ownerBlk->pv);

	sdoWriteTag(sdow, "pe");
	sdoWriteUInt(sdow, devCred->ownerBlk->pe);

	sdoWriteTag(sdow, "r");
	sdoRendezvousListWrite(sdow, devCred->ownerBlk->rvlst);

	sdoWriteTag(sdow, "g");
	sdoByteArrayWriteChars(sdow, devCred->ownerBlk->guid);

	sdoWriteTag(sdow, "d");
	sdoWriteStringLen(sdow, devCred->mfgBlk->d->bytes,
			  devCred->mfgBlk->d->byteSz);

	sdoWriteTag(sdow, "pk");
	sdoPublicKeyWrite(sdow, newPubKey);

	sdoWEndObject(sdow);

	int sigBlockEnd = sdow->b.cursor;
	int sigBlockSz = sigBlockEnd - sigBlockStart;
	uint8_t *plainText = sdoWGetBlockPtr(sdow, sigBlockStart);

	if (plainText == NULL) {
		LOG(LOG_ERROR, "sdoWGetBlockPtr() returned NULL, "
			       "sdoNewOVHdrSign() failed !!");
		return NULL;
	}

	SDOHash_t *hmac =
	    sdoHashAlloc(SDO_CRYPTO_HMAC_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);

	if (hmac &&
	    (0 != sdoDeviceOVHMAC(plainText, sigBlockSz, hmac->hash->bytes,
				  hmac->hash->byteSz))) {
		sdoHashFree(hmac);
		return NULL;
	}

	if (sdow->b.block) {
		sdoFree(sdow->b.block);
		sdow->b.block = NULL;
	}
	return hmac;
}

/**
 * Allocate a new Owner Supplied Credentials object
 * @return an SDOOwnerSuppliedCredentials_t object with all setting cleared
 */
SDOOwnerSuppliedCredentials_t *sdoOwnerSuppliedCredentialsAlloc(void)
{
	return sdoAlloc(sizeof(SDOOwnerSuppliedCredentials_t));
}

/**
 * Free the Owner Supplied Credential object
 * @param osc - The owner supplied credential object
 * @return none.
 */
void sdoOwnerSuppliedCredentialsFree(SDOOwnerSuppliedCredentials_t *osc)
{
	if (osc != NULL) {
		sdoRendezvousListFree(osc->rvlst);
		osc->rvlst = NULL;
		sdoServiceInfoFree(osc->si);
		sdoFree(osc);
	}
}

/**
 * Free the IV object
 * @param iv - The iv store object
 * @return none.
 */
void sdoIVFree(SDOIV_t *iv)
{
	if (iv != NULL)
		sdoFree(iv);
}
