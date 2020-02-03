/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 33.
 */

#include "safe_lib.h"
#include "util.h"
#include "sdoprot.h"

/**
 * msg33() - TO1.SDORedirect
 * This is the last message of TO1. The device receives the owner info from RV.
 *
 * --- Message Format Begins ---
 * {
 *     "bo": {
 *         "i1": IPAddress, # Owner IP address
 *         "dns1": String,  # DNS if owner is registered with DNS service
 *         "port1": UInt16, # TCP/UDP port to connect to
 *         "to0dh": Hash    # See TO0, msg22: Hash(to0d object, brace to brace)
 *     },
 *     "pk": PKNull,
 *     "sg": Signature      # Signed with “Owner key” that Device will get in
 * TO2
 * }
 * --- Message Format Begins ---
 *
 */
int32_t msg33(SDOProt_t *ps)
{
	int ret = -1;
	SDOSig_t sig = {0};
	int sigBlockSz = -1;
	int sigBlockEnd = -1;
	SDOHash_t *obHash = NULL;
	char buf[DEBUGBUFSZ] = {0};
	uint8_t *plainText = NULL;
	SDOPublicKey_t *tempPk = NULL;
	char prot[] = "SDOProtTO1";

	LOG(LOG_DEBUG, "\nStarting SDO_STATE_TO1_RCV_SDO_REDIRECT\n");

	/* Try to read from internal buffer */
	if (!sdoProtRcvMsg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /*Mark for retry */
		goto err;
	}

	/*
	 * Mark the beginning of "bo". The signature is calculated over
	 * braces to braces, so, saving the offset of starting "bo"
	 */
	if (!sdoBeginReadSignature(&ps->sdor, &sig)) {
		LOG(LOG_ERROR, "Could not read begin of signature\n");
		goto err;
	}

	/* Start parsing the "bo" (body) data now */
	if (!sdoRBeginObject(&ps->sdor)) {
		goto err;
	}

	/* TODO: In 0.8 these are i1 fields, check what is the
	 * difference */

	/* Read "i1" tag/value: IP address of owner */
	if (!sdoReadExpectedTag(&ps->sdor, "i1")) {
		goto err;
	}
	if (sdoReadIPAddress(&ps->sdor, &ps->i1) != true) {
		LOG(LOG_ERROR, "Read IP Address Failed\n");
		goto err;
	}

	/* Read "dns1" tag/value: URL of owner */
	if (!sdoReadExpectedTag(&ps->sdor, "dns1")) {
		goto err;
	}
	ps->dns1 = sdoReadDNS(&ps->sdor);

	/* Read "port1" tag/value: Port of owner machine */
	if (!sdoReadExpectedTag(&ps->sdor, "port1")) {
		goto err;
	}
	ps->port1 = sdoReadUInt(&ps->sdor);

	/* Read "to0dh" tag/value: Owner hash sent to RV */
	if (!sdoReadExpectedTag(&ps->sdor, "to0dh")) {
		goto err;
	}

	/*
	 * TODO: Check if the hash is just parsed to be discared.
	 * Do we have an API, where we just increased the cursor
	 * and not read the data at all?
	 */
	obHash = sdoHashAllocEmpty();
	if (!obHash || !sdoHashRead(&ps->sdor, obHash)) {
		goto err;
	}

	/* Mark the end of "bo" tag */
	if (!sdoREndObject(&ps->sdor)) {
		goto err;
	}

	/* Save the "bo" start and size. The signature is over this */
	sigBlockEnd = ps->sdor.b.cursor;
	sigBlockSz = sigBlockEnd - sig.sigBlockStart;

	/* Copy the full "bo" to ps */
	plainText = sdoRGetBlockPtr(&ps->sdor, sig.sigBlockStart);
	if (plainText == NULL) {
		ps->state = SDO_STATE_DONE;
		goto err;
	}

	ps->SDORedirect.plainText = sdoByteArrayAlloc(sigBlockSz);
	if (!ps->SDORedirect.plainText) {
		goto err;
	}
	if (memcpy_s(ps->SDORedirect.plainText->bytes, sigBlockSz, plainText,
		     sigBlockSz) != 0) {
		LOG(LOG_ERROR, "Memcpy failed\n");
		goto err;
	}

	ps->SDORedirect.plainText->byteSz = sigBlockSz;

	/* Read the public key */
	if (!sdoReadExpectedTag(&ps->sdor, "pk")) {
		goto err;
	}

	/*
	 * FIXME: Reading public key and freeing it. Why are we returning
	 * a pointer to be freed
	 */
	tempPk = sdoPublicKeyRead(&ps->sdor);
	if (tempPk) {
		sdoPublicKeyFree(tempPk);
	}

	/* Read the "sg" tag/value */
	if (!sdoReadExpectedTag(&ps->sdor, "sg")) {
		goto err;
	}

	if (!sdoRBeginSequence(&ps->sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		goto err;
	}

	/* These bytes will be thrown away, some issue with zero length */
	ps->SDORedirect.Obsig = sdoByteArrayAlloc(16);
	if (!ps->SDORedirect.Obsig) {
		goto err;
	}

	/* Read the signature to the signature object */
	if (!sdoByteArrayRead(&ps->sdor, ps->SDORedirect.Obsig)) {
		LOG(LOG_ERROR, "Obsig read error\n");
		goto err;
	}

	if (!sdoREndSequence(&ps->sdor)) {
		goto err;
	}

	if (!sdoREndObject(&ps->sdor)) {
		goto err;
	}

	/* TODO: Add support for signing message defined in spec
	 * 0.8 */

	sdoRFlush(&ps->sdor);

	LOG(LOG_DEBUG, "Received redirect: %s\n",
	    sdoIPAddressToString(&ps->i1, buf, sizeof buf) ? buf : "");

	/* Mark as success and ready for TO2 */
	ps->state = SDO_STATE_DONE;
	ret = 0;
	LOG(LOG_DEBUG, "Complete SDO_STATE_TO1_RCV_SDO_REDIRECT\n");

err:
	if (ps->SDORedirect.Obsig && ret) {
		sdoByteArrayFree(ps->SDORedirect.Obsig);
		ps->SDORedirect.Obsig = NULL;
	}
	if (obHash) {
		sdoHashFree(obHash);
	}
	return ret;
}
