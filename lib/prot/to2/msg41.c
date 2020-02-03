/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg41 of TO2 state machine.
 */

#include "sdoprot.h"
#include "safe_lib.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg41 - TO2.ProveOPHdr
 * The owner responds to the device with the Ownership Header. The body("bo")
 * is signed with owner Private key to start establishing that it is the
 * rightful owner of the Ownership Voucher and thus the device
 *
 * --- Message Format Begins ---
 * {
 *     bo: {
 *         "sz": UInt8,         # Number of Ownership Voucher entries
 *         "oh": {              # Ownership Voucher Header
 *             "pv": UInt16,    # Protocol Version
 *             "pe": UInt8,     # Public Key Encoding (RSA, ECDSA)
 *             "r": Rendezvous, # Whom to connect to next in customer
 *                              # premises (Rendezvous Server)
 *             "g": GUID,       # Securely generated random number
 *             "d": String,     # Device info
 *             "pk": PublicKey, # Manufacturer Public Key (First owner)
 *             "hdc": Hash      # Absent if EPID
 *         },
 *         "hmac":Hash,         # HMAC over "oh" tag above created during DI
 *         "n5": Nonce,         # n5 from TO2.HelloDevice
 *         "n6": Nonce,         # used below in TO2.ProveDevice.
 *         "eB": SigInfo,       # Device attestation signature info
 *         "xA": KeyExchange    # Key exchange first step
 *     },
 *     "pk": PublicKey,         # owner public key, may not be PKNull
 *     "sg": Signature          # Signature over "bo"
 * }
 * --- Message Format Ends ---
 */
int32_t msg41(SDOProt_t *ps)
{
	char prot[] = "SDOProtTO2";
	char buf[DEBUGBUFSZ] = {0};
	int ret = -1;
	uint16_t OVEntries = 0;
	int result_memcmp = 0;
	SDOSig_t sig = {0};
	SDOByteArray_t *xA = NULL;

	LOG(LOG_DEBUG, "SDO_STATE_TO2_RCV_PROVE_OVHDR: Starting\n");

	/*
	 * Check that we don't exceed Round Trip Times requirements. The reason
	 * for checking here is that sdoProtRcvMsg() fails the first time. So,
	 * the parent loop send the contents of previous message and receives
	 * for this message, thus, housing the Round Trip Times.
	 */
	if (!sdoCheckTO2RoundTrips(ps)) {
		LOG(LOG_ERROR, "Max round trips reached\n");
		goto err;
	}

	if (!sdoProtRcvMsg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	/* Save the start of ownership header. The signature is brace to brace
	 */
	if (!sdoBeginReadSignature(&ps->sdor, &sig)) {
		LOG(LOG_ERROR, "Could not read begin of signature\n");
		goto err;
	}

	/* Start reading the JSON object */
	if (!sdoRBeginObject(&ps->sdor)) {
		goto err;
	}

	/*
	 * Read the number of Ownership Vouchers present. The device does not
	 * know without "sz" tag, how many hops it has taken from Manufacturer
	 * to the real owner (end-user)
	 */
	if (!sdoReadExpectedTag(&ps->sdor, "sz")) {
		goto err;
	}
	OVEntries = sdoReadUInt(&ps->sdor);

	/* Read the ownership header */
	ps->ovoucher = sdoOvHdrRead(&ps->sdor, &ps->newOVHdrHMAC, true);
	if (!ps->ovoucher) {
		LOG(LOG_ERROR, "Invalid Ownership Header\n");
		goto err;
	}
	ps->ovoucher->numOVEntries = OVEntries;

	LOG(LOG_DEBUG, "Total number of Ownership Vouchers: %d\n", OVEntries);

	/*
	 * Compare the HMAC sent by owner with HMAC calculated by us. The key is
	 * the one used by the device in DI. The owner gets the HMAC from
	 * manufacturer ps->ovoucher->ovoucherHdrHash->hash->bytes: owner sent
	 * HMAC ps->newOVHdrHMAC->hash->byteSz            : Fresh HMAC
	 * calculated
	 */
	ret = memcmp_s(ps->ovoucher->ovoucherHdrHash->hash->bytes,
		       ps->ovoucher->ovoucherHdrHash->hash->byteSz,
		       ps->newOVHdrHMAC->hash->bytes,
		       ps->newOVHdrHMAC->hash->byteSz, &result_memcmp);
	if (ret || result_memcmp != 0) {
		LOG(LOG_ERROR, "Wrong HMAC received over Ownership header\n");
		goto err;
	}
	ret = -1; /* Reset to error */

	LOG(LOG_DEBUG, "Valid Ownership Header received\n");

	/* Read "n5". This must be same from msg40 (TO2.HelloDevice) */
	if (!sdoReadExpectedTag(&ps->sdor, "n5")) {
		goto err;
	}
	ps->n5r = sdoByteArrayAlloc(SDO_NONCE_BYTES);
	if (!ps->n5r || !sdoByteArrayReadChars(&ps->sdor, ps->n5r)) {
		goto err;
	}
	LOG(LOG_DEBUG, "Received n5r: %s\n",
	    sdoNonceToString(ps->n5r->bytes, buf, sizeof buf) ? buf : "");

	/* Read "n6" value. It will be used in msg44 (TO2.ProveDevice) */
	if (!sdoReadExpectedTag(&ps->sdor, "n6")) {
		goto err;
	}
	ps->n6 = sdoByteArrayAlloc(SDO_NONCE_BYTES);
	if (!ps->n6 || !sdoByteArrayReadChars(&ps->sdor, ps->n6)) {
		goto err;
	}

	LOG(LOG_DEBUG, "Received n6: %s\n",
	    sdoNonceToString(ps->n6->bytes, buf, sizeof buf) ? buf : "");

	/* Read Device Attestation key Info */
	if (!sdoReadExpectedTag(&ps->sdor, "eB")) {
		goto err;
	}

	/* Handle both EPID and ECDSA cases */
	if (0 != sdoEBRead(&ps->sdor)) {
		LOG(LOG_ERROR, "EB read in message 41 failed\n");
		goto err;
	}

	/*
	 * Read the key exchange info. This is the first part of key exchange of
	 * info. xA is used based on KEX selected (asym, RSA, DH)
	 */
	if (!sdoReadExpectedTag(&ps->sdor, "xA")) {
		goto err;
	}

	xA = sdoByteArrayAlloc(8);
	if (!xA) {
		LOG(LOG_ERROR, "Out of memory for key exchange info (xA)\n");
		goto err;
	}

	if (!sdoRBeginSequence(&ps->sdor)) {
		LOG(LOG_ERROR, "ERROR :Not at beginning of sequence\n");
		goto err;
	}
	sdoByteArrayRead(&ps->sdor, xA);

	LOG(LOG_DEBUG, "Key Exchange xA is %zu bytes\n", xA->byteSz);

	if (!sdoREndSequence(&ps->sdor)) {
		goto err;
	}

	/* TO2.ProveOPHdr.bo ends here */
	if (!sdoREndObject(&ps->sdor)) {
		goto err;
	}

	/* Here we will save a copy of the owner pk (TO2.ProveOVHdr bo.pk) */
	if (!sdoEndReadSignatureFull(&ps->sdor, &sig, &ps->ownerPublicKey)) {
		goto err;
	}

	if (!ps->ownerPublicKey) {
		goto err;
	}
#if LOG_LEVEL == LOG_MAX_LEVEL /* LOG_DEBUG */
	{
		char *tempBuf;

		LOG(LOG_DEBUG, "Owner Public Key returned\n");
		LOG(LOG_DEBUG,
		    "Owner Public Key : key1 : %zu, "
		    "key2 : %zu\n",
		    ps->ownerPublicKey->key1->byteSz,
		    ps->ownerPublicKey->key2 == NULL
			? 0
			: ps->ownerPublicKey->key2->byteSz);

		tempBuf = sdoAlloc(2048);
		if (!tempBuf) {
			goto err;
		}
		sdoPublicKeyToString(ps->ownerPublicKey, tempBuf, 2048);
		LOG(LOG_DEBUG, "Owner Public Key : %s\n", tempBuf);
		sdoFree(tempBuf);
	}
#endif

	/* The nonces "n5" (msg40) and "n6" here must match */
	if (!sdoNonceEqual(ps->n5r, ps->n5)) {
		LOG(LOG_ERROR, "Invalid Nonce send by owner\n");
		goto err;
	}

	/* The signature verification over TO2.ProveOPHdr.bo must verify */
	if (!sdoSignatureVerification(ps->SDORedirect.plainText,
				      ps->SDORedirect.Obsig,
				      ps->ownerPublicKey)) {
		LOG(LOG_ERROR, "SDORedirect verification Failed.\n");
		goto err;
	}
	LOG(LOG_DEBUG, "SDORedirect verification Successful \n");

	sdoRFlush(&ps->sdor);

	/* Save TO2.ProveOPHdr.pk for Asymmetric Key Exchange algorithm */

	if (sdoSetKexParamA(xA, ps->ownerPublicKey)) {
		goto err;
	}

	/*
	 * If the TO2.ProveOPHdr.bo.sz > 0, get next Ownership Voucher (msg42),
	 * else jump to msg44
	 */
	if (ps->ovoucher->numOVEntries) {
		ps->ovEntryNum = 0;
		ps->state = SDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY;
	} else {
		LOG(LOG_INFO, "No Ownership Vouchers, jumping to msg44\n");
		ps->state = SDO_STATE_TO2_SND_PROVE_DEVICE;
	}

	LOG(LOG_DEBUG,
	    "SDO_STATE_TO2_RCV_PROVE_OVHDR: Complete, %d "
	    "OVEntries to follow\n",
	    ps->ovoucher->numOVEntries);
	ret = 0; /* Mark as success */

err:
	/* sdoPublicKeyFree(ps->ownerPublicKey); */
	if (xA) {
		sdoByteArrayFree(xA);
	}
	if (sig.sg) {
		sdoByteArrayFree(sig.sg);
		sig.sg = NULL;
	}
	return ret;
}
