/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg47 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg47() - TO2.SetupDevice
 * This will overwrite the device credentials received during DI
 * --- Message Format Begins ---
 * {
 *     "osinn":UInt8,  # number of service info messages to come
 *     "noh":{         # update to ownership proxyvoucher header for resale.
 *         "bo":{
 *             "r3": Rendezvous, # replaces stored Rendevous
 *              "g3": GUID,      # replaces stored GUID
 *              "n7": Nonce      # proves freshness of signature
 *         },
 *         "pk": PublicKey,      # Owner2 key (replaces Manufacturer’s key).
 *         "sg": Signature       # Proof of Owner2 key.
 *     }
 * }
 * --- Message Format Ends ---
 */
int32_t msg47(SDOProt_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
	char buf[DEBUGBUFSZ] = {0};
	SDOSig_t sig = {0};
	uint32_t mtype = 0;
	SDOEncryptedPacket_t *pkt = NULL;

	LOG(LOG_DEBUG, "SDO_STATE_TO2_RCV_SETUP_DEVICE: Starting\n");

	if (!sdoCheckTO2RoundTrips(ps)) {
		goto err;
	}

	if (!sdoProtRcvMsg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	pkt = sdoEncryptedPacketRead(&ps->sdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "Trouble reading encrypted packet\n");
		goto err;
	}

	if (!sdoEncryptedPacketUnwind(&ps->sdor, pkt, ps->iv)) {
		goto err;
	}

	/* Get past any header */
	if (!sdoRNextBlock(&ps->sdor, &mtype)) {
		LOG(LOG_DEBUG, "SDOR doesn't seems to "
			       "have next block !!\n");
		goto err;
	}

	/* Create the destination of this final data */
	ps->osc = sdoOwnerSuppliedCredentialsAlloc();
	if (ps->osc == NULL) {
		goto err;
	}

	ps->osc->rvlst = sdoRendezvousListAlloc();
	if (ps->osc->rvlst == NULL) {
		goto err;
	}

	if (!sdoRBeginObject(&ps->sdor)) {
		goto err;
	}

	/* Read "osinn" - Owner Service Info Total count */
	if (!sdoReadExpectedTag(&ps->sdor, "osinn")) {
		goto err;
	}
	ps->ownerSuppliedServiceInfoCount = sdoReadUInt(&ps->sdor);

	/* Read "noh" - New Ownership Header */
	if (!sdoReadExpectedTag(&ps->sdor, "noh")) {
		goto err;
	}

	/* Store the "bo" tag "{" pointer */
	if (!sdoBeginReadSignature(&ps->sdor, &sig)) {
		goto err;
	}

	if (!sdoRBeginObject(&ps->sdor)) {
		goto err;
	}

	/* Store the new rendezvous entry */
	if (!sdoReadExpectedTag(&ps->sdor, "r3")) {
		goto err;
	}
	sdoRendezvousListRead(&ps->sdor, ps->osc->rvlst);
	LOG(LOG_DEBUG, "Rendezvous read, entries = %d\n",
	    ps->osc->rvlst->numEntries);

	/* Store the new GUID */
	if (!sdoReadExpectedTag(&ps->sdor, "g3")) {
		goto err;
	}
	ps->osc->guid = sdoByteArrayAlloc(0);
	if (ps->osc->guid == NULL) {
		goto err;
	}

	if (!sdoByteArrayReadChars(&ps->sdor, ps->osc->guid)) {
		LOG(LOG_ERROR, "Error parsing new GUID\n");
		goto err;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	LOG(LOG_DEBUG, "New guid is \"%s\"\n",
	    sdoGuidToString(ps->osc->guid, buf, sizeof buf) ? buf : "");
#endif
	/* "n7" (nonce) was sent to owner in msg44 */
	if (!sdoReadExpectedTag(&ps->sdor, "n7")) {
		goto err;
	}
	ps->n7r = sdoByteArrayAlloc(SDO_NONCE_BYTES);
	if (!ps->n7r || !sdoByteArrayReadChars(&ps->sdor, ps->n7r)) {
		goto err;
	}
	LOG(LOG_DEBUG, "Receiving n7: %s\n",
	    sdoNonceToString(ps->n7r->bytes, buf, sizeof buf) ? buf : "");

	if (!sdoREndObject(&ps->sdor)) {
		goto err;
	}

	/*
	 * "bo" ends. Let's verify signature */
	if (!sdoEndReadSignatureFull(&ps->sdor, &sig, &ps->new_pk)) {
		goto err;
	}

	/* FIXME: Is it not an error */
	if (!ps->new_pk) {
		LOG(LOG_ERROR, "No new owner public key returned\n");
	}

#if LOG_LEVEL == LOG_MAX_LEVEL /* LOG_DEBUG */
	{
		char *tempBuf;

		LOG(LOG_DEBUG,
		    "New Public Key : key1 "
		    ": %zu, key2 : %zu\n",
		    ps->new_pk->key1 == NULL ? 0 : ps->new_pk->key1->byteSz,
		    ps->new_pk->key2 == NULL ? 0 : ps->new_pk->key2->byteSz);
		tempBuf = sdoAlloc(2048);
		if (tempBuf == NULL) {
			sdoByteArrayFree(sig.sg);
			goto err;
		}
		sdoPublicKeyToString(ps->new_pk, tempBuf, 2048);
		LOG(LOG_DEBUG, "New Public Key: %s\n", tempBuf);
		sdoFree(tempBuf);
	}
#endif

	sdoByteArrayFree(sig.sg);

	sdoRFlush(&ps->sdor);

	if (ps->ownerSuppliedServiceInfoCount > 0) {
		ps->ownerSuppliedServiceInfoNum = 0;
		ps->osc->si = sdoServiceInfoAlloc();
		if (!ps->osc->si) {
			LOG(LOG_ERROR, "Out for memory for SI\n");
			goto err;
		}
		/* Move to msg48 */
		ps->state = SDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO;
	} else {
		ps->state = SDO_STATE_TO2_SND_DONE; /* Move to msg50*/
	}
	LOG(LOG_DEBUG, "SDO_STATE_TO2_RCV_SETUP_DEVICE: Complete\n");
	LOG(LOG_DEBUG, "Owner Service Info Messages to come: %d\n",
	    ps->ownerSuppliedServiceInfoCount);
	ret = 0; /* Mark as success */

err:
	return ret;
}
