/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg43 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdotypes.h"
#include "safe_lib.h"
#include "util.h"
#include "sdoCryptoApi.h"

/**
 * msg43() - TO2.OPNextEntry
 *
 * --- Message Format Begins ---
 * {
 *     "enn":UInt8,            # It must match the value sent in msg42
 *     "eni":{
 *         bo:{
 *             "hp": Hash,     # Hash of previous Ownership entry
 *             "hc": Hash,     # Hash of GUID and device info
 *             "pk": PublicKey # pk signed in previous entry
 *         },
 *     "pk": PKNull,           #
 *     "sg": Signature         # Signature by above 'pk'
 *     }
 * }
 * --- Message Format Ends ---
 */
int32_t msg43(SDOProt_t *ps)
{
	char prot[] = "SDOProtTO2";
	int ret = -1;
	int hpStart = 0;
	int hpEnd = 0;
	int result_memcmp = 0;
	uint8_t *hpText = NULL;
	SDOOvEntry_t *tempEntry = NULL;
	SDOHash_t *currentHpHash = NULL;
	SDOHash_t *tempHashHp;
	SDOHash_t *tempHashHc;
	SDOPublicKey_t *tempPk;
	SDOSig_t sig = {0};
	uint16_t entryNum;

	LOG(LOG_DEBUG, "SDO_STATE_T02_RCV_OP_NEXT_ENTRY: Starting\n");

	if (!sdoCheckTO2RoundTrips(ps)) {
		goto err;
	}

	if (!sdoProtRcvMsg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	if (!sdoRBeginObject(&ps->sdor)) {
		goto err;
	}

	/* Start with the first tag "enn" */
	if (!sdoReadExpectedTag(&ps->sdor, "enn")) {
		goto err;
	}
	entryNum = sdoReadUInt(&ps->sdor);

	/* "enn" value must match with the requested Ownership Voucher index */
	if (entryNum != ps->ovEntryNum) {
		LOG(LOG_ERROR,
		    "Invalid OP entry number, "
		    "expected %d, got %d\n",
		    ps->ovEntryNum, entryNum);
		goto err;
	}

	/* Process the next tag: "eni" */
	if (!sdoReadExpectedTag(&ps->sdor, "eni")) {
		goto err;
	}

	/*
	 * The sign is brace to brace of "eni", so, store the pointer
	 * to the beginning of the this block
	 */
	if (!sdoBeginReadSignature(&ps->sdor, &sig)) {
		LOG(LOG_ERROR, "Could not begin signature\n");
		goto err;
	}

	/* TODO: better to increment the pointer by reading "bo" tag */
	ps->sdor.needComma = false;
	hpStart = ps->sdor.b.cursor;
	if (!sdoRBeginObject(&ps->sdor)) {
		goto err;
	}

	/* Add a new entry to the Owner Proxy */
	tempEntry = sdoOvEntryAllocEmpty();
	if (!tempEntry) {
		LOG(LOG_ERROR, "Ownership Voucher "
			       "allocation failed!\n");
		goto err;
	}

	/* Save off the entry number */
	tempEntry->enn = entryNum;

	/*
	 * Read the "hp" value. It must be equal to:
	 *     SHA [TO2.ProveOPHdr.bo.oh||TO2.ProveOpHdr.bo.hmac])
	 * NOTE: TO2.ProveOPHdr is msg41.
	 */
	if (!sdoReadExpectedTag(&ps->sdor, "hp")) {
		goto err;
	}

	tempHashHp =
	    sdoHashAlloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_CRYPTO_HASH_TYPE_NONE);
	if (tempHashHp && sdoHashRead(&ps->sdor, tempHashHp) > 0) {
		tempEntry->hpHash = tempHashHp;
	}

	/*
	 * Read "hc" value. It must be equal to:
	 *     SHA[TO2.ProveOPHdr.bo.oh.g||TO2.ProveOPHdr.bo.oh.d]
	 * NOTE: TO2.ProveOPHdr is msg41.
	 */
	if (!sdoReadExpectedTag(&ps->sdor, "hc")) {
		goto err;
	}
	tempHashHc =
	    sdoHashAlloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_CRYPTO_HASH_TYPE_NONE);
	if (tempHashHc && sdoHashRead(&ps->sdor, tempHashHc) > 0) {
		tempEntry->hcHash = tempHashHc;
	}

	/* Read "pk". It must be equal to: TO2.ProveOPHdr.pk */
	if (!sdoReadExpectedTag(&ps->sdor, "pk")) {
		goto err;
	}

	tempPk = sdoPublicKeyRead(&ps->sdor);
	tempEntry->pk = tempPk;

	/* TO2.OPNextEntry.enn.eni.bo ends here */
	if (!sdoREndObject(&ps->sdor)) {
		goto err;
	}

	/* Get the buffer start/end over TO2.OPNextEntry.enn.eni.bo */
	hpEnd = ps->sdor.b.cursor;
	hpText = sdoRGetBlockPtr(&ps->sdor, hpStart);
	if (hpText == NULL) {
		goto err;
	}

	/* Calculate hash over received body ("bo") */
	currentHpHash =
	    sdoHashAlloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
	if (!currentHpHash) {
		goto err;
	}

	if (0 != sdoCryptoHash(hpText, (hpEnd - hpStart),
			       currentHpHash->hash->bytes,
			       currentHpHash->hash->byteSz)) {
		goto err;
	}

	/* Verify the signature over body */
	if (!sdoOVSignatureVerification(&ps->sdor, &sig,
					ps->ovoucher->OVEntries->pk)) {
		LOG(LOG_ERROR, "OVEntry Signature "
			       "verification fails\n");
		goto err;
	}
	LOG(LOG_DEBUG, "OVEntry Signature "
		       "verification "
		       "successful\n");
	sdoRFlush(&ps->sdor);

	/* Free the signature */
	sdoByteArrayFree(sig.sg);

	/* Compare hp hash (msg41 data) with the hp hash in this message */
	if (memcmp_s(ps->ovoucher->OVEntries->hpHash->hash->bytes,
		     ps->ovoucher->OVEntries->hpHash->hash->byteSz,
		     tempEntry->hpHash->hash->bytes,
		     ps->ovoucher->OVEntries->hpHash->hash->byteSz,
		     &result_memcmp) ||
	    result_memcmp) {
		LOG(LOG_ERROR, "Failed to match HP Hash at entry %d\n",
		    ps->ovEntryNum);
		goto err;
	}

	/* Compare hc hash (msg41 data) with the hc hash in this message */
	if (memcmp_s(ps->ovoucher->OVEntries->hcHash->hash->bytes,
		     ps->ovoucher->OVEntries->hcHash->hash->byteSz,
		     tempEntry->hcHash->hash->bytes,
		     ps->ovoucher->OVEntries->hcHash->hash->byteSz,
		     &result_memcmp) ||
	    result_memcmp) {
		LOG(LOG_ERROR, "Failed to match HC Hash at entry %d\n",
		    ps->ovEntryNum);
		goto err;
	}

	/* hp hash needs to be updated with current message ("bo") hash */
	sdoHashFree(ps->ovoucher->OVEntries->hpHash);
	ps->ovoucher->OVEntries->hpHash = currentHpHash;

	/* Update the pk with the "pk" from this msg data */
	sdoPublicKeyFree(ps->ovoucher->OVEntries->pk);
	ps->ovoucher->OVEntries->pk = tempEntry->pk;

	LOG(LOG_DEBUG, "Verified OP entry: %d\n", ps->ovEntryNum);

	/*
	 * if (TO2.ProveOPHdr.bo.sz - 1 == enn)
	 *     goto TO2.ProveDevice (msg44)
	 * else
	 *     goto TO2.GetOPNextEntry (msg42)
	 */
	ps->ovEntryNum++;
	if (ps->ovEntryNum < ps->ovoucher->numOVEntries) {
		sdoHashFree(currentHpHash);
		ps->state = SDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY;
	} else {
		LOG(LOG_DEBUG,
		    "All %d OP entries have been "
		    "verified successfully!\n",
		    ps->ovoucher->numOVEntries);
		/*
		 * If eni == TO2.ProveOpHdr.bo.sz-1; then
		 *     TO2.ProveOVHdr.pk == TO2.OpNextEntry.eni.bo.pk
		 */
		if (!sdoComparePublicKeys(ps->ownerPublicKey, tempEntry->pk)) {
			LOG(LOG_ERROR, "Failed to match Power "
				       "on Owner's pk to OVHdr "
				       "pk!\n");
			goto err;
		}
		ps->state = SDO_STATE_TO2_SND_PROVE_DEVICE;
	}

	ret = 0; /* Mark as success */
err:
	if (tempEntry) {
		if (tempEntry->hpHash) {
			sdoHashFree(tempEntry->hpHash);
		}
		if (tempEntry->hcHash) {
			sdoHashFree(tempEntry->hcHash);
		}
		sdoFree(tempEntry);
	}

	return ret;
}
