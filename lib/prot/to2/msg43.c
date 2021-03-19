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
#include "sdoCrypto.h"

/**
 * msg63() - TO2.OVNextEntry
 *
 * TO2.OVNextEntry = [
 *   OVEntryNum
 *   OVEntry
 * ]
 * where,
 * OVEntry = CoseSignature
 * $COSEProtectedHeaders //= (
 *   1: OVSignType
 * )
 * $COSEPayloads /= (
 *   OVEntryPayload
 * )
 * OVEntryPayload = [
 *   OVEHashPrevEntry: Hash,
 *   OVEHashHdrInfo:   Hash,  ;; hash[GUID||DeviceInfo] in header
 *   OVEPubKey:        PublicKey
 * ]
 */
int32_t msg63(sdo_prot_t *ps)
{
	char prot[] = "SDOProtTO2";
	int ret = -1;
	int result_memcmp = 0;
	sdo_ov_entry_t *temp_entry = NULL;
	sdo_hash_t *current_hp_hash = NULL;
	sdo_hash_t *temp_hash_hp;
	sdo_hash_t *temp_hash_hc;
	sdo_public_key_t *temp_pk;
	int entry_num;
	fdo_cose_t *cose = NULL;
	sdo_byte_array_t *cose_encoded = NULL;

	if (!sdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	LOG(LOG_DEBUG, "TO2.OVNextEntry started\n");

	if (!sdor_start_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read start array\n");
		goto err;
	}

	if (!sdor_signed_int(&ps->sdor, &entry_num)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read OVEntryNum\n");
		goto err;
	}

	// OVEntryNum value must match with the requested Ownership Voucher index
	if (entry_num != ps->ov_entry_num) {
		LOG(LOG_ERROR,
		    "TO2.OVNextEntry: Invalid OVEntryNum, "
		    "expected %d, got %d\n",
		    ps->ov_entry_num, entry_num);
		goto err;
	}

	// Allocate for cose object now. Allocate for its members when needed later.
	// Free immediately once its of no use.
	cose = sdo_alloc(sizeof(fdo_cose_t));
	if (!cose) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to alloc COSE\n");
		goto err;
	}

	if (!fdo_cose_read(&ps->sdor, cose, true)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read COSE\n");
		goto err;
	}

	if (!sdor_end_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read end array\n");
		goto err;
	}

	// verify the received COSE signature
	if (!sdo_signature_verification(cose->cose_payload,
					cose->cose_signature,
					ps->ovoucher->ov_entries->pk)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to verify OVEntry signature\n");
		goto err;
	}
	LOG(LOG_DEBUG, "TO2.OVNextEntry: OVEntry Signature verification successful\n");

	// Generate COSE as CBOR bytes again that is used to calculate OVEHashPrevEntry.
	if (!fdo_cose_write(&ps->sdow, cose)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to write COSE for OVEHashPrevEntry\n");
		goto err;
	}
	// Get encoded COSE and copy
	if (!sdow_encoded_length(&ps->sdow, &ps->sdow.b.block_size)) {
		LOG(LOG_ERROR,
			"TO2.OVNextEntry: Failed to get encoded COSE length for OVEHashPrevEntry\n");
		goto err;		
	}
	cose_encoded = sdo_byte_array_alloc(ps->sdow.b.block_size);
	if (!cose_encoded) {
		LOG(LOG_ERROR,
			"TO2.OVNextEntry: Failed to alloc encoded COSE for OVEHashPrevEntry\n");
		goto err;		
	}
	if (0 != memcpy_s(cose_encoded->bytes, cose_encoded->byte_sz,
		ps->sdow.b.block, ps->sdow.b.block_size)) {
		LOG(LOG_ERROR,
			"TO2.OVNextEntry: Failed to copy encoded COSE for OVEHashPrevEntry\n");
		goto err;
	}

	// clear the SDOR buffer and copy COSE payload into it,
	// in preparation to parse OVEntryPayload
	sdo_block_reset(&ps->sdor.b);
	ps->sdor.b.block_size = cose->cose_payload->byte_sz;
	if (0 != memcpy_s(ps->sdor.b.block, ps->sdor.b.block_size,
		cose->cose_payload->bytes, cose->cose_payload->byte_sz)) {
		LOG(LOG_ERROR,
			"TO2.OVNextEntry: Failed to copy encoded COSEPayload for OVEHashPrevEntry\n");
		goto err;
	}

	// free the COSE object now
	fdo_cose_free(cose);
	cose = NULL;

	// initialize the parser once the buffer contains COSE payload to be decoded.
	if (!sdor_parser_init(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to initilize SDOR parser\n");
		goto err;
	}

	// start parsing OVEntryPayload
	size_t num_payloadbasemap_items = 0;
	if (!sdor_array_length(&ps->sdor, &num_payloadbasemap_items) ||
		num_payloadbasemap_items != 3) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read array length\n");
		goto err;
	}

	if (!sdor_start_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to start OVEntryPayload array\n");
		goto err;
	}

	// Read OVEntryPayload.OVEHashPrevEntry
	temp_hash_hp = sdo_hash_alloc_empty();
	if (!temp_hash_hp || sdo_hash_read(&ps->sdor, temp_hash_hp) <= 0) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read OVEntryPayload.OVEHashPrevEntry\n");
		sdo_hash_free(temp_hash_hp);
		goto err;
	}

	if (temp_hash_hp->hash_type != SDO_CRYPTO_HASH_TYPE_USED) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Invalid Hash Type at OVEntryPayload.OVEHashPrevEntry\n");
		sdo_hash_free(temp_hash_hp);
		goto err;
	}

	// Read OVEntryPayload.OVEHashHdrInfo
	temp_hash_hc = sdo_hash_alloc_empty();
	if (!temp_hash_hc || sdo_hash_read(&ps->sdor, temp_hash_hc) <= 0) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read OVEntryPayload.OVEHashHdrInfo\n");
		sdo_hash_free(temp_hash_hc);
		goto err;
	}

	if (temp_hash_hc->hash_type != SDO_CRYPTO_HASH_TYPE_USED) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Invalid Hash Type at OVEntryPayload.OVEHashHdrInfo\n");
		sdo_hash_free(temp_hash_hp);
		goto err;
	}

	// Read OVEntryPayload.OVEPubKey
	temp_pk = sdo_public_key_read(&ps->sdor);
	if (!temp_pk) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read OVEntryPayload.OVEPubKey\n");
		goto err;
	}

	if (!sdor_end_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to end OVEntryPayload array\n");
		goto err;
	}

	// Add a new entry to the OwnershipVoucher struct
	temp_entry = sdo_ov_entry_alloc_empty();
	if (!temp_entry) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: OVEntry allocation failed!\n");
		goto err;
	}
	temp_entry->enn = entry_num;
	temp_entry->hp_hash = temp_hash_hp;
	temp_entry->hc_hash = temp_hash_hc;
	temp_entry->pk = temp_pk;

	// Compare OVEHashPrevEntry (msg61 data) with the OVEHashPrevEntry from this message
	if (memcmp_s(ps->ovoucher->ov_entries->hp_hash->hash->bytes,
		     ps->ovoucher->ov_entries->hp_hash->hash->byte_sz,
		     temp_entry->hp_hash->hash->bytes,
		     temp_entry->hp_hash->hash->byte_sz,
		     &result_memcmp) ||
	    result_memcmp) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to match OVEHashPrevEntry %d\n",
		    ps->ov_entry_num);
		goto err;
	}

	// Compare OVEHashHdrInfo (msg61 data) with the OVEHashHdrInfo from this message
	if (memcmp_s(ps->ovoucher->ov_entries->hc_hash->hash->bytes,
		     ps->ovoucher->ov_entries->hc_hash->hash->byte_sz,
		     temp_entry->hc_hash->hash->bytes,
		     temp_entry->hc_hash->hash->byte_sz,
		     &result_memcmp) ||
	    result_memcmp) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to match OVEHashHdrInfo %d\n",
		    ps->ov_entry_num);
		goto err;
	}

	// OVEHashPrevEntry needs to be updated with current OVEntry's hash
	current_hp_hash =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
	if (!current_hp_hash) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to alloc current OVEntry hash!\n");
		goto err;
	}

	if (0 != sdo_crypto_hash(cose_encoded->bytes, cose_encoded->byte_sz,
				 current_hp_hash->hash->bytes,
				 current_hp_hash->hash->byte_sz)) {
		sdo_hash_free(current_hp_hash);
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to generate current OVEntry hash!\n");
		goto err;
	}
	// free the previous hash and push the new one.
	sdo_hash_free(ps->ovoucher->ov_entries->hp_hash);
	ps->ovoucher->ov_entries->hp_hash = current_hp_hash;

	// replace the previous OVEPubKey with the OVEPubKey from this msg data
	sdo_public_key_free(ps->ovoucher->ov_entries->pk);
	ps->ovoucher->ov_entries->pk = temp_entry->pk;

	LOG(LOG_DEBUG, "TO2.OVNextEntry: Verified OVEntry: %d\n", ps->ov_entry_num);

	/*
	 * if (TO2.ProveOVHdr.NumOVEntries - 1 == OVEntryNum)
	 *     goto TO2.ProveDevice (msg64)
	 * else
	 *     goto TO2.GetOVNextEntry (msg62)
	 */
	ps->ov_entry_num++;
	if (ps->ov_entry_num < ps->ovoucher->num_ov_entries) {
		ps->state = SDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY;
	} else {
		LOG(LOG_DEBUG,
		    "TO2.OVNextEntry: All %d OVEntry(s) have been "
		    "verified successfully!\n",
		    ps->ovoucher->num_ov_entries);

		if (!sdo_compare_public_keys(ps->owner_public_key,
					     temp_entry->pk)) {
			LOG(LOG_ERROR,
				"TO2.OVNextEntry: Failed to match Owner's pk to OVHdr pk!\n");
			goto err;
		}
		ps->state = SDO_STATE_TO2_SND_PROVE_DEVICE;
	}
	ret = 0; /* Mark as success */
err:
	sdo_block_reset(&ps->sdor.b);
	ps->sdor.have_block = false;
	if (temp_entry) {
		if (temp_entry->hp_hash) {
			sdo_hash_free(temp_entry->hp_hash);
		}
		if (temp_entry->hc_hash) {
			sdo_hash_free(temp_entry->hc_hash);
		}
		sdo_free(temp_entry);
	}
	if (cose_encoded) {
		sdo_byte_array_free(cose_encoded);
	}

	return ret;
}
