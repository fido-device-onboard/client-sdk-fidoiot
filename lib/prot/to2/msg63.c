/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg63 of TO2 state machine.
 */

#include "fdoprot.h"
#include "fdotypes.h"
#include "safe_lib.h"
#include "util.h"
#include "fdoCrypto.h"

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
 *   OVEExtra:         null / bstr .cbor OVEExtraInfo
 *   OVEPubKey:        PublicKey
 * ]
 */
int32_t msg63(fdo_prot_t *ps)
{
	char prot[] = "FDOProtTO2";
	int ret = -1;
	int result_memcmp = 0;
	fdo_ov_entry_t *temp_entry = NULL;
	fdo_hash_t *current_hp_hash = NULL;
	fdo_hash_t *temp_hash_hp;
	fdo_hash_t *temp_hash_hc;
	fdo_byte_array_t *temp_ove_extra = NULL;
	size_t ove_extra_len = 0;
	fdo_public_key_t *temp_pk;
	int entry_num;
	fdo_cose_t *cose = NULL;
	fdo_byte_array_t *cose_encoded = NULL;
	fdo_byte_array_t *cose_sig_structure = NULL;

	if (!ps) {
		LOG(LOG_ERROR, "Invalid protocol state\n");
		return ret;
	}

	if (!fdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!fdo_prot_rcv_msg(&ps->fdor, &ps->fdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	LOG(LOG_DEBUG, "TO2.OVNextEntry started\n");

	if (!fdor_start_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read start array\n");
		goto err;
	}

	if (!fdor_signed_int(&ps->fdor, &entry_num)) {
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
	cose = fdo_alloc(sizeof(fdo_cose_t));
	if (!cose) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to alloc COSE\n");
		goto err;
	}

	if (!fdo_cose_read(&ps->fdor, cose, true)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read COSE\n");
		goto err;
	}

	if (!fdor_end_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read end array\n");
		goto err;
	}

	if (!fdo_cose_write_sigstructure(cose->cose_ph, cose->cose_payload, NULL,
		&cose_sig_structure) || !cose_sig_structure) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to write COSE Sig_structure\n");
		goto err;
	}
	// verify the received COSE signature
	if (!fdo_signature_verification(cose_sig_structure,
					cose->cose_signature,
					ps->ovoucher->ov_entries->pk)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to verify OVEntry signature\n");
		goto err;
	}
	LOG(LOG_DEBUG, "TO2.OVNextEntry: OVEntry Signature verification successful\n");

	// Generate COSE as CBOR bytes again that is used to calculate OVEHashPrevEntry.
	if (!fdo_cose_write(&ps->fdow, cose)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to write COSE for OVEHashPrevEntry\n");
		goto err;
	}
	// Get encoded COSE and copy
	if (!fdow_encoded_length(&ps->fdow, &ps->fdow.b.block_size)) {
		LOG(LOG_ERROR,
			"TO2.OVNextEntry: Failed to get encoded COSE length for OVEHashPrevEntry\n");
		goto err;
	}
	cose_encoded = fdo_byte_array_alloc(ps->fdow.b.block_size);
	if (!cose_encoded) {
		LOG(LOG_ERROR,
			"TO2.OVNextEntry: Failed to alloc encoded COSE for OVEHashPrevEntry\n");
		goto err;
	}
	if (0 != memcpy_s(cose_encoded->bytes, cose_encoded->byte_sz,
		ps->fdow.b.block, ps->fdow.b.block_size)) {
		LOG(LOG_ERROR,
			"TO2.OVNextEntry: Failed to copy encoded COSE for OVEHashPrevEntry\n");
		goto err;
	}

	// clear the FDOR buffer and copy COSE payload into it,
	// in preparation to parse OVEntryPayload
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.b.block_size = cose->cose_payload->byte_sz;
	if (0 != memcpy_s(ps->fdor.b.block, ps->fdor.b.block_size,
		cose->cose_payload->bytes, cose->cose_payload->byte_sz)) {
		LOG(LOG_ERROR,
			"TO2.OVNextEntry: Failed to copy encoded COSEPayload for OVEHashPrevEntry\n");
		goto err;
	}

	// free the COSE object now
	fdo_cose_free(cose);
	cose = NULL;

	// initialize the parser once the buffer contains COSE payload to be decoded.
	if (!fdor_parser_init(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to initilize FDOR parser\n");
		goto err;
	}

	// start parsing OVEntryPayload
	size_t num_payloadbasemap_items = 0;
	if (!fdor_array_length(&ps->fdor, &num_payloadbasemap_items) ||
		num_payloadbasemap_items != 4) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read array length\n");
		goto err;
	}

	if (!fdor_start_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to start OVEntryPayload array\n");
		goto err;
	}

	// Read OVEntryPayload.OVEHashPrevEntry
	temp_hash_hp = fdo_hash_alloc_empty();
	if (!temp_hash_hp || fdo_hash_read(&ps->fdor, temp_hash_hp) <= 0) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read OVEntryPayload.OVEHashPrevEntry\n");
		fdo_hash_free(temp_hash_hp);
		goto err;
	}

	if (temp_hash_hp->hash_type != FDO_CRYPTO_HASH_TYPE_USED) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Invalid Hash Type at OVEntryPayload.OVEHashPrevEntry\n");
		fdo_hash_free(temp_hash_hp);
		goto err;
	}

	// Read OVEntryPayload.OVEHashHdrInfo
	temp_hash_hc = fdo_hash_alloc_empty();
	if (!temp_hash_hc || fdo_hash_read(&ps->fdor, temp_hash_hc) <= 0) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read OVEntryPayload.OVEHashHdrInfo\n");
		fdo_hash_free(temp_hash_hc);
		goto err;
	}

	if (temp_hash_hc->hash_type != FDO_CRYPTO_HASH_TYPE_USED) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Invalid Hash Type at OVEntryPayload.OVEHashHdrInfo\n");
		fdo_hash_free(temp_hash_hc);
		goto err;
	}

	// Read OVEntryPayload.OVEExtra
	if (fdor_is_value_null(&ps->fdor)) {
		if (!fdor_next(&ps->fdor)) {
			LOG(LOG_ERROR,
				"TO2.OVNextEntry: Failed to read OVNextEntry as null\n");
			goto err;
		}
	} else {
		// Read the bin character length
		if (!fdor_string_length(&ps->fdor, &ove_extra_len) || ove_extra_len == 0) {
			LOG(LOG_DEBUG, "TO2.OVNextEntry: Unable to decode length of OVEExtra!\n");
			goto err;
		}
		temp_ove_extra = fdo_byte_array_alloc(ove_extra_len);
		if (!temp_ove_extra) {
			LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to alloc for OVEExtra as bstr\n");
			goto err;
		}
		if (!fdor_byte_string(&ps->fdor, temp_ove_extra->bytes, temp_ove_extra->byte_sz)) {
			LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read OVEExtra as bstr\n");
			goto err;
		}
	}

	// Read OVEntryPayload.OVEPubKey
	temp_pk = fdo_public_key_read(&ps->fdor);
	if (!temp_pk) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to read OVEntryPayload.OVEPubKey\n");
		goto err;
	}

	if (!fdor_end_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to end OVEntryPayload array\n");
		goto err;
	}

	// Add a new entry to the OwnershipVoucher struct
	temp_entry = fdo_ov_entry_alloc_empty();
	if (!temp_entry) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: OVEntry allocation failed!\n");
		goto err;
	}
	temp_entry->enn = entry_num;
	temp_entry->hp_hash = temp_hash_hp;
	temp_entry->hc_hash = temp_hash_hc;
	temp_entry->ove_extra = temp_ove_extra;
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
	    fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_USED, FDO_SHA_DIGEST_SIZE_USED);
	if (!current_hp_hash) {
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to alloc current OVEntry hash!\n");
		goto err;
	}

	if (0 != fdo_crypto_hash(cose_encoded->bytes, cose_encoded->byte_sz,
				 current_hp_hash->hash->bytes,
				 current_hp_hash->hash->byte_sz)) {
		fdo_hash_free(current_hp_hash);
		LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to generate current OVEntry hash!\n");
		goto err;
	}
	// free the previous hash and push the new one.
	fdo_hash_free(ps->ovoucher->ov_entries->hp_hash);
	ps->ovoucher->ov_entries->hp_hash = current_hp_hash;

	// replace the previous OVEPubKey with the OVEPubKey from this msg data
	fdo_public_key_free(ps->ovoucher->ov_entries->pk);
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
		ps->state = FDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY;
		// reset FDOW because it was used in this method, out of place
		fdo_block_reset(&ps->fdow.b);
		ps->fdor.b.block_size = ps->prot_buff_sz;
		if (!fdow_encoder_init(&ps->fdow)) {
			LOG(LOG_ERROR, "TO2.OVNextEntry: Failed to initialize FDOW encoder\n");
			goto err;
		}
	} else {
		LOG(LOG_DEBUG,
		    "TO2.OVNextEntry: All %d OVEntry(s) have been "
		    "verified successfully!\n",
		    ps->ovoucher->num_ov_entries);

		if (!fdo_compare_public_keys(ps->owner_public_key,
					     temp_entry->pk)) {
			LOG(LOG_ERROR,
				"TO2.OVNextEntry: Failed to match Owner's pk to OVHdr pk!\n");
			goto err;
		}
		ps->state = FDO_STATE_TO2_SND_PROVE_DEVICE;
	}
	ret = 0; /* Mark as success */
err:
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.have_block = false;
	if (temp_entry) {
		if (temp_entry->hp_hash) {
			fdo_hash_free(temp_entry->hp_hash);
		}
		if (temp_entry->hc_hash) {
			fdo_hash_free(temp_entry->hc_hash);
		}
		if (temp_ove_extra) {
			fdo_byte_array_free(temp_ove_extra);
		}
		fdo_free(temp_entry);
	}
	if (cose_encoded) {
		fdo_byte_array_free(cose_encoded);
	}
	if (cose_sig_structure) {
		fdo_byte_array_free(cose_sig_structure);
		cose_sig_structure = NULL;
	}
	return ret;
}
