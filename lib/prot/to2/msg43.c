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
 * msg43() - TO2.OPNext_entry
 *
 * --- Message Format Begins ---
 * {
 *     "enn":UInt8,            # It must match the value sent in msg42
 *     "eni":{
 *         bo:{
 *             "hp": Hash,     # Hash of previous Ownership entry
 *             "hc": Hash,     # Hash of GUID and device info
 *             "pk": Public_key # pk signed in previous entry
 *         },
 *     "pk": PKNull,           #
 *     "sg": Signature         # Signature by above 'pk'
 *     }
 * }
 * --- Message Format Ends ---
 */
int32_t msg43(sdo_prot_t *ps)
{
	char prot[] = "SDOProtTO2";
	int ret = -1;
	int hp_start = 0;
	int hp_end = 0;
	int result_memcmp = 0;
	uint8_t *hp_text = NULL;
	sdo_ov_entry_t *temp_entry = NULL;
	sdo_hash_t *current_hp_hash = NULL;
	sdo_hash_t *temp_hash_hp;
	sdo_hash_t *temp_hash_hc;
	sdo_public_key_t *temp_pk;
	sdo_sig_t sig = {0};
	uint16_t entry_num;

	LOG(LOG_DEBUG, "SDO_STATE_T02_RCV_OP_NEXT_ENTRY: Starting\n");

	if (!sdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	if (!sdor_begin_object(&ps->sdor)) {
		goto err;
	}

	/* Start with the first tag "enn" */
	if (!sdo_read_expected_tag(&ps->sdor, "enn")) {
		goto err;
	}
	entry_num = sdo_read_uint(&ps->sdor);

	/* "enn" value must match with the requested Ownership Voucher index */
	if (entry_num != ps->ov_entry_num) {
		LOG(LOG_ERROR,
		    "Invalid OP entry number, "
		    "expected %d, got %d\n",
		    ps->ov_entry_num, entry_num);
		goto err;
	}

	/* Process the next tag: "eni" */
	if (!sdo_read_expected_tag(&ps->sdor, "eni")) {
		goto err;
	}

	/*
	 * The sign is brace to brace of "eni", so, store the pointer
	 * to the beginning of the this block
	 */
	if (!sdo_begin_read_signature(&ps->sdor, &sig)) {
		LOG(LOG_ERROR, "Could not begin signature\n");
		goto err;
	}

	/* TODO: better to increment the pointer by reading "bo" tag */
	ps->sdor.need_comma = false;
	hp_start = ps->sdor.b.cursor;
	if (!sdor_begin_object(&ps->sdor)) {
		goto err;
	}

	/* Add a new entry to the Owner Proxy */
	temp_entry = sdo_ov_entry_alloc_empty();
	if (!temp_entry) {
		LOG(LOG_ERROR, "Ownership Voucher "
			       "allocation failed!\n");
		goto err;
	}

	/* Save off the entry number */
	temp_entry->enn = entry_num;

	/*
	 * Read the "hp" value. It must be equal to:
	 *     SHA [TO2.ProveOPHdr.bo.oh||TO2.Prove_op_hdr.bo.hmac])
	 * NOTE: TO2.ProveOPHdr is msg41.
	 */
	if (!sdo_read_expected_tag(&ps->sdor, "hp")) {
		goto err;
	}

	temp_hash_hp = sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_USED,
				      SDO_CRYPTO_HASH_TYPE_NONE);
	if (temp_hash_hp && sdo_hash_read(&ps->sdor, temp_hash_hp) > 0) {
		temp_entry->hp_hash = temp_hash_hp;
	} else {
		sdo_hash_free(temp_hash_hp);
		goto err;
	}

	/*
	 * Read "hc" value. It must be equal to:
	 *     SHA[TO2.ProveOPHdr.bo.oh.g||TO2.ProveOPHdr.bo.oh.d]
	 * NOTE: TO2.ProveOPHdr is msg41.
	 */
	if (!sdo_read_expected_tag(&ps->sdor, "hc")) {
		goto err;
	}
	temp_hash_hc = sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_USED,
				      SDO_CRYPTO_HASH_TYPE_NONE);
	if (temp_hash_hc && sdo_hash_read(&ps->sdor, temp_hash_hc) > 0) {
		temp_entry->hc_hash = temp_hash_hc;
	} else {
		sdo_hash_free(temp_hash_hc);
		goto err;
	}

	/* Read "pk". It must be equal to: TO2.ProveOPHdr.pk */
	if (!sdo_read_expected_tag(&ps->sdor, "pk")) {
		goto err;
	}

	temp_pk = sdo_public_key_read(&ps->sdor);
	temp_entry->pk = temp_pk;

	/* TO2.OPNext_entry.enn.eni.bo ends here */
	if (!sdor_end_object(&ps->sdor)) {
		goto err;
	}

	/* Get the buffer start/end over TO2.OPNext_entry.enn.eni.bo */
	hp_end = ps->sdor.b.cursor;
	hp_text = sdor_get_block_ptr(&ps->sdor, hp_start);
	if (hp_text == NULL) {
		goto err;
	}

	/* Calculate hash over received body ("bo") */
	current_hp_hash =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
	if (!current_hp_hash) {
		goto err;
	}

	if (0 != sdo_crypto_hash(hp_text, (hp_end - hp_start),
				 current_hp_hash->hash->bytes,
				 current_hp_hash->hash->byte_sz)) {
		goto err;
	}

	/* Verify the signature over body */
	if (!sdoOVSignature_verification(&ps->sdor, &sig,
					 ps->ovoucher->ov_entries->pk)) {
		LOG(LOG_ERROR, "OVEntry Signature "
			       "verification fails\n");
		goto err;
	}
	LOG(LOG_DEBUG, "OVEntry Signature "
		       "verification "
		       "successful\n");
	sdor_flush(&ps->sdor);

	/* Free the signature */
	sdo_byte_array_free(sig.sg);

	/* Compare hp hash (msg41 data) with the hp hash in this message */
	if (memcmp_s(ps->ovoucher->ov_entries->hp_hash->hash->bytes,
		     ps->ovoucher->ov_entries->hp_hash->hash->byte_sz,
		     temp_entry->hp_hash->hash->bytes,
		     ps->ovoucher->ov_entries->hp_hash->hash->byte_sz,
		     &result_memcmp) ||
	    result_memcmp) {
		LOG(LOG_ERROR, "Failed to match HP Hash at entry %d\n",
		    ps->ov_entry_num);
		goto err;
	}

	/* Compare hc hash (msg41 data) with the hc hash in this message */
	if (memcmp_s(ps->ovoucher->ov_entries->hc_hash->hash->bytes,
		     ps->ovoucher->ov_entries->hc_hash->hash->byte_sz,
		     temp_entry->hc_hash->hash->bytes,
		     ps->ovoucher->ov_entries->hc_hash->hash->byte_sz,
		     &result_memcmp) ||
	    result_memcmp) {
		LOG(LOG_ERROR, "Failed to match HC Hash at entry %d\n",
		    ps->ov_entry_num);
		goto err;
	}

	/* hp hash needs to be updated with current message ("bo") hash */
	sdo_hash_free(ps->ovoucher->ov_entries->hp_hash);
	ps->ovoucher->ov_entries->hp_hash = current_hp_hash;

	/* Update the pk with the "pk" from this msg data */
	sdo_public_key_free(ps->ovoucher->ov_entries->pk);
	ps->ovoucher->ov_entries->pk = temp_entry->pk;

	LOG(LOG_DEBUG, "Verified OP entry: %d\n", ps->ov_entry_num);

	/*
	 * if (TO2.ProveOPHdr.bo.sz - 1 == enn)
	 *     goto TO2.Prove_device (msg44)
	 * else
	 *     goto TO2.GetOPNext_entry (msg42)
	 */
	ps->ov_entry_num++;
	if (ps->ov_entry_num < ps->ovoucher->num_ov_entries) {
		ps->state = SDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY;
	} else {
		LOG(LOG_DEBUG,
		    "All %d OP entries have been "
		    "verified successfully!\n",
		    ps->ovoucher->num_ov_entries);
		/*
		 * If eni == TO2.Prove_op_hdr.bo.sz-1; then
		 *     TO2.ProveOVHdr.pk == TO2.Op_next_entry.eni.bo.pk
		 */
		if (!sdo_compare_public_keys(ps->owner_public_key,
					     temp_entry->pk)) {
			LOG(LOG_ERROR, "Failed to match Power "
				       "on Owner's pk to OVHdr "
				       "pk!\n");
			goto err;
		}
		ps->state = SDO_STATE_TO2_SND_PROVE_DEVICE;
	}

	ret = 0; /* Mark as success */
err:
	if (temp_entry) {
		if (temp_entry->hp_hash) {
			sdo_hash_free(temp_entry->hp_hash);
		}
		if (temp_entry->hc_hash) {
			sdo_hash_free(temp_entry->hc_hash);
		}
		sdo_free(temp_entry);
	}
	if (ret) {
		if (current_hp_hash) {
			sdo_hash_free(current_hp_hash);
		}
	}

	return ret;
}
