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
 * msg61 - TO2.ProveOVHdr
 * The owner responds to the device with the OVHeader. The COSESignature.signature
 * is signed with owner Private key to start establishing that it is the
 * rightful owner of the Ownership Voucher and thus the device.
 * 
 * TO2.ProveOVHdr = CoseSignature, where
 * TO2ProveOVHdrUnprotectedHeaders = (
 *   CUPHNonce:       Nonce6, ;; nonce6 is used below in TO2.ProveDevice and TO2.Done
 *   CUPHOwnerPubKey: PublicKey ;; Owner key, as hint
 * )
 * $COSEPayloads /= (
 *   TO2ProveOVHdrPayload
 * )
 * TO2ProveOVHdrPayload = [
 *   OVHeader,     ;; Ownership Voucher header
 *   NumOVEntries, ;; number of ownership voucher entries
 *   HMac,         ;; Ownership Voucher "hmac" of hdr
 *   Nonce5,       ;; nonce from TO2.HelloDevice
 *   eBSigInfo,    ;; Device attestation signature info
 *   xAKeyExchange ;; Key exchange first step
 * ]
 */
int32_t msg61(sdo_prot_t *ps)
{
	char prot[] = "SDOProtTO2";
	char buf[DEBUGBUFSZ] = {0};
	int ret = -1;
	int result_memcmp = 0;
	sdo_byte_array_t *xA = NULL;
	fdo_cose_t *cose = NULL;

	/*
	 * Check that we don't exceed Round Trip Times requirements. The reason
	 * for checking here is that sdo_prot_rcv_msg() fails the first time.
	 * So, the parent loop send the contents of previous message and
	 * receives for this message, thus, housing the Round Trip Times.
	 */
	if (!sdo_check_to2_round_trips(ps)) {
		LOG(LOG_ERROR, "Max round trips reached\n");
		goto err;
	}

	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	LOG(LOG_DEBUG, "TO2.ProveOVHdr started\n");

	// Allocate for cose object now. Allocate for its members when needed later.
	// Free immediately once its of no use.
	cose = sdo_alloc(sizeof(fdo_cose_t));
	if (!cose) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to alloc COSE\n");
		goto err;
	}

	if (!fdo_cose_read(&ps->sdor, cose, false)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read COSE\n");
		goto err;
	}

	// get the Owner public key & Nonce6 from the COSE's Unprotected header and save it
	ps->owner_public_key = sdo_public_key_clone(cose->cose_uph->cuphowner_public_key);
	ps->n6 = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n6) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to alloc Nonce6\n");
		goto err;
	}
	if (0 != memcpy_s(ps->n6->bytes, SDO_NONCE_BYTES,
		&cose->cose_uph->cuphnonce, sizeof(cose->cose_uph->cuphnonce))) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to copy Nonce6\n");
		goto err;
	}

	/* The signature verification over TO2.ProveOPHdr.bo must verify */
	if (!sdo_signature_verification(cose->cose_payload,
					cose->cose_signature,
					ps->owner_public_key)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: COSE signature verification failed\n");
		goto err;
	}
	LOG(LOG_DEBUG, "TO2.ProveOVHdr: COSE signature verification successful\n");

	// verify the to1d that was received during TO1.RVRedirect, Type 33
	// TO-DO : needs to happen only when TO2 was started without RVBypass flow.
	// Add one more condition check for bypass when it is fixed up.
	if (ps->to1d_cose) {
		if (!sdo_signature_verification(ps->to1d_cose->cose_payload,
					ps->to1d_cose->cose_signature,
					ps->owner_public_key)) {
			LOG(LOG_ERROR, "TO2.ProveOVHdr: COSE signature verification failed\n");
			goto err;
		}
		LOG(LOG_DEBUG, "TO2.ProveOVHdr: to1d signature verification successful\n");
	}

	// clear the SDOR buffer and push COSE payload into it, essentially reusing the SDOR object.
	sdo_block_reset(&ps->sdor.b);
	ps->sdor.b.block_size = cose->cose_payload->byte_sz;
	if (0 != memcpy_s(ps->sdor.b.block, ps->sdor.b.block_size,
		cose->cose_payload->bytes, cose->cose_payload->byte_sz)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to copy Nonce4\n");
		goto err;
	}
	fdo_cose_free(cose);
	cose = NULL;

	// initialize the parser once the buffer contains COSE payload to be decoded.
	if (!sdor_parser_init(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to initilize SDOR parser\n");
		goto err;
	}

	size_t num_payloadbasemap_items = 0;
	if (!sdor_array_length(&ps->sdor, &num_payloadbasemap_items) ||
		num_payloadbasemap_items != 6) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read array length\n");
		goto err;
	}

	if (!sdor_start_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to start TO2ProveOVHdrPayload array\n");
		goto err;
	}

	// Read the ownership header
	ps->ovoucher = sdo_ov_hdr_read(&ps->sdor, &ps->new_ov_hdr_hmac);
	if (!ps->ovoucher) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read OVHeader\n");
		goto err;
	}

	/*
	 * Read the number of Ownership Vouchers present. The device does not
	 * know without "sz" tag, how many hops it has taken from Manufacturer
	 * to the real owner (end-user)
	 */
	ps->ovoucher->num_ov_entries = 0;
	if (!sdor_signed_int(&ps->sdor, &ps->ovoucher->num_ov_entries) ||
		ps->ovoucher->num_ov_entries == 0) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read NumOVEntries\n");
		goto err;
	}
	LOG(LOG_DEBUG, "TO2.ProveOVHdr: Total number of OwnershipVoucher.OVEntries: %d\n",
		ps->ovoucher->num_ov_entries);

	ps->ovoucher->ovoucher_hdr_hash = sdo_hash_alloc_empty();
	if (!ps->ovoucher->ovoucher_hdr_hash) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to alloc HMac\n");
		goto err;
	}
	if (!sdo_hash_read(&ps->sdor, ps->ovoucher->ovoucher_hdr_hash)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read HMac\n");
		goto err;
	}

	/*
	 * Compare the HMAC sent by owner with HMAC calculated by us. The key is
	 * the one used by the device in DI. The owner gets the HMAC from
	 * manufacturer ps->ovoucher->ovoucher_hdr_hash->hash->bytes: owner sent
	 * HMAC ps->new_ov_hdr_hmac->hash->byte_sz            : Fresh HMAC
	 * calculated
	 */
	ret = memcmp_s(ps->ovoucher->ovoucher_hdr_hash->hash->bytes,
		       ps->ovoucher->ovoucher_hdr_hash->hash->byte_sz,
		       ps->new_ov_hdr_hmac->hash->bytes,
		       ps->new_ov_hdr_hmac->hash->byte_sz, &result_memcmp);
	if (ret || result_memcmp != 0) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Invalid HMac received over OVHeader\n");
		ret = -1;
		goto err;
	}
	ret = -1; /* Reset to error */
	LOG(LOG_DEBUG, "TO2.ProveOVHdr: Valid Ownership Header received\n");

	ps->n5r = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n5r) {
		goto err;
	}
	size_t nonce5_length = 0;
	if (!sdor_string_length(&ps->sdor, &nonce5_length) || nonce5_length != SDO_NONCE_BYTES) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Invalid/Failed to read Nonce5 length\n");
		goto err;
	}
	if (!sdor_byte_string(&ps->sdor, ps->n5r->bytes, ps->n5r->byte_sz)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read Nonce5\n");
		goto err;		
	}
	LOG(LOG_DEBUG, "TO2.ProveOVHdr: Received Nonce5: %s\n",
	    sdo_nonce_to_string(ps->n5r->bytes, buf, sizeof buf) ? buf : "");

	/* The nonces "n5" (msg40) and "n6" here must match */
	if (!sdo_nonce_equal(ps->n5r, ps->n5)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Received Nonce5 and Nonce5 do not match\n");
		goto err;
	}

	// clear them now since the Nonces have served their purpose
	sdo_byte_array_free(ps->n5);
	ps->n5 = NULL;
	sdo_byte_array_free(ps->n5r);
	ps->n5r = NULL;	

	if (!sdo_eb_read(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read eBSigInfo\n");
		goto err;
	}

	/*
	 * Read the key exchange info. This is the first part of key exchange of
	 * info. xA is used based on KEX selected (asym, RSA, DH)
	 */
	size_t xA_length = 8;
	if (!sdor_string_length(&ps->sdor, &xA_length)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read xAKeyExchange length\n");
		goto err;	
	}
	xA = sdo_byte_array_alloc(xA_length);
	if (!xA) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to allocate memory for xAKeyExchange\n");
		goto err;
	}
	if(!sdor_byte_string(&ps->sdor, xA->bytes, xA->byte_sz)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read xAKeyExchange\n");
		goto err;
	}
	LOG(LOG_DEBUG, "TO2.ProveOVHdr: Key Exchange xA is %zu bytes\n", xA->byte_sz);
	// Save TO2.ProveOPHdr.pk for Asymmetric Key Exchange algorithm
	if (sdo_set_kex_paramA(xA, ps->owner_public_key)) {
		goto err;
	}

	if (!sdor_end_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to end TO2ProveOVHdrPayload array\n");
		goto err;
	}

	// Save the initial OVEHashPrevEntry and OVEHashHdrInfo
	ps->ovoucher->ov_entries = sdo_ov_entry_alloc_empty();
	if (!ps->ovoucher->ov_entries) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to alloc OVEntry\n");
		goto err;		
	}
	if (!fdo_ove_hash_hdr_info_save(ps->ovoucher)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to save OVEHashHdrInfo\n");
		goto err;
	}
	// reset the SDOW block to prepare for OVEHashPrevEntry
	sdo_block_reset(&ps->sdow.b);
	ps->sdow.b.block_size = CBOR_BUFFER_LENGTH;
	if (!sdow_encoder_init(&ps->sdow)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to initilize SDOW encoder\n");
		goto err;
	}
	if (!fdo_ove_hash_prev_entry_save(&ps->sdow, ps->ovoucher, ps->ovoucher->ovoucher_hdr_hash)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to save OVEHashPrevEntry\n");
		goto err;
	}
	// To verify the next entry in the ownership voucher
	ps->ovoucher->ov_entries->pk = sdo_public_key_clone(ps->ovoucher->mfg_pub_key);

	/*
	 * If the TO2.ProveOPHdr.bo.sz > 0, get next Ownership Voucher (msg42),
	 * else jump to msg44
	 */
	if (ps->ovoucher->num_ov_entries > 0) {
		ps->ov_entry_num = 0;
		ps->state = SDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY;
	} else {
		LOG(LOG_INFO, "No Ownership Vouchers, jumping to msg44\n");
		ps->state = SDO_STATE_TO2_SND_PROVE_DEVICE;
	}

	LOG(LOG_DEBUG, "TO2.ProveOVHdr completed. %d OVEntry(s) to follow\n",
	    ps->ovoucher->num_ov_entries);
	ret = 0; /* Mark as success */

err:
	sdor_flush(&ps->sdor);
	ps->sdor.have_block = false;
	if (xA) {
		sdo_byte_array_free(xA);
	}
	if (cose) {
		fdo_cose_free(cose);
		cose = NULL;
	}
	if (ps->n5r != NULL) {
		sdo_byte_array_free(ps->n5r);
		ps->n5r = NULL;
	}
	return ret;
}
