/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg61 of TO2 state machine.
 */

#include "fdoprot.h"
#include "safe_lib.h"
#include "fdokeyexchange.h"
#include "util.h"
#include "fdoCryptoCommons.h"

/**
 * msg61 - TO2.ProveOVHdr
 * The owner responds to the device with the OVHeader. The COSESignature.signature
 * is signed with owner Private key to start establishing that it is the
 * rightful owner of the Ownership Voucher and thus the device.
 *
 * TO2.ProveOVHdr = CoseSignature, where
 * TO2ProveOVHdrUnprotectedHeaders = (
 *   CUPHNonce:       NonceTO2ProveDv, ;; NonceTO2ProveDv is used below in TO2.ProveDevice and TO2.Done
 *   CUPHOwnerPubKey: PublicKey ;; Owner key, as hint
 * )
 * $COSEPayloads /= (
 *   TO2ProveOVHdrPayload
 * )
 * TO2ProveOVHdrPayload = [
 *   OVHeader,     ;; Ownership Voucher header as bstr
 *   NumOVEntries, ;; number of ownership voucher entries
 *   HMac,         ;; Ownership Voucher "hmac" of hdr
 *   NonceTO2ProveOV,       ;; nonce from TO2.HelloDevice
 *   eBSigInfo,    ;; Device attestation signature info
 *   xAKeyExchange ;; Key exchange first step
 *   helloDeviceHash ;; hash of HelloDevice message
 *   maxOwnerMessageSize ;;
 * ]
 */
int32_t msg61(fdo_prot_t *ps)
{
	char prot[] = "FDOProtTO2";
	int ret = -1;
	int result_memcmp = 0;
	fdo_byte_array_t *xA = NULL;
	fdo_cose_t *cose = NULL;
	fdo_byte_array_t *cose_sig_structure = NULL;
	fdo_hash_t *ovheader_pubkey_hash = NULL;
	fdo_hash_t *hello_device_hash_rcv = NULL;
	fdo_byte_array_t *ovheader = NULL;
	size_t ovheader_sz = 0;

	if (!ps) {
		LOG(LOG_ERROR, "Invalid protocol state\n");
		return ret;
	}

	/*
	 * Check that we don't exceed Round Trip Times requirements. The reason
	 * for checking here is that fdo_prot_rcv_msg() fails the first time.
	 * So, the parent loop send the contents of previous message and
	 * receives for this message, thus, housing the Round Trip Times.
	 */
	if (!fdo_check_to2_round_trips(ps)) {
		LOG(LOG_ERROR, "Max round trips reached\n");
		goto err;
	}

	if (!fdo_prot_rcv_msg(&ps->fdor, &ps->fdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	LOG(LOG_DEBUG, "TO2.ProveOVHdr started\n");

	// Allocate for cose object now. Allocate for its members when needed later.
	// Free immediately once its of no use.
	cose = fdo_alloc(sizeof(fdo_cose_t));
	if (!cose) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to alloc COSE\n");
		goto err;
	}

	if (!fdo_cose_read(&ps->fdor, cose, false)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read COSE\n");
		goto err;
	}

	// get the Owner public key & NonceTO2ProveDv from the COSE's Unprotected header and save it
	ps->owner_public_key = fdo_public_key_clone(cose->cose_uph->cuphowner_public_key);
	ps->nonce_to2provedv = fdo_byte_array_alloc(FDO_NONCE_BYTES);
	if (!ps->nonce_to2provedv) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to alloc NonceTO2ProveDv\n");
		goto err;
	}
	if (0 != memcpy_s(ps->nonce_to2provedv->bytes, FDO_NONCE_BYTES,
		&cose->cose_uph->cuphnonce, sizeof(cose->cose_uph->cuphnonce))) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to copy NonceTO2ProveDv\n");
		goto err;
	}

	if (!fdo_cose_write_sigstructure(cose->cose_ph, cose->cose_payload, NULL,
		&cose_sig_structure) || !cose_sig_structure) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to write COSE Sig_structure\n");
		goto err;
	}

	/* The signature verification over TO2.ProveOVHdr.TO2ProveOVHdrPayload must verify */
	if (!fdo_signature_verification(cose_sig_structure,
					cose->cose_signature,
					ps->owner_public_key)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: COSE signature verification failed\n");
		goto err;
	}
	LOG(LOG_DEBUG, "TO2.ProveOVHdr: COSE signature verification successful\n");
	fdo_byte_array_free(cose_sig_structure);
	cose_sig_structure = NULL;

	// verify the to1d that was received during TO1.RVRedirect, Type 33
	// Happens only when TO2 was started without RVBypass flow.
	if (ps->to1d_cose) {
		if (!fdo_cose_write_sigstructure(ps->to1d_cose->cose_ph, ps->to1d_cose->cose_payload,
			NULL, &cose_sig_structure) || !cose_sig_structure) {
			LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to write COSE Sig_structure\n");
			goto err;
		}
		if (!fdo_signature_verification(cose_sig_structure,
					ps->to1d_cose->cose_signature,
					ps->owner_public_key)) {
			LOG(LOG_ERROR, "TO2.ProveOVHdr: COSE signature verification failed\n");
			goto err;
		}
		LOG(LOG_DEBUG, "TO2.ProveOVHdr: to1d signature verification successful\n");
	}

	// clear the FDOR buffer and push COSE payload into it, essentially reusing the FDOR object.
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.b.block_size = cose->cose_payload->byte_sz;
	if (0 != memcpy_s(ps->fdor.b.block, ps->fdor.b.block_size,
		cose->cose_payload->bytes, cose->cose_payload->byte_sz)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to copy Nonce4\n");
		goto err;
	}
	fdo_cose_free(cose);
	cose = NULL;

	// initialize the parser once the buffer contains COSE payload to be decoded.
	if (!fdor_parser_init(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to initilize FDOR parser\n");
		goto err;
	}

	size_t num_payloadbasemap_items = 0;
	// check if TO2.ProveOVHdrPayload consist of all entries i.e. 8 entries
	if (!fdor_array_length(&ps->fdor, &num_payloadbasemap_items) ||
		num_payloadbasemap_items != 8) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read array length\n");
		goto err;
	}

	if (!fdor_start_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to start TO2ProveOVHdrPayload array\n");
		goto err;
	}

	// Read the bin character length
	if (!fdor_string_length(&ps->fdor, &ovheader_sz) || ovheader_sz == 0) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Unable to decode length of ProveOVHdr!\n");
		goto err;
	}

	// bstr-unwrap OVHeader
	ovheader = fdo_byte_array_alloc(ovheader_sz);
	if (!ovheader) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to alloc for OVHeader as bstr\n");
		goto err;
	}
	if (!fdor_byte_string(&ps->fdor, ovheader->bytes, ovheader->byte_sz)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read OVHeader as bstr\n");
		goto err;
	}

	// Read the OVHeader
	ps->ovoucher = fdo_ov_hdr_read(ovheader);
	if (!ps->ovoucher) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read OVHeader\n");
		goto err;
	}

	ovheader_pubkey_hash = fdo_pub_key_hash(ps->ovoucher->mfg_pub_key);
	if (!ovheader_pubkey_hash) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Hash creation of OVHeader.OVPubKey failed\n");
		goto err;
	}
	if (!fdo_compare_hashes(ovheader_pubkey_hash, ps->dev_cred->owner_blk->pkh)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to verify OVHeader.OVPubKey hash\n");
		goto err;
	}
	LOG(LOG_DEBUG, "TO2.ProveOVHdr: OVHeader.OVPubKey hash verification successful\n");

	/*
	 * Read the number of OVEntries present.
	 */
	ps->ovoucher->num_ov_entries = 0;
	if (!fdor_signed_int(&ps->fdor, &ps->ovoucher->num_ov_entries) ||
		ps->ovoucher->num_ov_entries == 0) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read NumOVEntries\n");
		goto err;
	}
	LOG(LOG_DEBUG, "TO2.ProveOVHdr: Total number of OwnershipVoucher.OVEntries: %d\n",
		ps->ovoucher->num_ov_entries);

	if (ps->ovoucher->num_ov_entries > MAX_NO_OVENTRIES) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: NumOVEntries can not be greater than 255\n");
		goto err;
	}

	ps->ovoucher->ovoucher_hdr_hash = fdo_hash_alloc_empty();
	if (!ps->ovoucher->ovoucher_hdr_hash) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to alloc HMac\n");
		goto err;
	}
	if (!fdo_hash_read(&ps->fdor, ps->ovoucher->ovoucher_hdr_hash)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read HMac\n");
		goto err;
	}

#if defined(DEVICE_CSE_ENABLED)
/**
 * Note: In the case of CSE implementation, it compares the received ovheader
 * with the existing ovheader stored during DI.
 * If verification succeeds it loads the existing HMAC.
 *
 */
	if (!fdo_ov_hdr_cse_load_hmac(ovheader, &ps->new_ov_hdr_hmac)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to calculate OVHeader HMac\n");
		goto err;
	}
#else
	if (!fdo_ov_hdr_hmac(ovheader, &ps->new_ov_hdr_hmac)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to calculate OVHeader HMac\n");
		goto err;
	}
#endif

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

	ps->nonce_to2proveov_rcv = fdo_byte_array_alloc(FDO_NONCE_BYTES);
	if (!ps->nonce_to2proveov_rcv) {
		goto err;
	}
	size_t nonce5_length = 0;
	if (!fdor_string_length(&ps->fdor, &nonce5_length) || nonce5_length != FDO_NONCE_BYTES) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Invalid/Failed to read NonceTO2ProveOV length\n");
		goto err;
	}
	if (!fdor_byte_string(&ps->fdor, ps->nonce_to2proveov_rcv->bytes,
		ps->nonce_to2proveov_rcv->byte_sz)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read NonceTO2ProveOV\n");
		goto err;
	}

	/* The nonces "NonceTO2ProveOV" from Type 60 and 61 must match */
	if (!fdo_nonce_equal(ps->nonce_to2proveov_rcv, ps->nonce_to2proveov)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Received NonceTO2ProveOV does not match with"
		"existing NonceTO2ProveOV \n");
		goto err;
	}

	// clear them now since the Nonces have served their purpose
	fdo_byte_array_free(ps->nonce_to2proveov);
	ps->nonce_to2proveov = NULL;
	fdo_byte_array_free(ps->nonce_to2proveov_rcv);
	ps->nonce_to2proveov_rcv = NULL;

	if (!fdo_siginfo_read(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read eBSigInfo\n");
		goto err;
	}

	/*
	 * Read the key exchange info. This is the first part of key exchange of
	 * info. xA is used based on DA selected.
	 */
	size_t xA_length = 8;
	if (!fdor_string_length(&ps->fdor, &xA_length)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read xAKeyExchange length\n");
		goto err;
	}
	xA = fdo_byte_array_alloc(xA_length);
	if (!xA) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to allocate memory for xAKeyExchange\n");
		goto err;
	}
	if(!fdor_byte_string(&ps->fdor, xA->bytes, xA->byte_sz)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read xAKeyExchange\n");
		goto err;
	}

	// Save CUPHOwnerPubKey for Asymmetric Key Exchange algorithm
	if (fdo_set_kex_paramA(xA, ps->owner_public_key)) {
		goto err;
	}

	hello_device_hash_rcv = fdo_hash_alloc_empty();
	if (!hello_device_hash_rcv) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to alloc for helloDeviceHash\n");
		goto err;
	}
	if (!fdo_hash_read(&ps->fdor, hello_device_hash_rcv)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read helloDeviceHash\n");
		goto err;
	}

	if (!fdo_compare_hashes(hello_device_hash_rcv, ps->hello_device_hash)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to verify helloDeviceHash\n");
		goto err;
	}

	// maxOwnerMessageSize is read, but not really used since it may require changing
	// previously allocated buffer sizes for protocol messages
	if (!fdor_unsigned_int(&ps->fdor, &ps->max_owner_message_size)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to read maxOwnerMessageSize\n");
		goto err;
	}

	if (ps->max_owner_message_size > MAX_NEGO_MSG_SIZE) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: maxOwnerMessageSize can not be greater than 65535\n");
		goto err;
	}

	if (!fdor_end_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to end TO2ProveOVHdrPayload array\n");
		goto err;
	}

	// Save the initial OVEHashPrevEntry and OVEHashHdrInfo
	ps->ovoucher->ov_entries = fdo_ov_entry_alloc_empty();
	if (!ps->ovoucher->ov_entries) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to alloc OVEntry\n");
		goto err;
	}
	if (!fdo_ove_hash_hdr_info_save(ps->ovoucher)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to save OVEHashHdrInfo\n");
		goto err;
	}
	// reset the FDOW block to prepare for OVEHashPrevEntry
	fdo_block_reset(&ps->fdow.b);
	ps->fdow.b.block_size = ps->prot_buff_sz;
	if (!fdow_encoder_init(&ps->fdow)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to initilize FDOW encoder\n");
		goto err;
	}
	if (!fdo_ove_hash_prev_entry_save(&ps->fdow, ps->ovoucher, ps->ovoucher->ovoucher_hdr_hash)) {
		LOG(LOG_ERROR, "TO2.ProveOVHdr: Failed to save OVEHashPrevEntry\n");
		goto err;
	}
	// To verify the next entry in the ownership voucher
	ps->ovoucher->ov_entries->pk = fdo_public_key_clone(ps->ovoucher->mfg_pub_key);

	/*
	 * If the TO2.ProveOVHdr.TO2ProveOVHdrPayload.NumOVEntries > 0,
	 * get next Ownership Voucher in Type 62, else jump to Type 64
	 */
	if (ps->ovoucher->num_ov_entries > 0) {
		ps->ov_entry_num = 0;
		ps->state = FDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY;
	} else {
		LOG(LOG_INFO, "No OVEntries, jumping to msg64\n");
		ps->state = FDO_STATE_TO2_SND_PROVE_DEVICE;
	}

	LOG(LOG_DEBUG, "TO2.ProveOVHdr completed. %d OVEntry(s) to follow\n",
	    ps->ovoucher->num_ov_entries);
	ret = 0; /* Mark as success */

err:
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.have_block = false;
	if (xA) {
		fdo_byte_array_free(xA);
	}
	if (cose) {
		fdo_cose_free(cose);
		cose = NULL;
	}
	if (cose_sig_structure) {
		fdo_byte_array_free(cose_sig_structure);
		cose_sig_structure = NULL;
	}
	if (ps->nonce_to2proveov_rcv != NULL) {
		fdo_byte_array_free(ps->nonce_to2proveov_rcv);
		ps->nonce_to2proveov_rcv = NULL;
	}
	if (ovheader_pubkey_hash) {
		fdo_hash_free(ovheader_pubkey_hash);
		ovheader_pubkey_hash = NULL;
	}
	if (hello_device_hash_rcv) {
		fdo_hash_free(hello_device_hash_rcv);
		hello_device_hash_rcv = NULL;
	}
	if (ovheader) {
		fdo_byte_array_free(ovheader);
		ovheader = NULL;
	}
	return ret;
}
