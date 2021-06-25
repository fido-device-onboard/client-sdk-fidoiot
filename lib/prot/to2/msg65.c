/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg65 of TO2 state machine.
 */

#include "fdoprot.h"
#include "fdokeyexchange.h"
#include "util.h"
#include "safe_lib.h"

/**
 * msg65() - TO2.SetupDevice
 * So, the owner has verified that it is talking to right device and
 * is receiving the next Owner's credentials.
 * 
 * TO2.SetupDevice = CoseSignature
 * TO2SetupDevicePayload = [
 *   RendezvousInfo, ;; RendezvousInfo replacement
 *   Guid,           ;; GUID replacement
 *   NonceTO2SetupDv,         ;; proves freshness of signature
 *   Owner2Key       ;; Replacement for Owner key
 * ]
 * $COSEPayloads /= (
 *   TO2SetupDevicePayload
 * )
 */

int32_t msg65(fdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "FDOProtTO2";
	fdo_encrypted_packet_t *pkt = NULL;
	fdo_cose_t *cose = NULL;

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

	LOG(LOG_DEBUG, "TO2.SetupDevice started\n");

	/* If the packet is encrypted, decrypt it */
	pkt = fdo_encrypted_packet_read(&ps->fdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to parse encrypted packet\n");
		goto err;
	}

	if (!fdo_encrypted_packet_unwind(&ps->fdor, pkt)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to decrypt packet!\n");
		goto err;
	}

	// Allocate for cose object now. Allocate for its members when needed later.
	// Free immediately once its of no use.
	cose = fdo_alloc(sizeof(fdo_cose_t));
	if (!cose) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to alloc COSE\n");
		goto err;
	}

	if (!fdo_cose_read(&ps->fdor, cose, true)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read COSE\n");
		goto err;
	}

	// clear the FDOR buffer and push COSE payload into it, essentially reusing the FDOR object.
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.b.block_size = cose->cose_payload->byte_sz;
	if (0 != memcpy_s(ps->fdor.b.block, ps->fdor.b.block_size,
		cose->cose_payload->bytes, cose->cose_payload->byte_sz)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to copy COSE payload\n");
		goto err;
	}

	// initialize the parser once the buffer contains COSE payload to be decoded.
	if (!fdor_parser_init(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to initilize FDOR parser\n");
		goto err;
	}

	if (!fdor_start_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read start array\n");
		goto err;
	}
	/* Create the destination of this final data */
	ps->osc = fdo_owner_supplied_credentials_alloc();
	if (ps->osc == NULL) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to alloc for new set of credentials\n");
		goto err;
	}

	// update the replacement RendezvousInfo 
	ps->osc->rvlst = fdo_rendezvous_list_alloc();
	if (!ps->osc->rvlst) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to alloc for replacement RendezvousInfo\n");
		goto err;
	}

	if (!fdo_rendezvous_list_read(&ps->fdor, ps->osc->rvlst)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read replacement RendezvousInfo\n");
		goto err;
	}

	// update the replacement Guid
	size_t guid_length = 0;
	if (!fdor_string_length(&ps->fdor, &guid_length) ||
		guid_length != FDO_GUID_BYTES) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read replacement GUID length\n");
		goto err;
	}
	ps->osc->guid = fdo_byte_array_alloc(guid_length);
	if (!ps->osc->guid) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to alloc for replacement GUID\n");
		goto err;
	}
	if (!fdor_byte_string(&ps->fdor, ps->osc->guid->bytes, ps->osc->guid->byte_sz)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read replacement GUID\n");
		goto err;
	}

	size_t nonce7_length = 0;
	if (!fdor_string_length(&ps->fdor, &nonce7_length) ||
		nonce7_length != FDO_NONCE_BYTES) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read NonceTO2SetupDv length\n");
		goto err;
	}

	ps->nonce_to2setupdv_rcv = fdo_byte_array_alloc(FDO_NONCE_BYTES);
	if (!ps->nonce_to2setupdv_rcv) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to alloc NonceTO2SetupDv\n");
		goto err;
	}
	if (!fdor_byte_string(&ps->fdor, ps->nonce_to2setupdv_rcv->bytes, FDO_NONCE_BYTES)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read NonceTO2SetupDv\n");
		goto err;
	}

	if (!fdo_nonce_equal(ps->nonce_to2setupdv_rcv, ps->nonce_to2setupdv)) {
		LOG(LOG_ERROR,
			"TO2.SetupDevice: Received NonceTO2SetupDv does not match with existing NonceTO2SetupDv\n");
		goto err;
	}

	// update the replacement Owner key (Owner2Key)
	ps->osc->pubkey = fdo_public_key_read(&ps->fdor);
	if (!ps->osc->pubkey) {
		LOG(LOG_ERROR,
			"TO2.SetupDevice: Failed to read replacement Owner key (Owner2Key)\n");
		goto err;
	}

	if (!fdor_end_array(&ps->fdor)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read end array\n");
		goto err;
	}

	// verify the received COSE signature
	if (!fdo_signature_verification(cose->cose_payload,
					cose->cose_signature,
					ps->osc->pubkey)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to verify OVEntry signature\n");
		goto err;
	}
	LOG(LOG_DEBUG, "TO2.SetupDevice: OVEntry Signature verification successful\n");

	ps->state = FDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO;
	LOG(LOG_DEBUG, "TO2.SetupDevice completed successfully\n");
	ret = 0; /* Marks as success */

err:
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.have_block = false;

	if (cose) {
		fdo_cose_free(cose);
		cose = NULL;
	}

	return ret;
}
