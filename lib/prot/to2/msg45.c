/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg45 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
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
 *   Nonce7,         ;; proves freshness of signature
 *   Owner2Key       ;; Replacement for Owner key
 * ]
 * $COSEPayloads /= (
 *   TO2SetupDevicePayload
 * )
 */

int32_t msg65(sdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
	sdo_encrypted_packet_t *pkt = NULL;
	// fdo_cose_t *cose = NULL;

	if (!sdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	LOG(LOG_DEBUG, "TO2.SetupDevice started\n");

	/* If the packet is encrypted, decrypt it */
	pkt = sdo_encrypted_packet_read(&ps->sdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to parse encrypted packet\n");
		goto err;
	}

	if (!sdo_encrypted_packet_unwind(&ps->sdor, pkt, ps->iv)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to decrypt packet!\n");
		goto err;
	}

/*	TO-DO : This should ideally be a COSESignature object. To be updated after PRI update.
	// Allocate for cose object now. Allocate for its members when needed later.
	// Free immediately once its of no use.
	cose = sdo_alloc(sizeof(fdo_cose_t));
	if (!cose) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to alloc COSE\n");
		goto err;
	}

	if (!fdo_cose_read(&ps->sdor, cose, false)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read COSE\n");
		goto err;
	}

	// clear the SDOR buffer and push COSE payload into it, essentially reusing the SDOR object.
	sdo_block_reset(&ps->sdor.b);
	ps->sdor.b.block_size = cose->cose_payload->byte_sz;
	if (0 != memcpy_s(ps->sdor.b.block, ps->sdor.b.block_size,
		cose->cose_payload->bytes, cose->cose_payload->byte_sz)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to copy COSE payload\n");
		goto err;
	}

	// initialize the parser once the buffer contains COSE payload to be decoded.
	if (!sdor_parser_init(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to initilize SDOR parser\n");
		goto err;
	}
*/

	if (!sdor_start_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read start array\n");
		goto err;
	}
	/* Create the destination of this final data */
	ps->osc = sdo_owner_supplied_credentials_alloc();
	if (ps->osc == NULL) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to alloc for new set of credentials\n");
		goto err;
	}

	// update the replacement RendezvousInfo 
	ps->osc->rvlst = sdo_rendezvous_list_alloc();
	if (!ps->osc->rvlst) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to alloc for replacement RendezvousInfo\n");
		goto err;
	}

	if (!sdo_rendezvous_list_read(&ps->sdor, ps->osc->rvlst)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read replacement RendezvousInfo\n");
		goto err;
	}

	// update the replacement Guid
	size_t guid_length = 0;
	if (!sdor_string_length(&ps->sdor, &guid_length) ||
		guid_length != SDO_GUID_BYTES) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read replacement GUID length\n");
		goto err;
	}
	ps->osc->guid = sdo_byte_array_alloc(guid_length);
	if (!ps->osc->guid) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to alloc for replacement GUID\n");
		goto err;
	}
	if (!sdor_byte_string(&ps->sdor, ps->osc->guid->bytes, ps->osc->guid->byte_sz)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read replacement GUID\n");
		goto err;
	}

	size_t nonce7_length = 0;
	if (!sdor_string_length(&ps->sdor, &nonce7_length) ||
		nonce7_length != SDO_NONCE_BYTES) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read Nonce7 length\n");
		goto err;
	}

	ps->n7r = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n7r) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to alloc Nonce7\n");
		goto err;
	}
	if (!sdor_byte_string(&ps->sdor, ps->n7r->bytes, SDO_NONCE_BYTES)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read rNonce7\n");
		goto err;
	}

	if (!sdo_nonce_equal(ps->n7r, ps->n7)) {
		LOG(LOG_ERROR,
			"TO2.SetupDevice: Received Nonce7 does not match with existing Nonce7\n");
		goto err;
	}

	// update the replacement Owner key (Owner2Key)
	ps->osc->pubkey = sdo_public_key_read(&ps->sdor);
	if (!ps->osc->pubkey) {
		LOG(LOG_ERROR,
			"TO2.SetupDevice: Failed to read replacement Owner key (Owner2Key)\n");
		goto err;
	}

	if (!sdor_end_array(&ps->sdor)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to read end array\n");
		goto err;
	}

/*	Same as above comment. TBD later
	// verify the received COSE signature
	if (!sdo_signature_verification(cose->cose_payload,
					cose->cose_signature,
					ps->osc->pubkey)) {
		LOG(LOG_ERROR, "TO2.SetupDevice: Failed to verify OVEntry signature\n");
		goto err;
	}
	LOG(LOG_DEBUG, "TO2.SetupDevice: OVEntry Signature verification successful\n");
*/
	ps->state = SDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO;
	LOG(LOG_DEBUG, "TO2.SetupDevice completed successfully\n");
	ret = 0; /* Marks as success */

err:
	sdor_flush(&ps->sdor);
	ps->sdor.have_block = false;
/*
	if (cose) {
		fdo_cose_free(cose);
		cose = NULL;
	}
*/
	return ret;
}
