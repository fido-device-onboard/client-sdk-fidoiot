/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg64 of TO2 state machine.
 */

#include "fdoprot.h"
#include "fdokeyexchange.h"
#include "util.h"
#include "fdoCrypto.h"

/**
 * msg64() - TO2.ProveDevice
 * The device sends out data proving that it is authentic device.
 * TO2.ProveDevice = EAToken
 * $$EATPayloadBase //= (
 *   EAT-NONCE: NonceTO2ProveDv
 * )
 * TO2ProveDevicePayload = [
 *   xBKeyExchange
 * ]
 * $EATUnprotectedHeaders /= (
 *   EUPHNonce: NonceTO2SetupDv ;; NonceTO2SetupDv is used in TO2.SetupDevice and TO2.Done2
 * )
 * $EATPayloads /= (
 *   TO2ProveDevicePayload
 * )
 */
int32_t msg64(fdo_prot_t *ps)
{
	int ret = -1;

	fdo_eat_payload_base_map_t payloadbasemap;
	fdo_byte_array_t *encoded_payloadbasemap = NULL;
	fdo_byte_array_t *eat_sig_structure = NULL;

	if (!ps) {
		LOG(LOG_ERROR, "Invalid protocol state\n");
		return ret;
	}

	LOG(LOG_DEBUG, "TO2.ProveDevice started\n");

	// Allocate EAT object now. Initialize and fill the contents when needed to finally
	// CBOR encode. Free once used in this method later.
	fdo_eat_t *eat = fdo_eat_alloc();
	if (!eat) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to allocate for EAT\n");
		goto err;
	}

#if defined(ECDSA256_DA)
	eat->eat_ph->ph_sig_alg = FDO_CRYPTO_SIG_TYPE_ECSDAp256;
#else
	eat->eat_ph->ph_sig_alg = FDO_CRYPTO_SIG_TYPE_ECSDAp384;
#endif

	if (!ps->nonce_to2provedv) {
		LOG(LOG_ERROR, "TO2.ProveDevice: NonceTO2ProveDv not found\n");
		goto err;
	}

	// copy NonceTO2ProveDv and GUID into the struct
	if (0 != memcpy_s(&payloadbasemap.eatnonce, FDO_NONCE_BYTES,
		ps->nonce_to2provedv->bytes, ps->nonce_to2provedv->byte_sz)) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to copy NonceTO2ProveDv\n");
		goto err;
	}
	payloadbasemap.eatueid[0] = 1;
	if (0 != memcpy_s(&payloadbasemap.eatueid[1], FDO_GUID_BYTES,
		ps->dev_cred->owner_blk->guid->bytes, ps->dev_cred->owner_blk->guid->byte_sz)) {
			LOG(LOG_ERROR, "TO2.ProveDevice: Failed to copy GUID\n");
			goto err;
	}

	/* Get the second part of Key Exchange */
	payloadbasemap.eatpayloads = NULL;
	ret = fdo_get_kex_paramB(&payloadbasemap.eatpayloads);
	if (0 != ret || !payloadbasemap.eatpayloads) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to generate xBKeyExchange\n");
		goto err;
	}
	ret = -1;

	// reset the given FDOW for the next encoding
	// This is done out of cycle here because FDOW object was used in Type 63
	fdo_block_reset(&ps->fdow.b);
	ps->fdow.b.block_size = ps->prot_buff_sz;
	if (!fdow_encoder_init(&ps->fdow)) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to initialize FDOW encoder\n");
		goto err;
	}

	// Create the payload as CBOR map. Sign the encoded payload.
	// Then, wrap the encoded payload as a bstr later.
	if (!fdo_eat_write_payloadbasemap(&ps->fdow, &payloadbasemap)) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to write EATPayloadBaseMap\n");
		goto err;
	}
	size_t payload_length = 0;
	if (!fdow_encoded_length(&ps->fdow, &payload_length) || payload_length == 0) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to read EATPayload length\n");
		goto err;
	}
	ps->fdow.b.block_size = payload_length;

	LOG(LOG_DEBUG, "TO2.ProveDevice: EATPayloadBaseMap created successfuly\n");

	// Set the encoded payload into buffer
	encoded_payloadbasemap =
		fdo_byte_array_alloc_with_byte_array(ps->fdow.b.block, ps->fdow.b.block_size);
	if (!encoded_payloadbasemap) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to copy encoded EATPayload\n");
		goto err;
	}
	eat->eat_payload = encoded_payloadbasemap;

	// reset the FDOW block to prepare for the next encoding.
	fdo_block_reset(&ps->fdow.b);
	ps->fdow.b.block_size = ps->prot_buff_sz;
	if (!fdow_encoder_init(&ps->fdow)) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to initilize FDOW encoder\n");
		goto err;
	}

	if (!fdo_eat_write_sigstructure(eat->eat_ph, eat->eat_payload, NULL,
		&eat_sig_structure) || !eat_sig_structure) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to write COSE Sig_structure\n");
		goto err;
	}

	// generate the signature on encoded Sig_structure
	fdo_byte_array_t *eat_maroe = NULL;
	if (0 !=
	    fdo_device_sign(eat_sig_structure->bytes, eat_sig_structure->byte_sz,
			&eat->eat_signature, &eat_maroe)) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to generate signature\n");
		goto err;
	}
#if defined(DEVICE_CSE_ENABLED)
	eat->eat_uph->eatmaroeprefix = eat_maroe;
#endif

	// Set the EAT.UnprotectedHeader contents
	ps->nonce_to2setupdv = fdo_byte_array_alloc(FDO_NONCE_BYTES);
	if (!ps->nonce_to2setupdv) {
		LOG(LOG_ERROR, "Alloc failed \n");
		goto err;
	}
	fdo_nonce_init_rand(ps->nonce_to2setupdv);

	// copy NonceTO2SetupDv into the struct
	eat->eat_uph->euphnonce = fdo_byte_array_alloc_with_byte_array(
		ps->nonce_to2setupdv->bytes, ps->nonce_to2setupdv->byte_sz);
	if (!eat->eat_uph->euphnonce) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to copy NonceTO2SetupDv into EUPHNonce\n");
		goto err;
	}

	fdow_next_block(&ps->fdow, FDO_TO2_PROVE_DEVICE);
	// write the EAT structure
	if (!fdo_eat_write(&ps->fdow, eat)) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to write EAT\n");
		goto err;
	}

	ret = 0; /* Mark as success */
	ps->state = FDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO;
	LOG(LOG_DEBUG, "TO2.ProveDevice comleted successfully\n");
err:
	if (eat) {
		fdo_eat_free(eat);
	}
	if (eat_sig_structure) {
		fdo_byte_array_free(eat_sig_structure);
		eat_sig_structure = NULL;
	}
	return ret;
}
