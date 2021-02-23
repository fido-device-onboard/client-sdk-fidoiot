/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg44 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"
#include "sdoCrypto.h"

/**
 * msg64() - TO2.ProveDevice
 * The device sends out data proving that it is authentic device.
 * TO2.ProveDevice = EAToken
 * $$EATPayloadBase //= (
 *   EAT-NONCE: Nonce6
 * )
 * TO2ProveDevicePayload = [
 *   xBKeyExchange
 * ]
 * $EATUnprotectedHeaders /= (
 *   EUPHNonce: Nonce7 ;; Nonce7 is used in TO2.SetupDevice and TO2.Done2
 * )
 * $EATPayloads /= (
 *   TO2ProveDevicePayload
 * )
 */
int32_t msg64(sdo_prot_t *ps)
{
	int ret = -1;

	fdo_eat_payload_base_map_t payloadbasemap;
	sdo_byte_array_t *encoded_payloadbasemap = NULL;

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

	if (!ps->n6) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Nonce6 not found\n");
		goto err;
	}

	// copy Nonce6 and GUID into the struct
	if (0 != memcpy_s(&payloadbasemap.eatnonce, SDO_NONCE_BYTES,
		ps->n6->bytes, ps->n6->byte_sz)) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to copy Nonce6\n");
		goto err;
	}
	payloadbasemap.eatueid[0] = 1;
	if (0 != memcpy_s(&payloadbasemap.eatueid[1], SDO_GUID_BYTES,
		ps->dev_cred->owner_blk->guid->bytes, ps->dev_cred->owner_blk->guid->byte_sz)) {
			LOG(LOG_ERROR, "TO2.ProveDevice: Failed to copy GUID\n");
			goto err;
	}

	/* Get the second part of Key Exchange */
	payloadbasemap.eatpayloads = NULL;
	ret = sdo_get_kex_paramB(&payloadbasemap.eatpayloads);
	if (0 != ret || !payloadbasemap.eatpayloads) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to generate xBKeyExchange\n");
		goto err;
	}
	ret = -1;

	// reset the given SDOW for the next encoding
	// This is done out of cycle here because SDOW object was used in Type 63
	sdo_block_reset(&ps->sdow.b);
	ps->sdow.b.block_size = CBOR_BUFFER_LENGTH;
	if (!sdow_encoder_init(&ps->sdow)) {
		LOG(LOG_ERROR, "OVEHashPrevEntry: Failed to initialize SDOW encoder\n");
		goto err;
	}

	// Create the payload as CBOR map. Sign the encoded payload.
	// Then, wrap the encoded payload as a bstr later.
	if (!fdo_eat_write_payloadbasemap(&ps->sdow, &payloadbasemap)) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to write EATPayloadBaseMap\n");
		goto err;
	}
	size_t payload_length = 0;
	if (!sdow_encoded_length(&ps->sdow, &payload_length) || payload_length == 0) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to read EATPayload length\n");
		goto err;
	}
	ps->sdow.b.block_size = payload_length;

	LOG(LOG_DEBUG, "TO2.ProveDevice: EATPayloadBaseMap created successfuly\n");

	// Set the encoded payload into buffer
	encoded_payloadbasemap =
		sdo_byte_array_alloc_with_byte_array(ps->sdow.b.block, ps->sdow.b.block_size);
	if (!encoded_payloadbasemap) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to copy encoded EATPayload\n");
		goto err;
	}
	eat->eat_payload = encoded_payloadbasemap;

	// reset the SDOW block to prepare for the next encoding.
	sdo_block_reset(&ps->sdow.b);
	ps->sdow.b.block_size = CBOR_BUFFER_LENGTH;
	if (!sdow_encoder_init(&ps->sdow)) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to initilize SDOW encoder\n");
		goto err;
	}

	// generate the signature on encoded payload
	if (0 !=
	    sdo_device_sign(eat->eat_payload->bytes, eat->eat_payload->byte_sz,
			&eat->eat_signature)) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to generate signature\n");
		goto err;		
	}

	// Set the EAT.UnprotectedHeader contents
	ps->n7 = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n7) {
		LOG(LOG_ERROR, "Alloc failed \n");
		goto err;
	}
	sdo_nonce_init_rand(ps->n7);

	// copy Nonce7 into the struct
	eat->eat_uph->euphnonce = sdo_byte_array_alloc_with_byte_array(ps->n7->bytes, ps->n7->byte_sz);
	if (!eat->eat_uph->euphnonce) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to copy Nonce7 into EUPHNonce\n");
		goto err;
	}

	sdow_next_block(&ps->sdow, SDO_TO2_PROVE_DEVICE);
	// write the EAT structure
	if (!fdo_eat_write(&ps->sdow, eat)) {
		LOG(LOG_ERROR, "TO2.ProveDevice: Failed to write EAT\n");
		goto err;
	}

	ret = 0; /* Mark as success */
	ps->state = SDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO;
	LOG(LOG_DEBUG, "TO2.ProveDevice comleted successfully\n");
err:
	if (eat)
		fdo_eat_free(eat);
	return ret;
}
