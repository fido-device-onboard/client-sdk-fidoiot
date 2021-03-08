/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 32.
 */

#include "util.h"
#include "sdoprot.h"
#include "sdoCrypto.h"

/**
 * msg32() - TO1.ProveToRV, Type 32
 * The device responds with the data which potentially proves to RV that it is
 * the authorized device requesting the owner information
 *
 * TO1.ProveToRV = EAToken
 * EATPayloadBase //= (
    EAT-NONCE: Nonce4
 * )
 */
int32_t msg32(sdo_prot_t *ps)
{
	int ret = -1;
	fdo_eat_payload_base_map_t payloadbasemap;
	sdo_byte_array_t *encoded_payloadbasemap = NULL;

	LOG(LOG_DEBUG, "TO1.ProveToRV started\n");

	// Allocate EAT object now. Initialize and fill the contents when needed to finally
	// CBOR encode. Free once used in this method later.
	fdo_eat_t *eat = fdo_eat_alloc();
	if (!eat) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to allocate for EAT\n");
		goto err;
	}

#if defined(ECDSA256_DA)
	eat->eat_ph->ph_sig_alg = FDO_CRYPTO_SIG_TYPE_ECSDAp256;
#else
	eat->eat_ph->ph_sig_alg = FDO_CRYPTO_SIG_TYPE_ECSDAp384;
#endif

	if (!ps->n4) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Nonce4 not found\n");
		goto err;
	}

	// copy nonce4 and GUID into the struct
	if (0 != memcpy_s(&payloadbasemap.eatnonce, SDO_NONCE_BYTES,
		ps->n4->bytes, ps->n4->byte_sz)) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to copy Nonce4\n");
		goto err;
	}
	payloadbasemap.eatueid[0] = 1;
	if (0 != memcpy_s(&payloadbasemap.eatueid[1], SDO_GUID_BYTES,
		ps->dev_cred->owner_blk->guid->bytes, ps->dev_cred->owner_blk->guid->byte_sz)) {
			LOG(LOG_ERROR, "TO1.ProveToRV: Failed to copy GUID\n");
			goto err;
	}
	payloadbasemap.eatpayloads = NULL;

	// Create the payload as CBOR map. Sign the encoded payload.
	// Then, wrap the encoded payload a a bstr.
	if (!fdo_eat_write_payloadbasemap(&ps->sdow, &payloadbasemap)) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to write EATPayloadBaseMap\n");
		goto err;
	}
	size_t payload_length = 0;
	if (!sdow_encoded_length(&ps->sdow, &payload_length) || payload_length == 0) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to read EATPayload length\n");
		goto err;
	}
	ps->sdow.b.block_size = payload_length;
	// Set the encoded payload into buffer
	encoded_payloadbasemap =
		sdo_byte_array_alloc_with_byte_array(ps->sdow.b.block, ps->sdow.b.block_size);
	if (!encoded_payloadbasemap) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to alloc for encoded EATPayload\n");
		goto err;
	}
	eat->eat_payload = encoded_payloadbasemap;

	// reset the SDOW block to prepare for the next encoding.
	sdo_block_reset(&ps->sdow.b);
	ps->sdow.b.block_size = CBOR_BUFFER_LENGTH;
	if (!sdow_encoder_init(&ps->sdow)) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to initilize SDOW encoder\n");
		goto err;
	}

	// generate the signature on encoded payload
	if (0 !=
	    sdo_device_sign(eat->eat_payload->bytes, eat->eat_payload->byte_sz,
			&eat->eat_signature)) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to generate signature\n");
		goto err;		
	}

	/* Start writing the block for msg31 */
	sdow_next_block(&ps->sdow, SDO_TO1_TYPE_PROVE_TO_SDO);

	// write the EAT structure
	if (!fdo_eat_write(&ps->sdow, eat)) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to write EAT\n");
		goto err;
	}

	/* Mark as success and move to msg 33 */
	ps->state = SDO_STATE_TO1_RCV_SDO_REDIRECT;
	ret = 0;

	LOG(LOG_DEBUG, "TO1.ProveToRV completed successfully\n");

err:
	if (eat) {
		fdo_eat_free(eat);
		eat = NULL;
	}
	return ret;
}
