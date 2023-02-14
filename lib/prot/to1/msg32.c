/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 32.
 */

#include "util.h"
#include "fdoprot.h"
#include "fdoCrypto.h"

/**
 * msg32() - TO1.ProveToRV, Type 32
 * The device responds with the data which potentially proves to RV that it is
 * the authorized device requesting the owner information
 *
 * TO1.ProveToRV = EAToken
 * EATPayloadBase //= (
    EAT-NONCE: NonceTO1Proof
 * )
 */
int32_t msg32(fdo_prot_t *ps)
{
	int ret = -1;
	fdo_eat_payload_base_map_t payloadbasemap;
	fdo_byte_array_t *encoded_payloadbasemap = NULL;
	fdo_byte_array_t *eat_sig_structure = NULL;

	if (!ps) {
		LOG(LOG_ERROR, "Invalid protocol state\n");
		return ret;
	}

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

	if (!ps->nonce_to1proof) {
		LOG(LOG_ERROR, "TO1.ProveToRV: NonceTO1Proof not found\n");
		goto err;
	}

	// copy nonce4 and GUID into the struct
	if (0 != memcpy_s(&payloadbasemap.eatnonce, FDO_NONCE_BYTES,
		ps->nonce_to1proof->bytes, ps->nonce_to1proof->byte_sz)) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to copy NonceTO1Proof\n");
		goto err;
	}
	payloadbasemap.eatueid[0] = 1;
	if (0 != memcpy_s(&payloadbasemap.eatueid[1], FDO_GUID_BYTES,
		ps->dev_cred->owner_blk->guid->bytes, ps->dev_cred->owner_blk->guid->byte_sz)) {
			LOG(LOG_ERROR, "TO1.ProveToRV: Failed to copy GUID\n");
			goto err;
	}
	payloadbasemap.eatpayloads = NULL;

	// Create the payload as CBOR map. Sign the encoded payload.
	// Then, wrap the encoded payload a a bstr.
	if (!fdo_eat_write_payloadbasemap(&ps->fdow, &payloadbasemap)) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to write EATPayloadBaseMap\n");
		goto err;
	}
	size_t payload_length = 0;
	if (!fdow_encoded_length(&ps->fdow, &payload_length) || payload_length == 0) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to read EATPayload length\n");
		goto err;
	}
	ps->fdow.b.block_size = payload_length;
	// Set the encoded payload into buffer
	encoded_payloadbasemap =
		fdo_byte_array_alloc_with_byte_array(ps->fdow.b.block, ps->fdow.b.block_size);
	if (!encoded_payloadbasemap) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to alloc for encoded EATPayload\n");
		goto err;
	}
	eat->eat_payload = encoded_payloadbasemap;

	// reset the FDOW block to prepare for the next encoding.
	fdo_block_reset(&ps->fdow.b);
	ps->fdow.b.block_size = ps->prot_buff_sz;
	if (!fdow_encoder_init(&ps->fdow)) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to initilize FDOW encoder\n");
		goto err;
	}

	if (!fdo_eat_write_sigstructure(eat->eat_ph, eat->eat_payload, NULL,
		&eat_sig_structure) || !eat_sig_structure) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to write COSE Sig_structure\n");
		goto err;
	}

	fdo_byte_array_t *eat_maroe = NULL;
	// generate the signature on Sig_structure
	if (0 !=
	    fdo_device_sign(eat_sig_structure->bytes, eat_sig_structure->byte_sz,
			&eat->eat_signature, &eat_maroe)) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to generate signature\n");
		goto err;
	}
#if defined(DEVICE_CSE_ENABLED)
	eat->eat_uph->eatmaroeprefix = eat_maroe;
#endif


	/* Start writing the block for msg31 */
	fdow_next_block(&ps->fdow, FDO_TO1_TYPE_PROVE_TO_FDO);

	// write the EAT structure
	if (!fdo_eat_write(&ps->fdow, eat)) {
		LOG(LOG_ERROR, "TO1.ProveToRV: Failed to write EAT\n");
		goto err;
	}

	/* Mark as success and move to msg 33 */
	ps->state = FDO_STATE_TO1_RCV_FDO_REDIRECT;
	ret = 0;

	LOG(LOG_DEBUG, "TO1.ProveToRV completed successfully\n");

err:
	if (eat) {
		fdo_eat_free(eat);
		eat = NULL;
	}
	if (eat_sig_structure) {
		fdo_byte_array_free(eat_sig_structure);
		eat_sig_structure = NULL;
	}
	return ret;
}
