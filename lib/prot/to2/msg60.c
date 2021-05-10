/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg40 of TO2
 */

#include "fdoprot.h"
#include "util.h"
#include "fdoCrypto.h"

/**
 * msg60() - TO2.Hello_device
 * This message starts the Transfer of ownership of device to new owner. The
 * device sends some parameters to setup up trust with the owner
 *
 * TO2.HelloDevice = [
 *   Guid,
 *   NonceTO2ProveOV,
 *   kexSuiteName,
 *   cipherSuiteName,
 *   eASigInfo
 * ]
 */
int32_t msg60(fdo_prot_t *ps)
{
	int ret = -1;
	fdo_string_t *kx = fdo_get_device_kex_method();
	fdo_string_t *cs = fdo_get_device_crypto_suite();

	LOG(LOG_DEBUG, "TO2.HelloDevice started\n");

	fdow_next_block(&ps->fdow, FDO_TO2_HELLO_DEVICE);

	/* Begin the message */
	if (!fdow_start_array(&ps->fdow, 5)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to start array\n");
		return false;
	}

	/* Fill in the GUID */
	if (!fdow_byte_string(&ps->fdow, ps->g2->bytes, ps->g2->byte_sz)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to write Guid\n");
		return false;
	}

	/* Fill in the Nonce */
	ps->nonce_to2proveov = fdo_byte_array_alloc(FDO_NONCE_BYTES);
	if (!ps->nonce_to2proveov) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to allocate memory for NonceTO2ProveOV\n");
		goto err;
	}
	fdo_nonce_init_rand(ps->nonce_to2proveov);
	if (!fdow_byte_string(&ps->fdow, ps->nonce_to2proveov->bytes, ps->nonce_to2proveov->byte_sz)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to write NonceTO2ProveOV\n");
		return false;
	}

	/* Fill in the key exchange */
	if (!fdow_text_string(&ps->fdow, kx->bytes, kx->byte_sz)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to write kexSuiteName\n");
		return false;
	}

	/* Fill in the ciphersuite info */
	if (!fdow_text_string(&ps->fdow, cs->bytes, cs->byte_sz)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to write cipherSuiteName\n");
		return false;
	}

	/* Write the eA info */
	if (!fdo_siginfo_write(&ps->fdow)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to write eASigInfo\n");
		return false;
	}

	if (!fdow_end_array(&ps->fdow)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to end array\n");
		return false;
	}

	/* Mark to move to next message */
	ps->state = FDO_STATE_TO2_RCV_PROVE_OVHDR;
	ret = 0;
	LOG(LOG_DEBUG, "TO2.HelloDevice completed successfully\n");

err:
	return ret;
}
