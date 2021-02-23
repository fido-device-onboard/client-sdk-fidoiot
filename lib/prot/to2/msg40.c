/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg40 of TO2
 */

#include "sdoprot.h"
#include "util.h"
#include "sdoCrypto.h"

/**
 * msg60() - TO2.Hello_device
 * This message starts the Transfer of ownership of device to new owner. The
 * device sends some parameters to setup up trust with the owner
 *
 * TO2.HelloDevice = [
 *   Guid,
 *   Nonce5,
 *   kexSuiteName,
 *   cipherSuiteName,
 *   eASigInfo
 * ]
 */
int32_t msg60(sdo_prot_t *ps)
{
	int ret = -1;
	char buf[SDO_NONCE_BYTES] = {0};
	sdo_string_t *kx = sdo_get_device_kex_method();
	sdo_string_t *cs = sdo_get_device_crypto_suite();

	LOG(LOG_DEBUG, "TO2.HelloDevice started\n");

	sdow_next_block(&ps->sdow, SDO_TO2_HELLO_DEVICE);

	/* Begin the message */
	if (!sdow_start_array(&ps->sdow, 5)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to start array\n");
		return false;
	}

	/* Fill in the GUID */
	if (!sdow_byte_string(&ps->sdow, ps->g2->bytes, ps->g2->byte_sz)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to write Guid\n");
		return false;
	}

	/* Fill in the Nonce */
	ps->n5 = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n5) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to allocate memory for Nonce5\n");
		goto err;
	}
	sdo_nonce_init_rand(ps->n5);
	if (!sdow_byte_string(&ps->sdow, ps->n5->bytes, ps->n5->byte_sz)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to write Nonce5\n");
		return false;
	}

	LOG(LOG_DEBUG, "TO2.HelloDevice: Sending Nonce5: %s\n",
	    sdo_nonce_to_string(ps->n5->bytes, buf, sizeof buf) ? buf : "");

	/* Fill in the key exchange */
	if (!sdow_text_string(&ps->sdow, kx->bytes, kx->byte_sz)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to write kexSuiteName\n");
		return false;
	}

	/* Fill in the ciphersuite info */
	if (!sdow_text_string(&ps->sdow, cs->bytes, cs->byte_sz)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to write cipherSuiteName\n");
		return false;
	}

	/* Write the eA info */
	if (!sdo_siginfo_write(&ps->sdow)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to write eASigInfo\n");
		return false;
	}

	if (!sdow_end_array(&ps->sdow)) {
		LOG(LOG_ERROR, "TO2.HelloDevice: Failed to end array\n");
		return false;
	}

	/* Mark to move to next message */
	ps->state = SDO_STATE_TO2_RCV_PROVE_OVHDR;
	ret = 0;
	LOG(LOG_DEBUG, "TO2.HelloDevice completed successfully\n");

err:
	return ret;
}
