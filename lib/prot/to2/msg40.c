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
 * msg40() - TO2.Hello_device
 * This message starts the Transfer of ownership of device to new owner. The
 * device sends some parameters to setup up trust with the owner
 *
 * --- Message Format Begins ---
 * {
 *     "g2": GUID,   # GUID received from Manufacturer during DI
 *     "n5": Nonce,  # A random number to be used TODO: where?
 *     "pe": Uint8,  # Public key encoding (RSA, ECDSA)
 *     "kx": String, # Key exchange suite name (ASYM, RSA, ECDH)
 *     "cs": String, # Ciphersuite name
 *     "iv": IVData, # 12 bytes for CTR mode, 16 bytes for CBC
 *     "eA": Sig_info # Same as sent in msg30 to Rendezvous Server (RV)
 * }
 * --- Message Format Ends ---
 */
int32_t msg40(sdo_prot_t *ps)
{
	int ret = -1;
	char buf[DEBUGBUFSZ] = {0};
	sdo_string_t *kx = sdo_get_device_kex_method();
	sdo_string_t *cs = sdo_get_device_crypto_suite();

	LOG(LOG_DEBUG, "SDO_STATE_T02_SND_HELLO_DEVICE: Starting\n");

	sdow_next_block(&ps->sdow, SDO_TO2_HELLO_DEVICE);

	/* Begin the message */
	sdow_begin_object(&ps->sdow);

	/* Fill in the GUID */
	sdo_write_tag(&ps->sdow, "g2");
	sdo_byte_array_write_chars(&ps->sdow, ps->g2);

	/* Fill in the Nonce */
	sdo_write_tag(&ps->sdow, "n5");
	ps->n5 = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n5) {
		LOG(LOG_ERROR, "Out of memory for n5 (nonce)\n");
		goto err;
	}
	sdo_nonce_init_rand(ps->n5);
	LOG(LOG_DEBUG, "Sending n5: %s\n",
	    sdo_nonce_to_string(ps->n5->bytes, buf, sizeof buf) ? buf : "");
	sdo_byte_array_write_chars(&ps->sdow, ps->n5);

	/* Fill in the public key encoding */
	sdo_write_tag(&ps->sdow, "pe");
	sdo_writeUInt(&ps->sdow, ps->key_encoding);

	/* Fill in the key exchange */
	sdo_write_tag(&ps->sdow, "kx");
	sdo_write_string_len(&ps->sdow, kx->bytes, kx->byte_sz);

	/* Fill in the ciphersuite info */
	sdo_write_tag(&ps->sdow, "cs");
	sdo_write_string_len(&ps->sdow, cs->bytes, cs->byte_sz);

	/* Write the eA info */
	sdo_write_tag(&ps->sdow, "eA");
	sdo_gid_write(&ps->sdow);

	/* Close the JSON object */
	sdow_end_object(&ps->sdow);

	/* Mark to move to next message */
	ps->state = SDO_STATE_TO2_RCV_PROVE_OVHDR;
	ret = 0;
	LOG(LOG_DEBUG, "SDO_STATE_T02_SND_HELLO_DEVICE: Complete\n");

err:
	return ret;
}
