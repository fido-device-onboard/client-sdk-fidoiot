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
#include "sdoCryptoApi.h"

/**
 * msg40() - TO2.HelloDevice
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
 *     "eA": SigInfo # Same as sent in msg30 to Rendezvous Server (RV)
 * }
 * --- Message Format Ends ---
 */
int32_t msg40(SDOProt_t *ps)
{
	int ret = -1;
	char buf[DEBUGBUFSZ] = {0};
	SDOString_t *kx = sdoGetDeviceKexMethod();
	SDOString_t *cs = sdoGetDeviceCryptoSuite();

	LOG(LOG_DEBUG, "SDO_STATE_T02_SND_HELLO_DEVICE: Starting\n");

	sdoWNextBlock(&ps->sdow, SDO_TO2_HELLO_DEVICE);

	/* Begin the message */
	sdoWBeginObject(&ps->sdow);

	/* Fill in the GUID */
	sdoWriteTag(&ps->sdow, "g2");
	sdoByteArrayWriteChars(&ps->sdow, ps->g2);

	/* Fill in the Nonce */
	sdoWriteTag(&ps->sdow, "n5");
	ps->n5 = sdoByteArrayAlloc(SDO_NONCE_BYTES);
	if (!ps->n5) {
		LOG(LOG_ERROR, "Out of memory for n5 (nonce)\n");
		goto err;
	}
	sdoNonceInitRand(ps->n5);
	LOG(LOG_DEBUG, "Sending n5: %s\n",
	    sdoNonceToString(ps->n5->bytes, buf, sizeof buf) ? buf : "");
	sdoByteArrayWriteChars(&ps->sdow, ps->n5);

	/* Fill in the public key encoding */
	sdoWriteTag(&ps->sdow, "pe");
	sdoWriteUInt(&ps->sdow, ps->keyEncoding);

	/* Fill in the key exchange */
	sdoWriteTag(&ps->sdow, "kx");
	sdoWriteStringLen(&ps->sdow, kx->bytes, kx->byteSz);

	/* Fill in the ciphersuite info */
	sdoWriteTag(&ps->sdow, "cs");
	sdoWriteStringLen(&ps->sdow, cs->bytes, cs->byteSz);

	/* Write the eA info */
	sdoWriteTag(&ps->sdow, "eA");
	sdoGidWrite(&ps->sdow);

	/* Close the JSON object */
	sdoWEndObject(&ps->sdow);

	/* Mark to move to next message */
	ps->state = SDO_STATE_TO2_RCV_PROVE_OVHDR;
	ret = 0;
	LOG(LOG_DEBUG, "SDO_STATE_T02_SND_HELLO_DEVICE: Complete\n");

err:
	return ret;
}
