/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for RSA encryption routines of openssl library.
 */

#include "fdotypes.h"
#include "fdoCryptoHal.h"
#include "fdoCrypto.h"

/**
 * This function verifies if the signature message_signature of length
 * signature_length matches the signature of the message of length
 * message_length computed using public key passed in pubkey.
 * @param message In Pointer to the message
 * @param message_length In Size of the message
 * @param message_signature In Pointer to the signature of the message that is
 * to be verified
 * @param signature_length In Size of the message signature
 * @param pubkey In Pointer to the public key used to verify the signature
 * @param result Out TRUE if the signature is successfully verified, FALSE
 * if the signature does not match
 * @return 0 on success; -1 on failure. The result parameter must be checked
 * only when return value is 0.
 */
int32_t fdo_ov_verify(uint8_t *message, uint32_t message_length,
		      uint8_t *message_signature, uint32_t signature_length,
		      fdo_public_key_t *pubkey, bool *result)
{
	int32_t ret = -1;

	if (!message || !message_signature || !pubkey || !pubkey->key1 ||
	    !result) {
		return -1;
	}

	ret = crypto_hal_sig_verify(
	    pubkey->pkenc, pubkey->pkalg, message, message_length,
	    message_signature, signature_length, pubkey->key1->bytes,
	    pubkey->key1->byte_sz,
	    /* X.509 encoded pubkeys only have key1 parameter */
	    (pubkey->key2 ? pubkey->key2->bytes : NULL),
	    (pubkey->key2 ? pubkey->key2->byte_sz : 0));

	*result = (0 == ret) ? true : false;
	return ret;
}
