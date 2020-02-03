/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for RSA encryption routines of openssl library.
 */

#include "sdotypes.h"
#include "sdoCryptoHal.h"
#include "sdoCryptoApi.h"

/**
 * This function verifies if the signature messageSignature of length
 * signatureLength matches the signature of the message of length messageLength
 * computed using public key passed in pubkey.
 * @param message In Pointer to the message
 * @param messageLength In Size of the message
 * @param messageSignature In Pointer to the signature of the message that is
 * to be verified
 * @param signatureLength In Size of the message signature
 * @param pubkey In Pointer to the public key used to verify the signature
 * @param result Out TRUE if the signature is successfully verified, FALSE
 * if the signature does not match
 * @return 0 on success; -1 on failure. The result parameter must be checked
 * only when return value is 0.
 */
int32_t sdoOVVerify(uint8_t *message, uint32_t messageLength,
		    uint8_t *messageSignature, uint32_t signatureLength,
		    SDOPublicKey_t *pubkey, bool *result)
{
	int32_t ret = -1;

	if (!message || !messageSignature || !pubkey || !pubkey->key1 ||
	    !result) {
		return -1;
	}

	ret = sdoCryptoSigVerify(
	    pubkey->pkenc, pubkey->pkalg, message, messageLength,
	    messageSignature, signatureLength, pubkey->key1->bytes,
	    pubkey->key1->byteSz,
	    /* X.509 encoded pubkeys only have key1 parameter */
	    (pubkey->key2 ? pubkey->key2->bytes : NULL),
	    (pubkey->key2 ? pubkey->key2->byteSz : 0));

	*result = (0 == ret) ? true : false;
	return ret;
}
