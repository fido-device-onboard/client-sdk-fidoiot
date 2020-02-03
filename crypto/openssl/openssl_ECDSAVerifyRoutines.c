/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for ECDSA signature verification
 * \ APIs of openssl library.
 */

#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include "sdoCryptoHal.h"
#include "util.h"
#include "storage_al.h"
#include "safe_lib.h"

/**
 * Verify an ECC P-256/P-384 signature using provided ECDSA Public Keys.
 * @param keyEncoding - encoding typee.
 * @param keyAlgorithm - public key algorithm.
 * @param message - pointer of type uint8_t, holds the encoded message.
 * @param messageLength - size of message, type size_t.
 * @param messageSignature - pointer of type uint8_t, holds a valid
 *			ecdsa signature in big-endian format
 * @param signatureLength - size of signature, type unsigned int.
 * @param keyParam1 - pointer of type uint8_t, holds the public key.
 * @param keyParam1Length - size of public key, type size_t.
 * @param keyParam2 - not used.
 * @param keyParam2Length - not used
 * @return 0 if true, else -1.

 */
int32_t sdoCryptoSigVerify(uint8_t keyEncoding, uint8_t keyAlgorithm,
			   const uint8_t *message, uint32_t messageLength,
			   const uint8_t *messageSignature,
			   uint32_t signatureLength, const uint8_t *keyParam1,
			   uint32_t keyParam1Length, const uint8_t *keyParam2,
			   uint32_t keyParam2Length)
{
	int32_t ret = -1;
	EC_KEY *eckey = NULL;
	uint8_t hash[SHA512_DIGEST_LENGTH] = {0};
	size_t hashLength = 0;
	const unsigned char *pubKey = (const unsigned char *)keyParam1;

	/* Check validity of key type. */
	if (keyEncoding != SDO_CRYPTO_PUB_KEY_ENCODING_X509 ||
	    (keyAlgorithm != SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256 &&
	     keyAlgorithm != SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384)) {
		LOG(LOG_ERROR, "Incorrect key type\n");
		goto end;
	}

	if (NULL == pubKey || 0 == keyParam1Length ||
	    NULL == messageSignature || 0 == signatureLength ||
	    NULL == message || 0 == messageLength) {
		LOG(LOG_ERROR, "Invalid arguments!\n");
		goto end;
	}

	/* generate required EC_KEY based on type */
	if (keyAlgorithm == SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256) { // P-256 NIST
		eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		/* Perform SHA-256 digest of the message */
		if (SHA256((const unsigned char *)message, messageLength,
			   hash) == NULL) {
			LOG(LOG_ERROR, "SHA-256 calculation failed!\n");
			goto end;
		}
		hashLength = SHA256_DIGEST_LENGTH;

	} else { // P-384
		eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
		/* Perform SHA-384 digest of the message */
		if (SHA384((const unsigned char *)message, messageLength,
			   hash) == NULL) {
			LOG(LOG_ERROR, "SHA-384 calculation failed!\n");
			goto end;
		}
		hashLength = SHA384_DIGEST_LENGTH;
	}

	if (NULL == eckey) {
		LOG(LOG_ERROR, "EC_KEY allocation failed!\n");
		goto end;
	}

	/* decode EC_KEY struct from DER encoded EC public key */
	if (d2i_EC_PUBKEY(&eckey, &pubKey, (long)keyParam1Length) == NULL) {
		LOG(LOG_ERROR, "DER to EC_KEY struct decoding failed!\n");
		goto end;
	}

	if (1 != ECDSA_verify(0, hash, hashLength, messageSignature,
			      signatureLength, eckey)) {
		LOG(LOG_ERROR, "ECDSA Sig verification failed\n");
		goto end;
	}

	ret = 0;

end:
	if (eckey)
		EC_KEY_free(eckey);

	return ret;
}
