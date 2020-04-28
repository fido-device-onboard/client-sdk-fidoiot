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
 * @param key_encoding - encoding typee.
 * @param key_algorithm - public key algorithm.
 * @param message - pointer of type uint8_t, holds the encoded message.
 * @param message_length - size of message, type size_t.
 * @param message_signature - pointer of type uint8_t, holds a valid
 *			ecdsa signature in big-endian format
 * @param signature_length - size of signature, type unsigned int.
 * @param key_param1 - pointer of type uint8_t, holds the public key.
 * @param key_param1Length - size of public key, type size_t.
 * @param key_param2 - not used.
 * @param key_param2Length - not used
 * @return 0 if true, else -1.

 */
int32_t crypto_hal_sig_verify(uint8_t key_encoding, uint8_t key_algorithm,
			      const uint8_t *message, uint32_t message_length,
			      const uint8_t *message_signature,
			      uint32_t signature_length,
			      const uint8_t *key_param1,
			      uint32_t key_param1Length,
			      const uint8_t *key_param2,
			      uint32_t key_param2Length)
{
	int32_t ret = -1;
	EC_KEY *eckey = NULL;
	uint8_t hash[SHA512_DIGEST_LENGTH] = {0};
	size_t hash_length = 0;
	const unsigned char *pub_key = (const unsigned char *)key_param1;

	/* Unused parameter */
	(void)key_param2;
	(void)key_param2Length;

	/* Check validity of key type. */
	if (key_encoding != SDO_CRYPTO_PUB_KEY_ENCODING_X509 ||
	    (key_algorithm != SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256 &&
	     key_algorithm != SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384)) {
		LOG(LOG_ERROR, "Incorrect key type\n");
		goto end;
	}

	if (NULL == pub_key || 0 == key_param1Length ||
	    NULL == message_signature || 0 == signature_length ||
	    NULL == message || 0 == message_length) {
		LOG(LOG_ERROR, "Invalid arguments!\n");
		goto end;
	}

	/* generate required EC_KEY based on type */
	if (key_algorithm == SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256) { // P-256 NIST
		eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		/* Perform SHA-256 digest of the message */
		if (SHA256((const unsigned char *)message, message_length,
			   hash) == NULL) {
			LOG(LOG_ERROR, "SHA-256 calculation failed!\n");
			goto end;
		}
		hash_length = SHA256_DIGEST_LENGTH;

	} else { // P-384
		eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
		/* Perform SHA-384 digest of the message */
		if (SHA384((const unsigned char *)message, message_length,
			   hash) == NULL) {
			LOG(LOG_ERROR, "SHA-384 calculation failed!\n");
			goto end;
		}
		hash_length = SHA384_DIGEST_LENGTH;
	}

	if (NULL == eckey) {
		LOG(LOG_ERROR, "EC_KEY allocation failed!\n");
		goto end;
	}

	/* decode EC_KEY struct from DER encoded EC public key */
	if (d2i_EC_PUBKEY(&eckey, &pub_key, (long)key_param1Length) == NULL) {
		LOG(LOG_ERROR, "DER to EC_KEY struct decoding failed!\n");
		goto end;
	}

	if (1 != ECDSA_verify(0, hash, hash_length, message_signature,
			      signature_length, eckey)) {
		LOG(LOG_ERROR, "ECDSA Sig verification failed\n");
		goto end;
	}

	ret = 0;

end:
	if (eckey)
		EC_KEY_free(eckey);

	return ret;
}
