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
#include <openssl/ec.h>
#include "fdoCryptoHal.h"
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
int32_t crypto_hal_sig_verify(uint8_t key_encoding, int key_algorithm,
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
	unsigned char *sig_r = NULL;
	unsigned char *sig_s = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BIGNUM *r = NULL;
	BIGNUM *s = NULL;
	ECDSA_SIG *sig = NULL;

	/* Check validity of key type. */
	// Only COSEKEY and X509 are currently supported
	if ((key_encoding != FDO_CRYPTO_PUB_KEY_ENCODING_X509 &&
		 key_encoding != FDO_CRYPTO_PUB_KEY_ENCODING_COSEKEY) ||
	    (key_algorithm != FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256 &&
	     key_algorithm != FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384)) {
		LOG(LOG_ERROR, "Incorrect key type\n");
		goto end;
	}

	if (NULL == message_signature || 0 == signature_length ||
		0 != (signature_length % 2) ||
	    NULL == message || 0 == message_length) {
		LOG(LOG_ERROR, "Invalid arguments!\n");
		goto end;
	}

	/* generate required EC_KEY based on type */
	if (key_algorithm == FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256) { // P-256 NIST
		eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if (NULL == eckey) {
			LOG(LOG_ERROR, "EC_KEY allocation failed!\n");
			goto end;
		}
		/* Perform SHA-256 digest of the message */
		if (SHA256((const unsigned char *)message, message_length,
			   hash) == NULL) {
			LOG(LOG_ERROR, "SHA-256 calculation failed!\n");
			goto end;
		}
		hash_length = SHA256_DIGEST_LENGTH;

	} else { // P-384
		eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
		if (NULL == eckey) {
			LOG(LOG_ERROR, "EC_KEY allocation failed!\n");
			goto end;
		}
		/* Perform SHA-384 digest of the message */
		if (SHA384((const unsigned char *)message, message_length,
			   hash) == NULL) {
			LOG(LOG_ERROR, "SHA-384 calculation failed!\n");
			goto end;
		}
		hash_length = SHA384_DIGEST_LENGTH;
	}

	if (key_encoding == FDO_CRYPTO_PUB_KEY_ENCODING_X509) {

		if (NULL == pub_key || 0 == key_param1Length) {
			LOG(LOG_ERROR, "Invalid params!\n");
			goto end;
		}
		/* Unused parameter */
		(void)key_param2;
		(void)key_param2Length;

		/* decode EC_KEY struct from DER encoded EC public key */
		if (d2i_EC_PUBKEY(&eckey, &pub_key, (long)key_param1Length) == NULL) {
			LOG(LOG_ERROR, "DER to EC_KEY struct decoding failed!\n");
			goto end;
		}
	} else if (key_encoding == FDO_CRYPTO_PUB_KEY_ENCODING_COSEKEY) {
		if (NULL == key_param1 || 0 == key_param1Length ||
			NULL == key_param2 || 0 == key_param2Length) {
			LOG(LOG_ERROR, "Invalid params!\n");
			goto end;
		}
		/* decode EC_KEY struct using Affine X and Y co-ordinates */
		x = BN_bin2bn((const unsigned char*) key_param1, key_param1Length, NULL);
		y = BN_bin2bn((const unsigned char*) key_param2, key_param2Length, NULL);
		if (!x || !y) {
			LOG(LOG_ERROR, "Failed to convert affine-x and/or affine-y\n");
			goto end;
		}
		if (EC_KEY_set_public_key_affine_coordinates(eckey, x, y) == 0) {
			LOG(LOG_ERROR, "Failed to create EC Key from affine-x and affine-y!\n");
			goto end;
		}
	}

	// assemble r and s into a signature object
	sig = ECDSA_SIG_new();
	if (!sig) {
		LOG(LOG_ERROR, "ECDSA Sig create failed\n");
		goto end;
	}

	sig_r = fdo_alloc(signature_length/2);
	if (!sig_r) {
		LOG(LOG_ERROR, "Alloc of sig-r failed!\n");
		goto end;
	}
	if (0 != memcpy_s(sig_r, signature_length/2,
		message_signature, signature_length/2)) {
		LOG(LOG_ERROR, "Copy of sig-r failed!\n");
		goto end;
	}
	sig_s = fdo_alloc(signature_length/2);
	if (!sig_s) {
		LOG(LOG_ERROR, "Alloc of sig-s failed!\n");
		goto end;
	}
	if (0 != memcpy_s(sig_s, signature_length/2,
		message_signature + signature_length/2, signature_length/2)) {
		LOG(LOG_ERROR, "Copy of sig-s failed!\n");
		goto end;
	}
	// get r and s from buffers as BIGNUMs
	r = BN_bin2bn((const unsigned char*) sig_r, signature_length/2, NULL);
	if (!r) {
		LOG(LOG_ERROR, "Failed to convert r\n");
		goto end;
	}
	s = BN_bin2bn((const unsigned char*) sig_s, signature_length/2, NULL);
	if (!s) {
		LOG(LOG_ERROR, "Failed to convert s\n");
		BN_free(r);
		goto end;
	}

	// once set, this maintains r and s, no need to free explicitly
	// free only in case of an error
	if (1 != ECDSA_SIG_set0(sig, r, s)) {
		LOG(LOG_ERROR, "ECDSA Sig set failed\n");
		BN_free(r);
		BN_free(s);
		goto end;
	}

	if (1 != ECDSA_do_verify(hash, hash_length, sig, eckey)) {
		LOG(LOG_ERROR, "ECDSA Sig verification failed\n");
		goto end;
	}

	ret = 0;

end:
	if (eckey) {
		EC_KEY_free(eckey);
	}
	if (sig) {
		// this method also frees BIGNUMs r and s
		ECDSA_SIG_free(sig);
	}
	if (x) {
		BN_free(x);
	}
	if (y) {
		BN_free(y);
	}
	if (sig_r) {
		fdo_free(sig_r);
	}
	if (sig_s) {
		fdo_free(sig_s);
	}
	return ret;
}
