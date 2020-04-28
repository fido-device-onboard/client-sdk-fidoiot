/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \ brief Abstraction layer for ECDSA signature verification
 * \ routines of mbedTLS library.
 */

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform.h"
#include <mbedtls/ecdsa.h>
#include <mbedtls/pk.h>

#include "safe_lib.h"
#include "sdoCryptoHal.h"
#include "util.h"
#include "stdlib.h"
#include "storage_al.h"

/**
 * Verify an ECC P-256/P-384 signature using provided ECDSA Public Keys.
 * @param key_encoding - encoding typee.
 * @param key_algorithm - public key algorithm.
 * @param message - pointer of type uint8_t, holds the encoded message.
 * @param message_length - size of message, type size_t.
 * @param message_signature - pointer of type uint8_t, holds a valid
 *			ecdsa signature in big-endian format
 * @param signature_length - size of signature, type unsigned int.
 * @param key_param1 - pointer of type uint8_t, holds the EC public key.
 * @param key_param1Length - size of EC public key, type size_t.
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
	int result = 0;
	unsigned char hash[SHA512_DIGEST_SIZE] = {0};
	size_t hash_length = 0;
	mbedtls_ecdsa_context ec_ctx = {0};
	mbedtls_pk_context pk_ctx = {0};
	mbedtls_md_type_t mbedhash_type = MBEDTLS_MD_NONE;

	(void)key_param2;
	(void)key_param2Length;

	if (key_encoding != SDO_CRYPTO_PUB_KEY_ENCODING_X509 ||
	    (key_algorithm != SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256 &&
	     key_algorithm != SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384)) {
		LOG(LOG_ERROR, "Incorrect key type!\n");
		goto end;
	}

	if (NULL == key_param1 || 0 == key_param1Length ||
	    NULL == message_signature || 0 == signature_length ||
	    NULL == message || 0 == message_length) {
		LOG(LOG_ERROR, "Invalid arguments!\n");
		goto end;
	}

	/* Initialize mbedtls_ecdsa_context with EC group */
	mbedtls_ecdsa_init(&ec_ctx);

	if (key_algorithm == SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256) { // P-256 NIST
		LOG(LOG_DEBUG, "ECDSA256 verify\n");
		result = mbedtls_ecp_group_load(&(ec_ctx.grp),
						MBEDTLS_ECP_DP_SECP256R1);
		mbedhash_type = MBEDTLS_MD_SHA256;
		hash_length = SHA256_DIGEST_SIZE;
	} else { // P-384 NIST curve
		LOG(LOG_DEBUG, "ECDSA384 verify\n");
		result = mbedtls_ecp_group_load(&(ec_ctx.grp),
						MBEDTLS_ECP_DP_SECP384R1);

		mbedhash_type = MBEDTLS_MD_SHA384;
		hash_length = SHA384_DIGEST_SIZE;
	}
	if (result) {
		LOG(LOG_ERROR, "Initializing with required EC group failed!\n");
		goto end;
	}

	/* Initialize mbedtls_pk_context with incoming EC public-key */
	mbedtls_pk_init(&pk_ctx);

	result = mbedtls_pk_parse_public_key(&pk_ctx,
					     (const unsigned char *)key_param1,
					     (size_t)key_param1Length);
	if (result != 0) {
		LOG(LOG_ERROR, "Parsing EC public-key failed!\n");
		goto end;
	}

	/* Calculate the hash over message and sign that hash */
	if (mbedtls_md(mbedtls_md_info_from_type(mbedhash_type),
		       (const uint8_t *)message, message_length, hash) != 0) {
		LOG(LOG_ERROR, " mbedtls_md FAILED:\n");
		goto end;
	}
	/* Verify ECDSA signature with 'updated mbedtls_ecdsa_context with
	 * pubkey info'
	 */
	ret = mbedtls_ecdsa_read_signature(mbedtls_pk_ec(pk_ctx), hash,
					   hash_length, message_signature,
					   signature_length);
	if (ret != 0) {
		LOG(LOG_ERROR, "ECDSA Signature-verification failed!\n");
		goto end;
	}

	ret = 0;

end:
	mbedtls_ecdsa_free(&ec_ctx);
	mbedtls_pk_free(&pk_ctx);
	return ret;
}
