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
 * @param keyEncoding - encoding typee.
 * @param keyAlgorithm - public key algorithm.
 * @param message - pointer of type uint8_t, holds the encoded message.
 * @param messageLength - size of message, type size_t.
 * @param messageSignature - pointer of type uint8_t, holds a valid
 *			ecdsa signature in big-endian format
 * @param signatureLength - size of signature, type unsigned int.
 * @param keyParam1 - pointer of type uint8_t, holds the EC public key.
 * @param keyParam1Length - size of EC public key, type size_t.
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
	int result = 0;
	unsigned char hash[SHA512_DIGEST_SIZE] = {0};
	size_t hashLength = 0;
	mbedtls_ecdsa_context ec_ctx = {0};
	mbedtls_pk_context pk_ctx = {0};
	mbedtls_md_type_t mbedhashType = MBEDTLS_MD_NONE;

	(void)keyParam2;
	(void)keyParam2Length;

	if (keyEncoding != SDO_CRYPTO_PUB_KEY_ENCODING_X509 ||
	    (keyAlgorithm != SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256 &&
	     keyAlgorithm != SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384)) {
		LOG(LOG_ERROR, "Incorrect key type!\n");
		goto end;
	}

	if (NULL == keyParam1 || 0 == keyParam1Length ||
	    NULL == messageSignature || 0 == signatureLength ||
	    NULL == message || 0 == messageLength) {
		LOG(LOG_ERROR, "Invalid arguments!\n");
		goto end;
	}

	/* Initialize mbedtls_ecdsa_context with EC group */
	mbedtls_ecdsa_init(&ec_ctx);

	if (keyAlgorithm == SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256) { // P-256 NIST
		LOG(LOG_DEBUG, "ECDSA256 verify\n");
		result = mbedtls_ecp_group_load(&(ec_ctx.grp),
						MBEDTLS_ECP_DP_SECP256R1);
		mbedhashType = MBEDTLS_MD_SHA256;
		hashLength = SHA256_DIGEST_SIZE;
	} else { // P-384 NIST curve
		LOG(LOG_DEBUG, "ECDSA384 verify\n");
		result = mbedtls_ecp_group_load(&(ec_ctx.grp),
						MBEDTLS_ECP_DP_SECP384R1);

		mbedhashType = MBEDTLS_MD_SHA384;
		hashLength = SHA384_DIGEST_SIZE;
	}
	if (result) {
		LOG(LOG_ERROR, "Initializing with required EC group failed!\n");
		goto end;
	}

	/* Initialize mbedtls_pk_context with incoming EC public-key */
	mbedtls_pk_init(&pk_ctx);

	if ((result = mbedtls_pk_parse_public_key(
		 &pk_ctx, (const unsigned char *)keyParam1,
		 (size_t)keyParam1Length)) != 0) {

		LOG(LOG_ERROR, "Parsing EC public-key failed!\n");
		goto end;
	}

	/* Calculate the hash over message and sign that hash */
	if (mbedtls_md(mbedtls_md_info_from_type(mbedhashType),
		       (const uint8_t *)message, messageLength, hash) != 0) {
		LOG(LOG_ERROR, " mbedtls_md FAILED:\n");
		goto end;
	}
	/* Verify ECDSA signature with 'updated mbedtls_ecdsa_context with
	 * pubkey info' */
	if ((ret = mbedtls_ecdsa_read_signature(mbedtls_pk_ec(pk_ctx), hash,
						hashLength, messageSignature,
						signatureLength)) != 0) {
		LOG(LOG_ERROR, "ECDSA Signature-verification failed!\n");
		goto end;
	}

	ret = 0;

end:
	mbedtls_ecdsa_free(&ec_ctx);
	mbedtls_pk_free(&pk_ctx);
	return ret;
}
