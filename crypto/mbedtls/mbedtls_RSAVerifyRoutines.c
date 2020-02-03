/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for RSA signature verification routines of mbedTLS
 * library.
 */

// FIXME: should be abstracted, rsa_encrypt is missing
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform.h"
#include "mbedtls/rsa.h"
#include "safe_lib.h"

#include "sdoCryptoHal.h"
#include "util.h"
#include "stdlib.h"

#define mbedtls_calloc calloc

/**
 * Verify an RSA-SHA-256 signature using provided RSA Public Keys.
 * @param keyEncoding - RSA Key encoding typee.
 * @param keyAlgorithm - RSA public key algorithm.
 * @param message - pointer of type uint8_t, holds the encoded message.
 * @param messageLength - size of message, type size_t.
 * @param messageSignature - pointer of type uint8_t, holds a valid
 *			PKCS v1.5 signature in big-endian format
 * @param signatureLength - size of signature, type unsigned int.
 * @param keyParam1 - pointer of type uint8_t, holds the public key1.
 * @param keyParam1Length - size of public key1, type size_t.
 * @param keyParam2 - pointer of type uint8_t,holds the public key2.
 * @param keyParam2Length - size of public key2, type size_t
 * @return 0 if true, else -1.

 */
int32_t sdoCryptoSigVerify(uint8_t keyEncoding, uint8_t keyAlgorithm,
			   const uint8_t *message, uint32_t messageLength,
			   const uint8_t *messageSignature,
			   uint32_t signatureLength, const uint8_t *keyParam1,
			   uint32_t keyParam1Length, const uint8_t *keyParam2,
			   uint32_t keyParam2Length)
{
	int ret;
	unsigned char hash[32];
	mbedtls_rsa_context rsa;
	mbedtls_pk_context ctx;

	/* Check validity of key type. */
	if (keyEncoding != SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP ||
	    keyAlgorithm != SDO_CRYPTO_PUB_KEY_ALGO_RSA) {
		LOG(LOG_ERROR, "Incorrect key type\n");
		return -1;
	}

	if (NULL == keyParam1 || 0 == keyParam1Length || NULL == keyParam2 ||
	    0 == keyParam2Length || NULL == messageSignature ||
	    0 == signatureLength || NULL == message || 0 == messageLength) {
		LOG(LOG_ERROR, "Incorrect key type\n");
		return -1;
	}

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

	if ((ret = mbedtls_mpi_read_binary(&rsa.N, keyParam1,
					   keyParam1Length)) != 0 ||
	    (ret = mbedtls_mpi_read_binary(&rsa.E, keyParam2,
					   keyParam2Length)) != 0) {
		LOG(LOG_ERROR, "mbedtls_mpi_read_binary returned %d./n", ret);
		ret = -1;
		goto end;
	}
	rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;
	if (signatureLength != rsa.len) {
		LOG(LOG_ERROR, "Invalid RSA signature format.\n");
		ret = -1;
		goto end;
	}

	mbedtls_pk_init(&ctx);
	ctx.pk_ctx = &rsa;

	mbedtls_sha256_ret((const unsigned char *)message, messageLength, hash,
			   0);
	if ((ret = mbedtls_rsa_pkcs1_verify(
		 &rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 0,
		 hash, messageSignature)) != 0) {
		LOG(LOG_ERROR, " mbedtls_rsa_pkcs1_verify returned %d.\n", ret);
	}

end:
	mbedtls_rsa_free(&rsa);
	return ret;
}
