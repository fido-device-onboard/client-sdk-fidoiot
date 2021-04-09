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

#include "fdoCryptoHal.h"
#include "util.h"
#include "stdlib.h"

#define mbedtls_calloc calloc

/**
 * Verify an RSA-SHA-256 signature using provided RSA Public Keys.
 * @param key_encoding - RSA Key encoding typee.
 * @param key_algorithm - RSA public key algorithm.
 * @param message - pointer of type uint8_t, holds the encoded message.
 * @param message_length - size of message, type size_t.
 * @param message_signature - pointer of type uint8_t, holds a valid
 *			PKCS v1.5 signature in big-endian format
 * @param signature_length - size of signature, type unsigned int.
 * @param key_param1 - pointer of type uint8_t, holds the public key1.
 * @param key_param1Length - size of public key1, type size_t.
 * @param key_param2 - pointer of type uint8_t,holds the public key2.
 * @param key_param2Length - size of public key2, type size_t
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
	int ret;
	unsigned char hash[32];
	mbedtls_rsa_context rsa;
	mbedtls_pk_context ctx;

	/* Check validity of key type. */
	if (key_encoding != FDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP ||
	    key_algorithm != FDO_CRYPTO_PUB_KEY_ALGO_RSA) {
		LOG(LOG_ERROR, "Incorrect key type\n");
		return -1;
	}

	if (NULL == key_param1 || 0 == key_param1Length || NULL == key_param2 ||
	    0 == key_param2Length || NULL == message_signature ||
	    0 == signature_length || NULL == message || 0 == message_length) {
		LOG(LOG_ERROR, "Incorrect key type\n");
		return -1;
	}

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

	ret = mbedtls_rsa_import_raw(&rsa,
			       key_param1, key_param1Length,  /* N */
			       NULL, 0, /* P */
			       NULL, 0, /* Q */
			       NULL, 0, /* D */
			       key_param2, key_param2Length); /* E */

	if (ret != 0) {
		LOG(LOG_ERROR, "mbedtls_rsa_import_raw returned %d./n",
		    ret);
		ret = -1;
		goto end;
	}

	rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;
	if (signature_length != rsa.len) {
		LOG(LOG_ERROR, "Invalid RSA signature format.\n");
		ret = -1;
		goto end;
	}

	mbedtls_pk_init(&ctx);
	ctx.pk_ctx = &rsa;

	mbedtls_sha256_ret((const unsigned char *)message, message_length, hash,
			   0);

	ret = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
				       MBEDTLS_MD_SHA256, 0,
				       hash, message_signature);
	if (ret != 0) {
		LOG(LOG_ERROR, " mbedtls_rsa_pkcs1_verify returned %d.\n", ret);
	}

end:
	mbedtls_rsa_free(&rsa);
	return ret;
}
