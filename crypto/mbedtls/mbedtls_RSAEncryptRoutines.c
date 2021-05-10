/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for RSA encryption routines of mbedTLS library.
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
 * crypto_hal_rsa_encrypt -  Encrypt the block passed using the public key
 * passed, the key must be RSA
 * @param hash_type - Hash type (FDO_CRYPTO_HASH_TYPE_SHA_256)
 * @param key_encoding - RSA Key encoding typee.
 * @param key_algorithm - RSA public key algorithm.
 * @param clear_text - Input text to be encrypted.
 * @param clear_text_length - Plain text size in bytes.
 * @param cipher_text - Encrypted text(output).
 * @param cipher_text_length - Encrypted text size in bytes.
 * @param key_param1 - pointer of type uint8_t, holds the public key1.
 * @param key_param1Length - size of public key1, type size_t.
 * @param key_param2 - pointer of type uint8_t,holds the public key2.
 * @param key_param2Length - size of public key2, type size_t
 * @return ret
 *        return 0 on success. -1 on failure.
 *        return cypher_length in bytes while cypher_text passed as NULL, & all
 *        other parameters are passed as it is.
 */
int32_t crypto_hal_rsa_encrypt(uint8_t hash_type, uint8_t key_encoding,
			       uint8_t key_algorithm, const uint8_t *clear_text,
			       uint32_t clear_text_length, uint8_t *cipher_text,
			       uint32_t cipher_text_length,
			       const uint8_t *key_param1,
			       uint32_t key_param1Length,
			       const uint8_t *key_param2,
			       uint32_t key_param2Length)
{
	mbedtls_rsa_context rsa;

	int ret = -1;
	uint8_t *tmpkey1 = NULL;
	size_t tmpkey1Sz = 0;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	static const char pers[] = "test_string";
	uint32_t cipher_cal_length = 0;

	LOG(LOG_DEBUG, "rsa_encrypt starting.\n");

	/* Make sure we have a correct type of key. */
	if (key_encoding != FDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP ||
	    key_algorithm != FDO_CRYPTO_PUB_KEY_ALGO_RSA) {
		LOG(LOG_ERROR, "Incorrect key type.\n");
		return -1;
	}
	if (NULL == clear_text || 0 == clear_text_length) {
		LOG(LOG_ERROR, "Incorrect input text.\n");
		return -1;
	}
	if (key_param1 == NULL || key_param1Length == 0) {
		LOG(LOG_ERROR, "Missing Key1.\n");
		return -1;
	}
	if (key_param2 == NULL || key_param2Length == 0) {
		LOG(LOG_ERROR, "Missing Key2.\n");
		return -1;
	}
	if (key_param1Length == key_param2Length) {
		LOG(LOG_ERROR, "Incorrect Key.\n");
		return -1;
	}

	tmpkey1 = (uint8_t *)key_param1;
	tmpkey1Sz = key_param1Length;
	/*
	 * Removing extra byte in MSB of value 0x00, which is required
	 * for java compatibility,
	 * Desired condition here are,
	 * 1) Key size is 257 , including one extra byte from java
	 * 2) MSB is 0x00
	 * 3) correct key1 MSBit should be 1, so anding with 0x80 to
	 * ensure such condition.
	 */
	if ((key_param1Length == (RSA_SHA256_KEY1_SIZE + 1)) &&
	    !(key_param1[0]) && (key_param1[1] & BIT7_MASK)) {
		tmpkey1 = (uint8_t *)key_param1 + 1;
		tmpkey1Sz = key_param1Length - 1;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	hexdump("Public N", tmpkey1, tmpkey1Sz);
	hexdump("Public E", key_param2, key_param2Length);
#endif
	/* This PRNG is being created here in order to pass it into the RSA
	 * Encrypt function which needs the PRNG to create random values for
	 * OAEP padding.
	 */
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
			      (const unsigned char *)pers, sizeof(pers) - 1);

	// by default OEAP is selcted for PKCS_V21
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, 0);
	switch (hash_type) {
	case FDO_PK_HASH_SHA1:
		mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21,
					MBEDTLS_MD_SHA1);
		break;
	case FDO_PK_HASH_SHA256:
		mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21,
					MBEDTLS_MD_SHA256);
		break;
	case FDO_PK_HASH_SHA384:
		mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21,
					MBEDTLS_MD_SHA384);
		break;
	default:
		LOG(LOG_ERROR, "Hash algorithm not supported.");
		ret = -1;
		goto error;
	}

	ret = mbedtls_rsa_import_raw(&rsa,
				     tmpkey1, tmpkey1Sz,  /* N */
				     NULL, 0, /* P */
				     NULL, 0, /* Q */
				     NULL, 0, /* D */
				     key_param2, key_param2Length); /* E */

	if (ret != 0) {
		LOG(LOG_ERROR, "mbedtls_rsa_import_raw returned %d./n", ret);
		ret = -1;
		goto error;
	}

	rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

	ret = mbedtls_rsa_check_pubkey(&rsa);
	if (ret != 0) {
		LOG(LOG_ERROR, "mbedtls_i rsa pubkey error: %d.\n", ret);
		goto error;
	}
	cipher_cal_length = rsa.len;
	LOG(LOG_DEBUG, "rsa len : %zu.\n", rsa.len);

	/* send back required cipher budffer size */
	if (cipher_text == NULL) {
		ret = cipher_cal_length;
		goto error;
	}

	/*When caller sends cipher buffer */
	if (cipher_cal_length > cipher_text_length) {
		ret = -1;
		goto error;
	}

	ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random,
					&ctr_drbg, MBEDTLS_RSA_PUBLIC,
					clear_text_length,
					(unsigned char *)clear_text,
					cipher_text);
	if (ret != 0) {
		LOG(LOG_ERROR, "rsa encrypt failed ret: %x\n", ret);
		ret = -1;
		goto error;
	}

error:
	mbedtls_rsa_free(&rsa);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}

/**
 * crypto_hal_rsa_len - Returns the cipher length
 * @param key_param1 - pointer of type uint8_t, holds the public key1.
 * @param key_param1Length - size of public key1, type size_t.
 * @param key_param2 - pointer of type uint8_t,holds the public key2.
 * @param key_param2Length - size of public key2, type size_t
 * @return ret
 *        return cypher_length in bytes.
 */
uint32_t crypto_hal_rsa_len(const uint8_t *key_param1,
			    uint32_t key_param1Length,
			    const uint8_t *key_param2,
			    uint32_t key_param2Length)
{
	mbedtls_rsa_context rsa;
	uint32_t cipher_cal_length = 0;

	uint8_t *tmpkey1 = (uint8_t *)key_param1;
	uint32_t tmpkey1Sz = key_param1Length;
	/*
	 * Removing extra byte in MSB of value 0x00, which is required
	 * for java compatibility,
	 * Desired condition here are,
	 * 1) Key size is 257 , including one extra byte from java
	 * 2) MSB is 0x00
	 * 3) correct key1 MSBit should be 1, so anding with 0x80 to
	 * ensure such condition.
	 */
	if ((key_param1Length == (RSA_SHA256_KEY1_SIZE + 1)) &&
	    !(key_param1[0]) && (key_param1[1] & BIT7_MASK)) {
		tmpkey1 = (uint8_t *)key_param1 + 1;
		tmpkey1Sz = key_param1Length - 1;
	}

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, 0);
	mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

	if ((mbedtls_mpi_read_binary(&rsa.N, tmpkey1, tmpkey1Sz)) != 0 ||
	    (mbedtls_mpi_read_binary(&rsa.E, key_param2, key_param2Length)) !=
		0) {
		LOG(LOG_ERROR, "mbedtls_mpi_read_ error/n");
		goto error;
	}
	cipher_cal_length = ((mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3);

error:
	mbedtls_rsa_free(&rsa);
	return cipher_cal_length;
}
