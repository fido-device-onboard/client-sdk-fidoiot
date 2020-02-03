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

#include "sdoCryptoHal.h"
#include "util.h"
#include "stdlib.h"

#define mbedtls_calloc calloc

/**
 * sdoCryptoRSAEncrypt -  Encrypt the block passed using the public key
 * passed, the key must be RSA
 * @param hashType - Hash type (SDO_CRYPTO_HASH_TYPE_SHA_256)
 * @param keyEncoding - RSA Key encoding typee.
 * @param keyAlgorithm - RSA public key algorithm.
 * @param clearText - Input text to be encrypted.
 * @param clearTextLength - Plain text size in bytes.
 * @param cipherText - Encrypted text(output).
 * @param cipherTextLength - Encrypted text size in bytes.
 * @param keyParam1 - pointer of type uint8_t, holds the public key1.
 * @param keyParam1Length - size of public key1, type size_t.
 * @param keyParam2 - pointer of type uint8_t,holds the public key2.
 * @param keyParam2Length - size of public key2, type size_t
 * @return ret
 *        return 0 on success. -1 on failure.
 *        return cypherLength in bytes while cypherText passed as NULL, & all
 *        other parameters are passed as it is.
 */
int32_t sdoCryptoRSAEncrypt(uint8_t hashType, uint8_t keyEncoding,
			    uint8_t keyAlgorithm, const uint8_t *clearText,
			    uint32_t clearTextLength, uint8_t *cipherText,
			    uint32_t cipherTextLength, const uint8_t *keyParam1,
			    uint32_t keyParam1Length, const uint8_t *keyParam2,
			    uint32_t keyParam2Length)
{
	mbedtls_rsa_context rsa;

	int ret = -1;
	uint8_t *tmpkey1 = NULL;
	size_t tmpkey1Sz = 0;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	const char pers[] = "test_string";
	uint32_t cipherCalLength = 0;

	LOG(LOG_DEBUG, "rsa_encrypt starting.\n");

	/* Make sure we have a correct type of key. */
	if (keyEncoding != SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP ||
	    keyAlgorithm != SDO_CRYPTO_PUB_KEY_ALGO_RSA) {
		LOG(LOG_ERROR, "Incorrect key type.\n");
		return -1;
	}
	if (NULL == clearText || 0 == clearTextLength) {
		LOG(LOG_ERROR, "Incorrect input text.\n");
		return -1;
	}
	if (keyParam1 == NULL || keyParam1Length == 0) {
		LOG(LOG_ERROR, "Missing Key1.\n");
		return -1;
	}
	if (keyParam2 == NULL || keyParam2Length == 0) {
		LOG(LOG_ERROR, "Missing Key2.\n");
		return -1;
	}
	if (keyParam1Length == keyParam2Length) {
		LOG(LOG_ERROR, "Incorrect Key.\n");
		return -1;
	}

	tmpkey1 = (uint8_t *)keyParam1;
	tmpkey1Sz = keyParam1Length;
	/*
	 * Removing extra byte in MSB of value 0x00, which is required
	 * for java compatibility,
	 * Desired condition here are,
	 * 1) Key size is 257 , including one extra byte from java
	 * 2) MSB is 0x00
	 * 3) correct key1 MSBit should be 1, so anding with 0x80 to
	 * ensure such condition.
	 */
	if ((keyParam1Length == (RSA_SHA256_KEY1_SIZE + 1)) &&
	    !(keyParam1[0]) && (keyParam1[1] & BIT7_MASK)) {
		tmpkey1 = (uint8_t *)keyParam1 + 1;
		tmpkey1Sz = keyParam1Length - 1;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	hexdump("Public N", tmpkey1, tmpkey1Sz);
	hexdump("Public E", keyParam2, keyParam2Length);
#endif
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
			      (const unsigned char *)pers, sizeof(pers) - 1);

	// by default OEAP is selcted for PKCS_V15
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
	switch (hashType) {
	case SDO_PK_HASH_SHA1:
		mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21,
					MBEDTLS_MD_SHA1);
		break;
	case SDO_PK_HASH_SHA256:
		mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21,
					MBEDTLS_MD_SHA256);
		break;
	case SDO_PK_HASH_SHA384:
		mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21,
					MBEDTLS_MD_SHA384);
		break;
	default:
		LOG(LOG_ERROR, "Hash algorithm not supported.");
		ret = -1;
		goto error;
	}

	if ((mbedtls_mpi_read_binary(&rsa.N, tmpkey1, tmpkey1Sz)) != 0 ||
	    (mbedtls_mpi_read_binary(&rsa.E, keyParam2, keyParam2Length)) !=
		0) {
		LOG(LOG_ERROR, "mbedtls_mpi_read_ error/n");
		goto error;
	}
	rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

	if ((ret = mbedtls_rsa_check_pubkey(&rsa)) != 0) {
		LOG(LOG_ERROR, "mbedtls_i rsa pubkey error: %d.\n", ret);
		goto error;
	}
	cipherCalLength = rsa.len;
	LOG(LOG_DEBUG, "rsa len : %zu.\n", rsa.len);

	/* send back required cipher budffer size */
	if (cipherText == NULL) {
		ret = cipherCalLength;
		goto error;
	}

	/*When caller sends cipher buffer */
	if (cipherCalLength > cipherTextLength) {
		ret = -1;
		goto error;
	}

	if ((ret = mbedtls_rsa_pkcs1_encrypt(
		 &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC,
		 clearTextLength, (unsigned char *)clearText, cipherText)) !=
	    0) {
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
 * sdoCryptoRSALen - Returns the cipher length
 * @param keyParam1 - pointer of type uint8_t, holds the public key1.
 * @param keyParam1Length - size of public key1, type size_t.
 * @param keyParam2 - pointer of type uint8_t,holds the public key2.
 * @param keyParam2Length - size of public key2, type size_t
 * @return ret
 *        return cypherLength in bytes.
 */
uint32_t sdoCryptoRSALen(const uint8_t *keyParam1, uint32_t keyParam1Length,
			 const uint8_t *keyParam2, uint32_t keyParam2Length)
{
	mbedtls_rsa_context rsa;
	uint32_t cipherCalLength = 0;

	uint8_t *tmpkey1 = (uint8_t *)keyParam1;
	uint32_t tmpkey1Sz = keyParam1Length;
	/*
	 * Removing extra byte in MSB of value 0x00, which is required
	 * for java compatibility,
	 * Desired condition here are,
	 * 1) Key size is 257 , including one extra byte from java
	 * 2) MSB is 0x00
	 * 3) correct key1 MSBit should be 1, so anding with 0x80 to
	 * ensure such condition.
	 */
	if ((keyParam1Length == (RSA_SHA256_KEY1_SIZE + 1)) &&
	    !(keyParam1[0]) && (keyParam1[1] & BIT7_MASK)) {
		tmpkey1 = (uint8_t *)keyParam1 + 1;
		tmpkey1Sz = keyParam1Length - 1;
	}

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

	if ((mbedtls_mpi_read_binary(&rsa.N, tmpkey1, tmpkey1Sz)) != 0 ||
	    (mbedtls_mpi_read_binary(&rsa.E, keyParam2, keyParam2Length)) !=
		0) {
		LOG(LOG_ERROR, "mbedtls_mpi_read_ error/n");
		goto error;
	}
	cipherCalLength = ((mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3);

error:
	mbedtls_rsa_free(&rsa);
	return cipherCalLength;
}
