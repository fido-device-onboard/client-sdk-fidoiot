/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction of openssl library for crypto services required by FDO
 * library.
 */

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <assert.h>
#include "fdoCryptoHal.h"

#ifndef SECURE_ELEMENT
static bool g_random_initialised;
#endif /* SECURE_ELEMENT */

ENGINE * engine;

int32_t inc_rollover_ctr(uint8_t *first_iv, uint8_t *new_iv, uint8_t iv_len,
			 size_t aesblocks)
{
	uint8_t inc = 0, t1 = 1;
	int32_t ret = -1;
	BIGNUM *iv_bn_cur = NULL, *iv_bn_first = NULL, *iv_bn_new = NULL;
	BIGNUM *ctr_bn = NULL, *ctr_bn_tmp = NULL;

	if (!first_iv || !new_iv) {
		return -1;
	}

	/* Convert stored iv from buffer to bn */
	iv_bn_cur = BN_bin2bn(new_iv, iv_len, NULL);
	if (!iv_bn_cur) {
		LOG(LOG_ERROR, "Failed to convert cur iv buffer to bn\n");
		goto err;
	}

	/* Convert stored iv from buffer to bn */
	iv_bn_first = BN_bin2bn(first_iv, iv_len, NULL);
	if (!iv_bn_first) {
		LOG(LOG_ERROR, "Failed to convert first iv buffer to bn\n");
		goto err;
	}

	if (aesblocks <= 0xFFFFFFFF) {
		inc = 1;
	} else {
		inc = 2;
	}

	ctr_bn = BN_bin2bn(&inc, 1, NULL);
	if (!ctr_bn) {
		LOG(LOG_ERROR, "Failed to convert ctr to bn\n");
		goto err;
	}

	iv_bn_new = BN_new();
	if (!iv_bn_new) {
		LOG(LOG_ERROR, "Failed to allocate iv for ctr maintenance\n");
		goto err;
	}
	if (inc == 2) {
		ctr_bn_tmp = BN_bin2bn(&t1, 1, NULL);
		if (!ctr_bn_tmp) {
			LOG(LOG_ERROR, "Failed to convert ctr to bn\n");
			goto err;
		}
		if (!BN_add(iv_bn_new, iv_bn_cur, ctr_bn_tmp)) {
			LOG(LOG_ERROR,
			    "Failed to generate new from addition\n");
			goto err;
		}

		/* Check roll over happening? */
		if (0 == BN_cmp(iv_bn_first, iv_bn_new)) {
			LOG(LOG_ERROR, "Roll over iv not supportedv\n");
			goto err;
		}
		BN_clear(iv_bn_new);
		BN_clear_free(ctr_bn_tmp);
	}
	if (!BN_add(iv_bn_new, iv_bn_cur, ctr_bn)) {
		LOG(LOG_ERROR, "Failed to generate new from addition\n");
		goto err;
	}

	/* Check roll over happening? */
	if (0 == BN_cmp(iv_bn_first, iv_bn_new)) { // the roll over happening
		LOG(LOG_ERROR, "Roll over iv not supportedv\n");
		goto err;
	}

	/* Write bn to binary data */
	if (BN_bn2bin(iv_bn_new, new_iv) > iv_len) {
		LOG(LOG_ERROR, "New iv from BN write failed\n");
		goto err;
	}

	ret = 0;
err:
	BN_clear_free(iv_bn_new);
	BN_clear_free(iv_bn_cur);
	BN_clear_free(iv_bn_first);
	BN_clear_free(ctr_bn);
	return ret;
}

#ifndef SECURE_ELEMENT
/**
 * Initialize the random function by using RAND_poll function and
 * maintain the state of randomness by variable g_random_initialised.
 * @return 0 if succeeds,else -1.
 */
int random_init(void)
{
	if (!g_random_initialised) {
		if (1 != RAND_poll()) {
			return -1;
		}

		g_random_initialised = true;
	}
	return 0;
}

/**
 * Close the random number generation engine by changing g_random_initialised
 * variable to false.
 * @return 0 if succeeds,else -1.
 */

int random_close(void)
{
	if (!g_random_initialised) {
		return -1;
	}

	g_random_initialised = false;
	return 0;
}

#if !defined(DEVICE_CSE_ENABLED)
/**
 * If g_random_initialised is true, generate random bytes of data
 * of size num_bytes passed as paramater, else return error.
 * @param random_buffer - Pointer rand_data of type uint8_t to be filled with,
 * @param num_bytes - Number of bytes to be filled.
 * @return 0 if succeeds, else -1.
 */
int32_t crypto_hal_random_bytes(uint8_t *random_buffer, size_t num_bytes)
{
	if (!g_random_initialised) {
		return -1;
	} else if (NULL == random_buffer) {
		return -1;
	} else if (1 !=
		   RAND_priv_bytes((unsigned char *)random_buffer, num_bytes)) {
		return -1;
	}

	return 0;
}
#endif
#endif /* SECURE_ELEMENT */

/**
 * Allocate and initialize memory for key exchange.
 *
 * @return ret
 *        return 0 on success. -1 on failure.
 */
int32_t crypto_init(void)
{
	if (0 != random_init()) {
		return -1;
	}

	/* Load the human readable error strings for libcrypto */
	ERR_load_crypto_strings();

	/* Load all digest and cipher algorithms */
	OpenSSL_add_all_algorithms();

#ifdef SECURE_ELEMENT
	if (0 != crypto_hal_se_init()) {
		return -1;
	}
#endif /* SECURE_ELEMENT */
	return 0;
}

/**
 * Free all the crypto engine memory allocated for key exchange.
 *
 * @return ret
 *        return 0 on success. -1 on failure.
 */
int32_t crypto_close(void)
{
	if (0 != random_close()) {
		return -1;
	}

	ENGINE_cleanup();

	/* Removes all digests and ciphers */
	EVP_cleanup();

	/* if you omit the next, a small leak may be left when you make use of
	 * the BIO (low level API) for e.g. base64 transformations */
	CRYPTO_cleanup_all_ex_data();

	/* Remove error strings */
	ERR_free_strings();

	return 0;
}

#ifndef SECURE_ELEMENT
/**
 * fdo_crypto_hash function calculate hash on input data
 *
 * @param _hash_type - Hash type (FDO_CRYPTO_HASH_TYPE_SHA_256/
 *				FDO_CRYPTO_HASH_TYPE_SHA_384/
 *				FDO_CRYPTO_HASH_TYPE_SHA_512)
 * @param buffer - pointer to input data buffer of uint8_t type.
 * @param buffer_length - input data buffer size
 * @param output - pointer to output data buffer of uint8_t type.
 * @param output_length - output data buffer size
 *
 * @return
 *        return 0 on success. -ve value on failure.
 */

int32_t crypto_hal_hash(uint8_t _hash_type, const uint8_t *buffer,
			 size_t buffer_length, uint8_t *output,
			 size_t output_length)
{
	int hash_type = FDO_CRYPTO_HASH_TYPE_USED;

	(void)_hash_type; /* Unused parameter */

	if (NULL == output || 0 == output_length || NULL == buffer ||
	    0 == buffer_length) {
		return -1;
	}

	switch (hash_type) {
	case FDO_CRYPTO_HASH_TYPE_SHA_256:
		if (output_length < SHA256_DIGEST_SIZE) {
			return -1;
		}
		if (NULL == SHA256((const unsigned char *)buffer, buffer_length,
				   output)) {
			return -1;
		}
		break;
	case FDO_CRYPTO_HASH_TYPE_SHA_384:
		if (output_length < SHA384_DIGEST_SIZE) {
			return -1;
		}
		if (NULL == SHA384((const unsigned char *)buffer, buffer_length,
				   output)) {
			return -1;
		}
		break;
	default:
		return -1;
	}

	return 0;
}

/**
 * crypto_hal_hmac function calculate hmac on input data
 *
 * @param hmac_type - Hmac type (FDO_CRYPTO_HMAC_TYPE_SHA_256/
 *				FDO_CRYPTO_HMAC_TYPE_SHA_384/
 *				FDO_CRYPTO_HMAC_TYPE_SHA_512)
 * @param buffer - pointer to input data buffer of uint8_t type.
 * @param buffer_length - input data buffer size
 * @param output - pointer to output data buffer of uint8_t type.
 * @param output_length - output data buffer size
 * @param key - pointer to hmac key buffer of uint8_t type.
 * @param key_length - hmac key size
 * @return
 *        return 0 on success. -ve value on failure.
 */
int32_t crypto_hal_hmac(uint8_t hmac_type, const uint8_t *buffer,
			size_t buffer_length, uint8_t *output,
			size_t output_length, const uint8_t *key,
			size_t key_length)
{
	if (NULL == output || 0 == output_length || NULL == buffer ||
	    0 == buffer_length || NULL == key || 0 == key_length) {
		return -1;
	}

	switch (hmac_type) {
	case FDO_CRYPTO_HMAC_TYPE_SHA_256:
		if (output_length < SHA256_DIGEST_SIZE) {
			return -1;
		}
		if (NULL == HMAC(EVP_sha256(), key, key_length, buffer,
				 (int)buffer_length, output, NULL)) {
			return -1;
		}
		break;
	case FDO_CRYPTO_HMAC_TYPE_SHA_384:
		if (output_length < SHA384_DIGEST_SIZE) {
			return -1;
		}
		if (NULL == HMAC(EVP_sha384(), key, key_length, buffer,
				 (int)buffer_length, output, NULL)) {
			return -1;
		}
		break;
	default:
		return -1;
	}

	return 0;
}
#endif /* SECURE_ELEMENT */
