/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction of mbedTLS library for crypto services required by SDO
 * library.
 */

/* FIXME: test and fix this code */
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

#include "sdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"
#include "mbedtls_random.h"


int32_t inc_rollover_ctr(uint8_t *first_iv, uint8_t *new_iv, uint8_t iv_len,
			 size_t aesblocks)
{
	int32_t ret = -1;
	mbedtls_mpi iv_bn_cur, iv_bn_first, iv_bn_new, comparison_iv;
	size_t new_bit_length;

	if (!first_iv || !new_iv)
		return -1;

	(void)aesblocks;

	mbedtls_mpi_init(&iv_bn_cur);
	mbedtls_mpi_init(&iv_bn_first);
	mbedtls_mpi_init(&iv_bn_new);
	mbedtls_mpi_init(&comparison_iv);

	if (mbedtls_mpi_read_binary(&iv_bn_cur, new_iv, iv_len)) {
		LOG(LOG_ERROR, "Failed to convert cur iv buffer to bn\n");
		goto err;
	}
	if (mbedtls_mpi_read_binary(&iv_bn_first, first_iv, iv_len)) {
		LOG(LOG_ERROR, "Failed to convert first iv buffer to bn\n");
		goto err;
	}

	/* Add to generate new iv */
	if (mbedtls_mpi_add_int(&iv_bn_new, &iv_bn_cur, 1)) {
		LOG(LOG_ERROR, "Failed to generate new from addition\n");
		goto err;
	}

	/* Check the sizes of the iv. have they changed after add */
	if (mbedtls_mpi_size(&iv_bn_new) != mbedtls_mpi_size(&iv_bn_cur)) {
		/* Create a new MPI which has 17 bytes( or the size of the
		 * new iv)
		 */
		if (0 != mbedtls_mpi_grow(&comparison_iv,
					  mbedtls_mpi_size(&iv_bn_new))) {
			LOG(LOG_ERROR, "Unable to grow the new iv\n");
			goto err;
		}
		/* Get the highest set bit in the new iv */
		new_bit_length = mbedtls_mpi_bitlen(&iv_bn_new);

		/* Set the highest bit in the comparision_iv  */
		if (0 !=
		    mbedtls_mpi_set_bit(&comparison_iv, new_bit_length, 1)) {
			LOG(LOG_ERROR, "Unable to set highest bit\n");
			goto err;
		}

		/* Now subtract the new comparison_iv with iv_bn_new to
		 * eliminate the MSB
		 */
		if (0 != mbedtls_mpi_sub_mpi(&iv_bn_cur, &iv_bn_new,
					     &comparison_iv)) {
			LOG(LOG_ERROR, "Unable to subtract mpi\n");
			goto err;
		}

		if (0 != mbedtls_mpi_copy(&iv_bn_new, &iv_bn_cur)) {
			LOG(LOG_ERROR, "Unable to subtract mpi\n")
			goto err;
		}
	}

	/* Check for roll over. */
	if (0 == mbedtls_mpi_cmp_mpi(&iv_bn_first, &iv_bn_new)) {
		LOG(LOG_ERROR, "Roll over iv not supportedv\n");
		goto err;
	}

	/* Write bn to binary data */
	if (mbedtls_mpi_write_binary(&iv_bn_new, new_iv, iv_len)) {
		LOG(LOG_ERROR, "New iv from BN write failed\n");
		goto err;
	}

	ret = 0;
err:
	/* Free MPI */
	mbedtls_mpi_free(&iv_bn_new);
	mbedtls_mpi_free(&iv_bn_first);
	mbedtls_mpi_free(&iv_bn_cur);
	mbedtls_mpi_free(&comparison_iv);
	return ret;
}

#ifndef SECURE_ELEMENT
/**
 * If crypto init is true, generate random bytes of data
 * of size num_bytes passed as paramater, else return error.
 * @param random_buffer - Pointer random_buffer of type uint8_t to be filled
 * with,
 * @param num_bytes - Number of bytes to be filled.
 * @return 0 if succeeds, else -1.
 */
int32_t crypto_hal_random_bytes(uint8_t *random_buffer, size_t num_bytes)
{
	void *dbrg_ctx = get_mbedtls_random_ctx();

	if (!is_mbedtls_random_init() || !dbrg_ctx)
		return -1;

	if (NULL == random_buffer) {
		return -1;
	} else if (0 != mbedtls_ctr_drbg_random(
			    dbrg_ctx, (uint8_t *)random_buffer, num_bytes)) {
		return -1;
	}

	return 0;
}
#endif
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

#ifdef SECURE_ELEMENT
	if (0 != crypto_hal_se_init()) {
		return -1;
	}
#endif /* SECURE_ELEMENT */

	return 0;
}

#ifndef SECURE_ELEMENT
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

	return 0;
}

/**
 * sdo_crypto_hash function calculate hash on input data
 *
 * @param _hash_type - Hash type (SDO_CRYPTO_HASH_TYPE_SHA_256/
 *				SDO_CRYPTO_HASH_TYPE_SHA_384/
 *				SDO_CRYPTO_HASH_TYPE_SHA_512)
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
	mbedtls_md_type_t mbedhash_type = MBEDTLS_MD_NONE;
	uint8_t hash_type = SDO_CRYPTO_HASH_TYPE_USED;

	if (NULL == output || 0 == output_length || NULL == buffer ||
	    0 == buffer_length) {
		return -1;
	}

	(void)_hash_type;

	switch (hash_type) {
	case SDO_CRYPTO_HASH_TYPE_SHA_256:
		if (output_length < SHA256_DIGEST_SIZE)
			return -1;
		mbedhash_type = MBEDTLS_MD_SHA256;
		break;
	case SDO_CRYPTO_HASH_TYPE_SHA_384:
		if (output_length < SHA384_DIGEST_SIZE)
			return -1;
		mbedhash_type = MBEDTLS_MD_SHA384;
		break;

	default:
		return -1;
	}
	/* Calculate the hash over message and sign that hash */
	if (mbedtls_md(mbedtls_md_info_from_type(mbedhash_type),
		       (const uint8_t *)buffer, buffer_length, output) != 0) {
		LOG(LOG_ERROR, " mbedtls_md FAILED:\n");
		return -1;
	}

	return 0;
}

/**
 * crypto_hal_hmac function calculate hmac on input data
 *
 * @param hmac_type - Hmac type (SDO_CRYPTO_HMAC_TYPE_SHA_256/
 *				SDO_CRYPTO_HMAC_TYPE_SHA_384/
 *				SDO_CRYPTO_HMAC_TYPE_SHA_512)
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
	case SDO_CRYPTO_HMAC_TYPE_SHA_256:
		if (output_length < SHA256_DIGEST_SIZE)
			return -1;
		return mbedtls_md_hmac(
		    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		    (const uint8_t *)key, key_length, buffer, buffer_length,
		    output);
		break;
	case SDO_CRYPTO_HMAC_TYPE_SHA_384:
		if (output_length < SHA384_DIGEST_SIZE)
			return -1;
		return mbedtls_md_hmac(
		    mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
		    (const uint8_t *)key, key_length, buffer, buffer_length,
		    output);
		break;

	default:
		return -1;
	}

	return -1;
}
#endif /* SECURE_ELEMENT */
