/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for DH based key exchange crypto routines of mbedTLS
 * library.
 */

#include <stdlib.h>
#include "network_al.h"
#include "sdoCryptoHal.h"
#include "util.h"
#include "sdotypes.h"
#include "crypto_utils.h"
#include "BN_support.h"
#include "mbedtls/dhm.h"
#include "safe_lib.h"
#include "mbedtls_random.h"

#ifdef KEX_DH_ENABLED
#define PRIME_BIN MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN
#define GENERATOR_BIN MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN
#else
/* For DHKEXid15 */
#define PRIME_BIN MBEDTLS_DHM_RFC3526_MODP_3072_P_BIN
#define GENERATOR_BIN MBEDTLS_DHM_RFC3526_MODP_3072_G_BIN
#endif /* KEX_DH_ENABLED */

typedef struct {
	uint8_t *_shared_secret;
	uint32_t _shared_secret_length;
	uint8_t *_publicB;	/* Our B public value */
	uint32_t _publicB_length; /* Our B public value */
	mbedtls_dhm_context dhm;
} dh_context_t;

/**
 * Compute B from initial secret a passed to us in the clear
 * @param key_ex_data - pointer to the keyexchange data structure
 * @return
 *        returns true on success, false on error
 */
static bool compute_publicBDH(dh_context_t *key_ex_data);
#define MBEDTLS_INPUT_NUMBASE 16

/**
 * Initialize the key exchange of type DH
 * @param context - points to the initialised pointer to the key exchange data
 * structure
 * @return 0 if success else -1
 */
int32_t crypto_hal_kex_init(void **context)
{
	int32_t ret = -1;
	dh_context_t *key_ex_data = NULL;

	const uint8_t dhm_p_const[] = PRIME_BIN;
	const uint8_t dhm_g_const[] = GENERATOR_BIN;

	const uint8_t *dhm_P;
	const uint8_t *dhm_G;
	size_t dhm_P_size;
	size_t dhm_G_size;
	mbedtls_mpi prime, generator;

	dhm_P = dhm_p_const;
	dhm_G = dhm_g_const;
	dhm_P_size = sizeof(dhm_p_const);
	dhm_G_size = sizeof(dhm_g_const);

	mbedtls_mpi_init(&prime);
	mbedtls_mpi_init(&generator);

	/* Read the trustworthy DHM prime and generator values */
	if (0 != mbedtls_mpi_read_binary(&prime, dhm_P, dhm_P_size)) {
		LOG(LOG_ERROR, "Unable to get P values\n");
		goto err;
	}
	if (0 != mbedtls_mpi_read_binary(&generator, dhm_G, dhm_G_size)) {
		LOG(LOG_ERROR, "Unable to get G values\n");
		goto err;
	}

	key_ex_data = sdo_alloc(sizeof(dh_context_t));
	if (NULL == key_ex_data) {
		goto err;
	}
	mbedtls_dhm_init(&key_ex_data->dhm);
	if (0 != mbedtls_dhm_set_group(&key_ex_data->dhm, &prime, &generator)) {
		LOG(LOG_ERROR, "Unable to get P and G values\n");
		goto err;
	}

	if (compute_publicBDH(key_ex_data) == false) {
		goto err;
	}

	*context = (void *)key_ex_data;
	ret = 0;
err:
	if ((-1 == ret) && (NULL != key_ex_data)) {
		crypto_hal_kex_close((void *)&key_ex_data);
	}
	mbedtls_mpi_free(&prime);
	mbedtls_mpi_free(&generator);
	return ret;
}

/**
 * sdo_cryptoDHClose closes the dh section
 * @param context - dh context
 * @return
 *        returns 0 on success and -1 on failure
 */
int32_t crypto_hal_kex_close(void **context)
{
	dh_context_t *key_ex_data = *(dh_context_t **)context;

	if (!key_ex_data)
		return -1;

	mbedtls_dhm_free(&key_ex_data->dhm);
	if (key_ex_data->_shared_secret)
		sdo_free(key_ex_data->_shared_secret);
	if (key_ex_data->_publicB)
		sdo_free(key_ex_data->_publicB);

	sdo_free(key_ex_data);
	return 0;
}

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
	(void)rng_state;
	return crypto_hal_random_bytes(output, len);
}

/**
 * Compute B from initial secret a passed to us in the clear
 * @param key_ex_data - pointer to the keyexchange data structure
 * @return
 *        returns true on success, false on error
 */
static bool compute_publicBDH(dh_context_t *key_ex_data)
{
	bool ret = false;
	int retval = -1;

	LOG(LOG_DEBUG, "compute_publicB started\n");
	retval = mbedtls_mpi_size(&key_ex_data->dhm.P);
	if (retval == 0)
		goto err;
	key_ex_data->dhm.len = retval;
	key_ex_data->_publicB = sdo_alloc(key_ex_data->dhm.len);
	if (!key_ex_data->_publicB) {
		LOG(LOG_ERROR, "Failled to alloc Dev public\n");
		goto err;
	}
	key_ex_data->_publicB_length = key_ex_data->dhm.len;

	retval = mbedtls_dhm_make_public(
	    &key_ex_data->dhm, (int)key_ex_data->dhm.len, key_ex_data->_publicB,
	    key_ex_data->dhm.len, myrand, NULL);
	if (retval != 0) {
		LOG(LOG_ERROR, "Failled to make public:%x\n", retval);
		goto err;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	LOG(LOG_DEBUG, "Device Public Key (_publicB) : size %lu :\n",
	    (unsigned long)key_ex_data->_publicB_length);
	hexdump("Device Public Key (_publicB)", key_ex_data->_publicB,
		key_ex_data->_publicB_length);
#endif
	ret = true;
	LOG(LOG_DEBUG, "compute_publicB complete\n");
err:
	return ret;
}

/**
 * Step 1, allocate internal secrets and generate public shared value B
 * This is then sent to the other side of the connection.
 *
 * @param context - pointer to the key exchange data structure
 * @param dev_rand_value - buffer to store device random public shared value B
 * @param dev_rand_length - size of dev_rand_value buffer
 * @return 0 if success, -1 if fails
 */
int32_t crypto_hal_get_device_random(void *context, uint8_t *dev_rand_value,
				     uint32_t *dev_rand_length)
{
	dh_context_t *key_ex_data = (dh_context_t *)context;

	if (!key_ex_data || !dev_rand_length) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	if (!dev_rand_value) {
		*dev_rand_length = key_ex_data->_publicB_length;
		return 0;
	}

	if (memcpy_s(dev_rand_value, *dev_rand_length, key_ex_data->_publicB,
		     *dev_rand_length) != 0) {
		return -1;
	}
	return 0;
}

/**
 * Input A from other side of connection and compute shared secret[DH mode].
 * @param context - pointer to the key exchange data structure
 * @param peer_rand_value - value is encrypted from other side of connection
 * @param peer_rand_length - length of peer_rand_value buffer
 * @return 0 if success, else -1.
 */
int32_t crypto_hal_set_peer_random(void *context,
				   const uint8_t *peer_rand_value,
				   uint32_t peer_rand_length)
{
	dh_context_t *key_ex_data = (dh_context_t *)context;
	int ret = -1;

	if (!key_ex_data || !peer_rand_value ||
	    DH_PEER_RANDOM_SIZE != peer_rand_length) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	size_t olen = 0;
	uint8_t *public_abytes = (uint8_t *)peer_rand_value;

	if (public_abytes == NULL) {
		goto err;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	LOG(LOG_DEBUG, "set_publicA : bytes : %lu\n",
	    (unsigned long)peer_rand_length);
	hexdump("Public A", public_abytes, peer_rand_length);
#endif

	ret = mbedtls_dhm_read_public(&key_ex_data->dhm,
				      (const unsigned char *)public_abytes,
				      peer_rand_length);
	if (ret != 0) {
		LOG(LOG_ERROR, "Error reading public key\n");
		goto err;
	}
	key_ex_data->dhm.len = mbedtls_mpi_size(&key_ex_data->dhm.P);
	if (key_ex_data->dhm.len == 0)
		goto err;

	key_ex_data->_shared_secret_length = key_ex_data->dhm.len;
	key_ex_data->_shared_secret = sdo_alloc(key_ex_data->dhm.len);
	if (NULL == key_ex_data->_shared_secret)
		goto err;
	ret = mbedtls_dhm_calc_secret(
	    &key_ex_data->dhm, key_ex_data->_shared_secret,
	    key_ex_data->_shared_secret_length, &olen, NULL, NULL);
	if (ret) {
		LOG(LOG_ERROR, "Error calculating Shared Secret\n");
		goto err;
	}

	LOG(LOG_DEBUG, "Shared secret generated\n");
	ret = 0;
err:
	return ret;
}

/** This function returns the secret computed per the DH protocol in the
 * secret buffer
 * of length secret_length.
 *
 * @param context - context parameter is an initialized opaque context
 * structure.
 * @param secret - secret data buffer
 * @param secret_length - secret data size.
 * @return  0 on success or -1 on failure.
 */
int32_t crypto_hal_get_secret(void *context, uint8_t *secret,
			      uint32_t *secret_length)
{
	dh_context_t *key_ex_data = (dh_context_t *)context;

	if (!context || !secret_length) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	if (!secret) {
		*secret_length = key_ex_data->_shared_secret_length;
		return 0;
	}

	if (memcpy_s(secret, *secret_length, key_ex_data->_shared_secret,
		     *secret_length) != 0) {
		return -1;
	}

	return 0;
}
