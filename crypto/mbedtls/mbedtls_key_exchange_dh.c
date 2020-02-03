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
	uint8_t *_sharedSecret;
	uint32_t _shared_secret_length;
	uint8_t *_publicB;	/* Our B public value */
	uint32_t _publicB_length; /* Our B public value */
	mbedtls_dhm_context dhm;
} dh_context_t;

/**
 * Compute B from initial secret a passed to us in the clear
 * @param keyExData - pointer to the keyexchange data structure
 * @return
 *        returns true on success, false on error
 */
static bool computePublicBDH(dh_context_t *keyExData);
#define MBEDTLS_INPUT_NUMBASE 16

/**
 * Initialize the key exchange of type DH
 * @param context - points to the initialised pointer to the key exchange data
 * structure
 * @return 0 if success else -1
 */
int32_t sdoCryptoKEXInit(void **context)
{
	int32_t ret = -1;
	dh_context_t *keyExData = NULL;

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

	keyExData = sdoAlloc(sizeof(dh_context_t));
	if (NULL == keyExData) {
		goto err;
	}
	mbedtls_dhm_init(&keyExData->dhm);
	if (0 != mbedtls_dhm_set_group(&keyExData->dhm, &prime, &generator)) {
		LOG(LOG_ERROR, "Unable to get P and G values\n");
		goto err;
	}

	if (computePublicBDH(keyExData) == false) {
		goto err;
	}

	*context = (void *)keyExData;
	ret = 0;
err:
	if ((-1 == ret) && (NULL != keyExData)) {
		sdoCryptoKEXClose((void *)&keyExData);
	}
	mbedtls_mpi_free(&prime);
	mbedtls_mpi_free(&generator);
	return ret;
}

/**
 * sdoCryptoDHClose closes the dh section
 * @param context - dh context
 * @return
 *        returns 0 on success and -1 on failure
 */
int32_t sdoCryptoKEXClose(void **context)
{
	dh_context_t *keyExData = *(dh_context_t **)context;
	if (!keyExData)
		return -1;

	mbedtls_dhm_free(&keyExData->dhm);
	if (keyExData->_sharedSecret)
		sdoFree(keyExData->_sharedSecret);
	if (keyExData->_publicB)
		sdoFree(keyExData->_publicB);

	sdoFree(keyExData);
	return 0;
}

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
	return _sdoCryptoRandomBytes(output, len);
}

/**
 * Compute B from initial secret a passed to us in the clear
 * @param keyExData - pointer to the keyexchange data structure
 * @return
 *        returns true on success, false on error
 */
static bool computePublicBDH(dh_context_t *keyExData)
{
	bool ret = false;
	int retval = -1;

	LOG(LOG_DEBUG, "computePublicB started\n");
	retval = mbedtls_mpi_size(&keyExData->dhm.P);
	if (retval == 0)
		goto err;
	keyExData->dhm.len = retval;
	keyExData->_publicB = sdoAlloc(keyExData->dhm.len);
	if (!keyExData->_publicB) {
		LOG(LOG_ERROR, "Failled to alloc Dev public\n");
		goto err;
	}
	keyExData->_publicB_length = keyExData->dhm.len;

	retval = mbedtls_dhm_make_public(
	    &keyExData->dhm, (int)keyExData->dhm.len, keyExData->_publicB,
	    keyExData->dhm.len, myrand, NULL);
	if (retval != 0) {
		LOG(LOG_ERROR, "Failled to make public:%x\n", retval);
		goto err;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	LOG(LOG_DEBUG, "Device Public Key (_publicB) : size %lu :\n",
	    (unsigned long)keyExData->_publicB_length);
	hexdump("Device Public Key (_publicB)", keyExData->_publicB,
		keyExData->_publicB_length);
#endif
	ret = true;
	LOG(LOG_DEBUG, "computePublicB complete\n");
err:
	return ret;
}

/**
 * Step 1, allocate internal secrets and generate public shared value B
 * This is then sent to the other side of the connection.
 *
 * @param context - pointer to the key exchange data structure
 * @param devRandValue - buffer to store device random public shared value B
 * @param devRandLength - size of devRandValue buffer
 * @return 0 if success, -1 if fails
 */
int32_t sdoCryptoGetDeviceRandom(void *context, uint8_t *devRandValue,
				 uint32_t *devRandLength)
{
	dh_context_t *keyExData = (dh_context_t *)context;

	if (!keyExData || !devRandLength) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	if (!devRandValue) {
		*devRandLength = keyExData->_publicB_length;
		return 0;
	}

	if (memcpy_s(devRandValue, *devRandLength, keyExData->_publicB,
		     *devRandLength) != 0) {
		return -1;
	}
	return 0;
}

/**
 * Input A from other side of connection and compute shared secret[DH mode].
 * @param context - pointer to the key exchange data structure
 * @param peerRandValue - value is encrypted from other side of connection
 * @param peerRandLength - length of peerRandValue buffer
 * @return 0 if success, else -1.
 */
int32_t sdoCryptoSetPeerRandom(void *context, const uint8_t *peerRandValue,
			       uint32_t peerRandLength)
{
	dh_context_t *keyExData = (dh_context_t *)context;
	int ret = -1;

	if (!keyExData || !peerRandValue ||
	    DH_PEER_RANDOM_SIZE != peerRandLength) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	size_t olen = 0;
	uint8_t *publicAbytes = (uint8_t *)peerRandValue;
	if (publicAbytes == NULL) {
		goto err;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	LOG(LOG_DEBUG, "setPublicA : bytes : %lu\n",
	    (unsigned long)peerRandLength);
	hexdump("Public A", publicAbytes, peerRandLength);
#endif

	ret = mbedtls_dhm_read_public(&keyExData->dhm,
				      (const unsigned char *)publicAbytes,
				      peerRandLength);
	if (ret != 0) {
		LOG(LOG_ERROR, "Error reading public key\n");
		goto err;
	}
	keyExData->dhm.len = mbedtls_mpi_size(&keyExData->dhm.P);
	if (keyExData->dhm.len == 0)
		goto err;

	keyExData->_shared_secret_length = keyExData->dhm.len;
	keyExData->_sharedSecret = sdoAlloc(keyExData->dhm.len);
	if (NULL == keyExData->_sharedSecret)
		goto err;
	ret = mbedtls_dhm_calc_secret(&keyExData->dhm, keyExData->_sharedSecret,
				      keyExData->_shared_secret_length, &olen,
				      NULL, NULL);
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
 * of length secretLength.
 *
 * @param context - context parameter is an initialized opaque context
 * structure.
 * @param secret - secret data buffer
 * @param secretLength - secret data size.
 * @return  0 on success or -1 on failure.
 */
int32_t sdoCryptoGetSecret(void *context, uint8_t *secret,
			   uint32_t *secretLength)
{
	dh_context_t *keyExData = (dh_context_t *)context;

	if (!context || !secretLength) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	if (!secret) {
		*secretLength = keyExData->_shared_secret_length;
		return 0;
	}

	if (memcpy_s(secret, *secretLength, keyExData->_sharedSecret,
		     *secretLength) != 0) {
		return -1;
	}

	return 0;
}
