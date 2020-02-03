/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of Asymmetric Key exchange methods as defined in
 * protocol spec. These APIs inturn call crypto abstraction layer of SDO.
 */

#include "crypto_utils.h"
#include "base64.h"
#include "sdokeyexchange.h"
#include "sdoCryptoApi.h"
#include "sdoCryptoHal.h"
#include "util.h"
#include <stdlib.h>
#if defined(EPID_DA)
#include "epid.h"
#endif
#include "safe_lib.h"

typedef struct {
	uint8_t *_DeviceRandom;
	uint16_t _DevRandSize;
	uint8_t *_publicB; /* Our B public value */
	uint32_t _publicB_length;
	uint8_t *_publicA; /* The server's A public value */
	uint8_t *_sharedSecret;
	int32_t _shared_secret_length;
	SDOByteArray_t *key1;	// in RSA, the Modulus/ binary for DSA
	SDOByteArray_t *key2;	// In RSA, the Exponent
	SDOPublicKey_t *_encryptKey; // key used to encrypt my secret B
} rsa_context_t;

/**
 * sdoCryptoAsymClose closes the asym section
 *
 * @param context - asym context
 * @return
 *        returns 0 on success and -1 on failure
 **/
int32_t sdoCryptoKEXClose(void **context)
{
	rsa_context_t *keyExData;
	if (context == NULL)
		return -1;
	keyExData = *(rsa_context_t **)context;

	if (keyExData->_sharedSecret) {
		/* Not reading the return of memset_s because
		 * we are already in KEXclose().
		 */
		(void)memset_s(keyExData->_sharedSecret,
			       keyExData->_shared_secret_length, 0);
		sdoFree(keyExData->_sharedSecret);
	}
	if (keyExData->_publicA) {
		sdoFree(keyExData->_publicA);
	}
	if (keyExData->_publicB) {
		sdoFree(keyExData->_publicB);
	}
	if (keyExData->_DeviceRandom) {
		sdoFree(keyExData->_DeviceRandom);
	}
	if (memset_s(keyExData, sizeof(rsa_context_t), 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
	}
	sdoFree(keyExData);
	return 0;
}

/**
 * Initialize the key exchange of type ASYM
 * @param context - asym context, passed to other ecdh apis, pointer to
 * @return 0 on success and -1 on failure
 */
int32_t sdoCryptoKEXInit(void **context)
{
	rsa_context_t *keyExData = NULL;
	int ret = -1;

	if (!context) {
		LOG(LOG_ERROR, "Invalid input ");
		return -1;
	}

	keyExData = sdoAlloc(sizeof(rsa_context_t));
	if (!keyExData) {
		return ret;
	}

	keyExData->_DevRandSize = (DEVICE_RANDOM_SIZE / 8);

	keyExData->_DeviceRandom = sdoAlloc(keyExData->_DevRandSize);
	if (!keyExData->_DeviceRandom) {
		LOG(LOG_ERROR, "Memory alloc failed\n");
		goto error;
	}

	if (sdoCryptoRandomBytes(keyExData->_DeviceRandom,
				 keyExData->_DevRandSize) != 0) {
		LOG(LOG_ERROR, "Failed to generate device random\n");
		goto error;
	}

	keyExData->_sharedSecret = NULL;
	// Used to encrypt the xB secret, s/b the OwnerPublicKey
	keyExData->_encryptKey = NULL;

	*context = (void *)keyExData;
	return 0;
error:
	sdoCryptoKEXClose((void *)&keyExData);
	return -1;
}

/**
 * Internal API
 */
static bool computePublicBAsym(rsa_context_t *keyExData)
{
	LOG(LOG_DEBUG, "computePublicBAsym started\n");

	// compute public B, encrypted version of secret
	if (keyExData->_encryptKey != NULL) {
		// We have a key, encrypt xb using it, producing xB
		keyExData->_publicB_length = 0;
#if LOG_LEVEL == LOG_MAX_LEVEL
		char debug_buffer[2048] = {0};
		/* Have a look at the kpublic key provided. */
		sdoPublicKeyToString(keyExData->_encryptKey, debug_buffer,
				     2048);
		LOG(LOG_DEBUG, "Owner Public Key 2: %s\n", debug_buffer);
#endif
		/* Get the cipherLength required */
		keyExData->_publicB_length = sdoCryptoRSAEncrypt(
		    /* TODO : use hashtype, pkey encoding types/pubkey algos
		     * too from keyExdata */
		    SDO_PK_HASH_SHA256, SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP,
		    SDO_CRYPTO_PUB_KEY_ALGO_RSA, keyExData->_DeviceRandom,
		    keyExData->_DevRandSize, NULL, 0,
		    keyExData->_encryptKey->key1->bytes,
		    keyExData->_encryptKey->key1->byteSz,
		    keyExData->_encryptKey->key2->bytes,
		    keyExData->_encryptKey->key2->byteSz);

		if (keyExData->_publicB_length <= 0)
			goto err;

		/* Allocate cyphertxt placeholder */
		if (NULL == (keyExData->_publicB =
				 sdoAlloc(keyExData->_publicB_length))) {
			LOG(LOG_ERROR, "Public_B alloc Failed.\n");
			goto err;
		}

		if (0 != sdoCryptoRSAEncrypt(
			     SDO_PK_HASH_SHA256,
			     SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP,
			     SDO_CRYPTO_PUB_KEY_ALGO_RSA,
			     keyExData->_DeviceRandom, keyExData->_DevRandSize,
			     keyExData->_publicB, keyExData->_publicB_length,
			     keyExData->_encryptKey->key1->bytes,
			     keyExData->_encryptKey->key1->byteSz,
			     keyExData->_encryptKey->key2->bytes,
			     keyExData->_encryptKey->key2->byteSz)) {

			LOG(LOG_ERROR, "rsa_encrypt() finished with "
				       "some error !!\n");
			goto err;
		}

		// On each new encryption generate fresh KDF keys
#if LOG_LEVEL == LOG_MAX_LEVEL
		if (keyExData->_DeviceRandom) {
			SDOByteArray_t *pB = sdoByteArrayAllocWithByteArray(
			    keyExData->_DeviceRandom, keyExData->_DevRandSize);
			sdoByteArrayToString(pB, debug_buffer, 2048);
			if (debug_buffer[0] != 0)
				LOG(LOG_DEBUG, "rsa_encrypt result : %s.\n",
				    debug_buffer);
			sdoByteArrayFree(pB);
		}
#endif

	} else {
		/* No key specified so our random bits are directly made
		 * public */
		keyExData->_publicB = keyExData->_DeviceRandom;
		keyExData->_publicB_length = keyExData->_DevRandSize;
	}
	LOG(LOG_DEBUG, "computePublicBAsym complete\n");
	return true;
err:
	if (keyExData->_publicB) {
		sdoFree(keyExData->_publicB);
	}
	return false;
}

/**
 * Sets the key used to encrypt xB
 * RSA using the Owner Public Key
 * @param data - pointer to the keyexchange data structure
 * @param encryptKey - the Owner Public Key to use
 * @return none
 */
int32_t setEncryptKeyAsym(void *data, SDOPublicKey_t *encryptKey)
{
	rsa_context_t *keyExData = (rsa_context_t *)data;
	keyExData->_encryptKey = encryptKey;

	if (!computePublicBAsym(keyExData)) {
		LOG(LOG_DEBUG, "computePublicBAsym() failed!!\n");
		return -1;
	}
	return 0;
}

/**
 * Step 1, allocate internal secrets and generate public shared value B for
 * Asymmetric key exchange mode.
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
	rsa_context_t *keyExData = (rsa_context_t *)context;

	if (!keyExData || devRandLength == 0) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}
	if (!devRandValue) {
		*devRandLength = keyExData->_publicB_length;
		return 0;
	}
	if (*devRandLength < keyExData->_publicB_length) {
		LOG(LOG_ERROR, "Invalid buff size\n");
		return -1;
	}
	if (memcpy_s(devRandValue, *devRandLength, keyExData->_publicB,
		     keyExData->_publicB_length) != 0) {
		return -1;
	}
	return 0;
}

/**
 * Input A from other side of connection and compute shared secret[ECDH mode].
 * @param context - pointer to the key exchange data structure
 * @param peerRandValue - value is encrypted from other side of connection
 * @param peerRandLength - length of peerRandValue buffer
 * @return 0 if success, else -1 for failure.
 */

int32_t sdoCryptoSetPeerRandom(void *context, const uint8_t *peerRandValue,
			       uint32_t peerRandLength)
{
	rsa_context_t *keyExData = (rsa_context_t *)context;

	uint8_t *shse = NULL;
	size_t allocated_shse_size = 0;
	int ret = -1;
	size_t size = 0;

	if (!keyExData) {
		return -1;
	}

	if (!peerRandLength) {
		LOG(LOG_ERROR, "peerRandLength of 0 \n");
		goto exit;
	}
	hexdump("peerRand", peerRandValue, peerRandLength);
	keyExData->_publicA = sdoAlloc(peerRandLength);
	if (!keyExData->_publicA) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}

	if (memcpy_s(keyExData->_publicA, peerRandLength, peerRandValue,
		     peerRandLength) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}
#if LOG_LEVEL == LOG_MAX_LEVEL
	hexdump("Public A(bn)", keyExData->_publicA, peerRandLength);
#endif
	/* Derive the custom shared secret */
	allocated_shse_size = keyExData->_DevRandSize + peerRandLength;
	shse = sdoAlloc(allocated_shse_size);
	if (!shse) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}

	size = 0;
	if (memcpy_s(&shse[size], allocated_shse_size, keyExData->_DeviceRandom,
		     keyExData->_DevRandSize) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}
	size += keyExData->_DevRandSize;
	if (memcpy_s(&shse[size], allocated_shse_size - size, peerRandValue,
		     peerRandLength) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}

	keyExData->_sharedSecret = shse;
	keyExData->_shared_secret_length = allocated_shse_size;

	ret = 0;

exit:
	if (ret && shse) {
		if (memset_s(shse, allocated_shse_size, 0)) {
			LOG(LOG_ERROR, "Failed to clear Shared Secret\n");
			ret = -1;
		}
		sdoFree(shse);
	}

	if (ret && keyExData->_publicA) {
		if (memset_s(keyExData->_publicA, peerRandLength, 0)) {
			LOG(LOG_ERROR, "Failed to clear secret data Ay\n");
		}
		sdoFree(keyExData->_publicA);
	}
	return ret;
}

/** This function returns the secret computed per the ECDH protocol in the
 * secret buffer
 * of length secretLength.
 *
 * @param context - context parameter is an initialized opaque context
 * structure.
 * @param secret - Points to computed shared secret
 * @param secretLength - Length of computed shared secret
 * @return  0 on success or -1 on failure.
 */
int32_t sdoCryptoGetSecret(void *context, uint8_t *secret,
			   uint32_t *secretLength)
{
	rsa_context_t *keyExData = (rsa_context_t *)context;

	if (!keyExData || !secretLength) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}
	if (!secret) {
		*secretLength = keyExData->_shared_secret_length;
		return 0;
	}
	if (*secretLength < keyExData->_shared_secret_length) {
		LOG(LOG_ERROR, "Invalid buff size\n");
		return -1;
	}

	if (memcpy_s(secret, *secretLength, keyExData->_sharedSecret,
		     keyExData->_shared_secret_length) != 0) {
		return -1;
	}

	return 0;
}
