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
#include "sdoCrypto.h"
#include "sdoCryptoHal.h"
#include "util.h"
#include <stdlib.h>
#include "safe_lib.h"

#ifdef KEX_ASYM_ENABLED
#define DEVICE_RANDOM_SIZE SDO_ASYM_DEV_RANDOM
#else
/* ASYM3072 Generate Device Random bits(768) */
#define DEVICE_RANDOM_SIZE SDO_ASYM3072_DEV_RANDOM
#endif //	KEX_ASYM_ENABLED

typedef struct {
	uint8_t *_Device_random;
	uint16_t _Dev_rand_size;
	uint8_t *_publicB; /* Our B public value */
	uint32_t _publicB_length;
	uint8_t *_publicA; /* The server's A public value */
	uint8_t *_shared_secret;
	uint32_t _shared_secret_length;
	sdo_byte_array_t *key1;		// in RSA, the Modulus/ binary for DSA
	sdo_byte_array_t *key2;		// In RSA, the Exponent
	sdo_public_key_t *_encrypt_key; // key used to encrypt my secret B
} rsa_context_t;

/**
 * crypto_hal_kex_close closes the asym section
 *
 * @param context - asym context
 * @return
 *        returns 0 on success and -1 on failure
 **/
int32_t crypto_hal_kex_close(void **context)
{
	rsa_context_t *key_ex_data;

	if (context == NULL)
		return -1;
	key_ex_data = *(rsa_context_t **)context;

	if (key_ex_data->_shared_secret) {
		/* Not reading the return of memset_s because
		 * we are already in KEXclose().
		 */
		(void)memset_s(key_ex_data->_shared_secret,
			       key_ex_data->_shared_secret_length, 0);
		sdo_free(key_ex_data->_shared_secret);
	}
	if (key_ex_data->_publicA) {
		sdo_free(key_ex_data->_publicA);
	}
	if (key_ex_data->_publicB) {
		sdo_free(key_ex_data->_publicB);
	}
	if (key_ex_data->_Device_random) {
		sdo_free(key_ex_data->_Device_random);
	}
	if (memset_s(key_ex_data, sizeof(rsa_context_t), 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
	}
	sdo_free(key_ex_data);
	return 0;
}

/**
 * Initialize the key exchange of type ASYM
 * @param context - asym context, passed to other ecdh apis, pointer to
 * @return 0 on success and -1 on failure
 */
int32_t crypto_hal_kex_init(void **context)
{
	rsa_context_t *key_ex_data = NULL;
	int ret = -1;

	if (!context) {
		LOG(LOG_ERROR, "Invalid input ");
		return -1;
	}

	key_ex_data = sdo_alloc(sizeof(rsa_context_t));
	if (!key_ex_data) {
		return ret;
	}

	key_ex_data->_Dev_rand_size = (DEVICE_RANDOM_SIZE / 8);

	key_ex_data->_Device_random = sdo_alloc(key_ex_data->_Dev_rand_size);
	if (!key_ex_data->_Device_random) {
		LOG(LOG_ERROR, "Memory alloc failed\n");
		goto error;
	}

	if (sdo_crypto_random_bytes(key_ex_data->_Device_random,
				    key_ex_data->_Dev_rand_size) != 0) {
		LOG(LOG_ERROR, "Failed to generate device random\n");
		goto error;
	}

	key_ex_data->_shared_secret = NULL;
	// Used to encrypt the xB secret, s/b the Owner_public_key
	key_ex_data->_encrypt_key = NULL;

	*context = (void *)key_ex_data;
	return 0;
error:
	crypto_hal_kex_close((void *)&key_ex_data);
	return -1;
}

/**
 * Internal API
 */
static bool compute_publicBAsym(rsa_context_t *key_ex_data)
{
	LOG(LOG_DEBUG, "%s started\n", __func__);

	// compute public B, encrypted version of secret
	if (key_ex_data->_encrypt_key != NULL) {
		// We have a key, encrypt xb using it, producing xB
		key_ex_data->_publicB_length = 0;
#if LOG_LEVEL == LOG_MAX_LEVEL
		char debug_buffer[2048] = {0};
		/* Have a look at the kpublic key provided. */
		sdo_public_key_to_string(key_ex_data->_encrypt_key,
					 debug_buffer, 2048);
		LOG(LOG_DEBUG, "Owner Public Key 2: %s\n", debug_buffer);
#endif
		/* Get the cipher_length required */
		key_ex_data->_publicB_length = crypto_hal_rsa_encrypt(
		    /* TODO : use hashtype, pkey encoding types/pubkey algos
		     * too from key_exdata
		     */
		    SDO_PK_HASH_SHA256, SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP,
		    SDO_CRYPTO_PUB_KEY_ALGO_RSA, key_ex_data->_Device_random,
		    key_ex_data->_Dev_rand_size, NULL, 0,
		    key_ex_data->_encrypt_key->key1->bytes,
		    key_ex_data->_encrypt_key->key1->byte_sz,
		    key_ex_data->_encrypt_key->key2->bytes,
		    key_ex_data->_encrypt_key->key2->byte_sz);

		if (key_ex_data->_publicB_length <= 0)
			goto err;

		/* Allocate cyphertxt placeholder */
		key_ex_data->_publicB =
			sdo_alloc(key_ex_data->_publicB_length);
		if (NULL == key_ex_data->_publicB) {
			LOG(LOG_ERROR, "Public_B alloc Failed.\n");
			goto err;
		}

		if (0 != crypto_hal_rsa_encrypt(
			     SDO_PK_HASH_SHA256,
			     SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP,
			     SDO_CRYPTO_PUB_KEY_ALGO_RSA,
			     key_ex_data->_Device_random,
			     key_ex_data->_Dev_rand_size, key_ex_data->_publicB,
			     key_ex_data->_publicB_length,
			     key_ex_data->_encrypt_key->key1->bytes,
			     key_ex_data->_encrypt_key->key1->byte_sz,
			     key_ex_data->_encrypt_key->key2->bytes,
			     key_ex_data->_encrypt_key->key2->byte_sz)) {

			LOG(LOG_ERROR, "rsa_encrypt() finished with "
				       "some error !!\n");
			goto err;
		}

		// On each new encryption generate fresh KDF keys
#if LOG_LEVEL == LOG_MAX_LEVEL
		if (key_ex_data->_Device_random) {
			sdo_byte_array_t *pB =
			    sdo_byte_array_alloc_with_byte_array(
				key_ex_data->_Device_random,
				key_ex_data->_Dev_rand_size);
			sdo_byte_array_to_string(pB, debug_buffer, 2048);
			if (debug_buffer[0] != 0)
				LOG(LOG_DEBUG, "rsa_encrypt result : %s.\n",
				    debug_buffer);
			sdo_byte_array_free(pB);
		}
#endif

	} else {
		/* No key specified so our random bits are directly made
		 * public
		 */
		key_ex_data->_publicB = key_ex_data->_Device_random;
		key_ex_data->_publicB_length = key_ex_data->_Dev_rand_size;
	}
	LOG(LOG_DEBUG, "%s complete\n", __func__);
	return true;
err:
	if (key_ex_data->_publicB) {
		sdo_free(key_ex_data->_publicB);
	}
	return false;
}

/**
 * Sets the key used to encrypt xB
 * RSA using the Owner Public Key
 * @param data - pointer to the keyexchange data structure
 * @param encrypt_key - the Owner Public Key to use
 * @return none
 */
int32_t set_encrypt_key_asym(void *data, sdo_public_key_t *encrypt_key)
{
	rsa_context_t *key_ex_data = (rsa_context_t *)data;

	key_ex_data->_encrypt_key = encrypt_key;

	if (!compute_publicBAsym(key_ex_data)) {
		LOG(LOG_DEBUG, "compute_publicBAsym() failed!!\n");
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
 * @param dev_rand_value - buffer to store device random public shared value B
 * @param dev_rand_length - size of dev_rand_value buffer
 * @return 0 if success, -1 if fails
 */
int32_t crypto_hal_get_device_random(void *context, uint8_t *dev_rand_value,
				     uint32_t *dev_rand_length)
{
	rsa_context_t *key_ex_data = (rsa_context_t *)context;

	if (!key_ex_data || dev_rand_length == 0) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}
	if (!dev_rand_value) {
		*dev_rand_length = key_ex_data->_publicB_length;
		return 0;
	}
	if (*dev_rand_length < key_ex_data->_publicB_length) {
		LOG(LOG_ERROR, "Invalid buff size\n");
		return -1;
	}
	if (memcpy_s(dev_rand_value, *dev_rand_length, key_ex_data->_publicB,
		     key_ex_data->_publicB_length) != 0) {
		return -1;
	}
	return 0;
}

/**
 * Input A from other side of connection and compute shared secret[ECDH mode].
 * @param context - pointer to the key exchange data structure
 * @param peer_rand_value - value is encrypted from other side of connection
 * @param peer_rand_length - length of peer_rand_value buffer
 * @return 0 if success, else -1 for failure.
 */

int32_t crypto_hal_set_peer_random(void *context,
				   const uint8_t *peer_rand_value,
				   uint32_t peer_rand_length)
{
	rsa_context_t *key_ex_data = (rsa_context_t *)context;

	uint8_t *shse = NULL;
	size_t allocated_shse_size = 0;
	int ret = -1;
	size_t size = 0;

	if (!key_ex_data) {
		return -1;
	}

	if (!peer_rand_length) {
		LOG(LOG_ERROR, "peer_rand_length of 0\n");
		goto exit;
	}
	hexdump("peer_rand", peer_rand_value, peer_rand_length);
	key_ex_data->_publicA = sdo_alloc(peer_rand_length);
	if (!key_ex_data->_publicA) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}

	if (memcpy_s(key_ex_data->_publicA, peer_rand_length, peer_rand_value,
		     peer_rand_length) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}
#if LOG_LEVEL == LOG_MAX_LEVEL
	hexdump("Public A(bn)", key_ex_data->_publicA, peer_rand_length);
#endif
	/* Derive the custom shared secret */
	allocated_shse_size = key_ex_data->_Dev_rand_size + peer_rand_length;
	shse = sdo_alloc(allocated_shse_size);
	if (!shse) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}

	size = 0;
	if (memcpy_s(&shse[size], allocated_shse_size,
		     key_ex_data->_Device_random,
		     key_ex_data->_Dev_rand_size) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}
	size += key_ex_data->_Dev_rand_size;
	if (memcpy_s(&shse[size], allocated_shse_size - size, peer_rand_value,
		     peer_rand_length) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}

	key_ex_data->_shared_secret = shse;
	key_ex_data->_shared_secret_length = allocated_shse_size;

	ret = 0;

exit:
	if (ret && shse) {
		if (memset_s(shse, allocated_shse_size, 0)) {
			LOG(LOG_ERROR, "Failed to clear Shared Secret\n");
			ret = -1;
		}
		sdo_free(shse);
	}

	if (ret && key_ex_data->_publicA) {
		if (memset_s(key_ex_data->_publicA, peer_rand_length, 0)) {
			LOG(LOG_ERROR, "Failed to clear secret data Ay\n");
		}
		sdo_free(key_ex_data->_publicA);
	}
	return ret;
}

/** This function returns the secret computed per the ECDH protocol in the
 * secret buffer
 * of length secret_length.
 *
 * @param context - context parameter is an initialized opaque context
 * structure.
 * @param secret - Points to computed shared secret
 * @param secret_length - Length of computed shared secret
 * @return  0 on success or -1 on failure.
 */
int32_t crypto_hal_get_secret(void *context, uint8_t *secret,
			      uint32_t *secret_length)
{
	rsa_context_t *key_ex_data = (rsa_context_t *)context;

	if (!key_ex_data || !secret_length) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}
	if (!secret) {
		*secret_length = key_ex_data->_shared_secret_length;
		return 0;
	}
	if (*secret_length < key_ex_data->_shared_secret_length) {
		LOG(LOG_ERROR, "Invalid buff size\n");
		return -1;
	}

	if (memcpy_s(secret, *secret_length, key_ex_data->_shared_secret,
		     key_ex_data->_shared_secret_length) != 0) {
		return -1;
	}

	return 0;
}
