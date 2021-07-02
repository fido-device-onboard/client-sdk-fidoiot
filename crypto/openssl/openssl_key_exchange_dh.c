/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for DH based key exchange crypto routines of openssl
 * library.
 */

#include "network_al.h"
#include "fdoCryptoHal.h"
#include "util.h"
#include "crypto_utils.h"
#include "BN_support.h"
#include <openssl/bn.h>
#include "safe_lib.h"
#include <openssl/ec.h>
#define DECLARE_BIGNUM(bn) bignum_t *bn

#define DEFAULT_DH_SECRET_BITS 384

#ifdef KEX_DH_ENABLED
#define GET_PRIME get_rfc3526_prime_2048
#define RFC RFC3526_P2048
#else
/* For DHKEXid15 */
#define GET_PRIME get_rfc3526_prime_3072
#define RFC RFC3526_P3072
#endif /* KEX_DH_ENABLED */

typedef struct {
	DECLARE_BIGNUM(_p15); /* The group 14 MODP 2048 bit number */
	DECLARE_BIGNUM(_g15); /* The base */

	int _secret_bits;
	DECLARE_BIGNUM(_secretb); /* Out 320 bit secret */
	DECLARE_BIGNUM(_publicA); /* The server's A public value */
	DECLARE_BIGNUM(
	    _shared_secret);      /* Big num version of the shared secret */
	DECLARE_BIGNUM(_publicB); /* Our B public value */
} dh_context_t;

typedef union {
	int as_int;
	uint8_t as_bytes[sizeof(int)];
} _g15_t;

static bool compute_publicBDH(dh_context_t *key_ex_data);

/**
 * Initialize the key exchange of type DH
 * @param context - points to the initialised pointer to the key exchange data
 * structure
 * @return 0 if success else -1
 */
int32_t crypto_hal_kex_init(void **context)
{
	dh_context_t *key_ex_data = NULL;

	_g15_t _g15 = {0};

	key_ex_data = fdo_alloc(sizeof(dh_context_t));
	if (!key_ex_data) {
		return -1;
	}
	/*
	 * Start by memory allocation so then all pointers will be initialized
	 * in case of fdo_crypto_init error.
	 */
	key_ex_data->_g15 = BN_new();
	key_ex_data->_p15 = BN_new();
	key_ex_data->_secretb = BN_new();
	key_ex_data->_publicB = BN_new();
	key_ex_data->_publicA = BN_new();
	key_ex_data->_shared_secret = BN_new();

	key_ex_data->_p15 = GET_PRIME(key_ex_data->_p15);

	/* Must be big-endian for openssl */
	_g15.as_int = fdo_host_to_net_long(2);

	/* Create our _g15 value. */
	bn_bin2bn(_g15.as_bytes, sizeof(int), key_ex_data->_g15);

	if (compute_publicBDH(key_ex_data) == false) {
		goto err;
	}

	*context = (void *)key_ex_data;
	return 0;
err:
	if (NULL != key_ex_data) {
		crypto_hal_kex_close((void *)&key_ex_data);
	}
	return -1;
}

/**
 * fdo_cryptoDHClose closes the dh section
 * @param context - ecdh context
 * @return
 *        returns 0 on success and -1 on failure
 */
int32_t crypto_hal_kex_close(void **context)
{
	dh_context_t *key_ex_data = *(dh_context_t **)context;

	if (!key_ex_data) {
		return -1;
	}
#define BN_FREE(n)                                                             \
	if (n) {                                                               \
		BN_clear_free(n);                                              \
		n = NULL;                                                      \
	}
	BN_FREE(key_ex_data->_g15);
	BN_FREE(key_ex_data->_p15);
	BN_FREE(key_ex_data->_secretb);
	BN_FREE(key_ex_data->_publicB);
	BN_FREE(key_ex_data->_publicA);
	BN_FREE(key_ex_data->_shared_secret);

	fdo_free(key_ex_data);
	key_ex_data = NULL;
	return 0;
}

/**
 * Compute B from initial secret a passed to us in the clear
 * @param key_ex_data - pointer to the keyexchange data structure
 * @return
 *        returns true on success, false on error
 */
static bool compute_publicBDH(dh_context_t *key_ex_data)
{
	BN_CTX *ctx = NULL;
	bool ret = false;

	LOG(LOG_DEBUG, "compute_publicB started\n");

	/* Allocate secret a(b)*/

	/*
	 * Make our secret(Device Random), a BIGNUM sized secret
	 * This is asking for the top bit to be a zero and it can be
	 * either even or odd.
	 */
	key_ex_data->_secret_bits = (DEFAULT_DH_SECRET_BITS + 7) & (~7);
	if (bn_rand(key_ex_data->_secretb, key_ex_data->_secret_bits)) {
		LOG(LOG_ERROR, "Trouble with bn_rand\n");
		goto err;
	}

	/*
	 * Compute public B = g^a mod p
	 * _publicB = _g15 ^ _secretb mod _id15
	 */
	ctx = BN_CTX_new();

	/*
	 * This parameters are - destination, g, p, a, then a ctx used for the
	 * calculation.
	 */
	LOG(LOG_DEBUG, "Calculate _publicB\n");

	if (bn_mod_exp(key_ex_data->_publicB, key_ex_data->_g15,
		       key_ex_data->_secretb, key_ex_data->_p15, ctx)) {
		LOG(LOG_ERROR,
		    "compute_publicB : Trouble doing the bn_mod_exp\n");
		goto err;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	char *hexbuf = BN_bn2hex(key_ex_data->_publicB);

	LOG(LOG_DEBUG, "key_ex_data->_publicB %s : bytes %d, %s\n",
	    BN_is_negative(key_ex_data->_publicB) ? "Negative" : "Positive",
	    bn_num_bytes(key_ex_data->_publicB), hexbuf);
	OPENSSL_free(hexbuf);
#endif
	ret = true;
	LOG(LOG_DEBUG, "compute_publicB complete\n");
err:
	/* Consider using the bn cache in ctx. */
	BN_CTX_free(ctx);
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
		*dev_rand_length = bn_num_bytes(key_ex_data->_publicB);
		return 0;
	}

	if (0 >= bn_bn2bin(key_ex_data->_publicB, dev_rand_value)) {
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
	dh_context_t *key_ex_data = (dh_context_t *)context;
	BN_CTX *ctx = NULL;
	int ret = -1;

	if (!key_ex_data || !peer_rand_value ||
	    DH_PEER_RANDOM_SIZE != peer_rand_length) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

/* TODO: remove lib call and replace proper */
#if LOG_LEVEL == LOG_MAX_LEVEL
	/* Display publicB */
	fdo_byte_array_t *publicB = bn_to_byte_array(key_ex_data->_publicB);

	if (publicB) {
		LOG(LOG_DEBUG, "publicB : %lu bytes :\n", publicB->byte_sz);
		hexdump("Public B", publicB->bytes, publicB->byte_sz);
		fdo_byte_array_free(publicB);
	} else {
		LOG(LOG_ERROR, "publicB allocation failed!");
		return -1;
	}
#endif

	ret = bn_bin2bn((const unsigned char *)peer_rand_value,
			(int)peer_rand_length, key_ex_data->_publicA);

	if (ret == -1) {
		return ret;
	}

	ctx = BN_CTX_new();

	/*
	 * Create our shared secret
	 * _sharedsecret = _publicDHBA ^ _secretDHab mod _p15
	 */
	if (bn_mod_exp(key_ex_data->_shared_secret, /* Destination */
		       key_ex_data->_publicA,       /* Base */
		       key_ex_data->_secretb,       /* Power*/
		       key_ex_data->_p15,	   /* Modulo */
		       ctx)) {
		LOG(LOG_ERROR, "set_publicA : Trouble doing the bm_mod_exp\n");
	}
#if LOG_LEVEL == LOG_MAX_LEVEL
	hexdump("Public A (xA)", peer_rand_value, peer_rand_length);
#endif
	BN_CTX_free(ctx);

	LOG(LOG_DEBUG, "KDF Successful\n");
	return 0;
}

/** This function returns the secret computed per the DH protocol in the
 * secret buffer of length secret_length.
 *  @param context - The context parameter is an initialized opaque context
 *  structure.
 *  @param secret - buffer to contain shared secret
 *  @param secret_length - Size of secret buffer
 *  @return 0 on success or -1 on failure.
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
		*secret_length = bn_num_bytes(key_ex_data->_shared_secret);
		return 0;
	}

	if (0 >= bn_bn2bin(key_ex_data->_shared_secret, secret)) {
		return -1;
	}

	return 0;
}
