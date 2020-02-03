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
#include "sdoCryptoHal.h"
#include "util.h"
#include "crypto_utils.h"
#include "BN_support.h"
#include <openssl/bn.h>
#include "safe_lib.h"
#include <openssl/ec.h>
#define DECLARE_BIGNUM(bn) bignum_t *bn

#define DEFAULT_DH_SECRET_BITS 384

#define SECRET_BITS_256 256
#define SECRET_BITS_768 768

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

	int _secretBits;
	DECLARE_BIGNUM(_secretb); /* Out 320 bit secret */
	DECLARE_BIGNUM(_publicA); /* The server's A public value */
	DECLARE_BIGNUM(
	    _sharedSecret);       /* Big num version of the shared secret */
	DECLARE_BIGNUM(_publicB); /* Our B public value */
} dh_context_t;

typedef union {
	int asInt;
	uint8_t asBytes[sizeof(int)];
} _g15_t;

static bool computePublicBDH(dh_context_t *keyExData);

/**
 * Initialize the key exchange of type DH
 * @param context - points to the initialised pointer to the key exchange data
 * structure
 * @return 0 if success else -1
 */
int32_t sdoCryptoKEXInit(void **context)
{
	dh_context_t *keyExData = NULL;

	_g15_t _g15 = {0};

	keyExData = sdoAlloc(sizeof(dh_context_t));
	if (!keyExData)
		return -1;
	/*
	 * Start by memory allocation so then all pointers will be initialized
	 * in case of sdoCryptoInit error.
	 */
	keyExData->_g15 = BN_new();
	keyExData->_p15 = BN_new();
	keyExData->_secretb = BN_new();
	keyExData->_publicB = BN_new();
	keyExData->_publicA = BN_new();
	keyExData->_sharedSecret = BN_new();

	keyExData->_p15 = GET_PRIME(keyExData->_p15);

	/* Must be big-endian for openssl */
	_g15.asInt = sdoHostToNetLong(2);

	/* Create our _g15 value. */
	bn_bin2bn(_g15.asBytes, sizeof(int), keyExData->_g15);

	if (computePublicBDH(keyExData) == false)
		goto err;

	*context = (void *)keyExData;
	return 0;
err:
	if (NULL != keyExData)
		sdoCryptoKEXClose((void *)&keyExData);
	return -1;
}

/**
 * sdoCryptoDHClose closes the dh section
 * @param context - ecdh context
 * @return
 *        returns 0 on success and -1 on failure
 */
int32_t sdoCryptoKEXClose(void **context)
{
	dh_context_t *keyExData = *(dh_context_t **)context;
	if (!keyExData)
		return -1;
#define BN_FREE(n)                                                             \
	if (n) {                                                               \
		BN_clear_free(n);                                              \
		n = NULL;                                                      \
	}
	BN_FREE(keyExData->_g15);
	BN_FREE(keyExData->_p15);
	BN_FREE(keyExData->_secretb);
	BN_FREE(keyExData->_publicB);
	BN_FREE(keyExData->_publicA);
	BN_FREE(keyExData->_sharedSecret);

	sdoFree(keyExData);
	keyExData = NULL;
	return 0;
}

/**
 * Compute B from initial secret a passed to us in the clear
 * @param keyExData - pointer to the keyexchange data structure
 * @return
 *        returns true on success, false on error
 */
static bool computePublicBDH(dh_context_t *keyExData)
{
	BN_CTX *ctx = NULL;
	bool ret = false;

	LOG(LOG_DEBUG, "computePublicB started\n");

	/* Allocate secret a(b)*/

	/*
	 * Make our secret(Device Random), a BIGNUM sized secret
	 * This is asking for the top bit to be a zero and it can be
	 * either even or odd.
	 */
	keyExData->_secretBits = (DEFAULT_DH_SECRET_BITS + 7) & (~7);
	if (bn_rand(keyExData->_secretb, keyExData->_secretBits)) {
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

	if (bn_mod_exp(keyExData->_publicB, keyExData->_g15,
		       keyExData->_secretb, keyExData->_p15, ctx)) {
		LOG(LOG_ERROR,
		    "computePublicB : Trouble doing the bn_mod_exp\n");
		goto err;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	char *hexbuf = BN_bn2hex(keyExData->_publicB);
	LOG(LOG_DEBUG, "keyExData->_publicB %s : bytes %d, %s\n",
	    BN_is_negative(keyExData->_publicB) ? "Negative" : "Positive",
	    bn_num_bytes(keyExData->_publicB), hexbuf);
	OPENSSL_free(hexbuf);
#endif
	ret = true;
	LOG(LOG_DEBUG, "computePublicB complete\n");
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
		*devRandLength = bn_num_bytes(keyExData->_publicB);
		return 0;
	}

	if (0 >= bn_bn2bin(keyExData->_publicB, devRandValue))
		return -1;

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
	dh_context_t *keyExData = (dh_context_t *)context;
	BN_CTX *ctx = NULL;
	int ret = -1;

	if (!keyExData || !peerRandValue ||
	    DH_PEER_RANDOM_SIZE != peerRandLength) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

/* TODO: remove lib call and replace proper */
#if LOG_LEVEL == LOG_MAX_LEVEL
	/* Display publicB */
	SDOByteArray_t *publicB = bn_to_byte_array(keyExData->_publicB);
	if (publicB) {
		LOG(LOG_DEBUG, "publicB : %lu bytes :\n", publicB->byteSz);
		hexdump("Public B", publicB->bytes, publicB->byteSz);
		sdoByteArrayFree(publicB);
	} else {
		LOG(LOG_ERROR, "publicB allocation failed!");
		return -1;
	}
#endif

	ret = bn_bin2bn((const unsigned char *)peerRandValue,
			(int)peerRandLength, keyExData->_publicA);

	if (ret == -1) {
		return ret;
	}

	ctx = BN_CTX_new();

	/*
	 * Create our shared secret
	 * _sharedsecret = _publicDHBA ^ _secretDHab mod _p15
	 */
	if (bn_mod_exp(keyExData->_sharedSecret, /* Destination */
		       keyExData->_publicA,      /* Base */
		       keyExData->_secretb,      /* Power*/
		       keyExData->_p15,		 /* Modulo */
		       ctx)) {
		LOG(LOG_ERROR, "setPublicA : Trouble doing the bm_mod_exp\n");
	}
#if LOG_LEVEL == LOG_MAX_LEVEL
	hexdump("Public A (xA)", peerRandValue, peerRandLength);
#endif
	BN_CTX_free(ctx);

	LOG(LOG_DEBUG, "KDF Successful\n");
	return 0;
}

/** This function returns the secret computed per the DH protocol in the
 * secret buffer of length secretLength.
 *  @param context - The context parameter is an initialized opaque context
 *  structure.
 *  @param secret - buffer to contain shared secret
 *  @param secretLength - Size of secret buffer
 *  @return 0 on success or -1 on failure.
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
		*secretLength = bn_num_bytes(keyExData->_sharedSecret);
		return 0;
	}

	if (0 >= bn_bn2bin(keyExData->_sharedSecret, secret))
		return -1;

	return 0;
}
