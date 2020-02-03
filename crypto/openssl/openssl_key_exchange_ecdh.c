/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for ECDH based key exchange crypto routines of
 * openssl library.
 */

#include "util.h"
#include "sdoCryptoHal.h"
#include "crypto_utils.h"
#include "BN_support.h"
#include "openssl/ec.h"
#include "openssl/objects.h"
#include "safe_lib.h"
#define DECLARE_BIGNUM(bn) bignum_t *bn

#ifdef KEX_ECDH384_ENABLED
#define KEY_CURVE NID_secp384r1
#define BN_RANDOM_SIZE SDO_ECDH384_DEV_RANDOM
#else
#define KEY_CURVE NID_X9_62_prime256v1
#define BN_RANDOM_SIZE SDO_ECDH256_DEV_RANDOM
#endif /* KEX_ECDH384_ENABLED */

typedef struct {
	DECLARE_BIGNUM(_DeviceRandom);
	DECLARE_BIGNUM(_publicA); /* The server's A public value */
	EC_KEY *_key;
	const DECLARE_BIGNUM(_secretb); /* Out bit secret */
	DECLARE_BIGNUM(_publicB);       /* Our B public value */
	DECLARE_BIGNUM(_sharedSecret);
	uint8_t *_pubB;
	uint8_t _publicB_length;
} ecdh_context_t;

static bool computePublicBECDH(ecdh_context_t *keyExData);

/**
 * Initialize the key exchange of type ECDH
 * @param context - points to the initialised pointer to the key exchange
 * data structure
 * @return 0 if success else -1
 */
int32_t sdoCryptoKEXInit(void **context)
{
	ecdh_context_t *keyExData = NULL;
	EC_KEY *key = NULL;

	if (!context) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	keyExData = sdoAlloc(sizeof(ecdh_context_t));
	if (!keyExData) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto error;
	}

	/*
	 * Start by memory allocation so then all pointers will be initialized
	 * in case of sdoCryptoInit error.
	 */
	keyExData->_publicB = BN_new();
	keyExData->_publicA = BN_new();
	keyExData->_sharedSecret = BN_new();
	keyExData->_DeviceRandom = BN_new();

	if (!keyExData->_publicB || !keyExData->_publicA ||
	    !keyExData->_sharedSecret || !keyExData->_DeviceRandom) {
		LOG(LOG_ERROR, "BN alloc failed\n");
		goto error;
	}

	key = EC_KEY_new_by_curve_name(KEY_CURVE);
	/* Generate Device Random bits(384) */
	if (bn_rand(keyExData->_DeviceRandom, BN_RANDOM_SIZE)) {
		goto error;
	}

	if (key == NULL) {
		LOG(LOG_ERROR, "failed to get the curve parameters\n");
		goto error;
	}

	keyExData->_key = key;

	if (computePublicBECDH(keyExData) == false)
		goto error;

	*context = (void *)keyExData;
	return 0;
error:
	if (NULL != keyExData)
		sdoCryptoKEXClose((void *)&keyExData);
	return -1;
}

/* key_exchange_close_dh closes the ecdh section
 *
 * @param context - pointer to the keyexchange data structure
 * @return 0 if success else -1
 **/
int32_t sdoCryptoKEXClose(void **context)
{
	ecdh_context_t *keyExData;

	if (!context) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	keyExData = *(ecdh_context_t **)context;
	if (keyExData->_publicB)
		BN_clear_free(keyExData->_publicB);
	if (keyExData->_publicA)
		BN_clear_free(keyExData->_publicA);
	if (keyExData->_sharedSecret)
		BN_clear_free(keyExData->_sharedSecret);
	if (keyExData->_DeviceRandom)
		BN_clear_free(keyExData->_DeviceRandom);

	if (keyExData->_key != NULL) {
		EC_KEY_free(keyExData->_key);
		keyExData->_key = NULL;
	}
	if (keyExData->_pubB) {
		sdoFree(keyExData->_pubB);
	}
	sdoFree(keyExData);
	return 0;
}

/**
 * Compute B from initial secret a passed to us in the clear
 * @param keyExData - pointer to the keyexchange data structure
 * @return
 *        returns true on success, false on error
 */
static bool computePublicBECDH(ecdh_context_t *keyExData)
{
	BN_CTX *ctx = NULL;
	const EC_GROUP *group = NULL;
	EC_KEY *key = NULL;
	const EC_POINT *point = NULL;
	BIGNUM *x = NULL, *y = NULL;
	unsigned char *temp = NULL;
	int size = 0;
	int allocbytes = 0;
	uint16_t tmp = 0;
	bool ret = false;
	LOG(LOG_DEBUG, "computePublicB started\n");

	if (!keyExData) {
		LOG(LOG_ERROR, "invalid param\n");
		return ret;
	}

	ctx = BN_CTX_new();
	if (!ctx) {
		LOG(LOG_ERROR, "BN context new fail\n");
		return ret;
	}
	BN_CTX_start(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);
	if (!x || !y) {
		LOG(LOG_ERROR, "BN context get failed\n");
		goto exit;
	}

	key = keyExData->_key;
	if (!key) {
		LOG(LOG_ERROR, "EC key  is wrong\n");
		goto exit;
	}
	group = EC_KEY_get0_group(key);
	if (!group) {
		LOG(LOG_ERROR, "EC group get failed\n");
		goto exit;
	}

	/* generate the public key and private key */
	if (EC_KEY_generate_key(key) == 0) {
		LOG(LOG_ERROR, "EC key generation failed\n");
		goto exit;
	}

	/* Store the private key */
	keyExData->_secretb = EC_KEY_get0_private_key(key);
	if (!keyExData->_secretb) {
		LOG(LOG_ERROR, "EC private key get failed\n");
		goto exit;
	}

	/* Get the public key */
	point = EC_KEY_get0_public_key(key);
	if (!point) {
		LOG(LOG_ERROR, "EC public key get failed\n");
		goto exit;
	}
	if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx) == 0) {
		LOG(LOG_ERROR, "EC cordinate get failed\n");
		goto exit;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	/* Print the co-ordinates */
	char *hexbuf1 = BN_bn2hex(x);
	LOG(LOG_DEBUG, "Bx %s : bytes %d, %s\n",
	    BN_is_negative(x) ? "Negative" : "Positive", bn_num_bytes(x),
	    hexbuf1);
	OPENSSL_free(hexbuf1);

	char *hexbuf2 = BN_bn2hex(y);
	LOG(LOG_DEBUG, "By %s : bytes %d, %s\n",
	    BN_is_negative(y) ? "Negative" : "Positive", bn_num_bytes(y),
	    hexbuf2);
	OPENSSL_free(hexbuf2);

	char *hexbuf3 = BN_bn2hex(keyExData->_DeviceRandom);
	LOG(LOG_DEBUG, "Device Random  %s : bytes %d, %s\n",
	    BN_is_negative(keyExData->_DeviceRandom) ? "Negative" : "Positive",
	    bn_num_bytes(keyExData->_DeviceRandom), hexbuf3);
	OPENSSL_free(hexbuf3);
#endif

	/* 2byte for each blen 3x2 =6 */
	allocbytes = (bn_num_bytes(x) + bn_num_bytes(y) +
		      bn_num_bytes(keyExData->_DeviceRandom) + 6);
	temp = sdoAlloc(allocbytes);
	if (!temp) {
		LOG(LOG_ERROR, "Mem alloc failed\n");
		goto exit;
	}

	tmp = bn_num_bytes(x);
	if (tmp & 0xffff0000) // check size more than 2 byte size space
		goto exit;
	temp[0] = tmp >> 8;
	size = 1;
	temp[size] = (tmp & 0x00ff);
	size += 1;
	size += BN_bn2bin(x, &temp[size]);
	tmp = bn_num_bytes(y);
	if (tmp & 0xffff0000) // check size more than 2 byte size space
		goto exit;
	temp[size] = tmp >> 8;
	size += 1;
	temp[size] = (tmp & 0x00ff);
	size += 1;
	size += BN_bn2bin(y, &temp[size]);
	tmp = bn_num_bytes(keyExData->_DeviceRandom);
	if (tmp & 0xffff0000) // check size more than 2 byte size space
		goto exit;
	temp[size] = tmp >> 8;
	size += 1;
	temp[size] = (tmp & 0x00ff);
	size += 1;
	size += BN_bn2bin(keyExData->_DeviceRandom, &temp[size]);

	BN_bin2bn(temp, size, keyExData->_publicB);
	keyExData->_pubB = sdoAlloc(allocbytes);
	if (!keyExData->_pubB) {
		LOG(LOG_ERROR, "Memclloc failed\n");
		goto exit;
	}
	if (memcpy_s(keyExData->_pubB, allocbytes, temp, allocbytes) != 0) {
		LOG(LOG_ERROR, "Memcpy failed\n");
		sdoFree(keyExData->_pubB);
		goto exit;
	}

	keyExData->_publicB_length = allocbytes;
#if LOG_LEVEL == LOG_MAX_LEVEL
	hexdump("_publicB::", keyExData->_publicB, keyExData->_publicB_length);
	{
		char *hexbuf = BN_bn2hex(keyExData->_publicB);
		LOG(LOG_DEBUG, "keyExData->_publicB %s : bytes %d, %s\n",
		    BN_is_negative(keyExData->_publicB) ? "Negative"
							: "Positive",
		    bn_num_bytes(keyExData->_publicB), hexbuf);
		OPENSSL_free(hexbuf);
	}
#endif
	ret = true;
	LOG(LOG_DEBUG, "computePublicB complete\n");
exit:
	if (temp)
		sdoFree(temp);
	if (x)
		BN_clear(x);
	if (y)
		BN_clear(y);
	/* Consider using the bn cache in ctx. */
	if (ctx)
		BN_CTX_free(ctx);
	return ret;
}

/**
 * Step 1, allocate internal secrets and generate public shared value B for ECC
 * based Diffie Hellman key exchange mode.
 * This is then sent to the other side of the connection.
 *
 * @param context - pointer to the key exchange data structure
 * @param devRandValue - B secret to be shared with other side of connection
 * @param devRandLength - Size of devRandValue buffer
 * @return 0 if success, else -1
 */
int32_t sdoCryptoGetDeviceRandom(void *context, uint8_t *devRandValue,
				 uint32_t *devRandLength)
{
	ecdh_context_t *keyExData = (ecdh_context_t *)context;

	if (!keyExData || !devRandLength) {
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

	if (memcpy_s(devRandValue, *devRandLength, keyExData->_pubB,
		     *devRandLength) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		return -1;
	}

	return 0;
}

/**
 * Input A from other side of connection and compute shared secret[ECDH mode].
 * @param context - pointer to the key exchange data structure
 * @param peerRandValue - value is encrypted from other side of connection,
 * @param peerRandLength - Size of peerRandValue
 * @return 0 if success, else false.
 */
int32_t sdoCryptoSetPeerRandom(void *context, const uint8_t *peerRandValue,
			       uint32_t peerRandLength)
{
	ecdh_context_t *keyExData = (ecdh_context_t *)context;

	if (!keyExData || !peerRandValue || peerRandLength == 0) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	BN_CTX *ctx = NULL;
	const uint8_t *temp = NULL;
	size_t size_Ax = 0, size_Ay = 0, size_ownerRandom = 0;
	unsigned char *shse = NULL, *shx = NULL;
	int size = 0;
	BIGNUM *Ax_bn = NULL, *Ay_bn = NULL, *ownerRandom_bn = NULL;
	BIGNUM *Shx_bn = NULL, *Shy_bn = NULL;
	const EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	EC_POINT *ShSe_point = NULL;
	EC_KEY *key = NULL;
	int ret = -1;

	Ax_bn = BN_new();
	Ay_bn = BN_new();
	Shx_bn = BN_new();
	Shy_bn = BN_new();
	ownerRandom_bn = BN_new();

	if (!Ax_bn || !Ay_bn || !Shx_bn || !Shy_bn || !ownerRandom_bn) {
		LOG(LOG_ERROR, "BN alloc failed\n");
		goto error;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	LOG(LOG_DEBUG, "setPublicA : bytes : %u\n", peerRandLength);
	hexdump("Public A", peerRandValue, peerRandLength);
	/* Display public - B */
	char *hexbuf = BN_bn2hex(keyExData->_publicB);
	LOG(LOG_DEBUG, "keyExData->_publicB %s : bytes %d, 0x%s\n",
	    BN_is_negative(keyExData->_publicB) ? "Negative" : "Positive",
	    bn_num_bytes(keyExData->_publicB), hexbuf);
	OPENSSL_free(hexbuf);
#endif
	bn_bin2bn(peerRandValue, peerRandLength, keyExData->_publicA);

#if LOG_LEVEL == LOG_MAX_LEVEL
	/* Display Public - A */
	char *hexbuf1 = BN_bn2hex(keyExData->_publicA);
	LOG(LOG_DEBUG,
	    "Device Received: keyExData->_publicA %s : "
	    "bytes %d, 0x%s\n",
	    BN_is_negative(keyExData->_publicA) ? "Negative" : "Positive",
	    bn_num_bytes(keyExData->_publicA), hexbuf1);
	OPENSSL_free(hexbuf1);
#endif

	temp = peerRandValue;
	hexdump("Public A(bn)", temp, peerRandLength);
	size = 0;
	size_Ax = (temp[size] << 8) | temp[size + 1];
	size += 2;
	BN_bin2bn(&temp[size], size_Ax, Ax_bn);
	size += size_Ax;
	size_Ay = (temp[size] << 8) | temp[size + 1];
	size += 2;
	BN_bin2bn(&temp[size], size_Ay, Ay_bn);
	size += size_Ay;
	size_ownerRandom = (temp[size] << 8) | temp[size + 1];
	size += 2;
	BN_bin2bn(&temp[size], size_ownerRandom, ownerRandom_bn);

#if LOG_LEVEL == LOG_MAX_LEVEL
	char *hexbuf2 = BN_bn2hex(Ax_bn);
	LOG(LOG_DEBUG, "Device Reveived: Ax %s : bytes %d, %s\n",
	    BN_is_negative(Ax_bn) ? "Negative" : "Positive",
	    bn_num_bytes(Ax_bn), hexbuf2);
	OPENSSL_free(hexbuf2);
	char *hexbuf3 = BN_bn2hex(Ay_bn);
	LOG(LOG_DEBUG, "Device Received: Ay %s : bytes %d, %s\n",
	    BN_is_negative(Ay_bn) ? "Negative" : "Positive",
	    bn_num_bytes(Ay_bn), hexbuf3);
	OPENSSL_free(hexbuf3);
	char *hexbuf4 = BN_bn2hex(ownerRandom_bn);
	LOG(LOG_DEBUG, "Device Reveived: Owner Random  %s : bytes %d, %s\n",
	    BN_is_negative(ownerRandom_bn) ? "Negative" : "Positive",
	    bn_num_bytes(ownerRandom_bn), hexbuf4);
	OPENSSL_free(hexbuf4);
#endif
	ctx = BN_CTX_new();
	if (!ctx) {
		LOG(LOG_ERROR, "BN context new fail\n");
		goto error;
	}

	key = keyExData->_key;
	group = EC_KEY_get0_group(key);
	point = EC_POINT_new(group);
	if (group == NULL || point == NULL || key == NULL) {
		LOG(LOG_ERROR, "Error curve parameters are NULL\n");
		goto error;
	}
	EC_POINT_set_affine_coordinates_GFp(group, point, Ax_bn, Ay_bn, ctx);
	shx = sdoAlloc(bn_num_bytes(Ax_bn));
	if (!shx)
		goto error;
#if defined OPENSSL_2_0_1
	if (ECDH_compute_key(shx, 32, point, key, NULL) == 0) {
		LOG(LOG_ERROR, "ECDH compute key failed\n");
		goto error;
	}
	size_t shx_len = strlen_s(shx, SDO_MAX_STR_SIZE);
	if (!shx_len || shx_len == SDO_MAX_STR_SIZE)
		goto error;
	if (BN_bin2bn(shx, shx_len, Shx_bn) == NULL) {
		LOG(LOG_ERROR, "BN bin to bn conversion failed\n");
		goto error;
	}

#else
	ShSe_point = EC_POINT_new(group);
	if (!ShSe_point)
		goto error;
	if (EC_POINT_mul(group, ShSe_point, NULL, point, keyExData->_secretb,
			 ctx) == 0) {
		EC_POINT_free(ShSe_point);
		goto error;
	}
	if (EC_POINT_get_affine_coordinates_GFp(group, ShSe_point, Shx_bn,
						Shy_bn, ctx) == 0) {
		EC_POINT_free(ShSe_point);
		goto error;
	}

	if (BN_bn2bin(Shx_bn, shx) == 0) {
		LOG(LOG_ERROR, "BN bn to bin conversion failed\n");
		goto error;
	}

	EC_POINT_free(ShSe_point);
#endif
	shse = sdoAlloc(bn_num_bytes(keyExData->_DeviceRandom) +
			size_ownerRandom + bn_num_bytes(Shx_bn));
	if (!shse) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto error;
	}

	size = 0;
	if (BN_bn2bin(Shx_bn, &shse[size]) == 0) {
		LOG(LOG_ERROR, "BN bn to bin conversion failed\n");
		goto error;
	}
	size += bn_num_bytes(Shx_bn);
	if (BN_bn2bin(keyExData->_DeviceRandom, &shse[size]) == 0) {
		LOG(LOG_ERROR, "BN bn to bin conversion failed\n");
		goto error;
	}
	size += bn_num_bytes(keyExData->_DeviceRandom);
	if (BN_bn2bin(ownerRandom_bn, &shse[size]) == 0) {
		LOG(LOG_ERROR, "BN bn to bin conversion failed\n");
		goto error;
	}
	size += size_ownerRandom;

	if (BN_bin2bn(shse, size, keyExData->_sharedSecret) == 0) {
		LOG(LOG_ERROR, "BN bn to bin conversion failed\n");
		goto error;
	}

	ret = 0;
error:
	if (point)
		EC_POINT_free(point);
	if (shse)
		sdoFree(shse);
	if (Ax_bn)
		BN_clear_free(Ax_bn);
	if (Ay_bn)
		BN_clear_free(Ay_bn);
	if (ownerRandom_bn)
		BN_clear_free(ownerRandom_bn);
	if (Shx_bn)
		BN_clear_free(Shx_bn);
	if (Shy_bn)
		BN_clear_free(Shy_bn);
	if (ctx)
		BN_CTX_free(ctx);
	if (shx)
		sdoFree(shx);

	return ret;
}

/** This function returns the secret computed per the ECDH protocol in the
 * secret buffer of length secretLength.
 *  @param context - The context parameter is an initialized opaque context
 * structure.
 *  @param secret - buffer to contain shared secret
 *  @param secretLength - Size of secret buffer
 *  @return 0 on success or -1 on failure.
 */
int32_t sdoCryptoGetSecret(void *context, uint8_t *secret,
			   uint32_t *secretLength)
{
	ecdh_context_t *keyExData = (ecdh_context_t *)context;

	if (!keyExData || !secretLength) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	if (!secret) {
		*secretLength = bn_num_bytes(keyExData->_sharedSecret);
		return 0;
	}

	if (*secretLength < bn_num_bytes(keyExData->_sharedSecret)) {
		LOG(LOG_ERROR, "Invalid buff size\n");
		return -1;
	}

#if defined(KEX_ASYM_ENABLED)
	sharedSecret = keyExData->_sharedSecret;
#else
	if (0 >= bn_bn2bin(keyExData->_sharedSecret, secret))
		return -1;
#endif

	return 0;
}
