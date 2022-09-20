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
#include "fdoCryptoHal.h"
#include "crypto_utils.h"
#include "BN_support.h"
#include "openssl/ec.h"
#include "openssl/objects.h"
#include "openssl/core_names.h"
#include "safe_lib.h"
#define DECLARE_BIGNUM(bn) bignum_t *bn

#ifdef KEX_ECDH384_ENABLED
#define KEY_CURVE NID_secp384r1
#define BN_RANDOM_SIZE FDO_ECDH384_DEV_RANDOM
#else
#define KEY_CURVE NID_X9_62_prime256v1
#define BN_RANDOM_SIZE FDO_ECDH256_DEV_RANDOM
#endif /* KEX_ECDH384_ENABLED */

typedef struct {
	DECLARE_BIGNUM(_Device_random);
	DECLARE_BIGNUM(_publicA); /* The server's A public value */
	uint32_t group_name_nid;
	EVP_PKEY *_key;

	DECLARE_BIGNUM(_secretb); /* Out bit secret */
	DECLARE_BIGNUM(_publicB);       /* Our B public value */
	DECLARE_BIGNUM(_shared_secret);
	uint8_t *_pubB;
	uint8_t _publicB_length;
} ecdh_context_t;

static bool compute_publicBECDH(ecdh_context_t *key_ex_data);

/**
 * Initialize the key exchange of type ECDH
 * @param context - points to the initialised pointer to the key exchange
 * data structure
 * @return 0 if success else -1
 */
int32_t crypto_hal_kex_init(void **context)
{
	ecdh_context_t *key_ex_data = NULL;

	if (!context) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	key_ex_data = fdo_alloc(sizeof(ecdh_context_t));
	if (!key_ex_data) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto error;
	}

	/*
	 * Start by memory allocation so then all pointers will be initialized
	 * in case of fdo_crypto_init error.
	 */
	key_ex_data->_publicB = BN_new();
	key_ex_data->_publicA = BN_new();
	key_ex_data->_shared_secret = BN_new();
	key_ex_data->_Device_random = BN_new();

	if (!key_ex_data->_publicB || !key_ex_data->_publicA ||
			!key_ex_data->_shared_secret || !key_ex_data->_Device_random) {
		LOG(LOG_ERROR, "BN alloc failed\n");
		goto error;
	}

	key_ex_data->group_name_nid = KEY_CURVE;

	/* Generate Device Random bits(384) */
	if (bn_rand(key_ex_data->_Device_random, BN_RANDOM_SIZE)) {
		goto error;
	}

	if (compute_publicBECDH(key_ex_data) == false) {
		goto error;
	}

	*context = (void *)key_ex_data;
	return 0;
error:
	if (NULL != key_ex_data) {
		crypto_hal_kex_close((void *)&key_ex_data);
	}
	return -1;
}

/* key_exchange_close_dh closes the ecdh section
 *
 * @param context - pointer to the keyexchange data structure
 * @return 0 if success else -1
 **/
int32_t crypto_hal_kex_close(void **context)
{
	ecdh_context_t *key_ex_data;

	if (!context) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	key_ex_data = *(ecdh_context_t **)context;
	if (key_ex_data->_publicB) {
		BN_clear_free(key_ex_data->_publicB);
	}
	if (key_ex_data->_publicA) {
		BN_clear_free(key_ex_data->_publicA);
	}
	if (key_ex_data->_shared_secret) {
		BN_clear_free(key_ex_data->_shared_secret);
	}
	if (key_ex_data->_secretb) {
		BN_clear_free(key_ex_data->_secretb);
	}
	if (key_ex_data->_Device_random) {
		BN_clear_free(key_ex_data->_Device_random);
	}
	if (key_ex_data->_key != NULL) {
		EVP_PKEY_free(key_ex_data->_key);
		key_ex_data->_key = NULL;
	}
	if (key_ex_data->_pubB) {
		fdo_free(key_ex_data->_pubB);
	}
	fdo_free(key_ex_data);
	return 0;
}

/**
 * Compute B from initial secret a passed to us in the clear
 * @param key_ex_data - pointer to the keyexchange data structure
 * @return
 *        returns true on success, false on error
 */
static bool compute_publicBECDH(ecdh_context_t *key_ex_data)
{
	BN_CTX *ctx = NULL;

	EC_GROUP *group = NULL;
	BIGNUM *x = NULL, *y = NULL;
	unsigned char *temp = NULL;
	int size = 0;
	int allocbytes = 0;
	uint16_t tmp = 0;
	bool ret = false;

	if (!key_ex_data) {
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

	group = EC_GROUP_new_by_curve_name(key_ex_data->group_name_nid);
	if (group == NULL) {
		LOG(LOG_ERROR, "Failed to get the EC group\n");
		goto exit;
	}

	/* generate the public key and private key */
	key_ex_data->_key = EVP_EC_gen(OBJ_nid2sn(key_ex_data->group_name_nid));
	if (!key_ex_data->_key) {
		LOG(LOG_ERROR, "EC key generation failed\n");
		goto exit;
	}

	/* Store the private key */
	if (!EVP_PKEY_get_bn_param(key_ex_data->_key, OSSL_PKEY_PARAM_PRIV_KEY, &(key_ex_data->_secretb))) {
		LOG(LOG_ERROR, "EC private key get failed\n");
		goto exit;
	}

	/* Get the public key co-ordinates in x and y*/
	if (!EVP_PKEY_get_bn_param(key_ex_data->_key, OSSL_PKEY_PARAM_EC_PUB_X, &x) ||
			!EVP_PKEY_get_bn_param(key_ex_data->_key, OSSL_PKEY_PARAM_EC_PUB_Y, &y)) {
		LOG(LOG_ERROR, "EC cordinate get failed\n");
		goto exit;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	/* Print the co-ordinates */

	LOG(LOG_DEBUG, "Bx %s : bytes %d\n",
			BN_is_negative(x) ? "Negative" : "Positive", bn_num_bytes(x));

	LOG(LOG_DEBUG, "By %s : bytes %d\n",
			BN_is_negative(y) ? "Negative" : "Positive", bn_num_bytes(y));

	LOG(LOG_DEBUG, "Device Random  %s : bytes %d\n",
			BN_is_negative(key_ex_data->_Device_random) ? "Negative"
			: "Positive",
			bn_num_bytes(key_ex_data->_Device_random));
#endif

	/* 2byte for each blen 3x2 =6 */
	allocbytes = (bn_num_bytes(x) + bn_num_bytes(y) +
			bn_num_bytes(key_ex_data->_Device_random) + 6);
	temp = fdo_alloc(allocbytes);
	if (!temp) {
		LOG(LOG_ERROR, "Mem alloc failed\n");
		goto exit;
	}

	tmp = bn_num_bytes(x);
	if (tmp & 0xffff0000) { // check size more than 2 byte size space
		goto exit;
	}
	temp[0] = tmp >> 8;
	size = 1;
	temp[size] = (tmp & 0x00ff);
	size += 1;
	size += BN_bn2bin(x, &temp[size]);
	tmp = bn_num_bytes(y);
	if (tmp & 0xffff0000) { // check size more than 2 byte size space
		goto exit;
	}
	temp[size] = tmp >> 8;
	size += 1;
	temp[size] = (tmp & 0x00ff);
	size += 1;
	size += BN_bn2bin(y, &temp[size]);
	tmp = bn_num_bytes(key_ex_data->_Device_random);
	if (tmp & 0xffff0000) { // check size more than 2 byte size space
		goto exit;
	}
	temp[size] = tmp >> 8;
	size += 1;
	temp[size] = (tmp & 0x00ff);
	size += 1;
	size += BN_bn2bin(key_ex_data->_Device_random, &temp[size]);

	BN_bin2bn(temp, size, key_ex_data->_publicB);
	key_ex_data->_pubB = fdo_alloc(allocbytes);
	if (!key_ex_data->_pubB) {
		LOG(LOG_ERROR, "Memclloc failed\n");
		goto exit;
	}
	if (memcpy_s(key_ex_data->_pubB, allocbytes, temp, allocbytes) != 0) {
		LOG(LOG_ERROR, "Memcpy failed\n");
		fdo_free(key_ex_data->_pubB);
		goto exit;
	}

	key_ex_data->_publicB_length = allocbytes;
#if LOG_LEVEL == LOG_MAX_LEVEL
	hexdump("_publicB::", key_ex_data->_publicB,
			key_ex_data->_publicB_length);
	{

		LOG(LOG_DEBUG, "key_ex_data->_publicB %s : bytes %d\n",
				BN_is_negative(key_ex_data->_publicB) ? "Negative"
				: "Positive",
				bn_num_bytes(key_ex_data->_publicB));
	}
#endif
	ret = true;
exit:
	if (group) {
		EC_GROUP_free(group);
	}
	if (temp) {
		fdo_free(temp);
	}
	if (x) {
		BN_clear(x);
	}
	if (y) {
		BN_clear(y);
	}
	/* Consider using the bn cache in ctx. */
	if (ctx) {
		BN_CTX_free(ctx);
	}
	return ret;
}

/**
 * Step 1, allocate internal secrets and generate public shared value B for ECC
 * based Diffie Hellman key exchange mode.
 * This is then sent to the other side of the connection.
 *
 * @param context - pointer to the key exchange data structure
 * @param dev_rand_value - B secret to be shared with other side of connection
 * @param dev_rand_length - Size of dev_rand_value buffer
 * @return 0 if success, else -1
 */
int32_t crypto_hal_get_device_random(void *context, uint8_t *dev_rand_value,
		uint32_t *dev_rand_length)
{
	ecdh_context_t *key_ex_data = (ecdh_context_t *)context;

	if (!key_ex_data || !dev_rand_length) {
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

	if (memcpy_s(dev_rand_value, *dev_rand_length, key_ex_data->_pubB,
				*dev_rand_length) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		return -1;
	}

	return 0;
}

/**
 * Input A from other side of connection and compute shared secret[ECDH mode].
 * @param context - pointer to the key exchange data structure
 * @param peer_rand_value - value is encrypted from other side of connection,
 * @param peer_rand_length - Size of peer_rand_value
 * @return 0 if success, else false.
 */
int32_t crypto_hal_set_peer_random(void *context,
		const uint8_t *peer_rand_value,
		uint32_t peer_rand_length)
{
	ecdh_context_t *key_ex_data = (ecdh_context_t *)context;

	if (!key_ex_data || !peer_rand_value || peer_rand_length == 0) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	BN_CTX *ctx = NULL;
	const uint8_t *temp = NULL;
	size_t size_Ax = 0, size_Ay = 0, size_owner_random = 0;
	unsigned char *shse = NULL, *shx = NULL;
	int size = 0;
	BIGNUM *Ax_bn = NULL, *Ay_bn = NULL, *owner_random_bn = NULL;
	BIGNUM *Shx_bn = NULL, *Shy_bn = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	EC_POINT *Sh_se_point = NULL;
	int ret = -1;

	Ax_bn = BN_new();
	Ay_bn = BN_new();
	Shx_bn = BN_new();
	Shy_bn = BN_new();
	owner_random_bn = BN_new();

	if (!Ax_bn || !Ay_bn || !Shx_bn || !Shy_bn || !owner_random_bn) {
		LOG(LOG_ERROR, "BN alloc failed\n");
		goto error;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	LOG(LOG_DEBUG, "set_publicA : bytes : %u\n", peer_rand_length);
	hexdump("Public A", peer_rand_value, peer_rand_length);
	/* Display public - B */

	LOG(LOG_DEBUG, "key_ex_data->_publicB %s : bytes %d\n",
			BN_is_negative(key_ex_data->_publicB) ? "Negative" : "Positive",
			bn_num_bytes(key_ex_data->_publicB));
#endif
	bn_bin2bn(peer_rand_value, peer_rand_length, key_ex_data->_publicA);

#if LOG_LEVEL == LOG_MAX_LEVEL
	/* Display Public - A */
	LOG(LOG_DEBUG,
			"Device Received: key_ex_data->_publicA %s : "
			"bytes %d\n",
			BN_is_negative(key_ex_data->_publicA) ? "Negative" : "Positive",
			bn_num_bytes(key_ex_data->_publicA));
#endif

	temp = peer_rand_value;
#if LOG_LEVEL == LOG_MAX_LEVEL
	hexdump("Public A(bn)", temp, peer_rand_length);
#endif
	size = 0;
	size_Ax = (temp[size] << 8) | temp[size + 1];
	size += 2;
	BN_bin2bn(&temp[size], size_Ax, Ax_bn);
	size += size_Ax;
	size_Ay = (temp[size] << 8) | temp[size + 1];
	size += 2;
	BN_bin2bn(&temp[size], size_Ay, Ay_bn);
	size += size_Ay;
	size_owner_random = (temp[size] << 8) | temp[size + 1];
	size += 2;
	BN_bin2bn(&temp[size], size_owner_random, owner_random_bn);

#if LOG_LEVEL == LOG_MAX_LEVEL

	LOG(LOG_DEBUG, "Device Reveived: Ax %s : bytes %d\n",
			BN_is_negative(Ax_bn) ? "Negative" : "Positive",
			bn_num_bytes(Ax_bn));

	LOG(LOG_DEBUG, "Device Received: Ay %s : bytes %d\n",
			BN_is_negative(Ay_bn) ? "Negative" : "Positive",
			bn_num_bytes(Ay_bn));

	LOG(LOG_DEBUG, "Device Reveived: Owner Random  %s : bytes %d\n",
			BN_is_negative(owner_random_bn) ? "Negative" : "Positive",
			bn_num_bytes(owner_random_bn));
#endif
	ctx = BN_CTX_new();
	if (!ctx) {
		LOG(LOG_ERROR, "BN context new fail\n");
		goto error;
	}

	group = EC_GROUP_new_by_curve_name(key_ex_data->group_name_nid);
	if (group == NULL)
	{
		LOG(LOG_ERROR, "Failed to get the EC group\n");
		goto error;
	}
	point = EC_POINT_new(group);
	if (group == NULL || point == NULL) {
		LOG(LOG_ERROR, "Error curve parameters are NULL\n");
		goto error;
	}
	EC_POINT_set_affine_coordinates(group, point, Ax_bn, Ay_bn, ctx);
	shx = fdo_alloc(bn_num_bytes(Ax_bn));
	if (!shx) {
		goto error;
	}
#if defined OPENSSL_2_0_1
	if (ECDH_compute_key(shx, 32, point, key, NULL) == 0) {
		LOG(LOG_ERROR, "ECDH compute key failed\n");
		goto error;
	}
	size_t shx_len = strlen_s(shx, FDO_MAX_STR_SIZE);

	if (!shx_len || shx_len == FDO_MAX_STR_SIZE) {
		goto error;
	}
	if (BN_bin2bn(shx, shx_len, Shx_bn) == NULL) {
		LOG(LOG_ERROR, "BN bin to bn conversion failed\n");
		goto error;
	}

#else
	Sh_se_point = EC_POINT_new(group);
	if (!Sh_se_point) {
		goto error;
	}
	if (EC_POINT_mul(group, Sh_se_point, NULL, point, key_ex_data->_secretb,
				ctx) == 0) {
		EC_POINT_free(Sh_se_point);
		goto error;
	}
	if (EC_POINT_get_affine_coordinates(group, Sh_se_point, Shx_bn,
				Shy_bn, ctx) == 0) {
		EC_POINT_free(Sh_se_point);
		goto error;
	}

	if (BN_bn2bin(Shx_bn, shx) == 0) {
		LOG(LOG_ERROR, "BN bn to bin conversion failed\n");
		goto error;
	}

	EC_POINT_free(Sh_se_point);
#endif
	shse = fdo_alloc(bn_num_bytes(key_ex_data->_Device_random) +
			size_owner_random + bn_num_bytes(Shx_bn));
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
	if (BN_bn2bin(key_ex_data->_Device_random, &shse[size]) == 0) {
		LOG(LOG_ERROR, "BN bn to bin conversion failed\n");
		goto error;
	}
	size += bn_num_bytes(key_ex_data->_Device_random);
	if (BN_bn2bin(owner_random_bn, &shse[size]) == 0) {
		LOG(LOG_ERROR, "BN bn to bin conversion failed\n");
		goto error;
	}
	size += size_owner_random;

	if (BN_bin2bn(shse, size, key_ex_data->_shared_secret) == 0) {
		LOG(LOG_ERROR, "BN bn to bin conversion failed\n");
		goto error;
	}

	ret = 0;
error:
	if (group) {
		EC_GROUP_free(group);
	}
	if (point) {
		EC_POINT_free(point);
	}
	if (shse) {
		fdo_free(shse);
	}
	if (Ax_bn) {
		BN_clear_free(Ax_bn);
	}
	if (Ay_bn) {
		BN_clear_free(Ay_bn);
	}
	if (owner_random_bn) {
		BN_clear_free(owner_random_bn);
	}
	if (Shx_bn) {
		BN_clear_free(Shx_bn);
	}
	if (Shy_bn) {
		BN_clear_free(Shy_bn);
	}
	if (ctx) {
		BN_CTX_free(ctx);
	}
	if (shx) {
		fdo_free(shx);
	}

	return ret;
}

/** This function returns the secret computed per the ECDH protocol in the
 * secret buffer of length secret_length.
 *  @param context - The context parameter is an initialized opaque context
 * structure.
 *  @param secret - buffer to contain shared secret
 *  @param secret_length - Size of secret buffer
 *  @return 0 on success or -1 on failure.
 */
int32_t crypto_hal_get_secret(void *context, uint8_t *secret,
		uint32_t *secret_length)
{
	ecdh_context_t *key_ex_data = (ecdh_context_t *)context;

	if (!key_ex_data || !secret_length) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	if (!secret) {
		*secret_length = bn_num_bytes(key_ex_data->_shared_secret);
		return 0;
	}

	if (*secret_length <
			(uint32_t)bn_num_bytes(key_ex_data->_shared_secret)) {
		LOG(LOG_ERROR, "Invalid buff size\n");
		return -1;
	}

#if defined(KEX_ASYM_ENABLED)
	shared_secret = key_ex_data->_shared_secret;
#else
	if (0 >= bn_bn2bin(key_ex_data->_shared_secret, secret)) {
		return -1;
	}
#endif

	return 0;
}
