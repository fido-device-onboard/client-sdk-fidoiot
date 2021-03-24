/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include <stdlib.h>
#include "util.h"
#include "fdoCryptoHal.h"
#include "crypto_utils.h"
#include "BN_support.h"
#include "safe_lib.h"
#include <mbedtls/config.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#define DECLARE_BIGNUM(bn) bignum_t bn

#if defined(KEX_ECDH_ENABLED)
#define AX_AY_SIZE_DEF BUFF_SIZE_32_BYTES
#define OWNERRAND_SIZE_DEF BUFF_SIZE_16_BYTES
#define GROUP_ID_SIZE MBEDTLS_ECP_DP_SECP256R1
#define DEVICE_RANDOM_SIZE FDO_ECDH256_DEV_RANDOM
#elif defined(KEX_ECDH384_ENABLED)
#define AX_AY_SIZE_DEF BUFF_SIZE_48_BYTES
#define OWNERRAND_SIZE_DEF BUFF_SIZE_48_BYTES
#define GROUP_ID_SIZE MBEDTLS_ECP_DP_SECP384R1
#define DEVICE_RANDOM_SIZE FDO_ECDH384_DEV_RANDOM
#endif

typedef struct {
	uint8_t *_Device_random;
	uint16_t _Dev_rand_size;
	uint8_t *_publicA; /* The server's A public value */
	uint8_t *_shared_secret;
	uint32_t _shared_secret_length;
	mbedtls_ecp_group_id _key;
	mbedtls_ecdh_context ecdh;
	uint8_t *_publicB; /* Our B public value */
	uint8_t _publicB_length;
} ecdh_context_t;

static bool compute_publicBECDH(ecdh_context_t *key_ex_data);

/**
 * Initialize the key exchange of type ECDH
 * @param context - ecdh context, passed to other ecdh apis, pointer to
 * keyexchange data
 * @return 0 if success else -1
 */
int32_t crypto_hal_kex_init(void **context)
{
	ecdh_context_t *key_ex_data = NULL;

	if (!context) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	/* Allocate key_ex_data*/
	key_ex_data = fdo_alloc(sizeof(ecdh_context_t));
	if (!key_ex_data)
		goto error;

	key_ex_data->_key = GROUP_ID_SIZE;
	/* Generate Device Random bits */
	key_ex_data->_Dev_rand_size = DEVICE_RANDOM_SIZE;

	key_ex_data->_Device_random = fdo_alloc(key_ex_data->_Dev_rand_size);
	if (!key_ex_data->_Device_random) {
		LOG(LOG_ERROR, "Memory alloc failed\n");
		goto error;
	}

	if (crypto_hal_random_bytes(key_ex_data->_Device_random,
				     key_ex_data->_Dev_rand_size) != 0) {
		LOG(LOG_ERROR, "Failed to generate device random\n");
		goto error;
	}

	if (compute_publicBECDH(key_ex_data) == false)
		goto error;

	*context = (void *)key_ex_data;
	return 0;
error:
	crypto_hal_kex_close((void *)&key_ex_data);
	return -1;
}

/**
 * key_exchange_close_dh closes the ecdh section
 *
 * @param context - ecdh context
 * @return
 *        returns 0 on success and -1 on failure
 **/
int32_t crypto_hal_kex_close(void **context)
{
	if (!context) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	ecdh_context_t *key_ex_data;

	key_ex_data = *(ecdh_context_t **)context;

	if (!key_ex_data) {
		return -1;
	}

	if (key_ex_data->_shared_secret)
		fdo_free(key_ex_data->_shared_secret);
	if (key_ex_data->_publicA)
		fdo_free(key_ex_data->_publicA);
	if (key_ex_data->_publicB)
		fdo_free(key_ex_data->_publicB);
	if (key_ex_data->_Device_random)
		fdo_free(key_ex_data->_Device_random);
	mbedtls_ecdh_free(&key_ex_data->ecdh);
	if (key_ex_data)
		fdo_free(key_ex_data);

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
static bool compute_publicBECDH(ecdh_context_t *key_ex_data)
{
	size_t olen = 0;
	unsigned char buf[1024] = {0};
	unsigned char *temp = NULL;
	int size = 0, ret = -1;
	uint16_t tmp = 0;
	size_t allocbytes = 0;
	bool retval = false;
	uint32_t temp_size;

	/* Allocate random wrt Kex_curve*/
	/* Initialize ECDH based on the Group ID */
	mbedtls_ecdh_init(&key_ex_data->ecdh);
	ret = mbedtls_ecp_group_load(&key_ex_data->ecdh.grp, key_ex_data->_key);
	if (ret != 0) {
		LOG(LOG_ERROR, "ec group load failed, ret:%d\n", ret);
		goto error;
	}

	/* Generate private and public key */
	ret = mbedtls_ecdh_make_public(&key_ex_data->ecdh, &olen, buf,
				       sizeof(buf), myrand, NULL);
	if (ret != 0) {
		LOG(LOG_ERROR, "mbedtls_ecdh_make_public returned %d\n", ret);
		goto error;
	}

	/* 2byte for each blen 3x2 =6 */
	allocbytes = bn_num_bytes(&key_ex_data->ecdh.Q.X) +
		     bn_num_bytes(&key_ex_data->ecdh.Q.Y) +
		     key_ex_data->_Dev_rand_size + 6;
	temp = fdo_alloc(allocbytes);
	if (!temp) {
		LOG(LOG_ERROR, "Memory alloc failed\n");
		goto error;
	}

	tmp = bn_num_bytes(&key_ex_data->ecdh.Q.X);
	if (tmp & 0xffff0000) // check size more than 2 byte size space
		goto error;
	temp[0] = tmp >> 8;
	size = 1;
	temp[size] = (tmp & 0x00ff);
	size += 1;
	temp_size = allocbytes - size;
	if (tmp > (allocbytes - size)) {
		/* ensure that there is enough space for the conversion */
		LOG(LOG_ERROR,
		    "Big number to binary conversion, size insufficient\n");
		goto error;
	}
	temp_size = bn_bn2bin(&key_ex_data->ecdh.Q.X, &temp[size]);
	if (0 == temp_size) {
		LOG(LOG_ERROR, "Big number to binary conversion failed\n");
		goto error;
	}
	size += temp_size;
	tmp = bn_num_bytes(&key_ex_data->ecdh.Q.Y);
	if (tmp & 0xffff0000) // check size more than 2 byte size space
		goto error;
	temp[size] = tmp >> 8;
	size += 1;
	temp[size] = (tmp & 0x00ff);
	size += 1;
	if (tmp > (allocbytes - size)) {
		/* ensure that there is enough space for the conversion */
		LOG(LOG_ERROR,
		    "Big number to binary conversion, size insufficient\n");
		goto error;
	}

	temp_size = bn_bn2bin(&key_ex_data->ecdh.Q.Y, &temp[size]);
	if (0 == temp_size) {
		LOG(LOG_ERROR, "Big number to binary conversion failed\n");
		goto error;
	}
	size += temp_size;
	tmp = key_ex_data->_Dev_rand_size;
	if (tmp & 0xffff0000) // check size more than 2 byte size space
		goto error;
	temp[size] = tmp >> 8;
	size += 1;
	temp[size] = (tmp & 0x00ff);
	size += 1;
	/* copy device random number to leftover empty space of temp array */
	if (memcpy_s(&temp[size], allocbytes - size,
		     key_ex_data->_Device_random,
		     key_ex_data->_Dev_rand_size) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto error;
	}

	size += key_ex_data->_Dev_rand_size;

	/* Allocate public B*/
	key_ex_data->_publicB_length = size;
	key_ex_data->_publicB = temp;
#if LOG_LEVEL == LOG_MAX_LEVEL
	hexdump("generated _publicB::", temp, size);
#endif
	LOG(LOG_DEBUG, "compute_publicB complete\n");
	retval = true;
error:
	if (retval == false) {
		LOG(LOG_ERROR, "compute_publicB failed\n");
		if (temp)
			fdo_free(temp);
	}
	return retval;
}

/**
 * Step 1, allocate internal secrets and generate public shared value B for ECC
 * based Diffie Hellman key exchange mode.
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
	ecdh_context_t *key_ex_data = (ecdh_context_t *)context;

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
 * @return 0 if success, else -1.
 */

int32_t crypto_hal_set_peer_random(void *context,
				   const uint8_t *peer_rand_value,
				   uint32_t peer_rand_length)
{

	ecdh_context_t *key_ex_data = (ecdh_context_t *)context;

	if (!context || !peer_rand_value || peer_rand_length == 0) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	unsigned char *temp = NULL;
	size_t size_Ax = 0, size_Ay = 0, size_owner_random = 0;
	size_t secret_buf_MAX = BUFF_SIZE_512_BYTES, size_shse = 0;
	unsigned char *shse = NULL, *Ax = NULL, *Ay = NULL;
	unsigned char *owner_random = NULL, *secret = NULL;
	int ret = -1, size = 0;
	/*TODO: Should we work on a local buffer or the buffer passed to us */
	uint8_t *public_abytes = (uint8_t *)peer_rand_value;
	size_t allocated_shse_size;
	uint32_t custom_shse_size = 0;

	if (public_abytes == NULL) {
		return -1;
	}

	const mbedtls_ecp_curve_info *curve_info =
	    mbedtls_ecp_curve_info_from_grp_id(GROUP_ID_SIZE);

	if (curve_info && peer_rand_length > curve_info->bit_size) {
		LOG(LOG_ERROR, "peer_rand_length is too large\n");
		goto exit;
	}

	key_ex_data->_publicA = fdo_alloc(peer_rand_length);
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
	temp = key_ex_data->_publicA;
	/* Extract owner public co-ordinates and ower random */
	size = 0;
	size_Ax = (temp[size] << 8) | temp[size + 1];
	size += 2;
	if (size_Ax > AX_AY_SIZE_DEF) {
		LOG(LOG_ERROR, "Size of Ax more than 32 bytes\n");
		goto exit;
	}
	Ax = fdo_alloc(size_Ax);
	if (!Ax) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}
	if (memcpy_s(Ax, size_Ax, &public_abytes[size], size_Ax) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}
	size += size_Ax;
	size_Ay = (temp[size] << 8) | temp[size + 1];
	size += 2;
	if (size_Ay > AX_AY_SIZE_DEF) {
		LOG(LOG_ERROR, "Size of Ay more than 32 bytes\n");
		goto exit;
	}
	Ay = fdo_alloc(size_Ay);
	if (!Ay) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}

	if (memcpy_s(Ay, size_Ay, &public_abytes[size], size_Ay) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}
	size += size_Ay;
	size_owner_random = (temp[size] << 8) | temp[size + 1];
	size += 2;
	if (size_owner_random > OWNERRAND_SIZE_DEF) {
		LOG(LOG_ERROR, "Size of owner random more than 16/48 bytes\n");
		goto exit;
	}
	owner_random = fdo_alloc(size_owner_random);
	if (!owner_random) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}
	if (memcpy_s(owner_random, size_owner_random, &public_abytes[size],
		     size_owner_random) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}

	/* read peer (server) public in ecdh context */
	ret = mbedtls_mpi_lset(&key_ex_data->ecdh.Qp.Z, 1);
	if (ret != 0) {
		LOG(LOG_DEBUG, " mbedtls Qp.z, set fail, returned %d\n", ret);
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&key_ex_data->ecdh.Qp.X, Ax, size_Ax);
	if (ret != 0) {
		LOG(LOG_DEBUG, "mbedtls Qp.X read failed, returned %d\n", ret);
		goto exit;
	}
	ret = mbedtls_mpi_read_binary(&key_ex_data->ecdh.Qp.Y, Ay, size_Ay);
	if (ret != 0) {
		LOG(LOG_DEBUG, "mbedtls Qp.Y read failed, returned %d\n", ret);
		goto exit;
	}

	ret = -1; /* reset to -1 for correct error handling */

	secret = fdo_alloc(secret_buf_MAX);
	if (!secret) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}

	/* Compute the ECDH shared secret */
	ret = mbedtls_ecdh_calc_secret(&key_ex_data->ecdh, &size_shse, secret,
				       secret_buf_MAX, NULL, NULL);
	if (ret != 0) {
		LOG(LOG_DEBUG, "ecdh secret generation failed");
		LOG(LOG_DEBUG, "ret:%d\n", ret);
		goto exit;
	}
	LOG(LOG_DEBUG, "Shx size: %zu\n", size_shse);

	ret = -1; /* reset to -1 for correct error handling */

	/* Derive the custom shared secret */
	custom_shse_size =
	    key_ex_data->_Dev_rand_size + size_owner_random + size_shse;
	shse = fdo_alloc(custom_shse_size);
	if (!shse) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}

	size = 0;
	allocated_shse_size = custom_shse_size;
	if (memcpy_s(&shse[size], allocated_shse_size, secret, size_shse) !=
	    0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}

	size += size_shse;
	allocated_shse_size -= size_shse;
	if (memcpy_s(&shse[size], allocated_shse_size,
		     key_ex_data->_Device_random,
		     key_ex_data->_Dev_rand_size) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}

	size += key_ex_data->_Dev_rand_size;
	allocated_shse_size -= key_ex_data->_Dev_rand_size;
	if (memcpy_s(&shse[size], allocated_shse_size, owner_random,
		     size_owner_random) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}

	size += size_owner_random;

	key_ex_data->_shared_secret_length = size;
	key_ex_data->_shared_secret = shse;
	LOG(LOG_DEBUG, "She_she size= %x, ", size);

	ret = 0; /* Mark as success */

exit:
	if (ret && shse) {
		if (memset_s(shse, custom_shse_size, 0)) {
			LOG(LOG_ERROR, "Failed to clear Shared Secret\n");
			ret = -1;
		}
		fdo_free(shse);
	}
	if (Ax) {
		if (memset_s(Ax, size_Ax, 0)) {
			LOG(LOG_ERROR, "Failed to clear secret data Ax\n");
			ret = -1;
		}
		fdo_free(Ax);
	}
	if (Ay) {
		if (memset_s(Ay, size_Ay, 0)) {
			LOG(LOG_ERROR, "Failed to clear secret data Ay\n");
			ret = -1;
		}
		fdo_free(Ay);
	}
	if (owner_random) {
		if (memset_s(owner_random, size_owner_random, 0)) {
			LOG(LOG_ERROR, "Failed to clear secret data Ay\n");
			ret = -1;
		}
		fdo_free(owner_random);
	}
	if (secret) {
		if (memset_s(secret, secret_buf_MAX, 0)) {
			LOG(LOG_ERROR, "Failed to clear secret\n");
			ret = -1;
		}
		fdo_free(secret);
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
	ecdh_context_t *key_ex_data = (ecdh_context_t *)context;

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
