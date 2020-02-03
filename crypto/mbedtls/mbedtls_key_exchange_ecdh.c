/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include <stdlib.h>
#include "util.h"
#include "sdoCryptoHal.h"
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
#define DEVICE_RANDOM_SIZE SDO_ECDH256_DEV_RANDOM
#elif defined(KEX_ECDH384_ENABLED)
#define AX_AY_SIZE_DEF BUFF_SIZE_48_BYTES
#define OWNERRAND_SIZE_DEF BUFF_SIZE_48_BYTES
#define GROUP_ID_SIZE MBEDTLS_ECP_DP_SECP384R1
#define DEVICE_RANDOM_SIZE SDO_ECDH384_DEV_RANDOM
#endif

typedef struct {
	uint8_t *_DeviceRandom;
	uint16_t _DevRandSize;
	uint8_t *_publicA; /* The server's A public value */
	uint8_t *_sharedSecret;
	int32_t _shared_secret_length;
	mbedtls_ecp_group_id _key;
	mbedtls_ecdh_context ecdh;
	uint8_t *_publicB; /* Our B public value */
	uint8_t _publicB_length;
} ecdh_context_t;

static bool computePublicBECDH(ecdh_context_t *keyExData);

/**
 * Initialize the key exchange of type ECDH
 * @param context - ecdh context, passed to other ecdh apis, pointer to
 * keyexchange data
 * @return 0 if success else -1
 */
int32_t sdoCryptoKEXInit(void **context)
{
	ecdh_context_t *keyExData = NULL;
	if (!context) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	/* Allocate keyExData*/
	keyExData = sdoAlloc(sizeof(ecdh_context_t));
	if (!keyExData)
		goto error;

	keyExData->_key = GROUP_ID_SIZE;
	/* Generate Device Random bits */
	keyExData->_DevRandSize = DEVICE_RANDOM_SIZE;

	keyExData->_DeviceRandom = sdoAlloc(keyExData->_DevRandSize);
	if (!keyExData->_DeviceRandom) {
		LOG(LOG_ERROR, "Memory alloc failed\n");
		goto error;
	}

	if (_sdoCryptoRandomBytes(keyExData->_DeviceRandom,
				  keyExData->_DevRandSize) != 0) {
		LOG(LOG_ERROR, "Failed to generate device random\n");
		goto error;
	}

	if (computePublicBECDH(keyExData) == false)
		goto error;

	*context = (void *)keyExData;
	return 0;
error:
	sdoCryptoKEXClose((void *)&keyExData);
	return -1;
}

/**
 * key_exchange_close_dh closes the ecdh section
 *
 * @param context - ecdh context
 * @return
 *        returns 0 on success and -1 on failure
 **/
int32_t sdoCryptoKEXClose(void **context)
{
	if (!context) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	ecdh_context_t *keyExData;
	keyExData = *(ecdh_context_t **)context;

	if (keyExData->_sharedSecret)
		sdoFree(keyExData->_sharedSecret);
	if (keyExData->_publicA)
		sdoFree(keyExData->_publicA);
	if (keyExData->_publicB)
		sdoFree(keyExData->_publicB);
	if (keyExData->_DeviceRandom)
		sdoFree(keyExData->_DeviceRandom);
	mbedtls_ecdh_free(&keyExData->ecdh);
	if (keyExData)
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
static bool computePublicBECDH(ecdh_context_t *keyExData)
{
	size_t olen = 0;
	unsigned char buf[1024] = {0};
	unsigned char *temp = NULL;
	int size = 0, ret = -1;
	uint16_t tmp = 0;
	size_t allocbytes = 0;
	bool retval = false;
	uint32_t temp_size;

	/* Allocate random wrt KexCurve*/
	/* Initialize ECDH based on the Group ID */
	mbedtls_ecdh_init(&keyExData->ecdh);
	ret = mbedtls_ecp_group_load(&keyExData->ecdh.grp, keyExData->_key);
	if (ret != 0) {
		LOG(LOG_ERROR, "ec group load failed, ret:%d\n", ret);
		goto error;
	}

	/* Generate private and public key */
	ret = mbedtls_ecdh_make_public(&keyExData->ecdh, &olen, buf,
				       sizeof(buf), myrand, NULL);
	if (ret != 0) {
		LOG(LOG_ERROR, "mbedtls_ecdh_make_public returned %d\n", ret);
		goto error;
	}

	/* 2byte for each blen 3x2 =6 */
	allocbytes = bn_num_bytes(&keyExData->ecdh.Q.X) +
		     bn_num_bytes(&keyExData->ecdh.Q.Y) +
		     keyExData->_DevRandSize + 6;
	temp = sdoAlloc(allocbytes);
	if (!temp) {
		LOG(LOG_ERROR, "Memory alloc failed\n");
		goto error;
	}

	tmp = bn_num_bytes(&keyExData->ecdh.Q.X);
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
	temp_size = bn_bn2bin(&keyExData->ecdh.Q.X, &temp[size]);
	if (0 == temp_size) {
		LOG(LOG_ERROR, "Big number to binary conversion failed\n");
		goto error;
	}
	size += temp_size;
	tmp = bn_num_bytes(&keyExData->ecdh.Q.Y);
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

	temp_size = bn_bn2bin(&keyExData->ecdh.Q.Y, &temp[size]);
	if (0 == temp_size) {
		LOG(LOG_ERROR, "Big number to binary conversion failed\n");
		goto error;
	}
	size += temp_size;
	tmp = keyExData->_DevRandSize;
	if (tmp & 0xffff0000) // check size more than 2 byte size space
		goto error;
	temp[size] = tmp >> 8;
	size += 1;
	temp[size] = (tmp & 0x00ff);
	size += 1;
	/* copy device random number to leftover empty space of temp array */
	if (memcpy_s(&temp[size], allocbytes - size, keyExData->_DeviceRandom,
		     keyExData->_DevRandSize) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto error;
	}

	size += keyExData->_DevRandSize;

	/* Allocate public B*/
	keyExData->_publicB_length = size;
	keyExData->_publicB = temp;
#if LOG_LEVEL == LOG_MAX_LEVEL
	hexdump("generated _publicB::", temp, size);
#endif
	LOG(LOG_DEBUG, "computePublicB complete\n");
	retval = true;
error:
	if (retval == false) {
		LOG(LOG_ERROR, "computePublicB failed\n");
		if (temp)
			sdoFree(temp);
	}
	return retval;
}

/**
 * Step 1, allocate internal secrets and generate public shared value B for ECC
 * based Diffie Hellman key exchange mode.
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
	ecdh_context_t *keyExData = (ecdh_context_t *)context;

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
 * @return 0 if success, else -1.
 */

int32_t sdoCryptoSetPeerRandom(void *context, const uint8_t *peerRandValue,
			       uint32_t peerRandLength)
{

	ecdh_context_t *keyExData = (ecdh_context_t *)context;
	if (!context || !peerRandValue || peerRandLength == 0) {
		LOG(LOG_ERROR, "Invalid parameters\n");
		return -1;
	}

	unsigned char *temp = NULL;
	size_t size_Ax = 0, size_Ay = 0, size_ownerRandom = 0;
	size_t secret_buf_MAX = BUFF_SIZE_512_BYTES, size_shse = 0;
	unsigned char *shse = NULL, *Ax = NULL, *Ay = NULL;
	unsigned char *ownerRandom = NULL, *secret = NULL;
	int ret = -1, size = 0;
	/*TODO: Should we work on a local buffer or the buffer passed to us */
	uint8_t *publicAbytes = (uint8_t *)peerRandValue;
	size_t allocated_shse_size;
	uint32_t custom_shse_size;

	if (publicAbytes == NULL) {
		return -1;
	}

	const mbedtls_ecp_curve_info *curve_info =
	    mbedtls_ecp_curve_info_from_grp_id(GROUP_ID_SIZE);

	if (curve_info && peerRandLength > curve_info->bit_size) {
		LOG(LOG_ERROR, "peerRandLength is too large\n");
		goto exit;
	}

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
	temp = keyExData->_publicA;
	/* Extract owner public co-ordinates and ower random */
	size = 0;
	size_Ax = (temp[size] << 8) | temp[size + 1];
	size += 2;
	if (size_Ax > AX_AY_SIZE_DEF) {
		LOG(LOG_ERROR, "Size of Ax more than 32 bytes\n");
		goto exit;
	}
	Ax = sdoAlloc(size_Ax);
	if (!Ax) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}
	if (memcpy_s(Ax, size_Ax, &publicAbytes[size], size_Ax) != 0) {
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
	Ay = sdoAlloc(size_Ay);
	if (!Ay) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}

	if (memcpy_s(Ay, size_Ay, &publicAbytes[size], size_Ay) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}
	size += size_Ay;
	size_ownerRandom = (temp[size] << 8) | temp[size + 1];
	size += 2;
	if (size_ownerRandom > OWNERRAND_SIZE_DEF) {
		LOG(LOG_ERROR, "Size of owner random more than 16 bytes\n");
		goto exit;
	}
	ownerRandom = sdoAlloc(size_ownerRandom);
	if (!ownerRandom) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}
	if (memcpy_s(ownerRandom, size_ownerRandom, &publicAbytes[size],
		     size_ownerRandom) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}

	/* read peer (server) public in ecdh context */
	ret = mbedtls_mpi_lset(&keyExData->ecdh.Qp.Z, 1);
	if (ret != 0) {
		LOG(LOG_DEBUG, " mbedtls Qp.z, set fail, returned %d\n", ret);
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&keyExData->ecdh.Qp.X, Ax, size_Ax);
	if (ret != 0) {
		LOG(LOG_DEBUG, "mbedtls Qp.X read failed, returned %d\n", ret);
		goto exit;
	}
	ret = mbedtls_mpi_read_binary(&keyExData->ecdh.Qp.Y, Ay, size_Ay);
	if (ret != 0) {
		LOG(LOG_DEBUG, "mbedtls Qp.Y read failed, returned %d\n", ret);
		goto exit;
	}

	ret = -1; /* reset to -1 for correct error handling */

	secret = sdoAlloc(secret_buf_MAX);
	if (!secret) {
		LOG(LOG_ERROR, "Memalloc failed\n");
		goto exit;
	}

	/* Compute the ECDH shared secret */
	if ((ret =
		 mbedtls_ecdh_calc_secret(&keyExData->ecdh, &size_shse, secret,
					  secret_buf_MAX, NULL, NULL)) != 0) {
		LOG(LOG_DEBUG, "ecdh secret generation failed");
		LOG(LOG_DEBUG, "ret:%d\n", ret);
		goto exit;
	}
	LOG(LOG_DEBUG, "Shx size: %lu\n", size_shse);

	ret = -1; /* reset to -1 for correct error handling */

	/* Derive the custom shared secret */
	custom_shse_size =
	    keyExData->_DevRandSize + size_ownerRandom + size_shse;
	shse = sdoAlloc(custom_shse_size);
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
	if (memcpy_s(&shse[size], allocated_shse_size, keyExData->_DeviceRandom,
		     keyExData->_DevRandSize) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}

	size += keyExData->_DevRandSize;
	allocated_shse_size -= keyExData->_DevRandSize;
	if (memcpy_s(&shse[size], allocated_shse_size, ownerRandom,
		     size_ownerRandom) != 0) {
		LOG(LOG_ERROR, "Memcopy failed\n");
		goto exit;
	}

	size += size_ownerRandom;

	keyExData->_shared_secret_length = size;
	keyExData->_sharedSecret = shse;
	LOG(LOG_DEBUG, "SheShe size= %x, ", size);

	ret = 0; /* Mark as success */

exit:
	if (ret && shse) {
		if (memset_s(shse, custom_shse_size, 0)) {
			LOG(LOG_ERROR, "Failed to clear Shared Secret\n");
			ret = -1;
		}
		sdoFree(shse);
	}
	if (Ax) {
		if (memset_s(Ax, size_Ax, 0)) {
			LOG(LOG_ERROR, "Failed to clear secret data Ax\n");
			ret = -1;
		}
		sdoFree(Ax);
	}
	if (Ay) {
		if (memset_s(Ay, size_Ay, 0)) {
			LOG(LOG_ERROR, "Failed to clear secret data Ay\n");
			ret = -1;
		}
		sdoFree(Ay);
	}
	if (ownerRandom) {
		if (memset_s(ownerRandom, size_ownerRandom, 0)) {
			LOG(LOG_ERROR, "Failed to clear secret data Ay\n");
			ret = -1;
		}
		sdoFree(ownerRandom);
	}
	if (secret) {
		if (memset_s(secret, secret_buf_MAX, 0)) {
			LOG(LOG_ERROR, "Failed to clear secret\n");
			ret = -1;
		}
		sdoFree(secret);
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
	ecdh_context_t *keyExData = (ecdh_context_t *)context;

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
