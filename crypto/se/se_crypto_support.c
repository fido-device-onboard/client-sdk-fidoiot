/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "fdo_crypto_hal.h"
#include "safe_lib.h"
#include "util.h"
#include <atca_basic.h>
#include <stdbool.h>
#include "se_config.h"

static bool g_random_initialised;

/**
 * Initialize the random function by using RAND_poll function and
 * maintain the state of randomness by variable g_random_initialised.
 * @return 0 if succeeds,else -1.
 */
int random_init(void)
{
	if (!g_random_initialised) {
		g_random_initialised = true;
	}

	return 0;
}

/**
 * Free random engine resources and change state to false using
 * g_random_initialised variable.
 * @return 0 if succeeds,else -1.
 */
int random_close(void)
{
	if (!g_random_initialised) {
		return -1;
	}

	if (ATCA_SUCCESS != atcab_release()) {
		LOG(LOG_ERROR, "Unable to release the Secure element");
		return -1;
	}

	g_random_initialised = false;
	return 0;
}

/**
 * API will initialize the AT608A secure element and the i2c driver.
 *
 * @return ret
 *        return 0 on success. -1 on failure.
 */
int32_t crypto_hal_se_init(void)
{
	if (0 != random_init()) {
		return -1;
	}

	/* Setup the AT608A secure element */
	if (ATCA_SUCCESS != atcab_init(&cfg_ateccx08a_i2c_default)) {
		LOG(LOG_ERROR, "Unable to setup the Secure element");
		return -1;
	}
	return 0;
}

/**
 * If g_random_initialised is true, generate random bytes of data
 * of size num_bytes passed as paramater, else return error.
 * @param random_buffer - Pointer rand_data of type uint8_t to be filled with,
 * @param num_bytes - Number of bytes to be filled.
 * @return 0 if succeeds, else -1.
 */
int32_t crypto_hal_random_bytes(uint8_t *random_buffer, size_t num_bytes)
{
	/* Because the SE will  always give out 32 bytes of random data
	 * we might need to truncate it for FDO purposes.
	 */
	uint8_t local_buffer[32];

	if (!g_random_initialised) {
		return -1;
	} else if (NULL == random_buffer) {
		return -1;

	} else if (32 < num_bytes) {
		/* TODO loop over the rand number generation for bigger chunks.
		 */
		return -1;

	} else if (ATCA_SUCCESS != atcab_random(local_buffer)) {
		LOG(LOG_ERROR,
		    "Unable to generate random number from the Secure Element");
		return -1;
	}

	/* Transfer only the required number of random bytes. */
	if (0 != memcpy_s(random_buffer, num_bytes, local_buffer, num_bytes)) {
		return -1;
	}
	return 0;
}

/**
 * fdo_crypto_hash function calculate hash on input data
 *
 * @param hash_type - Hash type (FDO_CRYPTO_HASH_TYPE_SHA_256)
 * @param buffer - pointer to input data buffer of uint8_t type.
 * @param buffer_length - input data buffer size
 * @param output - pointer to output data buffer of uint8_t type.
 * @param output_length - output data buffer size
 *
 * @return
 *        return 0 on success. -ve value on failure.
 */
int32_t crypto_hal_hash(uint8_t hash_type, const uint8_t *buffer,
			size_t buffer_length, uint8_t *output,
			size_t output_length)
{
	if (NULL == output || 0 == output_length || NULL == buffer ||
	    0 == buffer_length) {
		return -1;
	}

	switch (hash_type) {
	case FDO_CRYPTO_HASH_TYPE_SHA_256:
		if (output_length < SHA256_DIGEST_SIZE) {
			return -1;
		}

		if (ATCA_SUCCESS != atcab_hw_sha2_256((const uint8_t *)buffer,
						      buffer_length, output)) {
			LOG(LOG_ERROR,
			    "Hash generation from the Secure Element failed");
			return -1;
		}
		break;

	case FDO_CRYPTO_HASH_TYPE_SHA_384:
		/* AT608A does not support this feature */
		LOG(LOG_ERROR, "Secure Element doesn't support the SHA 384");
		return -1;

	default:
		return -1;
	}
	return 0;
}

/* Helper API to write the required key into the given key slot.
 * if the data zone is locked make sure that the WRITE_KEY and WRITE_KEY_ID
 * are defined correctly in the header file.
 * if these 2 parameters are incorrect then this API will fail.
 *
 * key - (in) The key that needs to be written to the slot HMAC_KEY_SLOT
 *
 * return - returns 0 on success or a -1 on failure.
 */
static int32_t se_key_write(const uint8_t *key)
{
#if (HMAC_KEY_SLOT != ATCA_TEMPKEY_KEYID)
	bool data_locked, config_locked;
	int32_t ret = 0;
	uint8_t key_extend[36];
	uint8_t write_key_for_encryption[32] = WRITE_KEY;

	ret = atcab_is_locked(LOCK_ZONE_DATA, &data_locked);
	ret |= atcab_is_locked(LOCK_ZONE_CONFIG, &config_locked);
	if (ATCA_SUCCESS != ret) {
		LOG(LOG_ERROR, "Failed to retrieve locked information\n");
	}

	if (true == data_locked) {
		if (ATCA_SUCCESS != atcab_write_enc(HMAC_KEY_SLOT, 0, key,
						    write_key_for_encryption,
						    WRITE_KEY_ID)) {

			LOG(LOG_ERROR, "Encrypted key write to SE failed\n");
			return -1;
		}
	} else {
		/* priv write expects a key of 36Bytes to be written to the
		 * given slot. It also expects the first 4 Bytes to be 0.
		 * Therefore a new buffer is created with size of 36 bytes
		 * with leading 4 bytes as 0 and remaining 32Bytes is the
		 * the key.
		 */
		if (0 != memset_s(key_extend, 0, 4)) {
			LOG(LOG_ERROR, "memset failed\n");
			return -1;
		}
		if (0 != memcpy_s((key_extend + 4), 32, key, 32)) {
			LOG(LOG_ERROR, "memcpy failed\n");
			return -1;
		}

		/* priv_write wirte_key and write_key_id are NULL and 0 because
		 * the data zone is unlocked. Therefore we can do clear text
		 * write on these slots.
		 */
		if (ATCA_SUCCESS !=
		    atcab_priv_write(HMAC_KEY_SLOT, key_extend, 0x0, NULL)) {
			LOG(LOG_ERROR, "Encrypted key write to SE failed\n");
			return -1;
		}
	}

	return 0;
#else

	if (ATCA_SUCCESS != atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, key,
					     BUFF_SIZE_32_BYTES)) {
		LOG(LOG_ERROR, "Encrypted key write to SE failed\n");
		return -1;
	}

	return 0;

#endif /* (HMAC_KEY_SLOT != ATCA_TEMPKEY_KEYID)  */
}

/**
 * crypto_hal_hmac function calculate hmac on input data
 *
 * @param hmac_type - Hmac type (FDO_CRYPTO_HMAC_TYPE_SHA_256)
 * @param buffer - pointer to input data buffer of uint8_t type.
 * @param buffer_length - input data buffer size
 * @param output - pointer to output data buffer of uint8_t type.
 * @param output_length - output data buffer size
 * @param key - pointer to hmac key slot of uint16_t type and less than 15.
 * @param key_length - hmac key size
 * @return
 *        return 0 on success. -ve value on failure.
 */
int32_t crypto_hal_hmac(uint8_t hmac_type, const uint8_t *buffer,
			size_t buffer_length, uint8_t *output,
			size_t output_length, const uint8_t *key,
			size_t key_length)
{
	if (NULL == output || 0 == output_length || NULL == buffer ||
	    0 == buffer_length || NULL == key || 0 == key_length ||
	    hmac_type != FDO_CRYPTO_HMAC_TYPE_SHA_256) {
		return -1;
	}

	if (output_length < SHA256_DIGEST_SIZE) {
		return -1;
	}

	if (0 != se_key_write(key)) {
		return -1;
	}

	/* Start of the HMAC operation. Key here is the key_slot number.
	 * SHA_MODE_TARGET_TEMPKEY for AT508A SE device.
	 */
	if (ATCA_SUCCESS != atcab_sha_hmac(buffer, buffer_length, HMAC_KEY_SLOT,
					   output, SHA_MODE_TARGET_MSGDIGBUF)) {
		LOG(LOG_ERROR, "HMAC to SE failed errno %d\n", errno);
		return -1;
	}

	return 0;
}
