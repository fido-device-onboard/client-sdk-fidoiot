/*
 * Copyright 2022 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction of CSE crypto services required by FDO
 * library.
 */

#include "fdoCryptoHal.h"
#include "cse_utils.h"

/**
 * Generate random bytes of data of size num_bytes passed as paramater, else
 * 		return error.
 * @param random_buffer - Pointer rand_data of type uint8_t to be filled with,
 * @param num_bytes - Number of bytes to be filled.
 * @return 0 if succeeds, else -1.
 */
int32_t crypto_hal_random_bytes(uint8_t *random_buffer, size_t num_bytes)
{
	FDO_STATUS fdo_status;

	if (NULL == random_buffer) {
		return -1;
	} else if (TEE_SUCCESS != fdo_heci_generate_random(&fdo_cse_handle,
			random_buffer, (uint32_t)num_bytes, &fdo_status) ||
			FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO CSE generate ranom bytes failed!!\n");
		return -1;
	}

	return 0;
}

/**
 * crypto_hal_hmac function calculate hmac on input data
 *
 * @param buffer - pointer to input data buffer of uint8_t type.
 * @param buffer_length - input data buffer size
 * @param output - pointer to output data buffer of uint8_t type.
 * @param output_length - output data buffer size
 * @return return 0 on success. -ve value on failure.
 */
int32_t crypto_hal_hmac_cse(uint8_t *buffer,
			size_t buffer_length, uint8_t *output, size_t output_length)
{
	if (NULL == output || 0 == output_length || NULL == buffer ||
	    0 == buffer_length) {
		return -1;
	}

	FDO_STATUS fdo_status;

	if (TEE_SUCCESS != fdo_heci_load_file(&fdo_cse_handle, OVH_FILE_ID,
			&fdo_status) || FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO HECI LOAD failed!! %u\n", fdo_status);
		return -1;
	}

	if (TEE_SUCCESS != fdo_heci_update_file(&fdo_cse_handle, OVH_FILE_ID,
			buffer, buffer_length, output, output_length, &fdo_status) ||
			FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO HECI UPDATE failed!! %u\n", fdo_status);
		return -1;
	}
	LOG(LOG_DEBUG, "FDO HECI UPDATE succeeded  %u\n", fdo_status);

	return 0;
}

/**
 * Sign a message using CSE API.
 * @param data - pointer of type uint8_t, holds the plaintext message.
 * @param data_len - size of message, type size_t.
 * @param message_signature - pointer of type unsigned char, which will be
 * by filled with signature.
 * @param message_sig_len - size of signature, type unsigned int.
 * @param eat_maroe - pointer of type uint8_t, which will be
 * by filled with maroeprefix.
 * @param maroe_length - size of maroeprefix, type unsigned int.
 * @return 0 if true, else -1.
 */
int32_t crypto_hal_ecdsa_sign_cse(const uint8_t *data, size_t data_len,
		uint8_t *message_signature, size_t message_sig_len,
		uint8_t *eat_maroe, size_t *maroe_length)
{
	if (!data || !data_len || !message_signature || !message_sig_len ||
			!eat_maroe || !maroe_length) {
		LOG(LOG_ERROR, "fdo_cryptoECDSASign params not valid\n");
		return -1;
	}

	FDO_STATUS fdo_status;
	uint32_t mp_len = 0;

	if (TEE_SUCCESS != fdo_heci_ecdsa_device_sign_challenge(&fdo_cse_handle,
			(uint8_t *)data, (uint32_t)data_len, message_signature,
			message_sig_len, eat_maroe, &mp_len, &fdo_status) ||
			FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO HECI ECDSA DEVICE SIGN failed!! %u\n",
					fdo_status);
			return -1;
	}
	LOG(LOG_DEBUG, "FDO HECI ECDSA DEVICE SIGN compelete!! %u\n", fdo_status);

	*maroe_length = mp_len;

	return 0;
}
