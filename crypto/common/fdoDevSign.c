/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "fdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "stdlib.h"
#include "fdoCryptoCtx.h"
#include "fdoCrypto.h"
#if defined(DEVICE_CSE_ENABLED)
#include "cse_utils.h"
#endif

#define ECDSA_SIGNATURE_MAX_LEN BUFF_SIZE_256_BYTES

/* This function signs a message passed in message of size message_length.
 * The generated signature will be available in signature of size
 * signature_length. This API shall use the default device private key
 *  which has been either generated or provisioned into the device.
 * The decision to use either generated or provisioned key will be
 * made at the time of platform build.
 * @param  message In Pointer to the message
 * @param  message_length In Size of the message
 * @param  signature In/Out_pointer to the buffer where the signature is
 *                   stored after the signing operation is completed.
 *                   This buffer is allocated inside the API
 * @param  signature_length_in/Out_in: Size of the buffer pointed to by
 * 					 signature
 * @param  eat maroe In/Out_pointer to the buffer where the maroe is
 *                   stored after the signing operation is completed.
 *                   This buffer is allocated inside the API
 * @param Out: Size of the message signature
 * @return 0 on success and -1 on failure

 */
int32_t fdo_device_sign(const uint8_t *message, size_t message_length,
			fdo_byte_array_t **signature, fdo_byte_array_t **eat_maroe)
{
	int ret = -1;

	if (!signature) {
		return ret;
	}
#if defined(DEVICE_CSE_ENABLED)
	*signature = fdo_byte_array_alloc(FDO_SIGNATURE_LENGTH);
	if (NULL == *signature) {
		LOG(LOG_ERROR, "Alloc failed!\n");
		goto end;
	}

	*eat_maroe = fdo_byte_array_alloc(FDO_MAX_MAROE_PREFIX_SIZE);
	if (NULL == *eat_maroe) {
		LOG(LOG_ERROR, "Alloc failed!\n");
		goto end;
	}

	if (0 != crypto_hal_ecdsa_sign_cse(message, message_length, (*signature)->bytes,
			(*signature)->byte_sz, (*eat_maroe)->bytes, &(*eat_maroe)->byte_sz)) {
		LOG(LOG_ERROR, "ECDSA signing failed!\n");
		fdo_byte_array_free(*signature);
		fdo_byte_array_free(*eat_maroe);
		*signature = NULL;
		*eat_maroe = NULL;
		goto end;
	}

	ret = 0;
#elif defined(ECDSA256_DA) || defined(ECDSA384_DA)
	(void)eat_maroe;
	*signature = fdo_byte_array_alloc(ECDSA_SIGNATURE_MAX_LEN);
	if (NULL == *signature) {
		LOG(LOG_ERROR, "Alloc failed!\n");
		goto end;
	}

	if (0 != crypto_hal_ecdsa_sign(message, message_length, (*signature)->bytes,
				&(*signature)->byte_sz)) {
		LOG(LOG_ERROR, "ECDSA signing failed!\n");
		fdo_byte_array_free(*signature);
		*signature = NULL;
		goto end;
	}
	ret = 0;
#endif

end:
	return ret;
}
