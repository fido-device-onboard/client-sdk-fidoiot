/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \ brief Abstraction layer for ECDSA signing routine using SE
 */

#include "fdo_crypto_hal.h"
#include "util.h"
#include "storage_al.h"
#include "safe_lib.h"
#include "fdo_crypto.h"
#include <atca_basic.h>
#include "se_config.h"

/**
 * Sign a message using provided ECDSA Private Keys.
 * @param message - pointer of type uint8_t, holds the plaintext message.
 * @param message_len - size of message, type size_t.
 * @param signature - pointer of type unsigned char, which will be
 * by filled with signature.
 * @param signature_len - size of signature, type unsigned int.
 * @return 0 if true, else -1.
 */
int32_t crypto_hal_ecdsa_sign(const uint8_t *message, size_t message_len,
			      unsigned char *signature, size_t *signature_len)
{
	unsigned char hash[SHA256_DIGEST_SIZE] = {0};
	uint8_t raw_signature[BUFF_SIZE_64_BYTES];
	int ret = 0;

	if (!message || !message_len || !signature || !signature_len) {
		LOG(LOG_ERROR, "%s params not valid\n", __func__);
		ret = -1;
		goto err;
	}

	if (ATCA_SUCCESS != fdo_crypto_hash((uint8_t *)message, message_len,
					    hash, SHA256_DIGEST_SIZE)) {
		ret = -1;
		goto err;
	}

	if (ATCA_SUCCESS !=
	    atcab_sign(ECDSA_SIGN_KEY_ID, hash, raw_signature)) {
		LOG(LOG_ERROR, "ECDSA sign on SE failed with errno %d\n",
		    errno);
		ret = -1;
		goto err;
	}

	/* The signature returned by the SE is in R and S format which needs
	 * to get converted to DER format for transmission.
	 */
	ret = crypto_hal_der_encode(raw_signature, BUFF_SIZE_64_BYTES,
				    signature, signature_len);

err:
	if (-1 == ret) {
		(void)memset_s(raw_signature, BUFF_SIZE_64_BYTES, 0);
	}
	return ret;
}
