/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for ECDSA signature verification
 */

#include "fdoCryptoHal.h"
#include "util.h"
#include "storage_al.h"
#include "safe_lib.h"
#include "se_config.h"
#include "fdoCrypto.h"
#include <atca_basic.h>
#include <atcacert/atcacert_der.h>

/**
 * Verify an ECC P-256/P-384 signature using provided ECDSA Public Keys.
 * @param key_encoding - encoding type.
 * @param key_algorithm - public key algorithm.
 * @param message - pointer of type uint8_t, holds the encoded message.
 * @param message_length - size of message, type size_t.
 * @param message_signature - pointer of type uint8_t, holds a valid
 *			ecdsa signature in big-endian format
 * @param signature_length - size of signature, type unsigned int.
 * @param key_param1 - pointer of type uint8_t, holds the public key.
 * @param key_param1Length - size of public key, type size_t.
 * @param key_param2 - not used.
 * @param key_param2Length - not used
 * @return 0 if true, else -1.

 */
int32_t crypto_hal_sig_verify(uint8_t key_encoding, int key_algorithm,
			      const uint8_t *message, uint32_t message_length,
			      const uint8_t *message_signature,
			      uint32_t signature_length,
			      const uint8_t *key_param1,
			      uint32_t key_param1Length,
			      const uint8_t *key_param2,
			      uint32_t key_param2Length)
{
	uint8_t hash[SHA256_DIGEST_SIZE] = {0};
	bool verified = false;
	const unsigned char *pub_key = (const unsigned char *)key_param1;
	uint8_t raw_key[BUFF_SIZE_64_BYTES];
	uint8_t raw_sig[BUFF_SIZE_64_BYTES];
	int ret = 0;

	(void)key_param2;
	(void)key_param2Length;

	/* Check validity of key type. */
	if (key_encoding != FDO_CRYPTO_PUB_KEY_ENCODING_X509 ||
	    (key_algorithm != FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256)) {
		LOG(LOG_ERROR, "Incorrect key type\n");
		ret = -1;
		goto err;
	}

	if (NULL == message_signature || 0 == signature_length ||
	    NULL == message || 0 == message_length) {
		LOG(LOG_ERROR, "Invalid arguments!\n");
		ret = -1;
		goto err;
	}

	if (0 != fdo_crypto_hash((uint8_t *)message, message_length, hash,
				 BUFF_SIZE_32_BYTES)) {
		ret = -1;
		goto err;
	}

	/* SE requires that the public key and signature be present in the raw
	 * format i.e 64Byte rep of r and s. The following api will use the
	 * required API calls from openssl/mbedtls for the decoding operation
	 * and then pass the raw key and signature to the SE for verification.
	 */
	if (0 != crypto_hal_der_decode(raw_key, raw_sig, pub_key,
				       key_param1Length, message_signature,
				       signature_length, BUFF_SIZE_64_BYTES,
				       BUFF_SIZE_64_BYTES)) {
		LOG(LOG_ERROR, "Failed to decode from DER to raw format\n");
		ret = -1;
		goto err;
	}

	if (ATCA_SUCCESS !=
	    atcab_verify_extern(hash, raw_sig, raw_key, &verified)) {
		LOG(LOG_ERROR, "Verify command failed\n");
		ret = -1;
		goto err;
	}

	if (true != verified) {
		LOG(LOG_ERROR, "ECDSA Signature verification failed\n");
		ret = -1;
		goto err;
	}

err:
	if (-1 == ret) {
		/* Following 2 memsets are done on public data therefore return
		 * values are not checked.
		 */
		(void)memset_s(raw_sig, BUFF_SIZE_64_BYTES, 0);
		(void)memset_s(raw_key, BUFF_SIZE_64_BYTES, 0);
	}

	return ret;
}
