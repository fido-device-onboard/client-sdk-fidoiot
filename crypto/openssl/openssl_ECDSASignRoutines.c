/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \ brief Abstraction layer for ECDSA signing routine using
 * \ openssl library.
 */

#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include "fdoCryptoHal.h"
#include "util.h"
#include "storage_al.h"
#include "safe_lib.h"
#include "ec_key.h"

/**
 * Sign a message using provided ECDSA Private Keys.
 * @param data - pointer of type uint8_t, holds the plaintext message.
 * @param data_len - size of message, type size_t.
 * @param message_signature - pointer of type unsigned char, which will be
 * by filled with signature.
 * @param signature_length - size of signature, type unsigned int.
 * @return 0 if true, else -1.
 */
int32_t crypto_hal_ecdsa_sign(const uint8_t *data, size_t data_len,
		       unsigned char *message_signature,
		       size_t *signature_length)
{
	int ret = -1;
	EC_KEY *eckey = NULL;
	unsigned char hash[SHA512_DIGEST_SIZE] = {0};
	unsigned char *signature = NULL;
	unsigned int sig_len = 0;
	size_t hash_length = 0;

	if (!data || !data_len || !message_signature || !signature_length) {
		LOG(LOG_ERROR, "fdo_cryptoECDSASign params not valid\n");
		goto end;
	}

	eckey = get_ec_key();
	if (!eckey) {
		LOG(LOG_ERROR, "Failed to get the EC key\n");
		goto end;
	}

	sig_len = ECDSA_size(eckey);

	if (sig_len) {
		signature = OPENSSL_malloc(sig_len);
	}
	if (!sig_len || !signature) {
		goto end;
	}

	/* Supplied buffer is enough ? */
	if (sig_len > *signature_length) {
		LOG(LOG_ERROR,
		    "Supplied signature buffer is not enough, "
		    "supplied: %zu bytes, required: %d bytes!\n",
		    *signature_length, sig_len);
		goto end;
	}

#if defined(ECDSA256_DA)
	hash_length = SHA256_DIGEST_SIZE;
	if (SHA256(data, data_len, hash) == NULL)
		goto end;
#elif defined(ECDSA384_DA)
	hash_length = SHA384_DIGEST_SIZE;
	if (SHA384(data, data_len, hash) == NULL)
		goto end;
#endif

	// ECDSA_sign return 1 on success, 0 on failure
	int result =
	    ECDSA_sign(0, hash, hash_length, signature, &sig_len, eckey);
	if (result == 0) {
		LOG(LOG_ERROR, "ECDSA_sign() failed!\n");
		goto end;
	}

	*signature_length = sig_len;
	if (memcpy_s(message_signature, (size_t)sig_len, (char *)signature,
		     (size_t)sig_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto end;
	}
	ret = 0;

end:
	if (signature)
		OPENSSL_free(signature);
	if (eckey)
		EC_KEY_free(eckey);
	return ret;
}
