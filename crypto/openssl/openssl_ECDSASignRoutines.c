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
	unsigned int sig_len = 0;
	size_t hash_length = 0;
	ECDSA_SIG *sig = NULL;
	unsigned char *sig_r = NULL;
	int sig_r_len = 0;
	unsigned char *sig_s = NULL;
	int sig_s_len = 0;

	if (!data || !data_len || !message_signature || !signature_length) {
		LOG(LOG_ERROR, "fdo_cryptoECDSASign params not valid\n");
		goto end;
	}

	eckey = get_ec_key();
	if (!eckey) {
		LOG(LOG_ERROR, "Failed to get the EC key\n");
		goto end;
	}

	// this provides DER-encoded signature length
	// the received concatenated r|s would be of lesser length
	sig_len = ECDSA_size(eckey);

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
	if (SHA256(data, data_len, hash) == NULL) {
		goto end;
	}
#elif defined(ECDSA384_DA)
	hash_length = SHA384_DIGEST_SIZE;
	if (SHA384(data, data_len, hash) == NULL) {
		goto end;
	}
#endif

	// ECDSA_sign return 1 on success, 0 on failure
	sig = ECDSA_do_sign(hash, hash_length, eckey);
	if (!sig) {
		LOG(LOG_ERROR, "ECDSA signature generation failed!\n");
		goto end;
	}

	// both r and s are maintained by sig, no need to free explicitly
	const BIGNUM *r = ECDSA_SIG_get0_r(sig);
	const BIGNUM *s = ECDSA_SIG_get0_s(sig);
	if (!r || !s) {
		LOG(LOG_ERROR, "Failed to read r and/or s\n");
		goto end;
	}

	sig_r_len = BN_num_bytes(r);
	if (sig_r_len <= 0) {
		LOG(LOG_ERROR, "Sig r len invalid\n");
		goto end;
	}
	sig_r = fdo_alloc(sig_r_len);
	if (!sig_r) {
		LOG(LOG_ERROR, "Sig r alloc Failed\n");
		goto end;
	}
	if (BN_bn2bin(r, sig_r) <= 0) {
		LOG(LOG_ERROR, "Sig r conversion Failed\n");
		goto end;
	}

	sig_s_len = BN_num_bytes(s);
	if (sig_r_len <= 0) {
		LOG(LOG_ERROR, "Sig s len invalid\n");
		goto end;
	}
	sig_s = fdo_alloc(sig_s_len);
	if (!sig_s) {
		LOG(LOG_ERROR, "Sig s alloc Failed\n");
		goto end;
	}
	if (BN_bn2bin(s, sig_s) <= 0) {
		LOG(LOG_ERROR, "Sig s conversion Failed\n");
		goto end;
	}

	*signature_length = sig_r_len + sig_s_len;
	if (memcpy_s(message_signature, *signature_length, (char *)sig_r,
		     (size_t)sig_r_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto end;
	}
	if (memcpy_s(message_signature + sig_r_len, *signature_length, (char *)sig_s,
		     (size_t)sig_s_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto end;
	}
	ret = 0;

end:
	if (sig) {
		ECDSA_SIG_free(sig);
	}
	if (eckey) {
		EC_KEY_free(eckey);
	}
	if (sig_r) {
		fdo_free(sig_r);
	}
	if (sig_s) {
		fdo_free(sig_s);
	}
	return ret;
}
