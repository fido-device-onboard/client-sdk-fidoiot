/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \ brief Abstraction layer for ECDSA signing routine using
 * \ tpm2.0(tpm-tss & tpm-tss-engine) and openssl library.
 */

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include "safe_lib.h"
#include "util.h"
#include "fdoCryptoHal.h"

/**
 * Sign a message using provided ECDSA Private Keys.
 * @param data - pointer of type uint8_t, holds the plaintext message.
 * @param data_len - size of message, type size_t.
 * @param message_signature - pointer of type unsigned char, which will be
 * by filled with signature.
 * @param signature_length - size of signature, pointer of type size_t.
 * @return 0 if success, else -1.
 */
int32_t crypto_hal_ecdsa_sign(const uint8_t *data, size_t data_len,
		       unsigned char *message_signature,
		       size_t *signature_length)
{
	int32_t ret = -1;
	const char *engine_id = "dynamic";
	EVP_PKEY *pkey = NULL;
	EC_KEY *eckey = NULL;
	ECDSA_SIG *sig = NULL;
	uint8_t digest[SHA384_DIGEST_SIZE] = {0};
	ENGINE *engine = NULL;
	size_t hash_length = 0;
	unsigned char *sig_r = NULL;
	int sig_r_len = 0;
	unsigned char *sig_s = NULL;
	int sig_s_len = 0;

	if (!data || !data_len || !message_signature || !signature_length) {
		LOG(LOG_ERROR, "Invalid Parameters received.");
		goto error;
	}
#if defined(ECDSA256_DA)
	hash_length = SHA256_DIGEST_SIZE;
	if (SHA256(data, data_len, digest) == NULL) {
		LOG(LOG_DEBUG, "SHA256 digest generation failed.");
		goto error;
	}
#elif defined(ECDSA384_DA)
	hash_length = SHA384_DIGEST_SIZE;
	if (SHA384(data, data_len, digest) == NULL) {
		LOG(LOG_DEBUG, "SHA384 digest generation failed.");
		goto error;
	}
#endif

	ENGINE_load_dynamic();

	engine = ENGINE_by_id(engine_id);
	if (engine == NULL) {
		LOG(LOG_ERROR, "Could not find external engine.\n");
		goto error;
	}

	if (!ENGINE_ctrl_cmd_string(engine, "SO_PATH", TPM2_TSS_ENGINE_SO_PATH,
				    0)) {
		LOG(LOG_ERROR, "Could not set TPM Engine path.\n");
		goto error;
	}

	if (!ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0)) {
		LOG(LOG_ERROR, "Could not load TPM engine.\n");
		goto error;
	}

	LOG(LOG_DEBUG, "TPM Engine successfully loaded.\n");

	if (!ENGINE_init(engine)) {
		LOG(LOG_ERROR, "Could not initialize TPM engine.\n");
		goto error;
	}

	pkey =
	    ENGINE_load_private_key(engine, TPM_ECDSA_DEVICE_KEY, NULL, NULL);
	if (NULL == pkey) {
		LOG(LOG_DEBUG,
		    "Could not load private Key in TPM Engine format.\n");
		goto error;
	}

	LOG(LOG_DEBUG,
	    "Private key successfully loaded in TPM Engine format.\n");

	eckey = EVP_PKEY_get1_EC_KEY(pkey);
	if (NULL == eckey) {
		LOG(LOG_DEBUG, "Could not Load ECC Key.\n");
		goto error;
	}

	LOG(LOG_DEBUG, "ECDSA signature generation - "
		       "ECC key successfully loaded.\n");

	sig = ECDSA_do_sign(digest, hash_length, eckey);
	if (!sig) {
		LOG(LOG_DEBUG, "Failed to generate ECDSA signature.\n");
		goto error;
	}

	// both r and s are maintained by sig, no need to free explicitly
	const BIGNUM *r = ECDSA_SIG_get0_r(sig);
	const BIGNUM *s = ECDSA_SIG_get0_s(sig);
	if (!r || !s) {
		LOG(LOG_ERROR, "Failed to read r and/or s\n");
		goto error;
	}

	sig_r_len = BN_num_bytes(r);
	if (sig_r_len <= 0) {
		LOG(LOG_ERROR, "Sig r len invalid\n");
		goto error;
	}
	sig_r = fdo_alloc(sig_r_len);
	if (!sig_r) {
		LOG(LOG_ERROR, "Sig r alloc Failed\n");
		goto error;
	}
	if (BN_bn2bin(r, sig_r) <= 0) {
		LOG(LOG_ERROR, "Sig r conversion Failed\n");
		goto error;
	}

	sig_s_len = BN_num_bytes(s);
	if (sig_r_len <= 0) {
		LOG(LOG_ERROR, "Sig s len invalid\n");
		goto error;
	}
	sig_s = fdo_alloc(sig_s_len);
	if (!sig_s) {
		LOG(LOG_ERROR, "Sig s alloc Failed\n");
		goto error;
	}
	if (BN_bn2bin(s, sig_s) <= 0) {
		LOG(LOG_ERROR, "Sig s conversion Failed\n");
		goto error;
	}

	*signature_length = sig_r_len + sig_s_len;
	if (memcpy_s(message_signature, *signature_length, (char *)sig_r,
		     (size_t)sig_r_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto error;
	}
	if (memcpy_s(message_signature + sig_r_len, *signature_length, (char *)sig_s,
		     (size_t)sig_s_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto error;
	}

	ret = 0;

error:
	if (engine) {
		ENGINE_finish(engine);
		ENGINE_free(engine);
		ENGINE_cleanup();
	}
	if (pkey) {
		EVP_PKEY_free(pkey);
	}
	if (eckey) {
		EC_KEY_free(eckey);
	}
	if (sig) {
		ECDSA_SIG_free(sig);
	}
	if (sig_r) {
		fdo_free(sig_r);
	}
	if (sig_s) {
		fdo_free(sig_s);
	}
	return ret;
}
