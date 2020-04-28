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

#include "util.h"
#include "sdoCryptoHal.h"

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
	uint8_t digest[SHA384_DIGEST_SIZE] = {0};
	ENGINE *engine = NULL;
	size_t hash_length = 0;

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

	if (0 == ECDSA_sign(0, digest, hash_length, message_signature,
			    (unsigned int *)signature_length, eckey)) {
		LOG(LOG_DEBUG, "Failed to generate ECDSA signature.\n");
		goto error;
	}

	ret = 0;

error:
	if (engine) {
		ENGINE_finish(engine);
		ENGINE_cleanup();
	}
	if (pkey) {
		EVP_PKEY_free(pkey);
	}

	return ret;
}
