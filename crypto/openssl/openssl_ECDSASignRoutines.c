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
	EVP_PKEY *evpKey = NULL;
	unsigned char *der_sig = NULL;
	size_t der_sig_len = 0;
	EVP_MD_CTX *mdctx = NULL;
	int sig_r_len = 0;
	int sig_s_len = 0;
	unsigned char *sig_r = NULL;
	unsigned char *sig_s = NULL;
	ECDSA_SIG *sig = NULL;

	if (!data || !data_len || !message_signature || !signature_length) {
		LOG(LOG_ERROR, "fdo_cryptoECDSASign params not valid\n");
		goto end;
	}

	evpKey = get_evp_key();
	if (!evpKey) {
		LOG(LOG_ERROR, "Failed to get the EVP EC key\n");
		goto end;
	}

	// Create the Message Digest Context
	mdctx = EVP_MD_CTX_create();
	if(!mdctx) {
		LOG(LOG_ERROR, "Failed to create message digest context\n");
		goto end;
	}
#if defined(ECDSA256_DA)
	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, evpKey)) {
		LOG(LOG_ERROR, "EVP sign init failed \n");
		goto end;
	}
#elif defined(ECDSA384_DA)
	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL, evpKey)) {
		LOG(LOG_ERROR, "EVP sign init failed \n");
		goto end;
	}
#endif
	if (1 != EVP_DigestSignUpdate(mdctx, data, data_len)) {
		LOG(LOG_ERROR, "EVP sign update failed \n");
		goto end;
	}
	//First call with NULL param to obtain the DER encoded signature length
	if (1 != EVP_DigestSignFinal(mdctx, NULL, &der_sig_len)) {
		LOG(LOG_ERROR, "EVP sign final for size failed \n");
		goto end;
	}
	if (der_sig_len <= 0) {
		LOG(LOG_ERROR, "EVP_DigestSignFinal returned invalid signature length.\n");
		goto end;
	}

	der_sig = fdo_alloc(der_sig_len);
	if (!der_sig) {
		LOG(LOG_ERROR, "Signature alloc Failed\n");
		goto end;
	}
	//second call with actual param to obtain the DEr encoded signature
	if (1 != EVP_DigestSignFinal(mdctx, der_sig, &der_sig_len)) {
		LOG(LOG_ERROR, "EVP sign final failed \n");
		goto end;
	}

	// Decode DER encoded signature to convert to raw format
	sig = ECDSA_SIG_new();
	const unsigned char *sig_input = der_sig;
	if (!sig || d2i_ECDSA_SIG(&sig, &sig_input, der_sig_len) == NULL) {
		LOG(LOG_ERROR, "DER to EC_KEY struct decoding failed!\n");
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
	if (sig_r) {
		fdo_free(sig_r);
	}
	if (sig_s) {
		fdo_free(sig_s);
	}
	if (der_sig) {
		fdo_free(der_sig);
		sig_input = NULL;
	}
	if (mdctx) {
		EVP_MD_CTX_free(mdctx);
		mdctx = NULL;
	}
	if (evpKey) {
		EVP_PKEY_free(evpKey);
		evpKey = NULL;
	}
	return ret;
}
