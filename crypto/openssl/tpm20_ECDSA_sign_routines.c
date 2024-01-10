/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \ brief Abstraction layer for ECDSA signing routine using
 * \ tpm2.0(tpm-tss & tpm-tss-engine) and openssl library.
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/store.h>
#include <openssl/bio.h>
#include "safe_lib.h"
#include "util.h"
#include "fdo_crypto_hal.h"
#include "tpm20_Utils.h"
#include "tpm2_nv_storage.h"

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
	EVP_PKEY *pkey = NULL;
	ECDSA_SIG *sig = NULL;
	unsigned char *sig_r = NULL;
	int sig_r_len = 0;
	unsigned char *sig_s = NULL;
	int sig_s_len = 0;
	unsigned char *der_sig = NULL;
	size_t der_sig_len = 0;
	OSSL_PROVIDER *prov = NULL;
	EVP_MD_CTX *mdctx = NULL;
	OSSL_STORE_CTX *ctx = NULL;
	OSSL_STORE_INFO *info = NULL;
	BIO *mem = NULL;
	unsigned char *pri_key = NULL;

	if (!data || !data_len || !message_signature || !signature_length) {
		LOG(LOG_ERROR, "Invalid Parameters received.");
		goto error;
	}

	// Load OpenSSL TPM provider
	if ((prov = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL) {
		LOG(LOG_ERROR, "Failed to load tpm provider!\n");
		goto error;
	}

	// Read the key
	size_t file_size = fdo_tpm_nvread_size(TPM_ECDSA_DEVICE_KEY_NV_IDX);

	pri_key = fdo_alloc(file_size);
	if (!pri_key) {
		LOG(LOG_ERROR, "Failed to allocate memory for private key.\n");
		goto error;
	}

	if (fdo_tpm_nvread(TPM_ECDSA_DEVICE_KEY_NV_IDX, file_size, &pri_key) ==
	    -1) {
		LOG(LOG_ERROR,
		    "Failed to load TPM HMAC Private Key into buffer.\n");
		goto error;
	}

	mem = BIO_new_mem_buf(pri_key, file_size);
	if (mem == NULL) {
		LOG(LOG_ERROR, "Failed to create memory BIO\n");
		goto error;
	}

	pkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
	if (pkey == NULL) {
		LOG(LOG_ERROR, "Error during reading Private key.\n");
		BIO_free(mem);
		goto error;
	}

	LOG(LOG_DEBUG, "Private key successfully loaded in TPM format.\n");

	// Set EVP properties to use TPM provider
	if (EVP_set_default_properties(NULL, "provider=tpm2") == 0) {
		LOG(LOG_ERROR, "failed to load tpm provider!\n");
		goto error;
	}

	// Create the Message Digest Context
	mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		LOG(LOG_ERROR, "Failed to create message digest context\n");
		goto error;
	}

#if defined(ECDSA256_DA)
	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) {
		LOG(LOG_ERROR, "EVP sign init failed \n");
		goto error;
	}
#elif defined(ECDSA384_DA)
	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL, pkey)) {
		LOG(LOG_ERROR, "EVP sign init failed \n");
		goto error;
	}
#endif
	if (1 != EVP_DigestSignUpdate(mdctx, data, data_len)) {
		LOG(LOG_ERROR, "EVP sign update failed \n");
		goto error;
	}
	// First call with NULL param to obtain the DER encoded signature length
	if (1 != EVP_DigestSignFinal(mdctx, NULL, &der_sig_len)) {
		LOG(LOG_ERROR, "EVP sign final for size failed \n");
		goto error;
	}

	if (der_sig_len <= 0) {
		LOG(LOG_ERROR,
		    "EVP_DigestSignFinal returned invalid signature length.\n");
		goto error;
	}

	der_sig = fdo_alloc(der_sig_len);
	if (!der_sig) {
		LOG(LOG_ERROR, "Signature alloc Failed\n");
		goto error;
	}
	// second call with actual param to obtain the DEr encoded signature
	if (1 != EVP_DigestSignFinal(mdctx, der_sig, &der_sig_len)) {
		LOG(LOG_ERROR, "EVP sign final failed \n");
		goto error;
	}

	// Set EVP properties back to default.
	if (EVP_set_default_properties(NULL, "provider=default") == 0) {
		LOG(LOG_DEBUG, "failed to load tpm provider!\n");
		goto error;
	}

	// Decode DER encoded signature to convert to raw format
	sig = ECDSA_SIG_new();
	const unsigned char *sig_input = der_sig;
	if (!sig || d2i_ECDSA_SIG(&sig, &sig_input, der_sig_len) == NULL) {
		LOG(LOG_ERROR, "DER to EC_KEY struct decoding failed!\n");
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
	if (memcpy_s(message_signature + sig_r_len, *signature_length,
		     (char *)sig_s, (size_t)sig_s_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto error;
	}

	ret = 0;

error:
	if (pri_key) {
		fdo_free(pri_key);
	}
	if (mem) {
		BIO_free(mem);
	}
	if (pkey) {
		EVP_PKEY_free(pkey);
	}
	if (sig) {
		ECDSA_SIG_free(sig);
	}
	if (der_sig) {
		fdo_free(der_sig);
		sig_input = NULL;
	}
	if (sig_r) {
		fdo_free(sig_r);
	}
	if (sig_s) {
		fdo_free(sig_s);
	}
	if (prov) {
		OSSL_PROVIDER_unload(prov);
		prov = NULL;
	}
	if (mdctx) {
		EVP_MD_CTX_free(mdctx);
		mdctx = NULL;
	}
	if (ctx) {
		OSSL_STORE_close(ctx);
		ctx = NULL;
	}
	if (info) {
		OSSL_STORE_INFO_free(info);
		info = NULL;
	}
	return ret;
}
