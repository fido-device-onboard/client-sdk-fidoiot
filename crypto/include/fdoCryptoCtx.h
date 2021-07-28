/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __CRYTPO_CONTEXT_H__
#define __CRYTPO_CONTEXT_H__

typedef struct fdo_dev_key_ctx {
	fdo_sig_info_t *eA;
} fdo_dev_key_ctx_t;

typedef struct {
	fdo_byte_array_t *sek; // Symmetric AES key
	fdo_byte_array_t *svk; // HMAC key
} fdo_aes_keyset_t;

/* FDO crypto context */
typedef struct fdo_to2Sym_enc_ctx {
	fdo_aes_keyset_t keyset;
	uint8_t *initialization_vector;
	uint32_t ctr_value;
} fdo_to2Sym_enc_ctx_t;

typedef struct fdo_kex_ctx {
	fdo_string_t *kx;
	fdo_string_t *cs;
	fdo_byte_array_t *xB;
	fdo_byte_array_t *initial_secret;
	const char *kdf_label;
	const char *context_label;
	void *context;
} fdo_kex_ctx_t;

typedef struct {
	fdo_dev_key_ctx_t dev_key;
	fdo_to2Sym_enc_ctx_t to2Sym_enc;
	fdo_kex_ctx_t kex;
	fdo_byte_array_t *OVKey;
	fdo_byte_array_t *replacement_OVKey;
} fdo_crypto_context_t;

fdo_aes_keyset_t *get_keyset(void);
#endif /*__CRYTPO_CONTEXT_H__ */
