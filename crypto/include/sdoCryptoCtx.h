/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __CRYTPO_CONTEXT_H__
#define __CRYTPO_CONTEXT_H__

typedef struct sdo_dev_key_ctx {
	sdo_sig_info_t *eA;
} sdo_dev_key_ctx_t;

typedef struct {
	sdo_byte_array_t *sek; // Symmetric AES key
	sdo_byte_array_t *svk; // HMAC key
} sdo_aes_keyset_t;

/* SDO crypto context */
typedef struct sdo_to2Sym_enc_ctx {
	sdo_aes_keyset_t keyset;
	uint8_t *initialization_vector;
	uint32_t ctr_value;
} sdo_to2Sym_enc_ctx_t;

typedef struct sdo_oa_crypto_ctx {
	uint8_t *rsa_mod;
	uint32_t rsa_mod_len;
	uint8_t *rsa_exp;
	uint32_t rsa_exp_len;
	const uint8_t *ecdsa_pubkey;

} sdo_oa_crypto_ctx_t;

typedef struct sdo_kex_ctx {
	sdo_string_t *kx;
	sdo_string_t *cs;
	sdo_byte_array_t *xB;
	sdo_byte_array_t *initial_secret;
	const char *kdf_label;
	const char *sek_label;
	const char *svk_label;
	void *context;
} sdo_kex_ctx_t;

typedef struct {
	sdo_dev_key_ctx_t dev_key;
	sdo_to2Sym_enc_ctx_t to2Sym_enc;
	sdo_kex_ctx_t kex;
	sdo_byte_array_t *OVKey;
} sdo_crypto_context_t;

sdo_aes_keyset_t *get_keyset(void);
#endif /*__CRYTPO_CONTEXT_H__ */
