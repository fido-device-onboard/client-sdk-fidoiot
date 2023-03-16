/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __CRYTPO_API_H__
#define __CRYTPO_API_H__

#include "crypto_utils.h"
#include "util.h"
#include <stdlib.h>
#include "safe_lib.h"
#include "snprintf_s.h"
#include "fdoCryptoCtx.h"
#include "fdoCryptoCommons.h"

/* Function declarations */
int32_t fdo_crypto_init(void);
int32_t fdo_crypto_close(void);

int32_t fdo_crypto_random_bytes(uint8_t *random_buffer, size_t num_bytes);

int32_t fdo_kex_init(void);
int32_t fdo_kex_close(void);

fdo_string_t *fdo_get_device_kex_method(void);
size_t fdo_get_device_crypto_suite(void);
fdo_byte_array_t **getOVKey(void);
fdo_byte_array_t **getreplacementOVKey(void);
int32_t set_ov_key(fdo_byte_array_t *OVkey, size_t OVKey_len);
int32_t set_ov_replacement_key(fdo_byte_array_t *OVkey, size_t OVKey_len);
int32_t fdo_commit_ov_replacement_hmac_key(void);
int32_t fdo_ov_verify(uint8_t *message, uint32_t message_length,
		      uint8_t *message_signature, uint32_t signature_length,
		      fdo_public_key_t *pubkey, bool *result);

int32_t fdo_msg_encrypt_get_cipher_len(uint32_t clear_length,
				       uint32_t *cipher_length);
int32_t fdo_msg_encrypt(const uint8_t *clear_text, uint32_t clear_text_length,
			uint8_t *cipher, uint32_t *cipher_length, uint8_t *iv,
			uint8_t *tag, size_t tag_length,
			const uint8_t *aad, size_t aad_length);
int32_t fdo_msg_decrypt_get_pt_len(uint32_t cipher_length,
				   uint32_t *clear_text_length);
int32_t fdo_msg_decrypt(uint8_t *clear_text, uint32_t *clear_text_length,
			const uint8_t *cipher, uint32_t cipher_length, uint8_t *iv,
			uint8_t *tag, size_t tag_length,
			const uint8_t *aad, size_t aad_length);
int32_t fdo_device_ov_hmac(uint8_t *OVHdr, size_t OVHdr_len, uint8_t *hmac,
			   size_t hmac_len, bool is_replacement_hmac);
int32_t fdo_crypto_hash(const uint8_t *message, size_t message_length,
			uint8_t *hash, size_t hash_length);
int32_t fdo_to2_chained_hmac(uint8_t *to2Msg, size_t to2Msg_len, uint8_t *hmac,
			     size_t hmac_len, const uint8_t *previousHMAC,
			     size_t previousHMACLength);
int set_currentIV(uint8_t *iv);

int32_t fdo_device_sign(const uint8_t *message, size_t message_length,
			fdo_byte_array_t **signature, fdo_byte_array_t **eat_maroe);

fdo_dev_key_ctx_t *getfdo_dev_key_ctx(void);
fdo_kex_ctx_t *getfdo_key_ctx(void);
fdo_to2Sym_enc_ctx_t *get_fdo_to2_ctx(void);
int32_t dev_attestation_init(void);
void dev_attestation_close(void);
int32_t fdo_generate_ov_hmac_key(void);
int32_t fdo_generate_ov_replacement_hmac_key(void);
int32_t fdo_compute_storage_hmac(const uint8_t *data, uint32_t data_length,
				 uint8_t *computed_hmac,
				 int computed_hmac_size);
int32_t fdo_generate_storage_hmac_key(void);

int32_t fdo_get_device_csr(fdo_byte_array_t **csr);

#endif /*__CRYTPO_API_H__ */
