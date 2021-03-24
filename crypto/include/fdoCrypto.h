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
#include "base64.h"
#include "fdoCryptoCtx.h"

#ifdef KEX_ECDH384_ENABLED
#define SEK_KEY_SIZE 32
#define SVK_KEY_SIZE 64
#else
#define SEK_KEY_SIZE 16
#define SVK_KEY_SIZE 32
#endif /* KEX_ECDH384_ENABLED */

/* Cipher suite "cs" for msg 40 in TO2 */
#ifdef AES_256_BIT
#define AES_BITS 256
#else
#define AES_BITS 128
#endif /* AES_256_BIT */

#if !defined(KEX_ECDH384_ENABLED) /*TODO : replace with generic flag 256/384*/
#define FDO_SHA_DIGEST_SIZE_USED BUFF_SIZE_32_BYTES
#else
#define FDO_SHA_DIGEST_SIZE_USED BUFF_SIZE_48_BYTES
#endif

#ifdef AES_MODE_CTR_ENABLED
#define AES_MODE "CTR"
#else
#define AES_MODE "CBC"
#endif /* AES_MODE_CTR_ENABLED */

#ifdef KEX_ECDH384_ENABLED
#define HMAC_MODE 384
#else
#define HMAC_MODE 256
#endif /* KEX_ECDH384_ENABLED */

#define FDO_AES_BLOCK_SIZE BUFF_SIZE_16_BYTES /* 128 bits */
#define FDO_AES_IV_SIZE BUFF_SIZE_16_BYTES    /* 128 bits */
#define HMAC_KEY_LENGTH BUFF_SIZE_32_BYTES    /* 256 bits */
#if defined(AES_256_BIT)
#define FDO_AES_KEY_LENGTH BUFF_SIZE_32_BYTES /* 256 bits */
#else					      // defined(AES_128_BIT)
#define FDO_AES_KEY_LENGTH BUFF_SIZE_16_BYTES /* 128 bits */
#endif

#ifdef PK_ENC_ECDSA
#define FDO_OWNER_ATTEST_PK_ENC FDO_CRYPTO_PUB_KEY_ENCODING_X509
#elif defined PK_ENC_RSA
#define FDO_OWNER_ATTEST_PK_ENC FDO_PK_ENC_DEFAULT
#else
#error "PK_ENC is undefined, it is either rsa or ecdsa"
#endif /* PK_ENC_ECDSA */

#if defined(ECDSA256_DA)
#define FDO_PK_ALGO FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256
#define FDO_PK_EA_SIZE 0
#define FDO_PK_ENC FDO_CRYPTO_PUB_KEY_ENCODING_X509
#elif defined(ECDSA384_DA)
#define FDO_PK_ALGO FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384
#define FDO_PK_EA_SIZE 0
#define FDO_PK_ENC FDO_CRYPTO_PUB_KEY_ENCODING_X509
#endif

#if defined(AES_MODE_CTR_ENABLED) && AES_BITS == 128
#define AES_PLAIN_TYPE FDO_CRYPTO_COSEAES128CTR
#elif defined(AES_MODE_CTR_ENABLED) && AES_BITS == 256
#define AES_PLAIN_TYPE FDO_CRYPTO_COSEAES256CTR
#elif !defined(AES_MODE_CTR_ENABLED) && AES_BITS == 128
#define AES_PLAIN_TYPE FDO_CRYPTO_COSEAES256CBC
#elif !defined(AES_MODE_CTR_ENABLED) && AES_BITS == 256
#define AES_PLAIN_TYPE FDO_CRYPTO_COSEAES256CBC
#endif

/* Function declarations */
int32_t fdo_crypto_init(void);
int32_t fdo_crypto_close(void);

int32_t fdo_crypto_random_bytes(uint8_t *random_buffer, size_t num_bytes);

int32_t fdo_kex_init(void);
int32_t fdo_kex_close(void);

fdo_string_t *fdo_get_device_kex_method(void);
fdo_string_t *fdo_get_device_crypto_suite(void);
fdo_byte_array_t **getOVKey(void);
int32_t set_ov_key(fdo_byte_array_t *OVkey, size_t OVKey_len);
int32_t fdo_ov_verify(uint8_t *message, uint32_t message_length,
		      uint8_t *message_signature, uint32_t signature_length,
		      fdo_public_key_t *pubkey, bool *result);

int32_t fdo_msg_encrypt_get_cipher_len(uint32_t clear_length,
				       uint32_t *cipher_length);
int32_t fdo_msg_encrypt(uint8_t *clear_text, uint32_t clear_text_length,
			uint8_t *cipher, uint32_t *cipher_length, uint8_t *iv);
int32_t fdo_msg_decrypt_get_pt_len(uint32_t cipher_length,
				   uint32_t *clear_text_length);
int32_t fdo_msg_decrypt(uint8_t *clear_text, uint32_t *clear_text_length,
			uint8_t *cipher, uint32_t cipher_length, uint8_t *iv);
int32_t fdo_to2_hmac(uint8_t *to2Msg, size_t to2Msg_len, uint8_t *hmac,
		     size_t hmac_len);
int32_t fdo_device_ov_hmac(uint8_t *OVHdr, size_t OVHdr_len, uint8_t *hmac,
			   size_t hmac_len);
int32_t fdo_crypto_hash(const uint8_t *message, size_t message_length,
			uint8_t *hash, size_t hash_length);
int32_t fdo_to2_chained_hmac(uint8_t *to2Msg, size_t to2Msg_len, uint8_t *hmac,
			     size_t hmac_len, const uint8_t *previousHMAC,
			     size_t previousHMACLength);
int set_currentIV(uint8_t *iv);

int32_t fdo_device_sign(const uint8_t *message, size_t message_length,
			fdo_byte_array_t **signature);

fdo_dev_key_ctx_t *getfdo_dev_key_ctx(void);
fdo_kex_ctx_t *getfdo_key_ctx(void);
fdo_to2Sym_enc_ctx_t *get_fdo_to2_ctx(void);
int32_t dev_attestation_init(void);
void dev_attestation_close(void);
int32_t fdo_generate_ov_hmac_key(void);
int32_t fdo_compute_storage_hmac(const uint8_t *data, uint32_t data_length,
				 uint8_t *computed_hmac,
				 int computed_hmac_size);
int32_t fdo_generate_storage_hmac_key(void);

int32_t fdo_get_device_csr(fdo_byte_array_t **csr);

#endif /*__CRYTPO_API_H__ */
