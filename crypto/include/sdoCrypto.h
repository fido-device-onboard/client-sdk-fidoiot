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
#include "sdoCryptoCtx.h"

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
#define SDO_SHA_DIGEST_SIZE_USED BUFF_SIZE_32_BYTES
#else
#define SDO_SHA_DIGEST_SIZE_USED BUFF_SIZE_48_BYTES
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

#define SDO_AES_BLOCK_SIZE BUFF_SIZE_16_BYTES /* 128 bits */
#define SDO_AES_IV_SIZE BUFF_SIZE_16_BYTES    /* 128 bits */
#define HMAC_KEY_LENGTH BUFF_SIZE_32_BYTES    /* 256 bits */
#if defined(AES_256_BIT)
#define SDO_AES_KEY_LENGTH BUFF_SIZE_32_BYTES /* 256 bits */
#else					      // defined(AES_128_BIT)
#define SDO_AES_KEY_LENGTH BUFF_SIZE_16_BYTES /* 128 bits */
#endif

#ifdef PK_ENC_ECDSA
#define SDO_OWNER_ATTEST_PK_ENC SDO_CRYPTO_PUB_KEY_ENCODING_X509
#elif defined PK_ENC_RSA
#define SDO_OWNER_ATTEST_PK_ENC SDO_PK_ENC_DEFAULT
#else
#error "PK_ENC is undefined, it is either rsa or ecdsa"
#endif /* PK_ENC_ECDSA */

#if defined(ECDSA256_DA)
#define SDO_PK_ALGO SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256
#define SDO_PK_EA_SIZE 0
#define SDO_PK_ENC SDO_CRYPTO_PUB_KEY_ENCODING_X509
#elif defined(ECDSA384_DA)
#define SDO_PK_ALGO SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384
#define SDO_PK_EA_SIZE 0
#define SDO_PK_ENC SDO_CRYPTO_PUB_KEY_ENCODING_X509
#endif

/* Function declarations */
int32_t sdo_crypto_init(void);
int32_t sdo_crypto_close(void);

int32_t sdo_crypto_random_bytes(uint8_t *random_buffer, size_t num_bytes);

int32_t sdo_kex_init(void);
int32_t sdo_kex_close(void);

sdo_string_t *sdo_get_device_kex_method(void);
sdo_string_t *sdo_get_device_crypto_suite(void);
sdo_byte_array_t **getOVKey(void);
int32_t set_ov_key(sdo_byte_array_t *OVkey, size_t OVKey_len);
int32_t sdo_ov_verify(uint8_t *message, uint32_t message_length,
		      uint8_t *message_signature, uint32_t signature_length,
		      sdo_public_key_t *pubkey, bool *result);

int32_t sdo_msg_encrypt_get_cipher_len(uint32_t clear_length,
				       uint32_t *cipher_length);
int32_t sdo_msg_encrypt(uint8_t *clear_text, uint32_t clear_text_length,
			uint8_t *cipher, uint32_t *cipher_length, uint8_t *iv);
int32_t sdo_msg_decrypt_get_pt_len(uint32_t cipher_length,
				   uint32_t *clear_text_length);
int32_t sdo_msg_decrypt(uint8_t *clear_text, uint32_t *clear_text_length,
			uint8_t *cipher, uint32_t cipher_length, uint8_t *iv);
int32_t sdo_to2_hmac(uint8_t *to2Msg, size_t to2Msg_len, uint8_t *hmac,
		     size_t hmac_len);
int32_t sdo_device_ov_hmac(uint8_t *OVHdr, size_t OVHdr_len, uint8_t *hmac,
			   size_t hmac_len);
int32_t sdo_crypto_hash(const uint8_t *message, size_t message_length,
			uint8_t *hash, size_t hash_length);
int32_t sdo_to2_chained_hmac(uint8_t *to2Msg, size_t to2Msg_len, uint8_t *hmac,
			     size_t hmac_len, const uint8_t *previousHMAC,
			     size_t previousHMACLength);
int set_currentIV(uint8_t *iv);

int32_t sdo_device_sign(const uint8_t *message, size_t message_length,
			sdo_byte_array_t **signature);

sdo_dev_key_ctx_t *getsdo_dev_key_ctx(void);
sdo_kex_ctx_t *getsdo_key_ctx(void);
sdo_to2Sym_enc_ctx_t *get_sdo_to2_ctx(void);
int32_t dev_attestation_init(void);
void dev_attestation_close(void);
int32_t sdo_generate_ov_hmac_key(void);
int32_t sdo_compute_storage_hmac(const uint8_t *data, uint32_t data_length,
				 uint8_t *computed_hmac,
				 int computed_hmac_size);
int32_t sdo_generate_storage_hmac_key(void);

int32_t sdo_get_device_csr(sdo_byte_array_t **csr);

#endif /*__CRYTPO_API_H__ */
