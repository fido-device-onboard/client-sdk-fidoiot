/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */
#ifndef __CRYTPO_H__
#define __CRYTPO_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "sdokeyexchange.h"
#include "util.h"
#include "sdoCryptoCtx.h"
#ifdef USE_MBEDTLS
#if !defined(TARGET_OS_LINUX)
#include "mbedtls/net.h"
#else
#include "mbedtls/net_sockets.h"
#endif
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/gcm.h"
#elif defined(USE_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#endif

#define PLAIN_TEXT_SIZE BUFF_SIZE_1K_BYTES

#define SHA256_DIGEST_SIZE BUFF_SIZE_32_BYTES
#define SHA384_DIGEST_SIZE BUFF_SIZE_48_BYTES
#define SHA512_DIGEST_SIZE BUFF_SIZE_64_BYTES
#define HMACSHA256_KEY_SIZE BUFF_SIZE_32_BYTES
#define SDO_CRYPTO_AES_MODE_CBC 1
#define SDO_CRYPTO_AES_MODE_CTR 2
// AES GCM authenticated TAG length
#define AES_GCM_TAG_LEN BUFF_SIZE_16_BYTES

#define SDO_AES_BLOCK_SIZE BUFF_SIZE_16_BYTES /* 128 bits */
#define SDO_AES_IV_SIZE BUFF_SIZE_16_BYTES    /* 128 bits */
#define HMAC_KEY_LENGTH BUFF_SIZE_32_BYTES    /* 256 bits */
#if defined(AES_256_BIT)
#define SDO_AES_KEY_LENGTH BUFF_SIZE_32_BYTES /* 256 bits */
#else					      // defined(AES_128_BIT)
#define SDO_AES_KEY_LENGTH BUFF_SIZE_16_BYTES /* 128 bits */
#endif

/* Initialize randomization library. */
int random_init(void);

/* Undo what random_init does. */
int random_close(void);

/* Generate num_bytes of random data and place it in random_buffer.
 * random_buffer should point to a buffer large enough to store this data.
 */
int32_t crypto_hal_random_bytes(uint8_t *random_buffer, size_t num_bytes);

int32_t crypto_init(void);
int32_t crypto_close(void);

/* Calculate hash of "buffer" and place the result in "output". "output" must
 * be allocated already.
 */
int32_t crypto_hal_hash(uint8_t hash_type, const uint8_t *buffer,
			 size_t buffer_length, uint8_t *output,
			 size_t output_length);

/* Calculate hmac of "buffer" using "key", and place the result in "output".
 * "output" must be allocated already.
 */
int32_t crypto_hal_hmac(uint8_t hmac_type, const uint8_t *buffer,
			size_t buffer_length, uint8_t *output,
			size_t output_length, const uint8_t *key,
			size_t key_length);


/* crypto_hal_sig_verify
 * Verify an RSA PKCS v1.5 Signature using provided public key
 * or verify ecdsa signature verify
 *
 * @param key_encoding[in] - Key encoding typee.
 * @param key_algorithm[in] - Public key algorithm.
 * @param message[in] - pointer of type uint8_t, holds the encoded message.
 * @param message_length[in] - size of message, type size_t.
 * @param message_signature[in] - pointer of type uint8_t, holds a valid
 *				signature in big-endian format
 * @param signature_length[in] - size of signature, type unsigned int.
 * @param key_param1[in] - pointer of type uint8_t, holds the public key1.
 * @param key_param1Length[in] - size of public key1, type size_t.
 * @param key_param2[in] - pointer of type uint8_t,holds the public key2.
 * @param key_param2Length[in] - size of public key2, type size_t
 * @return 0 if true, else -1.
 */
int32_t crypto_hal_sig_verify(uint8_t key_encoding, uint8_t key_algorithm,
			      const uint8_t *message, uint32_t message_length,
			      const uint8_t *message_signature,
			      uint32_t signature_length,
			      const uint8_t *key_param1,
			      uint32_t key_param1Length,
			      const uint8_t *key_param2,
			      uint32_t key_param2Length);

/* ECDSA P-256/384 curve signature length, can be to used while allocating
 * buffer
 */

/* Sign and generate ECDSA signature for a given message */
int32_t crypto_hal_ecdsa_sign(const uint8_t *message, size_t message_len,
		       unsigned char *signature, size_t *signature_len);

/* Encrypt "clear_text" using rsa pubkeys. */
int32_t crypto_hal_rsa_encrypt(uint8_t hash_type, uint8_t key_encoding,
			       uint8_t key_algorithm, const uint8_t *clear_text,
			       uint32_t clear_text_length, uint8_t *cipher_text,
			       uint32_t cipher_text_length,
			       const uint8_t *key_param1,
			       uint32_t key_param1Length,
			       const uint8_t *key_param2,
			       uint32_t key_param2Length);

uint32_t crypto_hal_rsa_len(const uint8_t *key_param1,
			    uint32_t key_param1Length,
			    const uint8_t *key_param2,
			    uint32_t key_param2Length);

#define RSA_SHA256_KEY1_SIZE 256

/* Encrypt "clear_text" using "key" and put the result in "cypher_text".
 * "cipher_txt" must point to a buffer large enough to store the
 * encrypted message. cypher_text buffer size required can be derived
 * by passing NULL as cypher_text
 */
int32_t crypto_hal_aes_encrypt(const uint8_t *clear_text,
			       uint32_t clear_text_length, uint8_t *cypher_text,
			       uint32_t *cypher_length, size_t block_size,
			       const uint8_t *iv, const uint8_t *key,
			       uint32_t key_length);

/* Decrypt "cypher_text" using "key" and put the result in "clear_text".
 * and "clear_text" must point to a buffer large enough to store the
 * decrypted message.clear_text buffer size required can be derived
 * by passing NULL as clear_text.
 */
int32_t crypto_hal_aes_decrypt(uint8_t *clear_text, uint32_t *clear_text_length,
			       const uint8_t *cypher_text,
			       uint32_t cypher_length, size_t block_size,
			       const uint8_t *iv, const uint8_t *key,
			       uint32_t key_length);

/* AES-GCM authenticated encryption/decryption APIs */
int32_t sdo_crypto_aes_gcm_encrypt(const uint8_t *plain_text,
				   uint32_t plain_text_length,
				   uint8_t *cipher_text,
				   uint32_t cipher_text_length,
				   const uint8_t *iv, uint32_t iv_length,
				   const uint8_t *key, uint32_t key_length,
				   uint8_t *tag, uint32_t tag_length);

int32_t sdo_crypto_aes_gcm_decrypt(uint8_t *clear_text,
				   uint32_t clear_text_length,
				   const uint8_t *cipher_text,
				   uint32_t cipher_text_length,
				   const uint8_t *iv, uint32_t iv_length,
				   const uint8_t *key, uint32_t key_length,
				   uint8_t *tag, uint32_t tag_length);

/*
 * Helper API designed to convert the raw signature into DER format required by
 * SDO.
 * raw_sig: input a 64 Byte r and s format signature.
 * message_signature: outputs a DER encoded signature value
 * signature_length: outputs the size of the signature after converting to DER
 * format.
 */
int32_t crypto_hal_der_encode(uint8_t *raw_sig, size_t raw_sig_length,
		   uint8_t *message_signature, size_t *signature_length);

/*
 * This internal API is used to convert public key and signature which is in
 * DER format to raw format of r and s representation. This raw formatted
 * data will be of 64 Bytes.
 * raw_key: output, returns the public key in 64 byte format of r and s.
 * raw_sig: output, returns the signature in 64 byte format of r and s.
 * pub_key: input, the DER formatted public key that was received.
 * key_length: input, the size of the DER formatted public key.
 * message_signature: input, the DER formatted signature that was received
 * signature_length: input, the length of signature in bytes that was received.
 * raw_key_length: input, the buffer size of the raw_key
 */
int32_t crypto_hal_der_decode(uint8_t *raw_key, uint8_t *raw_sig,
		   const unsigned char *pub_key, size_t key_length,
		   const uint8_t *message_signature, size_t signature_length,
		   size_t raw_key_length, size_t raw_sig_length);

int32_t crypto_hal_get_device_csr(sdo_byte_array_t **csr);

/* SSL API's*/

int sdo_ssl_read(void *ssl, void *buf, int num);
int sdo_ssl_write(void *ssl, const void *buf, int num);

#ifdef USE_OPENSSL
void *sdo_ssl_setup(int sock);
int sdo_ssl_connect(void *ssl);
int sdo_ssl_close(void *ssl);
#endif

#ifdef USE_MBEDTLS
typedef struct ssl_info {
	mbedtls_net_context server_fd;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
} ssl_info;

void *sdo_ssl_setup_connect(char *server_name, char *port);
int sdo_ssl_close(void *ssl);
#define MBEDTLS_NET_DUMMY_SOCKET (void *)999
#endif

int32_t inc_rollover_ctr(uint8_t *first_iv, uint8_t *new_iv, uint8_t iv_len,
			 size_t aesblocks);

/* DH kex type */
#define SDO_CRYPTO_KEX_DH_GROUP_14 1
#define SDO_CRYPTO_KEX_DH_GROUP_15 2

#if defined(KEX_DH_ENABLED) //(m size =2048)
#define DH_PEER_RANDOM_SIZE 256
#else // KEX_DH_3072_ENABLED  (m size 3072)
#define DH_PEER_RANDOM_SIZE 768
#endif

/* ECDH kex type */
#define SDO_CRYPTO_KEX_ECDH_P256 0
#define SDO_CRYPTO_KEX_ECDH_P384 1

#define SDO_ECDH256_DEV_RANDOM BUFF_SIZE_16_BYTES // 128bits
#define SDO_ECDH384_DEV_RANDOM BUFF_SIZE_48_BYTES // 384bits

/* Asym  kex type */
#define SDO_ASYM_DEV_RANDOM 256
#define SDO_ASYM3072_DEV_RANDOM 768

int32_t crypto_hal_kex_init(void **context);
int32_t crypto_hal_get_device_random(void *context, uint8_t *dev_rand_value,
				     uint32_t *dev_rand_length);
int32_t crypto_hal_set_peer_random(void *context,
				   const uint8_t *peer_rand_value,
				   uint32_t peer_rand_length);
int32_t crypto_hal_get_secret(void *context, uint8_t *secret,
			      uint32_t *secret_length);
int32_t crypto_hal_kex_close(void **context);

int32_t set_encrypt_key_asym(void *context, sdo_public_key_t *encrypt_key);

#ifdef SECURE_ELEMENT
int32_t crypto_hal_se_init(void);
#endif

#ifdef __cplusplus
} // endof externc (CPP code)
#endif

#endif /* __TLS_H__ */
