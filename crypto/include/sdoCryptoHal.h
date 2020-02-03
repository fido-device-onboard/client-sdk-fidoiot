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
#else
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

#if defined(ECDSA256_DA)
#define ECDSA_PRIV_KEYSIZE BUFF_SIZE_32_BYTES // 256 bit
#elif defined(ECDSA384_DA)
#define ECDSA_PRIV_KEYSIZE BUFF_SIZE_48_BYTES // 384 bit
#else
#define ECDSA_PRIV_KEYSIZE BUFF_SIZE_0_BYTES // wrong key
#endif

#define SDO_ASYM_DEV_RANDOM 256
#define SDO_ASYM3072_DEV_RANDOM 768

#ifdef KEX_ASYM_ENABLED
#define DEVICE_RANDOM_SIZE SDO_ASYM_DEV_RANDOM
#else
/* ASYM3072 Generate Device Random bits(768) */
#define DEVICE_RANDOM_SIZE SDO_ASYM3072_DEV_RANDOM
#endif //	KEX_ASYM_ENABLED

/* Initialize randomization library. */
int random_init(void);

/* Undo what random_init does. */
int random_close(void);

/* Generate numBytes of random data and place it in randomBuffer. randomBuffer
 * should point to a buffer large enough to store this data. */
int32_t _sdoCryptoRandomBytes(uint8_t *randomBuffer, size_t numBytes);

int32_t cryptoInit(void);
int32_t cryptoClose(void);

/* Calculate hash of "buffer" and place the result in "output". "output" must
 * be allocated already. */
int32_t _sdoCryptoHash(uint8_t hashType, const uint8_t *buffer,
		       size_t bufferLength, uint8_t *output,
		       size_t outputLength);

/* Calculate hmac of "buffer" using "key", and place the result in "output".
 * "output" must be allocated already. */
int32_t sdoCryptoHMAC(uint8_t hmacType, const uint8_t *buffer,
		      size_t bufferLength, uint8_t *output, size_t outputLength,
		      const uint8_t *key, size_t keyLength);

/* sdoCryptoSigVerify
 * Verify an RSA PKCS v1.5 Signature using provided public key
 * or verify ecdsa signature verify
 *
 * @param keyEncoding[in] - Key encoding typee.
 * @param keyAlgorithm[in] - Public key algorithm.
 * @param message[in] - pointer of type uint8_t, holds the encoded message.
 * @param messageLength[in] - size of message, type size_t.
 * @param messageSignature[in] - pointer of type uint8_t, holds a valid
 *				signature in big-endian format
 * @param signatureLength[in] - size of signature, type unsigned int.
 * @param keyParam1[in] - pointer of type uint8_t, holds the public key1.
 * @param keyParam1Length[in] - size of public key1, type size_t.
 * @param keyParam2[in] - pointer of type uint8_t,holds the public key2.
 * @param keyParam2Length[in] - size of public key2, type size_t
 * @return 0 if true, else -1.
 */
int32_t sdoCryptoSigVerify(uint8_t keyEncoding, uint8_t keyAlgorithm,
			   const uint8_t *message, uint32_t messageLength,
			   const uint8_t *messageSignature,
			   uint32_t signatureLength, const uint8_t *keyParam1,
			   uint32_t keyParam1Length, const uint8_t *keyParam2,
			   uint32_t keyParam2Length);

/* ECDSA P-256/384 curve signature length, can be to used while allocating
 * buffer */

/* Sign and generate ECDSA signature for a given message */
int32_t sdoECDSASign(const uint8_t *message, size_t messageLen,
		     unsigned char *signature, size_t *signatureLen);

/* Encrypt "clearText" using rsa pubkeys. */
int32_t sdoCryptoRSAEncrypt(uint8_t hashType, uint8_t keyEncoding,
			    uint8_t keyAlgorithm, const uint8_t *clearText,
			    uint32_t clearTextLength, uint8_t *cipherText,
			    uint32_t cipherTextLength, const uint8_t *keyParam1,
			    uint32_t keyParam1Length, const uint8_t *keyParam2,
			    uint32_t keyParam2Length);

#define RSA_SHA256_KEY1_SIZE 256

/* Encrypt "clearText" using "key" and put the result in "cypherText".
 * "cipher_txt" must point to a buffer large enough to store the
 * encrypted message. cypherText buffer size required can be derived
 * by passing NULL as cypherText */
int32_t sdoCryptoAESEncrypt(const uint8_t *clearText, uint32_t clearTextLength,
			    uint8_t *cypherText, uint32_t *cypherLength,
			    size_t blockSize, const uint8_t *iv,
			    const uint8_t *key, uint32_t keyLength);

/* Decrypt "cypherText" using "key" and put the result in "clearText".
 * and "clearText" must point to a buffer large enough to store the
 * decrypted message.clearText buffer size required can be derived
 * by passing NULL as clearText.
 */
int32_t sdoCryptoAESDecrypt(uint8_t *clearText, uint32_t *clearTextLength,
			    const uint8_t *cypherText, uint32_t cypherLength,
			    size_t blockSize, const uint8_t *iv,
			    const uint8_t *key, uint32_t keyLength);

/* AES-GCM authenticated encryption/decryption APIs */
int32_t sdoCryptoAESGcmEncrypt(const uint8_t *plainText,
			       uint32_t plainTextLength, uint8_t *cipherText,
			       uint32_t cipherTextLength, const uint8_t *iv,
			       uint32_t ivLength, const uint8_t *key,
			       uint32_t keyLength, uint8_t *tag,
			       uint32_t tagLength);
int32_t sdoCryptoAESGcmDecrypt(uint8_t *clearText, uint32_t clearTextLength,
			       const uint8_t *cipherText,
			       uint32_t cipherTextLength, const uint8_t *iv,
			       uint32_t ivLength, const uint8_t *key,
			       uint32_t keyLength, uint8_t *tag,
			       uint32_t tagLength);

/*
 * Helper API designed to convert the raw signature into DER format required by
 * SDO.
 * raw_sig: input a 64 Byte r and s format signature.
 * messageSignature: outputs a DER encoded signature value
 * signatureLength: outputs the size of the signature after converting to DER
 * format.
 */
int32_t DEREncode(uint8_t *rawSig, size_t rawSigLength,
		  uint8_t *messageSignature, size_t *signatureLength);

/*
 * This internal API is used to convert public key and signature which is in
 * DER format to raw format of r and s representation. This raw formatted
 * data will be of 64 Bytes.
 * rawKey: output, returns the public key in 64 byte format of r and s.
 * rawSig: output, returns the signature in 64 byte format of r and s.
 * pubKey: input, the DER formatted public key that was received.
 * keyLength: input, the size of the DER formatted public key.
 * messageSignature: input, the DER formatted signature that was received
 * signatureLength: input, the length of signature in bytes that was received.
 * rawKeyLength: input, the buffer size of the rawKey
 */
int32_t DERDecode(uint8_t *rawKey, uint8_t *rawSig, const unsigned char *pubKey,
		  size_t keyLength, const uint8_t *messageSignature,
		  size_t signatureLength, size_t rawKeyLength,
		  size_t rawSigLength);

int32_t _sdoGetDeviceCsr(SDOByteArray_t **csr);

/* SSL API's*/

int sdo_ssl_read(void *ssl, void *buf, int num);
int sdo_ssl_write(void *ssl, const void *buf, int num);

#ifdef USE_OPENSSL
void *sdo_ssl_setup(int sock);
int sdo_ssl_connect(void *ssl);
int sdo_ssl_close(void *ssl);
#endif

#ifdef USE_MBEDTLS
typedef struct sslInfo {
	mbedtls_net_context server_fd;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
} sslInfo;

void *sdo_ssl_setup_connect(char *server_name, char *port);
int sdo_ssl_close(void *ssl);
#define MBEDTLS_NET_DUMMY_SOCKET 999
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

int32_t sdoCryptoKEXInit(void **context);
int32_t sdoCryptoGetDeviceRandom(void *context, uint8_t *devRandValue,
				 uint32_t *devRandLength);
int32_t sdoCryptoSetPeerRandom(void *context, const uint8_t *peerRandValue,
			       uint32_t peerRandLength);
int32_t sdoCryptoGetSecret(void *context, uint8_t *secret,
			   uint32_t *secretLength);
int32_t sdoCryptoKEXClose(void **context);

int32_t setEncryptKeyAsym(void *context, SDOPublicKey_t *encryptKey);

#ifdef __cplusplus
} // endof externc (CPP code)
#endif

#endif /* __TLS_H__ */
