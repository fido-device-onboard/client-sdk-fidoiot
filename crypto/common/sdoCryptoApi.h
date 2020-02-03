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
#elif defined(EPID_DA)
#define SDO_PK_ALGO SDOEPID_VERSION
#define SDO_PK_EA_SIZE SDOEPID20_GID_LEN
#define SDO_PK_ENC SDO_CRYPTO_PUB_KEY_ENCODING_EPID
#endif

/* Function declarations */
int32_t sdoCryptoInit(void);
int32_t sdoCryptoClose(void);

int32_t sdoCryptoRandomBytes(uint8_t *randomBuffer, size_t numBytes);

int32_t sdoKexInit(void);
int32_t sdoKexClose(void);

SDOString_t *sdoGetDeviceKexMethod(void);
SDOString_t *sdoGetDeviceCryptoSuite(void);
SDOByteArray_t **getOVKey(void);
SDOEPIDInfoeB_t **getDeviceSigCtx(void);
int32_t setOVKey(SDOByteArray_t *OVkey, size_t OVKeyLen);
int32_t sdoOVVerify(uint8_t *message, uint32_t messageLength,
		    uint8_t *messageSignature, uint32_t signatureLength,
		    SDOPublicKey_t *pubkey, bool *result);

int32_t sdoMsgEncryptGetCipherLen(uint32_t clearLength, uint32_t *cipherLength);
int32_t sdoMsgEncrypt(uint8_t *clearText, uint32_t clearTextLength,
		      uint8_t *cipher, uint32_t *cipherLength, uint8_t *iv);
int32_t sdoMsgDecryptGetPTLen(uint32_t cipherLength, uint32_t *clearTextLength);
int32_t sdoMsgDecrypt(uint8_t *clearText, uint32_t *clearTextLength,
		      uint8_t *cipher, uint32_t cipherLength, uint8_t *iv);
int32_t sdoTo2HMAC(uint8_t *to2Msg, size_t to2MsgLen, uint8_t *hmac,
		   size_t hmacLen);
int32_t sdoDeviceOVHMAC(uint8_t *OVHdr, size_t OVHdrLen, uint8_t *hmac,
			size_t hmacLen);
int32_t sdoCryptoHash(uint8_t *message, size_t messageLength, uint8_t *hash,
		      size_t hashLength);
int32_t sdoTo2chainedHMAC(uint8_t *to2Msg, size_t to2MsgLen, uint8_t *hmac,
			  size_t hmacLen, const uint8_t *previousHMAC,
			  size_t previousHMACLength);
int setCurrentIV(uint8_t *iv);
int32_t cryptoInit(void);

SDOSigInfo_t *sdoGetDeviceSigInfoeA(void);
int32_t sdoSetDeviceSigInfoeA(uint8_t *eA, size_t *eALen);
int32_t sdoSetDeviceSigInfoeB(SDOByteArray_t *sigRL, SDOByteArray_t *pubkey);

int32_t sdoDeviceSign(const uint8_t *message, size_t messageLength,
		      SDOByteArray_t **signature);

sdoDevKeyCtx_t *getsdoDevKeyCtx(void);
sdoKexCtx_t *getsdoKeyCtx(void);
sdoTo2SymEncCtx_t *getsdoTO2Ctx(void);
int32_t dev_attestation_init(void);
void dev_attestation_close(void);
int32_t sdoGenerateOVHMACKey(void);
int32_t sdoComputeStorageHMAC(const uint8_t *data, uint32_t dataLength,
			      uint8_t *computedHmac, int computedHmacSize);
int32_t sdoGenerateStorageHMACKey(void);

int32_t sdoGetDeviceCsr(SDOByteArray_t **csr);

#endif /*__CRYTPO_API_H__ */
