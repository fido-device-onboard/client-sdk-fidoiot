/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __CRYTPO_COMMONS_H__
#define __CRYTPO_COMMONS_H__

#define FDO_AES_BLOCK_SIZE BUFF_SIZE_16_BYTES /* 128 bits */
#define FDO_AES_IV_SIZE BUFF_SIZE_16_BYTES    /* 128 bits */
#define HMAC_KEY_LENGTH BUFF_SIZE_32_BYTES    /* 256 bits */

// default Owner attestation
#define FDO_OWNER_ATTEST_PK_ENC FDO_CRYPTO_PUB_KEY_ENCODING_COSEX509

// Device Attestation (DA) is used to decide the size of the key used for the following:
// 1. Key-Exchange
// 2. Encryption/Decryption
// 3. Hash/HMAC
// See Section 3.6 in the FIDO Device Onboard Specification
#if defined(ECDSA256_DA)

// Device Attestation: ECDSA256
#define FDO_PK_ALGO FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256

// Key-Exchange: ECDH
#define KEX_ECDH_ENABLED
#define SEK_KEY_SIZE 16
#define KEX "ECDH"
#define FDO_SHA_DIGEST_SIZE_USED BUFF_SIZE_32_BYTES

// Encryption/Decryption Algorithms: AES128
#define AES_128_BIT
#define AES_BITS 128
#define FDO_AES_KEY_LENGTH BUFF_SIZE_16_BYTES

#else

// Device Attestation: ECDSA384
#define FDO_PK_ALGO FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384

// Key-Exchange: ECDH384
#define KEX_ECDH384_ENABLED
#define SEK_KEY_SIZE 32
#define KEX "ECDH384"
#define FDO_SHA_DIGEST_SIZE_USED BUFF_SIZE_48_BYTES

// Encryption/Decryption Algorithms: AES256
#define AES_256_BIT
#define AES_BITS 256
#define FDO_AES_KEY_LENGTH BUFF_SIZE_32_BYTES
#endif

#if defined(AES_MODE_GCM_ENABLED) && AES_BITS == 128
#define COSE_ENC_TYPE FDO_CRYPTO_A128GCM
#elif defined(AES_MODE_GCM_ENABLED) && AES_BITS == 256
#define COSE_ENC_TYPE FDO_CRYPTO_A256GCM
#elif defined(AES_MODE_CCM_ENABLED) && AES_BITS == 128
#define COSE_ENC_TYPE FDO_CRYPTO_A128CCM
#elif defined(AES_MODE_CCM_ENABLED) && AES_BITS == 256
#define COSE_ENC_TYPE FDO_CRYPTO_A256CCM
#endif

#endif