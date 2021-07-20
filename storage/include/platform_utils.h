/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Platform Utilities declaration
 *
 */

// default key sizes used by platform for blob(s) sealing/encryption
#define PLATFORM_IV_DEFAULT_LEN AES_IV_LEN
#define PLATFORM_AES_BLOCK_LEN BUFF_SIZE_16_BYTES
#ifdef ECDSA384_DA
#define PLATFORM_AES_KEY_DEFAULT_LEN BUFF_SIZE_32_BYTES
#else
#define PLATFORM_AES_KEY_DEFAULT_LEN BUFF_SIZE_16_BYTES
#endif
#define PLATFORM_HMAC_KEY_DEFAULT_LEN BUFF_SIZE_32_BYTES

bool get_platform_hmac_key(uint8_t *key, size_t len);
bool get_platform_iv(uint8_t *iv, size_t len, size_t datalen);
bool get_platform_aes_key(uint8_t *key, size_t len);
