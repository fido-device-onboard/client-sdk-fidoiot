/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Platform Utilities declaration
 *
 */

// default key sizes used by platform for blob(s) sealing/encryption
#define PLATFORM_IV_DEFAULT_LEN BUFF_SIZE_12_BYTES
#define PLATFORM_AES_BLOCK_LEN BUFF_SIZE_16_BYTES
#define PLATFORM_AES_KEY_DEFAULT_LEN BUFF_SIZE_16_BYTES
#define PLATFORM_HMAC_KEY_DEFAULT_LEN BUFF_SIZE_32_BYTES

bool getPlatformHMACKey(uint8_t *key, size_t len);
bool getPlatformIV(uint8_t *iv, size_t len, size_t datalen);
bool getPlatformAESKey(uint8_t *key, size_t len);
