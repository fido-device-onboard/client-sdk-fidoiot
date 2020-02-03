/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Storage Abstraction Layer Header
 *
 * The file is a header implementation of storage abstraction layer for Linux OS
 * running on PC.
 */

#ifndef __STORAGE_AL_H__
#define __STORAGE_AL_H__

#include "sdotypes.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

// platform HMAC and GCM tag size
#define PLATFORM_HMAC_SIZE BUFF_SIZE_32_BYTES
#define PLATFORM_GCM_TAG_SIZE BUFF_SIZE_16_BYTES

#define BLOB_CONTENT_SIZE BUFF_SIZE_4_BYTES

typedef enum {
	SDO_SDK_SECURE_DATA = 1,
	SDO_SDK_NORMAL_DATA = 2,
	SDO_SDK_OTP_DATA = 4,
	SDO_SDK_RAW_DATA = 8
} sdoSdkBlobFlags;
#ifdef __cplusplus
extern "C" {
#endif

int32_t sdoBlobRead(const char *blobName, sdoSdkBlobFlags flags,
		    uint8_t *buffer, uint32_t length);

int32_t sdoBlobWrite(const char *blobName, sdoSdkBlobFlags flags,
		     const uint8_t *buffer, uint32_t length);

int32_t sdoBlobSize(const char *blobName, sdoSdkBlobFlags flags);

int32_t sdoReadEPIDKey(uint8_t *buffer, uint32_t *size);

int32_t createHMACForNormalBlob(void);

#ifdef __cplusplus
} // endof externc (CPP code)
#endif
#endif /* __STORAGE_AL_H__ */
