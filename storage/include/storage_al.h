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
} sdo_sdk_blob_flags;
#ifdef __cplusplus
extern "C" {
#endif

int32_t sdo_blob_read(const char *blob_name, sdo_sdk_blob_flags flags,
		      uint8_t *buffer, uint32_t length);

int32_t sdo_blob_write(const char *blob_name, sdo_sdk_blob_flags flags,
		       const uint8_t *buffer, uint32_t length);

int32_t sdo_blob_size(const char *blob_name, sdo_sdk_blob_flags flags);

int32_t create_hmac_normal_blob(void);

#ifdef __cplusplus
} // endof externc (CPP code)
#endif
#endif /* __STORAGE_AL_H__ */
