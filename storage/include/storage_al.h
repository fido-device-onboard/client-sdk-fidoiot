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

#include "fdotypes.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

// platform HMAC and blob size
#if defined(DEVICE_TPM20_ENABLED) && defined(ECDSA384_DA)
	#define PLATFORM_HMAC_SIZE BUFF_SIZE_48_BYTES
#else
	#define PLATFORM_HMAC_SIZE BUFF_SIZE_32_BYTES
#endif
#define BLOB_CONTENT_SIZE BUFF_SIZE_4_BYTES

typedef enum {
	FDO_SDK_SECURE_DATA = 1,
	FDO_SDK_NORMAL_DATA = 2,
	FDO_SDK_OTP_DATA = 4,
	FDO_SDK_RAW_DATA = 8
} fdo_sdk_blob_flags;
#ifdef __cplusplus
extern "C" {
#endif

int32_t fdo_blob_read(const char *blob_name, fdo_sdk_blob_flags flags,
		      uint8_t *buffer, uint32_t length);

int32_t fdo_blob_write(const char *blob_name, fdo_sdk_blob_flags flags,
		       const uint8_t *buffer, uint32_t length);

size_t fdo_blob_size(const char *blob_name, fdo_sdk_blob_flags flags);

int32_t create_hmac_normal_blob(void);

#ifdef __cplusplus
} // endof externc (CPP code)
#endif
#endif /* __STORAGE_AL_H__ */
