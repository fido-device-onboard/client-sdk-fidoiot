/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Platform Utilities header file.
 *
 */

#ifndef __BLOB_H__
#define __BLOB_H__

#ifndef PLATFORM_HMAC_KEY_DEFAULT_LEN
#define PLATFORM_HMAC_KEY_DEFAULT_LEN 32
#endif
#ifndef PLATFORM_HMAC_SIZE
#define PLATFORM_HMAC_SIZE 32
#endif
#ifndef DATA_CONTENT_SIZE
#define DATA_CONTENT_SIZE 4
#endif

#include <stdint.h>

int32_t configureNormalBlob(void);

#endif // #ifndef __BLOB_H__
