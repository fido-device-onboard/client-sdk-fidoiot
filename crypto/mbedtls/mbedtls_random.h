/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */
#ifndef __MBEDTLS_RANDOM_H__
#define __MBEDTLS_RANDOM_H__

/* These are internal functions exported for specific crypto functionality */
void *get_mbedtls_random_ctx(void);
bool is_mbedtls_random_init(void);
typedef int (*entropy_src_funp)(void *data, unsigned char *output, size_t len,
				size_t *olen);
#endif
