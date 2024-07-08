/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */
#ifndef __EC_KEY_H__
#define __EC_KEY_H__

#include <openssl/ec.h>

EVP_PKEY *get_evp_key(void);
#endif
