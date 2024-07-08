/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __TEST_AESROUTINES_H__
#define __TEST_AESROUTINES_H__

#include "fdotypes.h"
#include "unity.h"
#include <stdbool.h>
#include <string.h>

#include "BN_support.h"
#include <fdo_crypto_hal.h>

#ifdef USE_OPENSSL
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#endif

#ifdef USE_MBEDTLS
#include <stdlib.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/x509.h>
#define KEY_SIZE 2048
#define EXPONENT 65537
#endif
#endif /* __TEST_AESROUTINES_H__ */
