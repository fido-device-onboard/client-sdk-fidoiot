/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

#ifndef __TEST_AESROUTINES_H__
#define __TEST_AESROUTINES_H__

#include "sdotypes.h"
#include "unity.h"
#include <stdbool.h>
#include <string.h>

#include "BN_support.h"
#include <sdoCryptoHal.h>

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
