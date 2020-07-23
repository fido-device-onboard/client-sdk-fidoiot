/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

#include "sdotypes.h"
#include "util.h"
#include "unity.h"
#include <stdbool.h>
#include <string.h>

#include "BN_support.h"
#include <sdoCryptoHal.h>
#include "stdlib.h"

#ifdef USE_OPENSSL
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#endif

#ifdef USE_MBEDTLS
#include <stdlib.h>
#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include <mbedtls/rsa.h>
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/x509.h>
#define KEY_SIZE BUFF_SIZE_2K_BYTES
#define EXPONENT 65537
#endif
