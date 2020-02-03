/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDOKEYEXCHANGE_H__
#define __SDOKEYEXCHANGE_H__

#include "sdotypes.h"
#include <stdbool.h>

typedef enum { KEXSUITE_NONE, DHKEXid14, ASYMKEX, ECDH } KeyExSuite_t;
typedef enum { HMAC_NONE, HMAC_SHA256, HMAC_SHA384 } HmacName_t;
typedef enum { HASH_SHA1, HASH_SHA256, HASH_SHA384 } HashType_t;
typedef enum { NIST_P_256, NIST_P_384 } ECCCurveType_t;
typedef enum { RFC3526_P2048, RFC3526_P3072 } ModpGroupKe_t;

int32_t sdoSetKexParamA(SDOByteArray_t *xA, SDOPublicKey_t *encryptKey);
int32_t sdoGetKexParamB(SDOByteArray_t **xB);
SDOString_t *getKexName(void);
SDOString_t *getCipherSuiteName(void);

int setSekSvk(uint8_t *sek, uint32_t sekLen, uint8_t *svk, uint8_t svkLen);

#endif /* __SDOKEYEXCHANGE_H__ */
