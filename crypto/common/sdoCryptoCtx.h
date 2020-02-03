/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __CRYTPO_CONTEXT_H__
#define __CRYTPO_CONTEXT_H__

typedef struct sdoDevKeyCtx {
	SDOSigInfo_t *eA;
	SDOEPIDInfoeB_t *eB;
} sdoDevKeyCtx_t;

typedef struct {
	SDOByteArray_t *sek; // Symmetric AES key
	SDOByteArray_t *svk; // HMAC key
} SDOAESKeyset_t;

/* SDO crypto context */
typedef struct sdoTo2SymEncCtx {
	SDOAESKeyset_t keyset;
	uint8_t *initializationVector;
	uint32_t ctr_value;
} sdoTo2SymEncCtx_t;

typedef struct sdoOACryptoCtx {
	uint8_t *rsaMod;
	uint32_t rsaModLen;
	uint8_t *rsaExp;
	uint32_t rsaExpLen;
	const uint8_t *ecdsaPubkey;

} sdoOACryptoCtx_t;

typedef struct sdoKexCtx {
	SDOString_t *kx;
	SDOString_t *cs;
	SDOByteArray_t *xB;
	SDOByteArray_t *initialSecret;
	const char *kdfLabel;
	const char *sekLabel;
	const char *svkLabel;
	void *context;
} sdoKexCtx_t;

typedef struct {
	sdoDevKeyCtx_t devKey;
	sdoTo2SymEncCtx_t to2SymEnc;
	sdoKexCtx_t kex;
	SDOByteArray_t *OVKey;
} sdoCryptoContext_t;

SDOAESKeyset_t *getKeyset(void);
#endif /*__CRYTPO_CONTEXT_H__ */
