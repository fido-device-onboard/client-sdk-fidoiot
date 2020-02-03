/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "sdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "stdlib.h"
#include "sdoCryptoCtx.h"
#include "sdoCryptoApi.h"

static sdoCryptoContext_t crypto_ctx;
static void cleanup_ctx(void);

/***********************************************************************************/
/**
 * This function returns the kx value needed by the protocol
 * @return kx string which was stored during init.
 */
SDOString_t *sdoGetDeviceKexMethod(void)
{
	return crypto_ctx.kex.kx;
}

/**
 * This function returns the cs value needed by the protocol
 * @return cs string which was stored during init.
 */
SDOString_t *sdoGetDeviceCryptoSuite(void)
{
	return crypto_ctx.kex.cs;
}

/**
 * This function returns the keyset which holds sek and svk values.
 * @return struct of type SDOAESKeyset_t which has sek and svk.
 */
SDOAESKeyset_t *getKeyset(void)
{
	return &crypto_ctx.to2SymEnc.keyset;
}

/**
 * This function returns the address of Ownership voucher hmac key.
 * @return Byte array which holds the OV hmac key
 */
SDOByteArray_t **getOVKey(void)
{
	return &crypto_ctx.OVKey;
}

/**
 * This function returns the address of the dev key struct inside crypto
 * context.
 */
sdoDevKeyCtx_t *getsdoDevKeyCtx(void)
{
	return &crypto_ctx.devKey;
}

/**
 * This function returns the address of the kex struct inside crypto
 * context.
 */
sdoKexCtx_t *getsdoKeyCtx(void)
{
	return &crypto_ctx.kex;
}

/**
 * This function returns the address of the kex struct inside crypto
 * context.
 */
sdoTo2SymEncCtx_t *getsdoTO2Ctx(void)
{
	return &crypto_ctx.to2SymEnc;
}

int32_t sdoCryptoInit(void)
{
	int32_t ret = -1;

	if (cryptoInit()) {
		goto err;
	}
	if (dev_attestation_init()) {
		goto err;
	}
	ret = 0;
err:
	return ret;
}

int32_t sdoCryptoClose(void)
{
	int32_t ret = 0;
	dev_attestation_close();

	ret = cryptoClose();
	/* CLeanup of context structs */
	cleanup_ctx();
	return ret;
}

static void cleanup_ctx(void)
{
	/* devKey cleanup*/
	if (crypto_ctx.devKey.eA) {
		sdoPublicKeyFree(crypto_ctx.devKey.eA->pubkey);
		sdoFree(crypto_ctx.devKey.eA);
		crypto_ctx.devKey.eA = NULL;
	}
	sdoEPIDInfoEBFree(crypto_ctx.devKey.eB);
	crypto_ctx.devKey.eB = NULL;

	/* cleanup ovkey */
	sdoByteArrayFree(crypto_ctx.OVKey);
	crypto_ctx.OVKey = NULL;
}

/**
 * If crypto init is true, generate random bytes of data
 * of size numBytes passed as paramater, else return error.
 * @param randomBuffer - Pointer randomBuffer of type uint8_t to be filled with,
 * @param numBytes - Number of bytes to be filled.
 * @return 0 if succeeds, else -1.
 */
int32_t sdoCryptoRandomBytes(uint8_t *randomBuffer, size_t numBytes)
{
	return (_sdoCryptoRandomBytes(randomBuffer, numBytes));
}

/**
 * Internal API
 * Interface to get device CSR (certificate generated shall be used during
 * Device Attestation to RV/OWN server).
 * @return pointer to a byteArray holding a valid device CSR.
 */
int32_t sdoGetDeviceCsr(SDOByteArray_t **csr)
{
#if !defined(EPID_DA)
	return (_sdoGetDeviceCsr(csr));
#endif
	return 0;
}
