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
#include "sdoCrypto.h"

static sdo_crypto_context_t crypto_ctx;
static void cleanup_ctx(void);

/******************************************************************************/
/**
 * This function returns the kx value needed by the protocol
 * @return kx string which was stored during init.
 */
sdo_string_t *sdo_get_device_kex_method(void)
{
	return crypto_ctx.kex.kx;
}

/**
 * This function returns the cs value needed by the protocol
 * @return cs string which was stored during init.
 */
sdo_string_t *sdo_get_device_crypto_suite(void)
{
	return crypto_ctx.kex.cs;
}

/**
 * This function returns the keyset which holds sek and svk values.
 * @return struct of type sdo_aes_keyset_t which has sek and svk.
 */
sdo_aes_keyset_t *get_keyset(void)
{
	return &crypto_ctx.to2Sym_enc.keyset;
}

/**
 * This function returns the address of Ownership voucher hmac key.
 * @return Byte array which holds the OV hmac key
 */
sdo_byte_array_t **getOVKey(void)
{
	return &crypto_ctx.OVKey;
}

/**
 * This function returns the address of the dev key struct inside crypto
 * context.
 */
sdo_dev_key_ctx_t *getsdo_dev_key_ctx(void)
{
	return &crypto_ctx.dev_key;
}

/**
 * This function returns the address of the kex struct inside crypto
 * context.
 */
sdo_kex_ctx_t *getsdo_key_ctx(void)
{
	return &crypto_ctx.kex;
}

/**
 * This function returns the address of the kex struct inside crypto
 * context.
 */
sdo_to2Sym_enc_ctx_t *get_sdo_to2_ctx(void)
{
	return &crypto_ctx.to2Sym_enc;
}

int32_t sdo_crypto_init(void)
{
	int32_t ret = -1;

	if (crypto_init()) {
		goto err;
	}
	if (dev_attestation_init()) {
		goto err;
	}
	ret = 0;
err:
	return ret;
}

int32_t sdo_crypto_close(void)
{
	int32_t ret = 0;

	dev_attestation_close();

	ret = crypto_close();
	/* CLeanup of context structs */
	cleanup_ctx();
	return ret;
}

static void cleanup_ctx(void)
{
	/* dev_key cleanup*/
	if (crypto_ctx.dev_key.eA) {
		sdo_public_key_free(crypto_ctx.dev_key.eA->pubkey);
		sdo_free(crypto_ctx.dev_key.eA);
		crypto_ctx.dev_key.eA = NULL;
	}

	/* cleanup ovkey */
	sdo_byte_array_free(crypto_ctx.OVKey);
	crypto_ctx.OVKey = NULL;
}

/**
 * If crypto init is true, generate random bytes of data
 * of size num_bytes passed as paramater, else return error.
 * @param random_buffer - Pointer random_buffer of type uint8_t to be filled
 * with,
 * @param num_bytes - Number of bytes to be filled.
 * @return 0 if succeeds, else -1.
 */
int32_t sdo_crypto_random_bytes(uint8_t *random_buffer, size_t num_bytes)
{
	return crypto_hal_random_bytes(random_buffer, num_bytes);
}

/**
 * Internal API
 * Interface to get device CSR (certificate generated shall be used during
 * Device Attestation to RV/OWN server).
 * @return pointer to a byte_array holding a valid device CSR.
 */
int32_t sdo_get_device_csr(sdo_byte_array_t **csr)
{
	return crypto_hal_get_device_csr(csr);
}
