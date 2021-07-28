/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "fdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "stdlib.h"
#include "fdoCryptoCtx.h"
#include "fdoCrypto.h"
#if defined(DEVICE_TPM20_ENABLED)
#include "tpm20_Utils.h"
#endif

static fdo_crypto_context_t crypto_ctx;
static void cleanup_ctx(void);

/******************************************************************************/
/**
 * This function returns the kx value needed by the protocol
 * @return kx string which was stored during init.
 */
fdo_string_t *fdo_get_device_kex_method(void)
{
	return crypto_ctx.kex.kx;
}

/**
 * This function returns the cs value needed by the protocol
 * @return cs string which was stored during init.
 */
fdo_string_t *fdo_get_device_crypto_suite(void)
{
	return crypto_ctx.kex.cs;
}

/**
 * This function returns the keyset which holds sek and svk values.
 * @return struct of type fdo_aes_keyset_t which has sek and svk.
 */
fdo_aes_keyset_t *get_keyset(void)
{
	return &crypto_ctx.to2Sym_enc.keyset;
}

/**
 * This function returns the address of Ownership voucher hmac key.
 * @return Byte array which holds the OV hmac key
 */
fdo_byte_array_t **getOVKey(void)
{
	return &crypto_ctx.OVKey;
}

/**
 * This function returns the address of Ownership voucher replacement hmac key.
 * @return Byte array which holds the OV replacement hmac key
 */
fdo_byte_array_t **getreplacementOVKey(void)
{
	return &crypto_ctx.replacement_OVKey;
}

/**
 * This function returns the address of the dev key struct inside crypto
 * context.
 */
fdo_dev_key_ctx_t *getfdo_dev_key_ctx(void)
{
	return &crypto_ctx.dev_key;
}

/**
 * This function returns the address of the kex struct inside crypto
 * context.
 */
fdo_kex_ctx_t *getfdo_key_ctx(void)
{
	return &crypto_ctx.kex;
}

/**
 * This function returns the address of the kex struct inside crypto
 * context.
 */
fdo_to2Sym_enc_ctx_t *get_fdo_to2_ctx(void)
{
	return &crypto_ctx.to2Sym_enc;
}

int32_t fdo_crypto_init(void)
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

int32_t fdo_crypto_close(void)
{
	int32_t ret = 0;

	dev_attestation_close();

	ret = crypto_close();
	/* CLeanup of context structs */
	cleanup_ctx();
#if defined(DEVICE_TPM20_ENABLED)
	/* clear the replacement hmac key objects */
	fdo_tpm_clear_replacement_hmac_key();
#endif
	return ret;
}

static void cleanup_ctx(void)
{
	/* dev_key cleanup*/
	if (crypto_ctx.dev_key.eA) {
		fdo_public_key_free(crypto_ctx.dev_key.eA->pubkey);
		fdo_free(crypto_ctx.dev_key.eA);
		crypto_ctx.dev_key.eA = NULL;
	}

	/* cleanup ovkey */
	fdo_byte_array_free(crypto_ctx.OVKey);
	crypto_ctx.OVKey = NULL;
	if (crypto_ctx.replacement_OVKey) {
		fdo_byte_array_free(crypto_ctx.replacement_OVKey);
		crypto_ctx.replacement_OVKey = NULL;
	}
}

/**
 * If crypto init is true, generate random bytes of data
 * of size num_bytes passed as paramater, else return error.
 * @param random_buffer - Pointer random_buffer of type uint8_t to be filled
 * with,
 * @param num_bytes - Number of bytes to be filled.
 * @return 0 if succeeds, else -1.
 */
int32_t fdo_crypto_random_bytes(uint8_t *random_buffer, size_t num_bytes)
{
	return crypto_hal_random_bytes(random_buffer, num_bytes);
}

/**
 * Internal API
 * Interface to get device CSR (certificate generated shall be used during
 * Device Attestation to RV/OWN server).
 * @return pointer to a byte_array holding a valid device CSR.
 */
int32_t fdo_get_device_csr(fdo_byte_array_t **csr)
{
	return crypto_hal_get_device_csr(csr);
}
