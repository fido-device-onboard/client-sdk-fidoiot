/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */
#ifndef __TPM20_UTILS_H__
#define __TPM20_UTILS_H__

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#define TPM_HMAC_PRIV_KEY_CONTEXT_SIZE_128 128

#if defined(ECDSA256_DA)
#define FDO_TPM2_CURVE_ID TPM2_ECC_NIST_P256
#define TPM_AES_BITS 128
#define FDO_TPM2_ALG_SHA TPM2_ALG_SHA256
#define TPM_HMAC_PRIV_KEY_CONTEXT_SIZE 160
#define TPM_HMAC_PUB_KEY_CONTEXT_SIZE 48
#else
#define FDO_TPM2_CURVE_ID TPM2_ECC_NIST_P384
#define TPM_AES_BITS 256
#define FDO_TPM2_ALG_SHA TPM2_ALG_SHA384
#define TPM_HMAC_PRIV_KEY_CONTEXT_SIZE 224
#define TPM_HMAC_PUB_KEY_CONTEXT_SIZE 64
#endif

#define TPM2_ZEROISE_FREE(ref)                                                 \
	{                                                                      \
		if (ref) {                                                     \
			memset_s(ref, sizeof(*ref), 0);                        \
			free(ref);                                             \
			ref = NULL;                                            \
		}                                                              \
	}

static const TPM2B_PUBLIC in_public_primary_key_template = {
    .size = 0,
    .publicArea = {
	.type = TPM2_ALG_ECC,
	.nameAlg = FDO_TPM2_ALG_SHA,
	.objectAttributes =
	    (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
	     TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
	     TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
	.authPolicy =
	    {
		.size = 0,
	    },
	.parameters
	    .eccDetail = {.symmetric = {.algorithm = TPM2_ALG_AES,
					.keyBits.aes = TPM_AES_BITS,
					.mode.aes = TPM2_ALG_CFB},
			  .scheme = {.scheme = TPM2_ALG_NULL, .details = {{0}}},
			  .curveID = FDO_TPM2_CURVE_ID,
			  .kdf = {.scheme = TPM2_ALG_NULL, .details = {{0}}}},
	.unique.ecc = {.x = {.size = 0, .buffer = {0}},
		       .y = {.size = 0, .buffer = {0}}}}};

static const TPM2B_PUBLIC in_publicECKey_template = {
    .size = 0,
    .publicArea = {
	.type = TPM2_ALG_ECC,
	.nameAlg = FDO_TPM2_ALG_SHA,
	.objectAttributes =
	    (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT |
	     TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
	     TPMA_OBJECT_SENSITIVEDATAORIGIN),
	.authPolicy =
	    {
		.size = 0,
	    },
	.parameters.eccDetail =
	    {.symmetric = {.algorithm = TPM2_ALG_NULL,
			   .keyBits.aes = 0,
			   .mode.aes = 0},
	     .scheme = {.scheme = TPM2_ALG_ECDSA,
			.details = {.ecdsa = {.hashAlg = FDO_TPM2_ALG_SHA}}},
	     .curveID = FDO_TPM2_CURVE_ID,
	     .kdf = {.scheme = TPM2_ALG_NULL, .details = {{0}}}},
	.unique.ecc = {.x = {.size = 0, .buffer = {0}},
		       .y = {.size = 0, .buffer = {0}}}}};

static const TPM2B_PUBLIC in_publicHMACKey_template = {
    .size = 0,
    .publicArea = {
	.type = TPM2_ALG_KEYEDHASH,
	.nameAlg = FDO_TPM2_ALG_SHA,
	.objectAttributes =
	    (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT |
	     TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
	     TPMA_OBJECT_SENSITIVEDATAORIGIN),
	.authPolicy =
	    {
		.size = 0,
	    },
	.parameters.keyedHashDetail =
	    {.scheme = {.scheme = TPM2_ALG_HMAC,
			.details = {.hmac = {.hashAlg = FDO_TPM2_ALG_SHA}}}},
	.unique.keyedHash =
	    {
		.size = 0,
		.buffer = {0},
	    },
    }};

int32_t fdo_tpm_get_hmac(const uint8_t *data, size_t data_length, uint8_t *hmac,
			 size_t hmac_length,
			 TPMI_DH_PERSISTENT persistent_handle);
int32_t fdo_tpm_generate_hmac_key(TPMI_DH_PERSISTENT persistent_handle);

int32_t fdoTPMEsys_context_init(ESYS_CONTEXT **esys_context);
int32_t fdoTPMEsys_auth_session_init(ESYS_CONTEXT *esys_context,
				     ESYS_TR *session_handle);
int32_t fdoTPMTSSContext_clean_up(ESYS_CONTEXT **esys_context,
				  ESYS_TR *auth_session_handle,
				  ESYS_TR *primary_handle);
int32_t fdoTPMGenerate_primary_key_context(ESYS_CONTEXT **esys_context,
					   ESYS_TR *primary_handle,
					   ESYS_TR *auth_session_handle);

#endif /* #ifndef __TPM20_UTILS_H__ */
