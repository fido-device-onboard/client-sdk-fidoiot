/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */
#ifndef __TPM20_UTILS_H__
#define __TPM20_UTILS_H__

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#define TPM_HMAC_PRIV_KEY_CONTEXT_SIZE 128
#define TPM_HMAC_PUB_KEY_CONTEXT_SIZE 48

#if defined(ECDSA256_DA)
#define SDO_TPM2_CURVE_ID TPM2_ECC_NIST_P256
#else
#define SDO_TPM2_CURVE_ID TPM2_ECC_NIST_P384
#endif

#define TPM2_ZEROISE_FREE(ref)                                                 \
	{                                                                      \
		if (ref) {                                                     \
			memset_s(ref, sizeof(*ref), 0);                        \
			free(ref);                                             \
			ref = NULL;                                            \
		}                                                              \
	}

static const TPM2B_PUBLIC inPublicPrimaryKeyTemplate = {
    .size = 0,
    .publicArea =
	{
	    .type = TPM2_ALG_ECC,
	    .nameAlg = TPM2_ALG_SHA256,
	    .objectAttributes =
		(TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
		 TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
		 TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
	    .authPolicy =
		{
		    .size = 0,
		},
	    .parameters.eccDetail = {.symmetric =
					 {
					     .algorithm = TPM2_ALG_AES,
					     .keyBits.aes = 128,
					     .mode.aes = TPM2_ALG_CFB,
					 },
				     .scheme =
					 {
					     .scheme = TPM2_ALG_NULL,
					     .details = {},
					 },
				     .curveID = SDO_TPM2_CURVE_ID,
				     .kdf = {.scheme = TPM2_ALG_NULL,
					     .details = {}}},
	    .unique.ecc =
		{
		    .x = {.size = 0, .buffer = {}},
		    .y = {.size = 0, .buffer = {}},
		},
	},
};

static const TPM2B_PUBLIC inPublicHMACKeyTemplate = {
    .size = 0,
    .publicArea =
	{
	    .type = TPM2_ALG_KEYEDHASH,
	    .nameAlg = TPM2_ALG_SHA256,
	    .objectAttributes =
		(TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_DECRYPT |
		 TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM |
		 TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
	    .authPolicy =
		{
		    .size = 0,
		},
	    .parameters.keyedHashDetail =
		{
		    .scheme =
			{
			    .scheme = TPM2_ALG_NULL,
			    .details = {},
			},
		},
	    .unique.keyedHash =
		{
		    .size = 0,
		    .buffer = {0},
		},
	},
};

int32_t sdoTPMGetHMAC(const uint8_t *data, size_t dataLength, uint8_t *hmac,
		      size_t hmacLength, char *tpmHMACPubKey,
		      char *tpmHMACPrivKey);
int32_t sdoTPMGenerateHMACKey(char *tpmHMACPubKey, char *tpmHMACPrivKey);
int32_t isValidTPMDataProtectionKeyPresent(void);

#endif /* #ifndef __TPM20_UTILS_H__ */
