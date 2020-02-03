/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \ brief Abstraction layer for ECDSA signature (signing)
 * \ routines of mbedTLS library.
 */

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform.h"
#include "mbedtls/ecdsa.h"

#include "safe_lib.h"
#include "sdoCryptoHal.h"
#include "util.h"
#include "stdlib.h"
#include "storage_al.h"
#include "mbedtls_random.h"
#include "ecdsa_privkey.h"

/**
 * Sign a message using provided ECDSA Private Keys.
 * @param data - pointer of type uint8_t, holds the plaintext message.
 * @param dataLen - size of message, type size_t.
 * @param messageSignature - pointer of type unsigned char, which will be
 * by filled with signature.
 * @param signatureLength - size of signature, type unsigned int.
 * @return 0 if true, else -1.
 */
int32_t sdoECDSASign(const uint8_t *data, size_t dataLen,
		     unsigned char *messageSignature, size_t *signatureLength)
{
	int ret = -1;
	int retval = -1;
	mbedtls_ecdsa_context ctx_sign = {0};
	mbedtls_ctr_drbg_context *drbg_ctx = get_mbedtls_random_ctx();
	unsigned char hash[SHA512_DIGEST_SIZE] = {0};
	unsigned char *privkey = NULL;
	size_t privkeysize = 0;
#if !defined(ECDSA_PEM)
	mbedtls_mpi d = {0};
#else
	mbedtls_pk_context pk_ctx = {0};
	mbedtls_ecp_keypair *ecp = NULL;
#endif
	mbedtls_md_type_t hashType = MBEDTLS_MD_NONE;
	size_t hashLength = 0;
	uint32_t curvetype = 0;

	if (!data || !dataLen || !messageSignature || !signatureLength ||
	    !drbg_ctx) {
		LOG(LOG_ERROR, "sdoCryptoDSASign params not valid\n");
		ret = -1;
		goto end;
	}

	mbedtls_ecdsa_init(&ctx_sign);

#if defined(ECDSA256_DA)
	hashType = MBEDTLS_MD_SHA256;
	hashLength = SHA256_DIGEST_SIZE;
	curvetype = MBEDTLS_ECP_DP_SECP256R1;
#elif defined(ECDSA384_DA)
	hashType = MBEDTLS_MD_SHA384;
	hashLength = SHA384_DIGEST_SIZE;
	curvetype = MBEDTLS_ECP_DP_SECP384R1;
#endif

	/* Calculate the hash over message and sign that hash */
	if ((retval = mbedtls_md(mbedtls_md_info_from_type(hashType), data,
				 dataLen, hash)) != 0) {
		LOG(LOG_ERROR, " mbedtls_md FAILED:%d\n", retval);
		goto end;
	}

	if ((retval = mbedtls_ecp_group_load(&ctx_sign.grp, curvetype)) != 0) {
		LOG(LOG_ERROR, "signatur_ecp_group_load FAILED:%d\n", retval);
		goto end;
	}

	/* Load the EC private key from storage */
	retval = load_ecdsa_privkey(&privkey, &privkeysize);
	if (retval) {
		LOG(LOG_ERROR, "No valid EC private key present\n");
		goto end;
	}

#if !defined(ECDSA_PEM)

	// Load private key from buffer to mbedtls mpi
	if ((retval = mbedtls_mpi_read_binary(&d, privkey, (int)privkeysize)) !=
	    0) {
		LOG(LOG_ERROR,
		    "Reading private key from buf to mbedtls structure:%d\n",
		    retval);
		goto end;
	}
	ctx_sign.d = d;
#else // use ecdsa pem file
	mbedtls_pk_init(&pk_ctx);

	// parse key api expect NULL char at the end
	retval = mbedtls_pk_parse_key(&pk_ctx, privkey, privkeysize, NULL, 0);
	if (retval != 0) {
		LOG(LOG_ERROR, "Parsing key from buf failed:%d\n", retval);
		goto end;
	}

	/* From the EC keypair, get the private key */
	ecp = mbedtls_pk_ec(pk_ctx);
	if (ecp == NULL ||
	    (retval = mbedtls_mpi_copy(&(ctx_sign.d),
				       (const mbedtls_mpi *)&(ecp->d))) != 0)
		goto end;
#endif

	// Generate Signature
	if ((retval = mbedtls_ecdsa_write_signature(
		 &ctx_sign, hashType, hash, hashLength, messageSignature,
		 (size_t *)signatureLength, mbedtls_ctr_drbg_random,
		 drbg_ctx)) != 0) {
		LOG(LOG_ERROR, "signature creation failed ret:%d\n", retval);
		goto end;
	}

	ret = 0;

end:
	mbedtls_ecdsa_free(&ctx_sign);
#if defined(ECDSA_PEM)
	mbedtls_pk_free(&pk_ctx);
#endif
	if (privkey) {
		if (memset_s(privkey, privkeysize, 0) != 0)
			LOG(LOG_ERROR, "Memset Failed\n");
		sdoFree(privkey);
	}
	return ret;
}
