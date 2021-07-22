/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements CSR generation for EC
 */

#include <mbedtls/pk.h>
#include <mbedtls/x509_csr.h>

#include "util.h"
#include "fdotypes.h"
#include "mbedtls_random.h"
#include "fdoCryptoHal.h"
#include "safe_lib.h"
#include "ecdsa_privkey.h"
#include "fdocred.h"

#define CSR_BUFFER_SIZE (4 * 1024)

static int f_rng(void *ctx, unsigned char *buf, size_t size)
{
	(void)ctx;
	return crypto_hal_random_bytes(buf, size);
}

/**
 * Internal API
 * Interface to get device CSR (certificate generated shall be used during
 * Device Attestation to RV/OWN server).
 * @return pointer to a byte_array holding a valid device CSR.
 */
int32_t crypto_hal_get_device_csr(fdo_byte_array_t **csr)
{
	int ret = -1;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;
	uint8_t *csr_buf = NULL;
	fdo_byte_array_t *pem_byte_arr = NULL;
	size_t pem_buf_size = 0;
	mbedtls_pk_context pk_ctx;
	mbedtls_x509write_csr csr_ctx;
	mbedtls_ecp_keypair *keypair = NULL;
	void *dbrg_ctx = get_mbedtls_random_ctx();
	mbedtls_md_type_t md_algo = MBEDTLS_MD_SHA256;
	mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_SECP256R1;
	/*
	 * FIXME: CN is generally URL which will be present in certificate.
	 * The below data should be unique for each CSR.
	 * What are the mandatory parameters for CSR? Check with credtool team
	 */
	const char *attr_list = "C=IN, CN=fdo, L=Blr, O=Intel";

	/* Initialize the key context for CSR */
	mbedtls_pk_init(&pk_ctx);

	/* Load the EC private key from storage */
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	if (!privkey) {
		LOG(LOG_ERROR, "Failed to load the EC private key\n");
		goto key_err;
	}

	/* Set the key type to ec key */
	ret = mbedtls_pk_setup(&pk_ctx,
			       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	if (ret) {
		LOG(LOG_ERROR, "Failed to setup pk context as ec key\n");
		goto key_err;
	}

	/* Get the access to private key of the keypair */
	keypair = mbedtls_pk_ec(pk_ctx);
	if (!keypair) {
		LOG(LOG_ERROR, "No EC private key context found\n");
		goto key_err;
	}

#ifdef ECDSA384_DA
	grp_id = MBEDTLS_ECP_DP_SECP384R1;
	md_algo = MBEDTLS_MD_SHA384;
#endif

	/* Load the EC group before reading data into the private point */
	ret = mbedtls_ecp_group_load(&keypair->grp, grp_id);
	if (ret) {
		LOG(LOG_ERROR, "Failed to load EC pair with the group id\n");
		goto key_err;
	}

#ifdef ECDSA_PEM
	ret = mbedtls_pk_parse_key(&pk_ctx, privkey, privkey_size, NULL, 0);
	if (ret) {
		LOG(LOG_ERROR, "Failed to parse EC (PEM) private key\n");
		goto key_err;
	}
#else
	/* Copy binary data into EC private member and ready to roll */
	ret = mbedtls_mpi_read_binary(&keypair->d, privkey, privkey_size);
	if (ret) {
		LOG(LOG_ERROR, "Failed to load binary data into EC priv ctx\n");
		goto key_err;
	}
#endif

	/* Fill the public key in the context */
	ret = mbedtls_ecp_mul(&keypair->grp, &keypair->Q, &keypair->d,
			      &keypair->grp.G, f_rng, dbrg_ctx);
	if (ret) {
		LOG(LOG_ERROR, "Failed to fill in public key\n");
		goto key_err;
	}

	/* Initialize the mbedTLS CSR context */
	mbedtls_x509write_csr_init(&csr_ctx);

	/* Set the subject name (fdo) and other information (C=xx, ...) */
	ret = mbedtls_x509write_csr_set_subject_name(&csr_ctx, attr_list);
	if (ret) {
		LOG(LOG_ERROR, "Failed to parse certificate attribute list\n");
		goto csr_err;
	}

	/* Set the key and algo on CSR context */
	mbedtls_x509write_csr_set_key(&csr_ctx, &pk_ctx);
	mbedtls_x509write_csr_set_md_alg(&csr_ctx, md_algo);

	/* TODO: What should be the max size of buf */
	csr_buf = fdo_alloc(CSR_BUFFER_SIZE);
	if (!csr_buf) {
		LOG(LOG_ERROR, "Failed to allocate memory for CSR\n");
		goto csr_err;
	}

	/* Generate CSR in PEM format */
	ret = mbedtls_x509write_csr_pem(&csr_ctx, csr_buf, CSR_BUFFER_SIZE,
					f_rng, dbrg_ctx);
	if (ret) {
		LOG(LOG_ERROR, "Failed to fill buffer with PEM CSR data\n");
		goto csr_err;
	}

	/* Allocate CSR byte array */
	pem_buf_size = strnlen_s((const char *)csr_buf, CSR_BUFFER_SIZE);
	if (!pem_buf_size || pem_buf_size == CSR_BUFFER_SIZE) {
		LOG(LOG_ERROR, "Memory corruption in CSR buffer\n");
		goto csr_err;
	}

	pem_byte_arr = fdo_byte_array_alloc(pem_buf_size);
	if (!pem_byte_arr) {
		LOG(LOG_ERROR, "Out of memory for CSR byte array\n");
		goto csr_err;
	}

	/* Fill the buffer with CSR */
	if (memcpy_s(pem_byte_arr->bytes, pem_buf_size, csr_buf,
		     pem_buf_size)) {
		LOG(LOG_ERROR, "Failed to copy pem data in byte array\n");
		goto csr_err;
	}

	ret = 0;

csr_err:
	if (privkey) {
		if (memset_s(privkey, privkey_size, 0)) {
			LOG(LOG_ERROR, "Failed to clear ecdsa privkey\n");
			ret = -1;
		}
		fdo_free(privkey);
	}
	if (pem_byte_arr && ret) {
		fdo_byte_array_free(pem_byte_arr);
		pem_byte_arr = NULL;
	}
	if (csr_buf)
		fdo_free(csr_buf);
	mbedtls_x509write_csr_free(&csr_ctx);
key_err:
	mbedtls_pk_free(&pk_ctx);
	*csr = pem_byte_arr;
	return ret;
}
