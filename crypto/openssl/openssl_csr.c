/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements CSR generation for ECDSA
 */

#include <openssl/ec.h>
#include <openssl/x509.h>

#include "fdotypes.h"
#include "util.h"
#include "safe_lib.h"
#include "ec_key.h"
#include "fdocred.h"
#include "fdoCryptoHal.h"

/**
 * crypto_hal_get_device_csr() - get the device CSR
 */
int32_t crypto_hal_get_device_csr(fdo_byte_array_t **csr)
{
	int ret = -1;
	uint8_t *csr_data = NULL;
	size_t csr_size = 0;
	EC_KEY *ec_key = NULL;

	const EC_GROUP *ec_grp = NULL;
	BIO *csr_mem_bio = NULL;
	EC_POINT *pub_key = NULL;

	const BIGNUM *privkey_bn = NULL;
	X509_NAME *x509_name = NULL;
	EVP_PKEY *ec_pkey = EVP_PKEY_new();
	X509_REQ *x509_req = X509_REQ_new();
	fdo_byte_array_t *csr_byte_arr = NULL;

	if (!ec_pkey || !x509_req) {
		ret = -1;
		goto err;
	}

	/* Get the EC private key from storage */
	ec_key = get_ec_key();
	if (!ec_key) {
		LOG(LOG_ERROR, "Failed to load the ec key for CSR\n");
		ret = -1;
		goto err;
	}

	/*
	 * Generate the EC public key
	 * a. Get the EC group
	 * b. Generate a new point
	 * c. Create the public key
	 */
	ec_grp = EC_KEY_get0_group(ec_key);
	if (!ec_grp) {
		LOG(LOG_ERROR, "Failed to create a group on ec curve\n");
		ret = -1;
		goto err;
	}

	pub_key = EC_POINT_new(ec_grp);
	if (!pub_key) {
		LOG(LOG_ERROR, "Failed to generate a point on curve\n");
		ret = -1;
		goto err;
	}

	privkey_bn = EC_KEY_get0_private_key(ec_key);
	if (!privkey_bn) {
		LOG(LOG_ERROR, "Failed to get private key bn\n");
		ret = -1;
		goto err;
	}

	ret = EC_POINT_mul(ec_grp, pub_key, privkey_bn, NULL, NULL, NULL);
	if (!ret) {
		LOG(LOG_ERROR, "Failed to generate public key\n");
		ret = -1;
		goto err;
	}

	/* Set the ec_key instance with both public/private key */
	ret = EC_KEY_set_public_key(ec_key, pub_key);
	if (!ret) {
		LOG(LOG_ERROR, "Failed to set the public key\n");
		ret = -1;
		goto err;
	}

	/* Fill in the the data associated with this device */
	x509_name = X509_REQ_get_subject_name(x509_req);
	if (!x509_name) {
		LOG(LOG_ERROR, "Failed to get the name info from x509 req\n");
		ret = -1;
		goto err;
	}

	if (!X509_NAME_add_entry_by_NID(x509_name, NID_countryName,
					MBSTRING_ASC, (unsigned char *)"IN", -1,
					-1, 0) ||
	    !X509_NAME_add_entry_by_NID(x509_name, NID_commonName, MBSTRING_ASC,
					(unsigned char *)"fdo", -1, -1, 0) ||
	    !X509_NAME_add_entry_by_NID(x509_name, NID_localityName,
					MBSTRING_ASC, (unsigned char *)"Blr",
					-1, -1, 0) ||
	    !X509_NAME_add_entry_by_NID(x509_name, NID_organizationName,
					MBSTRING_ASC, (unsigned char *)"Intel",
					-1, -1, 0)) {
		LOG(LOG_ERROR, "Failed to add name info into x509 csr req\n");
		ret = -1;
		goto err;
	}

	ret = EVP_PKEY_assign_EC_KEY(ec_pkey, ec_key);
	if (!ret) {
		LOG(LOG_ERROR, "Failed to get ec_key reference\n");
		ret = -1;
		goto err;
	}

	/* Set the public key on the CSR */
	ret = X509_REQ_set_pubkey(x509_req, ec_pkey);
	if (!ret) {
		LOG(LOG_ERROR, "Failed to set the public key in CSR\n");
		ret = -1;
		goto err;
	}

	/* Sign to generate the final CSR */
	ret = X509_REQ_sign(x509_req, ec_pkey, EVP_sha256());
	if (!ret) {
		LOG(LOG_ERROR, "Failed to generate CSR data\n");
		ret = -1;
		goto err;
	}

	/*
	 * Get the data in DER format.
	 * a. Create a memory bio
	 * b. Write the CSR in DER into memory bio
	 * c. Read the memory bio into buffer
	 */

	csr_mem_bio = BIO_new(BIO_s_mem());
	if (!csr_mem_bio) {
		LOG(LOG_ERROR, "Failed to create a BIO for DER CSR\n");
		ret = -1;
		goto err;
	}

	ret = i2d_X509_REQ_bio(csr_mem_bio, x509_req);
	if (!ret) {
		LOG(LOG_ERROR, "Failed to write CSR in DER format\n");
		ret = -1;
		goto err;
	}

	csr_size = BIO_get_mem_data(csr_mem_bio, &csr_data);
	if (!csr_size) {
		LOG(LOG_ERROR, "Failed to get the DER CSR data in buffer\n");
		ret = -1;
		goto err;
	}

	/* Allocate byte array to send back data to DI state machine */
	csr_byte_arr = fdo_byte_array_alloc(csr_size);
	if (!csr_byte_arr) {
		LOG(LOG_ERROR,
		    "Failed to allocate data for storing csr data\n");
		ret = -1;
		goto err;
	}

	ret = memcpy_s(csr_byte_arr->bytes, csr_size, csr_data, csr_size);
	if (ret) {
		LOG(LOG_ERROR, "Failed to copy csr data\n");
		ret = -1;
		goto err;
	}

	ret = 0;
err:
	if (csr_byte_arr && ret) {
		fdo_byte_array_free(csr_byte_arr);
		csr_byte_arr = NULL;
	}
	if (csr_mem_bio) {
		BIO_free(csr_mem_bio);
	}
	if (ec_pkey) {
		EVP_PKEY_free(ec_pkey);
		ec_key = NULL; // evp_pkey_free clears attached ec_key too
	}
	if (ec_key) {
		EC_KEY_free(ec_key);
	}
	if (pub_key) {
		EC_POINT_free(pub_key);
	}
	if (x509_req) {
		X509_REQ_free(x509_req);
	}
	*csr = csr_byte_arr;
	return ret;
}
