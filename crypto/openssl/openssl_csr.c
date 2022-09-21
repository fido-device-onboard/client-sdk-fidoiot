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
#include <openssl/core_names.h>

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
	EVP_PKEY *evp_key = NULL;
	size_t group_name_size;
	char group_name[64];
	size_t pub_key_size;
	fdo_byte_array_t* octet_pub_key = NULL;

	EC_GROUP *ec_grp = NULL;
	BIO *csr_mem_bio = NULL;
	EC_POINT *pub_key = NULL;

	BIGNUM *privkey_bn = NULL;
	X509_NAME *x509_name = NULL;
	X509_REQ *x509_req = X509_REQ_new();
	fdo_byte_array_t *csr_byte_arr = NULL;

	if (!x509_req) {
		ret = -1;
		goto err;
	}

	/* Get the EC private key from storage */
	evp_key = get_evp_key();
	if (!evp_key) {
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
	EVP_PKEY_get_utf8_string_param(evp_key, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, &group_name_size);
	if (group_name_size >= sizeof(group_name)) {
		LOG(LOG_ERROR, "Unexpected long group name : %zu for EC key\n",group_name_size);
		ret = -1;
		goto err;
	}
	if (!EVP_PKEY_get_utf8_string_param(evp_key, OSSL_PKEY_PARAM_GROUP_NAME, group_name, sizeof(group_name),
												&group_name_size))
	{
		LOG(LOG_ERROR, "Failed to get the group name fo EC EVP key\n");
		ret = -1;
		goto err;
	}
	int group_nid = OBJ_sn2nid(group_name);	
	ec_grp = EC_GROUP_new_by_curve_name(group_nid);
	if (ec_grp == NULL)
	{
		LOG(LOG_ERROR, "Failed to get the group name fo EC EVP key\n");
		ret = -1;
		goto err;
	}

	pub_key = EC_POINT_new(ec_grp);
	if (!pub_key) {
		LOG(LOG_ERROR, "Failed to generate a point on curve\n");
		ret = -1;
		goto err;
	}

	if (!EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_PRIV_KEY, &privkey_bn)) {
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
	
	pub_key_size = EC_POINT_point2oct(ec_grp, pub_key, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    octet_pub_key = fdo_byte_array_alloc(pub_key_size);
	if (!EC_POINT_point2oct(ec_grp, pub_key, POINT_CONVERSION_COMPRESSED, octet_pub_key->bytes,
		                       octet_pub_key->byte_sz, NULL)) {
		LOG(LOG_ERROR, "Failed to process public key\n");
		ret = -1;
		goto err;           
	}
    // Set the evp_key instance with public key
	if (!EVP_PKEY_set_octet_string_param(evp_key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, octet_pub_key->bytes,
		                                     octet_pub_key->byte_sz)) {
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

	/* Set the public key on the CSR */
	ret = X509_REQ_set_pubkey(x509_req, evp_key);
	if (!ret) {
		LOG(LOG_ERROR, "Failed to set the public key in CSR\n");
		ret = -1;
		goto err;
	}

	/* Sign to generate the final CSR */
	ret = X509_REQ_sign(x509_req, evp_key, EVP_sha256());
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
	if (evp_key) {
		EVP_PKEY_free(evp_key);
	}
	if (pub_key) {
		EC_POINT_free(pub_key);
	}
	if (ec_grp) {
		EC_GROUP_free(ec_grp);
		}
	if (octet_pub_key) {
		fdo_byte_array_free(octet_pub_key);
		}
	if (privkey_bn) {
		BN_clear_free(privkey_bn);
		}
	if (x509_req) {
		X509_REQ_free(x509_req);
	}
	*csr = csr_byte_arr;
	return ret;
}
