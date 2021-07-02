/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file returns an EC_KEY * of ECDSA private key from storage
 */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "fdotypes.h"
#include "storage_al.h"
#include "util.h"
#include "ec_key.h"
#include "ecdsa_privkey.h"
#include "safe_lib.h"

#ifdef ECDSA_PEM
EC_KEY *get_ec_key(void)
{
	int ret = -1;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;
	EC_KEY *ec_key = NULL;
	BIO *ecprivkey_bio = NULL;
	EVP_PKEY *ecprivkey_evp = NULL;

	/* Get the private key from storage */
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	if (ret) {
		LOG(LOG_ERROR, "Failed to load ec private key from memory\n");
		goto err;
	}

	/*
	 * Prepare the private key from the buffer. PEM key comes as
	 * NULL terminated, so, the API will take care internally
	 */
	ecprivkey_bio = BIO_new_mem_buf(privkey, -1);
	if (!ecprivkey_bio) {
		LOG(LOG_ERROR, "Failed to load ec key\n");
		goto err;
	}

	ecprivkey_evp = EVP_PKEY_new();
	if (ecprivkey_evp == NULL) {
		LOG(LOG_ERROR, "New PKEY Alloc failed!\n");
		goto err;
	}

	if (PEM_read_bio_PrivateKey(ecprivkey_bio, &ecprivkey_evp, NULL,
				    NULL) == NULL) {
		LOG(LOG_ERROR, "EC_KEY read from bio failed!\n");
		goto err;
	}

	ec_key = EVP_PKEY_get1_EC_KEY(ecprivkey_evp);
	if (!ec_key) {
		LOG(LOG_ERROR, "Invalid EC key format\n");
		goto err;
	}

err:
	/* At this point ret is already 0 */
	if (privkey) {
		if (memset_s(privkey, privkey_size, 0)) {
			LOG(LOG_ERROR, "clearing ecdsa privkey failed\n");
			ret = -1; /* Mark as fail */
		}
		fdo_free(privkey);
	}
	if (ecprivkey_evp) {
		EVP_PKEY_free(ecprivkey_evp);
	}
	if (ecprivkey_bio) {
		BIO_free(ecprivkey_bio);
	}
	if (ec_key && ret) {
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	return ec_key;
}
#else
EC_KEY *get_ec_key(void)
{
	int ret = 0;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;
	EC_KEY *ec_key = NULL;
	BIGNUM *ec_key_bn = NULL;
	int32_t curve = NID_X9_62_prime256v1;

#ifdef ECDSA384_DA
	curve = NID_secp384r1;
#endif

	/* Get the private key from storage */
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	if (ret) {
		LOG(LOG_ERROR, "Failed to load ec private key from memory\n");
		goto err;
	}

	/* Load the key from memory into ec_key */
	ec_key_bn = BN_bin2bn(privkey, privkey_size, NULL);
	if (!ec_key_bn) {
		LOG(LOG_ERROR, "Failed to create eckey BN\n");
		goto err;
	}

	/* Create and initialize openssl EC private key */
	ec_key = EC_KEY_new_by_curve_name(curve);
	if (!ec_key) {
		LOG(LOG_ERROR, "Failed to allocate ec key\n");
		goto err;
	}

	ret = EC_KEY_set_private_key(ec_key, ec_key_bn);
	if (!ret) {
		LOG(LOG_ERROR, "Failed to set ec private key\n");
		goto err;
	}

err:
	if (privkey) {
		if (memset_s(privkey, privkey_size, 0) != 0) {
			LOG(LOG_ERROR, "Memset Failed\n");
			ret = 0; /* Mark as fail */
		}
		fdo_free(privkey);
	}
	if (ec_key && !ret) {
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	if (ec_key_bn) {
		BN_free(ec_key_bn);
	}

	return ec_key;
}
#endif
