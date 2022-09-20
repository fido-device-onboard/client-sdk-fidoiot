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
#include <openssl/core_names.h>
#include "fdotypes.h"
#include "storage_al.h"
#include "util.h"
#include "ec_key.h"
#include "ecdsa_privkey.h"
#include "safe_lib.h"

#ifdef ECDSA_PEM
EVP_PKEY *get_evp_key(void)
{
	int ret = -1;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;
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

err:
	/* At this point ret is already 0 */
	if (privkey) {
		if (memset_s(privkey, privkey_size, 0)) {
			LOG(LOG_ERROR, "clearing ecdsa privkey failed\n");
			ret = -1; /* Mark as fail */
		}
		fdo_free(privkey);
	}
	if (ecprivkey_evp && ret) {
		EVP_PKEY_free(ecprivkey_evp);
		ecprivkey_evp = NULL;
	}
	if (ecprivkey_bio) {
		BIO_free(ecprivkey_bio);
	}
	return ecprivkey_evp;
}
#else
EVP_PKEY *get_evp_key(void)
{
	int ret = 0;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;
	int32_t curve = NID_X9_62_prime256v1;
	EVP_PKEY *evp_key_ec = NULL;
	EVP_PKEY_CTX *evp_ctx = NULL;

#ifdef ECDSA384_DA
	curve = NID_secp384r1;
#endif

	/* Get the private key from storage */
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	if (ret) {
		LOG(LOG_ERROR, "Failed to load ec private key from memory\n");
		goto err;
	}

    evp_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!evp_ctx) {
		LOG(LOG_ERROR, "Failed to create evp ctx context \n");
		goto err;
	}

	const char* group_name = OBJ_nid2sn(curve);
	OSSL_PARAM params[] = { OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, privkey, privkey_size),
							OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group_name, strlen(group_name)),
								  OSSL_PARAM_END 
								  };
    if (EVP_PKEY_fromdata_init(evp_ctx) <=0) {
		LOG(LOG_ERROR, "Failed to init the ec key from data object\n");
		goto err;
    	}

		if ( EVP_PKEY_fromdata(evp_ctx,&evp_key_ec,EVP_PKEY_KEYPAIR, params) <=0) {
		LOG(LOG_ERROR, "Failed to create the ec key from data\n");// %s", (char *)params2);
		goto err;
    	}
        ret = 1; // success

err:
	if (evp_ctx) {
		EVP_PKEY_CTX_free(evp_ctx);
		evp_ctx = NULL;
		}
	if (privkey) {
		if (memset_s(privkey, privkey_size, 0) != 0) {
			LOG(LOG_ERROR, "Memset Failed\n");
			ret = 0; /* Mark as fail */
		}
		fdo_free(privkey);
	}
	if (evp_key_ec && !ret) {
		EVP_PKEY_free(evp_key_ec);
		evp_key_ec = NULL;
	}
	return evp_key_ec;
}
#endif
