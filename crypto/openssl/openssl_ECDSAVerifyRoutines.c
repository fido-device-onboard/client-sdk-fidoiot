/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for ECDSA signature verification
 * \ APIs of openssl library.
 */

#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include "fdoCryptoHal.h"
#include "util.h"
#include "storage_al.h"
#include "safe_lib.h"

/**
 * Verify an ECC P-256/P-384 signature using provided ECDSA Public Keys.
 * @param key_encoding - encoding typee.
 * @param key_algorithm - public key algorithm.
 * @param message - pointer of type uint8_t, holds the encoded message.
 * @param message_length - size of message, type size_t.
 * @param message_signature - pointer of type uint8_t, holds a valid
 *			ecdsa signature in big-endian format
 * @param signature_length - size of signature, type unsigned int.
 * @param key_param1 - pointer of type uint8_t, holds the public key.
 * @param key_param1Length - size of public key, type size_t.
 * @param key_param2 - not used.
 * @param key_param2Length - not used
 * @return 0 if true, else -1.

*/
int32_t crypto_hal_sig_verify(uint8_t key_encoding, int key_algorithm,
		const uint8_t *message, uint32_t message_length,
		const uint8_t *message_signature,
		uint32_t signature_length,
		const uint8_t *key_param1,
		uint32_t key_param1Length,
		const uint8_t *key_param2,
		uint32_t key_param2Length)
{
	int32_t ret = -1;
	EVP_PKEY *eckey = NULL;
	EVP_PKEY_CTX *evp_ctx = NULL;
	EVP_MD_CTX *mdctx = NULL;
	uint32_t group_name_nid;
	const unsigned char *pub_key = (const unsigned char *)key_param1;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	uint32_t der_sig_len = 0;
	uint8_t * der_sig = NULL;
	ECDSA_SIG *sig = NULL;

	/* Check validity of key type. */
	// Only COSEKEY and X509 are currently supported
	if ((key_encoding != FDO_CRYPTO_PUB_KEY_ENCODING_X509 &&
				key_encoding != FDO_CRYPTO_PUB_KEY_ENCODING_COSEKEY) ||
			(key_algorithm != FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256 &&
			 key_algorithm != FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384)) {
		LOG(LOG_ERROR, "Incorrect key type\n");
		goto end;
	}

	if (NULL == message_signature || 0 == signature_length ||
			0 != (signature_length % 2) ||
			NULL == message || 0 == message_length) {
		LOG(LOG_ERROR, "Invalid arguments!\n");
		goto end;
	}

	if (key_encoding == FDO_CRYPTO_PUB_KEY_ENCODING_X509) {

		if (NULL == pub_key || 0 == key_param1Length) {
			LOG(LOG_ERROR, "Invalid params!\n");
			goto end;
		}
		/* Unused parameter */
		(void)key_param2;
		(void)key_param2Length;

		/* decode EC_KEY struct from DER encoded EC public key */
		if (d2i_PUBKEY(&eckey, &pub_key, (long)key_param1Length) == NULL) {
			LOG(LOG_ERROR, "DER to EC_KEY struct decoding failed!\n");
			goto end;
		}
	} else if (key_encoding == FDO_CRYPTO_PUB_KEY_ENCODING_COSEKEY) {
		/* generate required EC_KEY based on type */
		if (key_algorithm == FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256) {
			group_name_nid = NID_X9_62_prime256v1;
		}
		else { // P-384
			group_name_nid = NID_secp384r1;
		}
		const char* group_name = OBJ_nid2sn(group_name_nid);
		evp_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if (!evp_ctx) {
			LOG(LOG_ERROR, "Failed to create evp ctx context \n");
			goto end;
		}

		if (NULL == key_param1 || 0 == key_param1Length ||
				NULL == key_param2 || 0 == key_param2Length) {
			LOG(LOG_ERROR, "Invalid params!\n");
			goto end;
		}
		/* decode EC_KEY struct using Affine X and Y co-ordinates */
		x = BN_bin2bn((const unsigned char*) key_param1, key_param1Length, NULL);
		y = BN_bin2bn((const unsigned char*) key_param2, key_param2Length, NULL);
		if (!x || !y) {
			LOG(LOG_ERROR, "Failed to convert affine-x and/or affine-y\n");
			goto end;
		}
		OSSL_PARAM params[] = {
			OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, &x, sizeof(x)),
			OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, &y, sizeof(y)),
			OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group_name, strlen(group_name)),
			OSSL_PARAM_END
		};
		if(EVP_PKEY_fromdata_init(evp_ctx) <= 0 ||
				EVP_PKEY_fromdata(evp_ctx, &eckey, EVP_PKEY_KEYPAIR, params) <= 0) {
			LOG(LOG_ERROR, "Failed to create EC Key from affine-x and affine-y!\n");
			goto end;
		}
	}

	if(!(mdctx = EVP_MD_CTX_create())) {
		LOG(LOG_ERROR, "Msg Digest init failed \n");
		goto end;
	}
	if (key_algorithm == FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256) {
		if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, eckey)){
			LOG(LOG_ERROR, "EVP verify init failed \n");
			goto end;
		}
	}
	else {
		if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha384(), NULL, eckey)){
			LOG(LOG_ERROR, "EVP verify init failed \n");
			goto end;
		}
	}

	if(1 != EVP_DigestVerifyUpdate(mdctx, message, message_length)) {
		LOG(LOG_ERROR, "EVP verify update failed \n");
		goto end;
	}

	// Convert the raw signature to DER encoded format
	sig = ECDSA_SIG_new();
	BIGNUM *r = BN_bin2bn(message_signature, signature_length/2, NULL);
	BIGNUM *s = BN_bin2bn(message_signature + signature_length/2, signature_length/2, NULL);
	if (!sig || !r || !s || (1 != ECDSA_SIG_set0(sig, r, s))) {
		LOG(LOG_ERROR, "Failure in parsing the signature \n");
		goto end;
	}
	der_sig_len = i2d_ECDSA_SIG(sig, NULL);
	if (!der_sig_len) {
		LOG(LOG_ERROR, "Failure in format conversion of signature \n");
		goto end;
	}
	der_sig_len = i2d_ECDSA_SIG(sig, &der_sig);
	if (!der_sig_len || !der_sig) {
		LOG(LOG_ERROR, "Failure in format conversion of signature \n");
		goto end;
	}

	if(1 != EVP_DigestVerifyFinal(mdctx, der_sig, der_sig_len)) {
		LOG(LOG_ERROR, "ECDSA Sig verification failed\n");
		goto end;
	}
	ret = 0;

end:
	if (eckey) {
		EVP_PKEY_free(eckey);
		eckey = NULL;
	}
	if (evp_ctx) {
		EVP_PKEY_CTX_free(evp_ctx);
		evp_ctx = NULL;
	}
	if (mdctx) {
		EVP_MD_CTX_free(mdctx);
		mdctx = NULL;
	}
	if (x) {
		BN_free(x);
	}
	if (y) {
		BN_free(y);
	}
	if (sig) {
		ECDSA_SIG_free(sig);
	}
	if (der_sig) {
		fdo_free(der_sig);
	}
	return ret;
}
