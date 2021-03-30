/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for RSA encryption routines of openssl library.
 */

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include "BN_support.h"
#include "fdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"

/* An Example Public Key
 * Formats are described in the FDO documentation, but here is a public key
encoded with the RSAMODEXP format:

["0228", # length in bytes
  4, # message type = persisted public key
  5, # version = 0.5
  # public key object
  [   1, # algorithm = RSA
      3, # encoding = RSAMODENC
      [   257, # modulus length in bytes, followed by modulus in base64
	 "00a293ae46ca4e532c5abe7e173cb0fa91a12eee06ea355b2a785d654401bfe7d13b97d5bbce977788a701c038032ea5b30f6892fa343205bdeda3eb5516e7782e44bbdfe9eafe3cce65b0d2d92dbbc879483506fb355ad35f8b2f48d53ac44e39d05ad51d816b44e36704eae9dd631a392de7147d0a512c489e9d36fdf98230972247618f833c6cb7cae01688be27ab827c75554425b42787c80fa4937a2e80bd0ca1c1759c6f18d59b68a4833f266911fbaf536c9b1e527b6da2332daa288e9c3bb06f42d2324419404b596582968d513d2b04c9e77dd6abf90ffcdf25bea063164dbf70385d706f9c20afcf5a103135986fa444076354bcdefcc86b0c763adf",
	 3, # exponent length in bytes, followed by exponent in hex
	 "010001"
      ]
  ] #end public key
] #end persisted message

 */

/* **************************************************************************/
/*  CONVERT2PKEY */
/*  Convert a public key into an OpenSSL PKEY for use by the libcrypto */
/* routines */
/*  PURPOSE: Convert a public key into an OpenSSL key */

/*  REQUIRE: An public key in FDOPublic_key structure */
/*           A pointer to a PKEY structure, which will be allocated by this */
/* routine */
/*           using OpenSSL's EVP_PKEY alloc and free functions */

/*  PROMISE: if FDOPublic_key is a valid RSA public key in version 0.5  */
/* structure in RSAMODENC */
/*           this routine will take the modulus and public key and format  */
/* them into a PKEY structure */

/*  RESULT: Return 0 with the modulus and exponent placed into a the PKEY */
/* structure in the "out" parameter */
/*          or return -1 on failure */
/***************************************************************************/
static int convert2pkey(EVP_PKEY **out, RSA **rsa_in, const uint8_t *key1,
			uint32_t key_param1Length1, const uint8_t *key2,
			uint32_t key_param1Length2)
{
	RSA *rsa = NULL;

	if (!out || key1 == NULL || key2 == NULL) {
		return -1;
	}

	if (*out != NULL) {
		EVP_PKEY_free(*out);
		*out = NULL;
	}

	if (*rsa_in != NULL) {
		RSA_free(*rsa_in); /* deep free of all rsa elements */
	}

	*rsa_in = RSA_new();
	rsa = *rsa_in;

	*out = EVP_PKEY_new();
	if (*out == NULL) {
		return -1;
	}

	BIGNUM * n = NULL;
	BIGNUM *d = NULL;
	BIGNUM *e = NULL;
	BIGNUM *p = NULL;
	BIGNUM *q = NULL;
	BIGNUM *dmp1 = NULL;
	BIGNUM *dmq1 = NULL;
	BIGNUM *iqmp = NULL;

	/* We need the RSA components non-NULL. */
	if (rsa == NULL) {
		return -1;
	}
	n = BN_new();
	if (n == NULL) {
		goto err;
	}
	d = BN_new();
	if (d == NULL) {
		goto err;
	}
	e = BN_new();
	if (e == NULL) {
		goto err;
	}
	p = BN_new();
	if (p == NULL) {
		goto err;
	}
	q = BN_new();
	if (q == NULL) {
		goto err;
	}
	dmp1 = BN_new();
	if (dmp1 == NULL) {
		goto err;
	}
	dmq1 = BN_new();
	if (dmq1 == NULL) {
		goto err;
	}
	iqmp = BN_new();
	if (iqmp == NULL) {
		goto err;
	}
	/* Set verifier key's MODULUS. */
	if (BN_bin2bn((const unsigned char *)key1, key_param1Length1, n) ==
	    NULL) {
		goto err;
	}

	/* Set verifier key's EXPONENT. */
	if (BN_bin2bn((const unsigned char *)key2, key_param1Length2, e) ==
	    NULL) {
		goto err;
	}

	if (0 == RSA_set0_key(rsa, n, e, d) ||
	    0 == RSA_set0_factors(rsa, p, q) ||
	    0 == RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp))
		goto err;

	if (!EVP_PKEY_set1_RSA(*out, rsa))
		goto err;

	return 0;
err:
	// no null check here as lib has it
	BN_clear_free(n);
	BN_clear_free(d);
	BN_clear_free(e);
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(dmp1);
	BN_clear_free(dmq1);
	BN_clear_free(iqmp);
	return -1;
}

/**
 * fdo_cryptoRSAVerify
 * Verify an RSA PKCS v1.5 Signature using provided public key
 * @param key_encoding - RSA Key encoding typee.
 * @param key_algorithm - RSA public key algorithm.
 * @param message - pointer of type uint8_t, holds the encoded message.
 * @param message_length - size of message, type size_t.
 * @param message_signature - pointer of type uint8_t, holds a valid
 *			PKCS v1.5 signature in big-endian format
 * @param signature_length - size of signature, type unsigned int.
 * @param key_param1 - pointer of type uint8_t, holds the public key1.
 * @param key_param1Length - size of public key1, type size_t.
 * @param key_param2 - pointer of type uint8_t,holds the public key2.
 * @param key_param2Length - size of public key2, type size_t
 * @return 0 if true, else -1.
 */
int32_t crypto_hal_sig_verify(uint8_t key_encoding, uint8_t key_algorithm,
			      const uint8_t *message, uint32_t message_length,
			      const uint8_t *message_signature,
			      uint32_t signature_length,
			      const uint8_t *key_param1,
			      uint32_t key_param1Length,
			      const uint8_t *key_param2,
			      uint32_t key_param2Length)
{
	int ret = 0;
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;
	uint8_t *hash = NULL;

	/* Make sure we have a valid key type. */
	if (key_encoding != FDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP ||
	    key_algorithm != FDO_CRYPTO_PUB_KEY_ALGO_RSA) {
		LOG(LOG_ERROR, "Incorrect key type.\n");
		ret = -1;
		goto end;
	}

	if (NULL == key_param1 || 0 == key_param1Length || NULL == key_param2 ||
	    0 == key_param2Length || NULL == message_signature ||
	    0 == signature_length || NULL == message || 0 == message_length) {
		LOG(LOG_ERROR, "Incorrect key type\n");
		return -1;
	}

	if (convert2pkey(&pkey, &rsa, key_param1, key_param1Length, key_param2,
			 key_param2Length) != 0) {
		LOG(LOG_ERROR, "Cannot convert public key to OpenSSL "
			       "EVP_PKEY.\n ");
		ret = -1;
		goto end;
	}

	/* Verify that the signature is appropriate length for the
	 * modulus of RSA key
	 */
	if (signature_length != (unsigned int)RSA_size(rsa)) {
		LOG(LOG_ERROR, "Wrong size signature\n");
		RSAerr(RSA_F_RSA_VERIFY_ASN1_OCTET_STRING,
		       RSA_R_WRONG_SIGNATURE_LENGTH);
		ret = -1;
		goto end;
	}

	/* Perform SHA-256 digest of the message */
	hash =
	    (unsigned char *)OPENSSL_malloc((unsigned int)SHA256_DIGEST_LENGTH);
	if (NULL == hash) {
		ret = -1;
		goto end;
	}
	if (SHA256((const unsigned char *)message, message_length, hash) ==
	    NULL) {
		ret = -1;
		goto end;
	}

	if (1 != RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
			    message_signature, signature_length, rsa)) {
		ret = -1;
	}
end:

	if (hash != NULL) {
		OPENSSL_cleanse(hash, (unsigned int)SHA256_DIGEST_LENGTH);
		OPENSSL_free(hash);
	}
	if (rsa)
		RSA_free(rsa);
	if (pkey)
		EVP_PKEY_free(pkey);

	return ret;
}
