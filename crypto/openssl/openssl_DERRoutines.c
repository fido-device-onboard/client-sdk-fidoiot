/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \ brief Abstraction layer for ECDSA signing routine using SE
 */

#include "sdoCryptoHal.h"
#include "util.h"
#include "storage_al.h"
#include "safe_lib.h"

/*
 * Helper API designed to convert the raw signature into DER format required by
 * SDO.
 * rawSig: input a 64 Byte r and s format signature.
 * messageSignature: outputs a DER encoded signature value
 * signatureLength: outputs the size of the signature after converting to DER
 * format.
 */
int32_t DEREncode(uint8_t *rawSig, size_t rawSigLength,
		  uint8_t *messageSignature, size_t *signatureLength)
{
	/* Encode */
	int ret = 0;
	BIGNUM *r = BN_new();
	BIGNUM *s = BN_new();
	ECDSA_SIG *sig = ECDSA_SIG_new();
	uint8_t *msg = (uint8_t *)messageSignature;

	if ((NULL == rawSig) || (BUFF_SIZE_64_BYTES != rawSigLength) ||
	    (NULL == messageSignature) || (NULL == signatureLength)) {
		ret = -1;
		goto err;
	}

	if ((NULL == sig) || (NULL == msg) || (NULL == r) || (NULL == s)) {
		ret = -1;
		goto err;
	}

	/* Read the binary and populate the BIGNUM r and s needed by openssl */
	if (NULL == BN_bin2bn(rawSig, BUFF_SIZE_32_BYTES, r)) {
		ret = -1;
		goto err;
	}
	if (NULL ==
	    BN_bin2bn(rawSig + BUFF_SIZE_32_BYTES, BUFF_SIZE_32_BYTES, s)) {
		ret = -1;
		goto err;
	}

	/* This creates a ECDSA signature struct using the r and s values */
	if (0 == ECDSA_SIG_set0(sig, r, s)) {
		ret = -1;
		goto err;
	}

	/* Convert from an internal rep i.e r and S format to DER format */
	if (0 == i2d_ECDSA_SIG(sig, &msg)) {
		LOG(LOG_ERROR, "signature encoding to der failed!\n");
		ret = -1;
		goto err;
	}

	/* Return the length of the encoded DER signature  */
	*signatureLength = (size_t)i2d_ECDSA_SIG(sig, NULL);

err:
	/* Frees up sig, r and s variables */
	ECDSA_SIG_free(sig);

	return ret;
}

/*
 * This internal API is used to convert public key and signature which is in
 * DER format to raw format of r and s representation. This raw formatted
 * data will be of 64 Bytes which the SE can use to verify.
 * rawKey: output, returns the public key in 64 byte format of r and s.
 * rawSig: output, returns the signature in 64 byte format of r and s.
 * pubKey: input, the DER formatted public key that was received.
 * keyLength: input, the size of the DER formatted public key.
 * messageSignature: input, the DER formatted signature that was received
 * signatureLength: input, the length of signature in bytes that was received.
 * rawKeyLength: input, the buffer size of the rawKey
 */
int32_t DERDecode(uint8_t *rawKey, uint8_t *rawSig, const unsigned char *pubKey,
		  size_t keyLength, const uint8_t *messageSignature,
		  size_t signatureLength, size_t rawKeyLength,
		  size_t rawSigLength)
{
	size_t buff_size;
	int ret = 0;
	/* bn_ctx is a temp var needed for only some openssl internal operations
	 */
	BN_CTX *bn_ctx = BN_CTX_new();
	uint8_t *local_raw_key;
	EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	const BIGNUM *r = BN_new();
	const BIGNUM *s = BN_new();
	ECDSA_SIG *sig = ECDSA_SIG_new();
	const EC_GROUP *ecgroup;
	const EC_POINT *ecpoint;

	if ((NULL == rawKey) || (NULL == rawSig) || (NULL == pubKey) ||
	    (NULL == messageSignature) ||
	    (BUFF_SIZE_64_BYTES != rawSigLength) ||
	    (BUFF_SIZE_64_BYTES != rawKeyLength)) {
		ret = -1;
		goto err;
	}

	if ((NULL == bn_ctx) || (NULL == eckey) || (NULL == r) || (NULL == s) ||
	    (NULL == sig)) {
		ret = -1;
		goto err;
	}

	/* decode EC_KEY struct from DER encoded EC public key */
	if (d2i_EC_PUBKEY(&eckey, &pubKey, (long)keyLength) == NULL) {
		LOG(LOG_ERROR, "DER to EC_KEY struct decoding failed!\n");
		ret = -1;
		goto err;
	}
	ecgroup = EC_KEY_get0_group(eckey);
	ecpoint = EC_KEY_get0_public_key(eckey);
	if ((NULL == ecgroup) || (NULL == ecpoint)) {
		ret = -1;
		goto err;
	}

	/* This will get the r and s values from the DER formated public key
	 * into a buffer */
	buff_size =
	    EC_POINT_point2buf(ecgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED,
			       &local_raw_key, bn_ctx);

	if (0 == buff_size) {
		LOG(LOG_ERROR, "ecpoint to buffer write failed!\n");
		ret = -1;
		goto err;
	}

	/* local_raw_key is moved by one becuase the first byte will hold
	 * information
	 * regarding compressed/uncompressed format.
	 */
	if (0 != memcpy_s(rawKey, rawKeyLength, local_raw_key + 1, 64)) {
		ret = -1;
		goto err;
	}

	/* Decode  signature*/
	if (d2i_ECDSA_SIG(&sig, &messageSignature, signatureLength) == NULL) {
		LOG(LOG_ERROR, "DER to EC_KEY struct decoding failed!\n");
		ret = -1;
		goto err;
	}

	ECDSA_SIG_get0(sig, &r, &s);

	/* This will populate the rawSig with the r and s formatted data. */
	if (0 == BN_bn2bin(r, rawSig)) {
		ret = -1;
		goto err;
	}
	if (0 == BN_bn2bin(s, rawSig + 32)) {
		ret = -1;
		goto err;
	}

err:
	/* Cleanup */
	if (NULL != sig) {
		/* Frees up sig, r and s variables */
		ECDSA_SIG_free(sig);
	}
	EC_KEY_free(eckey);
	BN_CTX_free(bn_ctx);
	OPENSSL_free(local_raw_key);
	return ret;
}
