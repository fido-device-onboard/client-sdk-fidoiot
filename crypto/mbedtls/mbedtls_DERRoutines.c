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
#include "mbedtls/asn1write.h"

#define BUFF_SIZE_65_BYTES 65

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
	int ret;
	mbedtls_mpi r, s;
	unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
	unsigned char *p = buf + sizeof(buf);
	size_t len = 0;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	if ((NULL == rawSig) || (BUFF_SIZE_64_BYTES != rawSigLength) ||
	    (NULL == messageSignature) || (NULL == signatureLength)) {
		ret = -1;
		goto err;
	}

	/* Encode */
	/* Read from the rawSig buffer into a MPI r and s needed by mbedtls */
	ret = mbedtls_mpi_read_binary(&r, rawSig, BUFF_SIZE_32_BYTES);
	ret |= mbedtls_mpi_read_binary(&s, (rawSig + BUFF_SIZE_32_BYTES),
				       BUFF_SIZE_32_BYTES);
	if (0 != ret) {
		LOG(LOG_ERROR, "failed at mpi write for signature \n");
		ret = -1;
		goto err;
	}

	if (0 > (ret = mbedtls_asn1_write_mpi(&p, buf, &s))) {
		LOG(LOG_ERROR,
		    "Unable to convert the raw signature into DER format");
		ret = -1;
		goto err;
	}
	len = ret;

	if (0 > (ret = mbedtls_asn1_write_mpi(&p, buf, &r))) {
		LOG(LOG_ERROR,
		    "Unable to convert the raw signature into DER format");
		ret = -1;
		goto err;
	}
	len += ret;

	if (0 > (ret = mbedtls_asn1_write_len(&p, buf, len))) {
		LOG(LOG_ERROR,
		    "Unable to convert the raw signature into DER format");
		ret = -1;
		goto err;
	}
	len += ret;

	if (0 >
	    (ret = mbedtls_asn1_write_tag(
		 &p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))) {
		LOG(LOG_ERROR,
		    "Unable to convert the raw signature into DER format");
		ret = -1;
		goto err;
	}
	len += ret;

	if (0 != memcpy_s(messageSignature, BUFF_SIZE_256_BYTES, p, len)) {
		LOG(LOG_ERROR, "Memcpy to messageSignature failed \n");
		ret = -1;
		goto err;
	}
	ret = 0;
	*signatureLength = len;

err:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
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
	int ret;
	mbedtls_pk_context pk_ctx = {0};
	size_t len;
	mbedtls_mpi r, s;
	const uint8_t *end = messageSignature + signatureLength;
	uint8_t *p = (unsigned char *)messageSignature;
	uint8_t *local_raw_key = NULL;
	uint8_t *end_buf;

	if ((NULL == rawKey) || (NULL == rawSig) || (NULL == pubKey) ||
	    (NULL == messageSignature) ||
	    (BUFF_SIZE_64_BYTES != rawSigLength) ||
	    (BUFF_SIZE_64_BYTES != rawKeyLength)) {
		ret = -1;
		goto err;
	}

	mbedtls_pk_init(&pk_ctx);

	if ((ret = mbedtls_pk_parse_public_key(&pk_ctx, pubKey,
					       (size_t)keyLength)) != 0) {

		LOG(LOG_ERROR, "Parsing EC public-key failed!\n");
		ret = -1;
		goto err;
	}

	/* one extra byte for compression information. */
	local_raw_key = (uint8_t *)sdoAlloc(BUFF_SIZE_65_BYTES);
	if (NULL == local_raw_key) {
		LOG(LOG_ERROR, "Allocation of buffer for raw key failed\n");
		ret = -1;
		goto err;
	}

	/* The mbedtls_pk_write_pubkey uses the buffer from the end of buffer */
	end_buf = local_raw_key + BUFF_SIZE_65_BYTES;

	/* public key converted */
	ret = mbedtls_pk_write_pubkey(&end_buf, local_raw_key, &pk_ctx);
	if ((BUFF_SIZE_64_BYTES + 1) != ret) {
		LOG(LOG_ERROR, "failed at mpi write for public key \n");
		ret = -1;
		goto err;
	}

	if (0 != memcpy_s(rawKey, rawKeyLength, local_raw_key + 1,
			  BUFF_SIZE_64_BYTES)) {
		ret = -1;
		goto err;
	}

	/* convert signature now */
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
					MBEDTLS_ASN1_CONSTRUCTED |
					    MBEDTLS_ASN1_SEQUENCE)) != 0) {
		LOG(LOG_ERROR, "failed at tag for  signature %d \n", ret);
		ret = -1;
		goto err;
	}

	ret = mbedtls_asn1_get_mpi(&p, end, &r);
	ret |= mbedtls_asn1_get_mpi(&p, end, &s);
	if (0 != ret) {
		LOG(LOG_ERROR, "failed at r and s for  signature %d \n", ret);
		ret = -1;
		goto err;
	}

	ret = mbedtls_mpi_write_binary(&r, rawSig, BUFF_SIZE_32_BYTES);
	ret |= mbedtls_mpi_write_binary(&s, (rawSig + BUFF_SIZE_32_BYTES),
					BUFF_SIZE_32_BYTES);
	if (0 != ret) {
		LOG(LOG_ERROR, "failed at mpi write for signature \n");
		ret = -1;
		goto err;
	}

err:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	if (0 != memset_s(local_raw_key, BUFF_SIZE_65_BYTES, 0)) {
		LOG(LOG_ERROR, "Memset for local raw key failed \n");
		ret = -1;
	}
	sdoFree(local_raw_key);
	mbedtls_pk_free(&pk_ctx);
	return ret;
}
