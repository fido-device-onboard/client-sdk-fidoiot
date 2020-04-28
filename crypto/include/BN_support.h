/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */
#ifndef __BNSUPPORT_H__
#define __BNSUPPORT_H__

#include "sdotypes.h"

#ifdef USE_OPENSSL
#include <openssl/bn.h>
#include <openssl/ssl.h>
#else
#include <mbedtls/dhm.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#endif

#ifdef USE_OPENSSL
typedef BIGNUM bignum_t;
#else
typedef mbedtls_mpi bignum_t;
typedef mbedtls_mpi BN_CTX;
#endif

int bn_rand(bignum_t *rnd, int size);
int byte_array_to_bn(bignum_t *bn, sdo_byte_array_t *in);
sdo_byte_array_t *bn_to_byte_array(bignum_t *in);

#ifdef USE_MBEDTLS
static inline int bn_bin2bn(const unsigned char *s, int len, bignum_t *bn)
{
	return mbedtls_mpi_read_binary(bn, s, len);
}

static inline int bn_bn2bin(const bignum_t *a, unsigned char *to)
{
	int len = mbedtls_mpi_size(a);
	int ret = mbedtls_mpi_write_binary(a, to, len);

	if (ret != 0) {
		return 0;
	}
	return len;
}

/* Compute r = a^p mod m */
static inline int bn_mod_exp(bignum_t *r, bignum_t *a, const bignum_t *p,
			     const bignum_t *m, BN_CTX *ctx)
{
	return mbedtls_mpi_exp_mod(r, a, p, m, ctx);
}

static inline int bn_num_bytes(const bignum_t *a)
{
	return mbedtls_mpi_size(a);
}

#else

static inline int bn_bin2bn(const unsigned char *s, int len, bignum_t *bn)
{
	BIGNUM *ret = BN_bin2bn(s, len, bn);

	return (ret == bn) ? 0 : -1;
}

static inline int bn_bn2bin(const bignum_t *a, unsigned char *to)
{
	return BN_bn2bin(a, to);
}

/* Compute r = a^p mod m */
static inline int bn_mod_exp(bignum_t *r, bignum_t *a, const bignum_t *p,
			     const bignum_t *m, BN_CTX *ctx)
{
	int ret = BN_mod_exp(r, a, p, m, ctx);

	return (ret == 1) ? 0 : -1;
}

static inline int bn_num_bytes(const bignum_t *a)
{
	return BN_num_bytes(a);
}

#endif

#endif /* __BNSUPPORT_H__ */
