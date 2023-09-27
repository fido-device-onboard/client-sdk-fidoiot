/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief bignum format conversion utilities.
 */

#include "BN_support.h"
#include "fdo_crypto_hal.h"
#include <stdlib.h>
#include "safe_lib.h"
#include "util.h"

/**
 * Convert a FDOBits object to a bignum_t
 */
int byte_array_to_bn(bignum_t *bn, fdo_byte_array_t *in)
{

	if (in == NULL || bn == NULL) {
		return -1;
	}
	if (in->byte_sz == 0 || in->bytes == NULL) {
		return -1;
	}

	return bn_bin2bn(in->bytes, in->byte_sz, bn);
}

/**
 * Java does an odd thing when a bignum_t is converted to a byte array.  If the
 * top bit  of the resulting byte array is set they add a byte of zeros to the
 * top of the array.
 * We must do the same thing if we are to interwork with java
 */
fdo_byte_array_t *bn_to_byte_array(bignum_t *in)
{
	int len;
	fdo_byte_array_t *ba;

	if (in == NULL) {
		return NULL;
	}

	len = bn_num_bytes(in);
	ba = fdo_byte_array_alloc(len + 1);
	if (ba == NULL) {
		return NULL;
	}

	/* do the conversion*/
	if (bn_bn2bin(in, ba->bytes) == 0) {
		fdo_byte_array_free(ba);
		return NULL;
	}

	/*
	 * If upper bit, here in byte 0 due to bigendian ordering, is set, add a
	 * zero byte
	 */
	if (ba->bytes[0] & 0x80) {
		if (memmove_s(&ba->bytes[1], ba->byte_sz, ba->bytes, len) !=
		    0) {
			LOG(LOG_ERROR, "Memmove Failed\n");
			fdo_byte_array_free(ba);
			return NULL;
		}
		ba->bytes[0] = 0;
	} else {
		ba->byte_sz--;
	}

	return ba;
}

/**
 * Internal API
 * return 0 on success, -1 on error
 */
int bn_rand(bignum_t *rnd, int size)
{
	if (NULL == rnd) {
		return -1;
	}
	int ret = BN_rand(rnd, size * 8, false, -1);
	return (ret == 1) ? 0 : -1;
}
