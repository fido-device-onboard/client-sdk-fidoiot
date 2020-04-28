/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Base64 encoding/decoding utilities.
 */

#include "base64.h"
#include "mbedtls/base64.h"
/**
 * Computes length of base64 output given binary input.
 * @param bin_length length of binary data.
 * @return number of bytes of binary data this will convert into
 */
int bin_toB64Length(int bin_length)
{
	/* Base64 length is ceil(4*(n/3)). */
	if (bin_length)
		return (((bin_length + 2) / 3) * 4);
	else
		return 0;
}

/**
 * Computes length of binary output given base64 input.
 * Actual output depends on the number of '=' at the end of the input stream.
 * This API would return the maximum probable buffer size.
 * @param b64Len length of b64 data, will be rounded down to a mulitple of 4.
 * @return number of bytes of binary data this will convert into
 */
int b64To_bin_length(int b64Len)
{
	if (b64Len)
		return ((b64Len / 4) * 3 + 2);
	else
		return 0;
}

/**
 * Converts binary to base64.
 * This routine does NOT put a zero at the end, do not assume the result is a
 * string
 * @param bin_length number of binary input bytes
 * @param bin_bytes binary input
 * @param bin_offset offset of bin_bytes to first input byte
 * @param b64Len number of free bytes in the buffer
 * @param b64Bytes output bytes, should be at least
 * b64Offset+bin_toB64Length(length) bytes
 * @param b64Offset offset into output array
 * @return number of bytes in b64 representation
 */
int bin_toB64(size_t bin_length, uint8_t *bin_bytes, size_t bin_offset,
	      size_t b64Len, uint8_t *b64Bytes, size_t b64Offset)
{
	size_t b64OLen = 0;
	(void)bin_offset;

	(void)bin_offset; /* Unused Warning */

	if (!bin_length || !bin_bytes || !b64Bytes) {
		return -1;
	}

	int ret = mbedtls_base64_encode(&b64Bytes[b64Offset], b64Len, &b64OLen,
					bin_bytes, bin_length);

	if (ret == 0) {
		if (b64OLen)
			return b64OLen;
		else
			return -1;
	} else
		return -1;
}

/**
 * Convert base64 input into binary output.
 * The output buffer may exactly overlap the input buffer, to achieve in-place
 * conversion.
 * Output buffer must be at least bin_offset+bin_toB64(...) bytes long.
 * @param b64Len number of base64 input bytes
 * @param b64bytes base64 input
 * @param b64Offset offset to first byte of base64 input
 * @param bin_len number of binary output buffer bytes
 * @param bin_bytes output buffer.  Compute length with b64To_bin_length
 * @param bin_offset offset into output buffer
 * @return length of binary output, -1 if the base64 string is invalid.
 */
int b64To_bin(size_t b64Len, uint8_t *b64bytes, size_t b64Offset,
	      size_t bin_len, uint8_t *bin_bytes, size_t bin_offset)
{
	size_t binOLen = 0;
	int ret = -1;
	size_t b64Len_check = b64Len;

	if (!bin_len || !bin_bytes || !b64bytes) {
		return -1;
	}

	b64Len_check &= (size_t)(~3); // must be multiple of 4 bytes
	if (b64Len_check == 0) {
		return 0;
	}

	ret = mbedtls_base64_decode(&bin_bytes[bin_offset], bin_len, &binOLen,
				    &b64bytes[b64Offset], b64Len);
	if (ret == 0 && binOLen != 0)
		return binOLen;
	else
		return -1;
}
