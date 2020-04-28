/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __BASE64_H__
#define __BASE64_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/**
 * Computes length of base64 output given binary input.
 * @param bin_length length of binary data.
 * @return number of bytes of binary data this will convert into
 */
int bin_toB64Length(int bin_length);

/**
 * Computes length of binary output given base64 input.
 * Actual output depends on the number of '=' at the end of the input stream.
 * @param b64Len length of b64 data, will be rounded down to a mulitple of 4.
 * @return number of bytes of binary data this will convert into
 */
int b64To_bin_length(int b64Len);

/**
 * Converts binary to base64.
 * @param bin_bytes binary input
 * @param offset offset of bin_bytes to first input byte
 * @param length number of binary input bytes
 * @param b64Bytes output bytes, should be at least
 * b64Offset+bin_toB64Length(length) bytes
 * @param b64Offset offset into output array
 * @return number of bytes in b64 representation
 */
int bin_toB64(size_t length, uint8_t *bin_bytes, size_t offset, size_t b64Len,
	      uint8_t *b64Bytes, size_t b64Offset);
/**
 * Convert base64 input into binary output.
 * The output buffer may exactly overlap the input buffer, to achieve in-place
 * conversion.
 * Output buffer must be at least bin_offset+bin_toB64(...) bytes long.
 * @param length number of base64 input bytes
 * @param b64bytes base64 variable length input array
 * @param offset offset to first byte of base64 input
 * @param bin_len length of the binary output buffer
 * @param bin_bytes veriable length output buffer.  Compute length with
 * b64To_bin_length
 * @param bin_offset offset into output buffer
 * @return length of binary output
 */
int b64To_bin(size_t length, uint8_t *b64bytes, size_t offset, size_t bin_len,
	      uint8_t *bin_bytes, size_t bin_offset);

#endif /* __BASE64_H__ */
