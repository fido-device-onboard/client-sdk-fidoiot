/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Base64 encoding/decoding utilities.
 */

#include "base64.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
/**
 * Computes length of base64 output given binary input.
 * @param binLength length of binary data.
 * @return number of bytes of binary data this will convert into
 */
int binToB64Length(int binLength)
{
	/* Base64 length is ceil(4*(n/3)). */
	if (binLength)
		return (((binLength + 2) / 3) * 4);
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
int b64ToBinLength(int b64Len)
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
 * @param binLength number of binary input bytes
 * @param binBytes binary input
 * @param binOffset offset of binBytes to first input byte
 * @param b64Len number of free bytes in the buffer
 * @param b64Bytes output bytes, should be at least
 * b64Offset+binToB64Length(length) bytes
 * @param b64Offset offset into output array
 * @return number of bytes in b64 representation, -1 on failures
 */
int binToB64(size_t binLength, uint8_t *binBytes, size_t binOffset,
	     size_t b64Len, uint8_t *b64Bytes, size_t b64Offset)
{
	int ret = -1;

	if (!binLength || !binBytes || !b64Bytes)
		return -1;

	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *bio = BIO_new(BIO_s_mem());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, bio);

	ret = BIO_write(b64, &binBytes[binOffset], (int)binLength);
	BIO_flush(b64);
	if (ret > 0) {
		ret = BIO_read(bio, &b64Bytes[b64Offset], (int)b64Len);
	}
	BIO_free_all(b64);

	if (ret <= 0)
		ret = -1;

	return ret;
}

/**
 * Convert base64 input into binary output.
 * The output buffer may exactly overlap the input buffer, to achieve in-place
 * conversion.
 * Output buffer must be at least binOffset+binToB64(...) bytes long.
 * @param b64Len number of base64 input bytes
 * @param b64bytes base64 input
 * @param b64Offset offset to first byte of base64 input
 * @param binLen number of binary output buffer bytes
 * @param binBytes output buffer.  Compute length with b64ToBinLength
 * @param binOffset offset into output buffer
 * @return length of binary output, -1 if the base64 string is invalid.
 */
int b64ToBin(size_t b64Len, uint8_t *b64bytes, size_t b64Offset, size_t binLen,
	     uint8_t *binBytes, size_t binOffset)
{
	int ret = -1;
	if (!binLen || !binBytes || !b64bytes)
		return -1;

	size_t b64LenCheck = b64Len;

	b64LenCheck &= (size_t)(~3); // must be multiple of 4 bytes
	if (b64LenCheck == 0) {
		return 0;
	}

	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *bio = BIO_new(BIO_s_mem());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, bio);

	ret = BIO_write(bio, &b64bytes[b64Offset], (int)b64Len);
	BIO_flush(bio);
	if (ret) {
		ret = BIO_read(b64, &binBytes[binOffset], (int)binLen);
	}

	BIO_free_all(b64);
	if (ret <= 0)
		ret = -1;

	return ret;
}
