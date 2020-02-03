/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of low level JSON parsing(reading/writing) APIs.
 */

#include "sdoblockio.h"
#include "base64.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "safe_lib.h"
#include "snprintf_s.h"

#define SDO_TAG_MAX_LEN 32

/*
 * Internal function prototypes
 */
bool _readExpectedChar(SDOR_t *sdor, char expected);
bool _readComma(SDOR_t *sdor);
// bool _readExpectedCharNC(SDOR_t *sdor, char expected);
void _padstring(SDOW_t *sdow, const char *s, int len, bool escape);
void _writespecialchar(SDOW_t *sdow, char c);

// These are intended to be inlined...
int SDOBPeekc(SDOBlock_t *sdob);
int sdoBGetC(SDOBlock_t *sdob);
void sdoSkipC(SDOBlock_t *sdob);
void sdoBPutC(SDOBlock_t *sdob, char c);

int SDOBPeekc(SDOBlock_t *sdob)
{
	if ((NULL == sdob->block) || (sdob->cursor >= sdob->blockSize)) {
		return -1;
	}
	return sdob->block[sdob->cursor];
}

/**
 * Internal API
 */
int sdoBGetC(SDOBlock_t *sdob)
{
	if ((NULL == sdob->block) || (sdob->cursor >= sdob->blockSize)) {
		return -1;
	}
	return sdob->block[sdob->cursor++];
}

/**
 * Internal API
 */
void sdoSkipC(SDOBlock_t *sdob)
{
	if (sdob->cursor < sdob->blockSize)
		sdob->cursor++;
}

/**
 * Internal API
 */
void sdoBPutC(SDOBlock_t *sdob, char c)
{
	if (sdob->cursor >= sdob->blockMax)
		sdoResizeBlock(sdob, sdob->blockMax + 1);
	sdob->block[sdob->cursor++] = c;
}

/**
 * Internal API
 */
void sdoBlockInit(SDOBlock_t *sdob)
{
	if (sdob->block != NULL)
		sdoFree(sdob->block);
	sdob->block = NULL;
	sdob->blockMax = 0;
	sdoBlockReset(sdob);
}

/**
 * Internal API
 */
void sdoBlockReset(SDOBlock_t *sdob)
{
	if (sdob) {
		sdob->cursor = 0;
		sdob->blockSize = 0;
	}
}

#if 0 // deprecated
/**
 * Internal API
 */
int hexitToInt(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else {
		LOG(LOG_ERROR, "SDO: expected hex digit, got %c\n", c);
		return 0;
	}
}

/**
 * Internal API
 */
int intToHexit(int v)
{
	v &= 0xf;
	return v + (v <= 9 ? '0' : 'a' - 10);
}
#endif

/**
 * Internal API
 */
void sdoResizeBlock(SDOBlock_t *sdob, int need)
{
	if (need > sdob->blockMax) {
		int newSize = (need + SDO_BLOCKINC - 1) & SDO_BLOCK_MASK;
		sdob->block = realloc(sdob->block, newSize);
		sdob->blockMax = newSize;

		if (!sdob->block) {
			LOG(LOG_ERROR, "realloc failure at %s:%d\r\n", __FILE__,
			    __LINE__);
		}
	}
}

/**
 * Initialize SDO JSON packet reader engine
 *
 * @param sdor - Pointer of struct containing SDOR data structure,
 *
 * @param rcv - Pointer to function that can parse received file using SDOR(like
 *              sdoFILERecv).
 *
 * @param rcvData - Pointer to received file data.
 *
 * @return
 *        return 0 on success. -ve value on failure.
 */
bool sdoRInit(SDOR_t *sdor, SDOReceiveFcnPtr_t rcv, void *rcvData)
{
	if (memset_s(sdor, sizeof *sdor, 0) != 0) {
		LOG(LOG_ERROR, "SDOR memset() failed!\n");
		return false;
	}

	sdoBlockInit(&sdor->b);

	sdor->receive = rcv;
	sdor->receiveData = rcvData;
	sdor->haveBlock = false;

	return true;
}

/**
 * Internal API
 */
int sdoRPeek(SDOR_t *sdor)
{
	SDOBlock_t *sdob = &sdor->b;
	return SDOBPeekc(sdob);
}

/**
 * Internal API
 */
void sdoRFlush(SDOR_t *sdor)
{
	SDOBlock_t *sdob = &sdor->b;
	sdoBlockReset(sdob);
	sdor->needComma = false;
	sdor->haveBlock = false;
}

/**
 * Internal API
 */
bool sdoRHaveBlock(SDOR_t *sdor)
{
	return sdor->haveBlock;
}

/**
 * Internal API
 */
void sdoRSetHaveBlock(SDOR_t *sdor)
{
	sdor->haveBlock = true;
}

/**
 * Internal API
 */
bool sdoRNextBlock(SDOR_t *sdor, uint32_t *typep)
{
	if (!sdor->haveBlock)
		return false;

	*typep = sdor->msgType;
	//	sdoRBeginObject(sdor);
	return true;
}

/**
 * Internal API
 */
uint8_t *sdoRGetBlockPtr(SDOR_t *sdor, int fromCursor)
{
	if (fromCursor < 0)
		fromCursor = sdor->b.cursor;
	if (fromCursor > sdor->b.blockSize) {
		LOG(LOG_ERROR, "sdoRGetBlockPtr(%u) is too big\n", fromCursor);
		return NULL;
	}
	return &sdor->b.block[fromCursor];
}

/**
 * Internal API
 */
uint8_t *sdoWGetBlockPtr(SDOW_t *sdow, int fromCursor)
{
	if (fromCursor < 0)
		fromCursor = sdow->b.cursor;
	if (fromCursor > sdow->b.blockSize) {
		LOG(LOG_ERROR, "sdoWGetBlockPtr(%u) is too big\n", fromCursor);
		return NULL;
	}
	return &sdow->b.block[fromCursor];
}

/**
 * Internal API
 */
bool _readExpectedChar(SDOR_t *sdor, char expected)
{
	char c = sdoBGetC(&sdor->b);
	if (c != expected) {
		LOG(LOG_ERROR, "expected '%c' at cursor %u, got '%c'.\n",
		    expected, sdor->b.cursor - 1, c);
		return false;
	}
	return true;
}

/**
 * Internal API
 */
bool _readComma(SDOR_t *sdor)
{
	if (sdor->needComma) {
		sdor->needComma = false;
		return _readExpectedChar(sdor, ',');
	}
	return true;
}

/**
 * Internal API
 */
bool _readExpectedCharCommaBefore(SDOR_t *sdor, char expected)
{
	int r;
	if (!_readComma(sdor)) {
		LOG(LOG_ERROR, "we were expecting , here!\n");
		return false;
	}

	r = _readExpectedChar(sdor, expected);
	sdor->needComma = false;
	return r;
}

/**
 * Internal API
 */
bool _readExpectedCharCommaAfter(SDOR_t *sdor, char expected)
{
	int r = _readExpectedChar(sdor, expected);
	sdor->needComma = true;
	return r;
}

/**
 * Internal API
 */
bool sdoRBeginSequence(SDOR_t *sdor)
{
	return _readExpectedCharCommaBefore(sdor, '[');
}

/**
 * Internal API
 */
bool sdoREndSequence(SDOR_t *sdor)
{
	return _readExpectedCharCommaAfter(sdor, ']');
}

/**
 * Internal API
 */
bool sdoRBeginObject(SDOR_t *sdor)
{
	return _readExpectedCharCommaBefore(sdor, '{');
}

/**
 * Internal API
 */
bool sdoREndObject(SDOR_t *sdor)
{
	return _readExpectedCharCommaAfter(sdor, '}');
}

/**
 * Internal API
 */
void sdoRReadAndIgnoreUntil(SDOR_t *sdor, char expected)
{
	char c;
	while (1) {
		c = sdoBGetC(&sdor->b);
		if (expected != c && c != '\0')
			continue;
		break;
	}
}

/**
 * Internal API
 */
void sdoRReadAndIgnoreUntilEndSequence(SDOR_t *sdor)
{
	sdoRReadAndIgnoreUntil(sdor, ']');
	sdor->needComma = true;
}

/**
 * Internal API
 */
uint32_t sdoReadUInt(SDOR_t *sdor)
{
	uint32_t r = 0;
	int c;
	SDOBlock_t *sdob = &sdor->b;

	if (!_readComma(sdor))
		LOG(LOG_ERROR, "we were expecting , here!\n");

	while ((c = SDOBPeekc(sdob)) != -1 && c >= '0' && c <= '9') {
		sdoSkipC(sdob);
		r = (r * 10) + (c - '0');
	}
	sdor->needComma = true;
	return r;
}

/**
 * Internal API
 */
int sdoReadStringSz(SDOR_t *sdor)
{
	int n, saveCursor;
	bool saveNeedComma;
	char c;

	saveNeedComma = sdor->needComma;
	saveCursor = sdor->b.cursor;
	n = sdoReadString(sdor, &c, 1);
	sdor->b.cursor = saveCursor;
	sdor->needComma = saveNeedComma;
	return n;
}

/**
 * Internal API
 * Read the complete array block without changing the cursor and
 * return the size required. i.e "[" to "]"
 */
int sdoReadArraySz(SDOR_t *sdor)
{
	int saveCursor;
	bool saveNeedComma;
	char c;
	uint32_t size_of_buffer = 0;
	bool ct_end_wait = false;

	saveNeedComma = sdor->needComma;
	saveCursor = sdor->b.cursor;
	sdor->b.cursor--;
	while (1) {
		c = sdoBGetC(&sdor->b);
		if (-1 == c) {
			return -1;
		}
		size_of_buffer++;

		if (']' != c && c != '\0' && ct_end_wait == false) {
			continue;
		} else {
			if (']' == c && ct_end_wait == false) {
				ct_end_wait = true;
			} else {
				if (']' == c && c != '\0' &&
				    ct_end_wait == true)
					break;
			}
		}
	}

	sdor->b.cursor = saveCursor;
	sdor->needComma = saveNeedComma;
	return size_of_buffer;
}

/**
 * Internal API
 * Read the complete array block without changing the cursor and
 * return the size populated in the buf. i.e "[" to "]"
 */
int sdoReadArrayNoStateChange(SDOR_t *sdor, uint8_t *buf)
{
	int saveCursor;
	bool saveNeedComma;
	char c;
	uint32_t size_of_buffer = 0;
	bool ct_end_wait = false;

	saveNeedComma = sdor->needComma;
	saveCursor = sdor->b.cursor;
	sdor->b.cursor--;
	while (1) {
		c = sdoBGetC(&sdor->b);
		if (-1 == c) {
			return -1;
		}
		buf[size_of_buffer++] = c;

		if (']' != c && c != '\0' && ct_end_wait == false) {
			continue;
		} else {
			if (']' == c && ct_end_wait == false) {
				ct_end_wait = true;
			} else {
				if (']' == c && c != '\0' &&
				    ct_end_wait == true)
					break;
			}
		}
	}

	sdor->b.cursor = saveCursor;
	sdor->needComma = saveNeedComma;
	return size_of_buffer;
}

/**
 * Internal API
 */
int sdoReadString(SDOR_t *sdor, char *bufp, int bufSz)
{
	int n, c;
	char *limit = bufp + (bufSz - 1);
	SDOBlock_t *sdob = &sdor->b;

	if (!_readComma(sdor)) {
		LOG(LOG_ERROR, "we were expecting , here!\n");
		return 0;
	}

	if (!_readExpectedChar(sdor, '"')) {
		LOG(LOG_ERROR, "Expected char read is not \"\n");
		return 0;
	}

	n = 0;
	while ((c = sdoBGetC(sdob)) != '"' && c != -1) {
		++n;
		if (bufp < limit)
			*bufp++ = c;
	}
	*bufp = 0;
	sdor->needComma = true;
	return n;
}

/**
 * Internal API
 */
int sdoReadTag(SDOR_t *sdor, char *bufp, int bufSz)
{
	int n = sdoReadString(sdor, bufp, bufSz);

	if (!_readExpectedChar(sdor, ':')) {
		LOG(LOG_ERROR, "Expected char read is not :\n");
		return 0;
	}

	sdor->needComma = false;
	return n;
}

/**
 * Internal API
 */
bool sdoReadTagFinisher(SDOR_t *sdor)
{
	sdor->needComma = false;
	return _readExpectedChar(sdor, ':');
}

/**
 * Internal API
 */
int sdoReadExpectedTag(SDOR_t *sdor, char *tag)
{
	char buf[SDO_TAG_MAX_LEN] = {0};
	int strcmp_result = 0;

	sdoReadTag(sdor, &buf[0], sizeof buf);
	strcmp_s(buf, SDO_TAG_MAX_LEN, tag, &strcmp_result);
	if (strcmp_result == 0)
		return 1;
	else
		return 0;
}

#if 0 // Deprecated
/**
 * Internal API
 */
int sdoReadBigNumField(SDOR_t *sdor, uint8_t *bufp, int bufSz)
{
	return sdoReadBigNumAsteriskHack(sdor, bufp, bufSz, NULL);
}

/**
 * Internal API
 */
int sdoReadBigNumAsteriskHack(SDOR_t *sdor, uint8_t *bufp, int bufSz,
			      bool *haveAsterisk)
{
	int n, c, v;
	uint8_t *limit = bufp + bufSz;
	SDOBlock_t *sdob = &sdor->b;

	if (!_readComma(sdor)) {
		LOG(LOG_ERROR, "we were expecting , here!\n");
		return 0;
	}

	if (!_readExpectedChar(sdor, '"')) {
		LOG(LOG_ERROR, "Expected char read is not \"\n");
		return 0;
	}

	n = 0;
	v = 0;
	while ((c = sdoBGetC(sdob)) != '"' && c != -1) {
		if (n == 0 && haveAsterisk != NULL && c == '*') {
			*haveAsterisk = true;
			c = '0';
		}
		if ((n & 1) == 0) {
			v = hexitToInt(c) << 4;
		} else {
			v += hexitToInt(c);
			if (bufp < limit)
				*bufp++ = v;
		}
		++n;
	}
	sdor->needComma = true;
	return n >> 1;
}
#endif

/**
 * Reads a byte array base64 into the buffer provided
 */
int sdoReadByteArrayField(SDOR_t *sdor, int b64Sz, uint8_t *bufp, int bufSz)
{
	int converted = 0;

	if (!_readComma(sdor)) {
		LOG(LOG_ERROR, "we were expecting , here!\n");
		goto err;
	}

	// LOG(LOG_ERROR, "SDOReadByteArray\n");
	if (!_readExpectedChar(sdor, '"'))
		goto err;

	converted = b64ToBin((size_t)b64Sz, sdor->b.block, sdor->b.cursor,
			     (size_t)bufSz, bufp, 0);

	if (converted == -1) {
		LOG(LOG_ERROR, "Base64 string is invalid!\n");
		goto err;
	}
	sdor->b.cursor += b64Sz;

	if (!_readExpectedChar(sdor, '"'))
		goto err;

	sdor->needComma = true;

	return converted;

err:
	return 0; /* Any failure means no bytes read */
}

//==============================================================================
// Write values
//

/**
 * SDOW - SDO Writer
 */
bool sdoWInit(SDOW_t *sdow)
{
	if (memset_s(sdow, sizeof *sdow, 0) != 0) {
		LOG(LOG_ERROR, "SDOW memset() failed!\n");
		return false;
	}

	sdoBlockInit(&sdow->b);

	return true;
}

/**
 * Internal API
 */
void sdoWBlockReset(SDOW_t *sdow)
{
	SDOBlock_t *sdob = &sdow->b;
	sdob->cursor = sdob->blockSize = 0;
	sdow->needComma = false;
}

/**
 * Internal API
 */
int sdoWNextBlock(SDOW_t *sdow, int type)
{
	sdoWBlockReset(sdow);
	sdow->msgType = type;
	return true;
}

/**
 * Internal API
 */
void _writeComma(SDOW_t *sdow)
{
	SDOBlock_t *sdob = &sdow->b;
	if (sdow->needComma) {
		sdow->needComma = false;
		sdoBPutC(sdob, ',');
		if (sdob->blockSize < sdob->cursor)
			sdob->blockSize = sdob->cursor;
	}
}

/**
 * Write a string to the block, extending block and converting
 * special characters.  Does NOT handle commas.
 */
void _padstring(SDOW_t *sdow, const char *s, int len, bool escape)
{
	SDOBlock_t *sdob = &sdow->b;
	char ucode[10], *ucs;
	unsigned char c;
	while (len-- != 0 && (c = (unsigned char)*s++) != 0) {
		if (escape &&
		    (c < 0x20 || c > 0x7d || c == '[' || c == ']' || c == '"' ||
		     c == '\\' || c == '{' || c == '}' || c == '&')) {

			if (snprintf_s_i(ucode, sizeof ucode, "\\u%04x", c) <
			    0) {
				LOG(LOG_ERROR, "snprintf() failed!\n");
				return;
			}

			for (ucs = &ucode[0]; *ucs; ucs++) {
				sdoBPutC(sdob, *ucs);
			}
		} else {
			sdoBPutC(sdob, c);
		}
	}
	if (sdob->blockSize < sdob->cursor)
		sdob->blockSize = sdob->cursor;
}

/**
 * Internal API
 */
void _writespecialchar(SDOW_t *sdow, char c)
{
	SDOBlock_t *sdob = &sdow->b;

	_writeComma(sdow);
	sdoBPutC(sdob, c);
	sdow->needComma = false;
	if (sdob->blockSize < sdob->cursor)
		sdob->blockSize = sdob->cursor;
}

/**
 * Internal API
 */
void sdoWBeginSequence(SDOW_t *sdow)
{
	_writespecialchar(sdow, '[');
}

/**
 * Internal API
 */
void sdoWEndSequence(SDOW_t *sdow)
{
	sdow->needComma = false;
	_writespecialchar(sdow, ']');
	sdow->needComma = true;
}

/**
 * Internal API
 */
void sdoWBeginObject(SDOW_t *sdow)
{
	_writespecialchar(sdow, '{');
}

/**
 * Internal API
 */
void sdoWEndObject(SDOW_t *sdow)
{
	sdow->needComma = false;
	_writespecialchar(sdow, '}');
	sdow->needComma = true;
}

/**
 * Internal API
 */
void sdoWriteTag(SDOW_t *sdow, char *tag)
{
	sdoWriteString(sdow, tag);
	sdow->needComma = false;
	_writespecialchar(sdow, ':');
}

/**
 * Internal API
 */
void sdoWriteTagLen(SDOW_t *sdow, char *tag, int len)
{
	sdoWriteStringLen(sdow, tag, len);
	sdow->needComma = false;
	_writespecialchar(sdow, ':');
}

/**
 * Internal API
 */
void sdoWriteUInt(SDOW_t *sdow, uint32_t i)
{
	SDOBlock_t *sdob = &sdow->b;
	char num[20] = {0};

	_writeComma(sdow);
	if (snprintf_s_i(num, sizeof(num), "%u", i) < 0) {
		LOG(LOG_ERROR, "snprintf() failed!\n");
		return;
	}
	_padstring(sdow, num, -1, false);
	sdow->needComma = true;
	if (sdob->blockSize < sdob->cursor)
		sdob->blockSize = sdob->cursor;
}

/**
 * Internal API
 */
void sdoWriteString(SDOW_t *sdow, const char *s)
{
	SDOBlock_t *sdob = &sdow->b;

	_writeComma(sdow);
	sdoBPutC(sdob, '"');
	_padstring(sdow, s, -1, true);
	sdoBPutC(sdob, '"');
	sdow->needComma = true;
	if (sdob->blockSize < sdob->cursor)
		sdob->blockSize = sdob->cursor;
}

/**
 * Internal API
 */
void sdoWriteStringLen(SDOW_t *sdow, char *s, int len)
{
	SDOBlock_t *sdob = &sdow->b;

	_writeComma(sdow);
	sdoBPutC(sdob, '"');
	_padstring(sdow, s, len, true);
	sdoBPutC(sdob, '"');
	sdow->needComma = true;
	if (sdob->blockSize < sdob->cursor)
		sdob->blockSize = sdob->cursor;
}
#if 0
/**
 * Internal API
 */
// This is base16 as it should be
void sdoWriteBigNumField(SDOW_t *sdow, uint8_t *bufp, int bufSz)
{
	SDOBlock_t *sdob = &sdow->b;
	char hex[3];

	_writeComma(sdow);
	sdoBPutC(sdob, '"');
	while (bufSz-- > 0) {
		if (snprintf_s_i(hex, sizeof hex, "%02X", *bufp++) < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return;
		}
		sdoBPutC(sdob, hex[0]);
		sdoBPutC(sdob, hex[1]);
	}
	sdoBPutC(sdob, '"');
	sdow->needComma = true;
	if (sdob->blockSize < sdob->cursor)
		sdob->blockSize = sdob->cursor;
}
#endif
/**
 * Internal API
 * This is base16 as it should be
 */
void sdoWriteBigNum(SDOW_t *sdow, uint8_t *bufp, int bufSz)
{
	SDOBlock_t *sdob = &sdow->b;
	char hex[3];

	sdoWBeginSequence(sdow); // Write out the '['
	sdoWriteUInt(sdow, bufSz);
	_writeComma(sdow);
	sdoBPutC(sdob, '"');
	while (bufSz-- > 0) {
		if (snprintf_s_i(hex, sizeof hex, "%02X", *bufp++) < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return;
		}
		sdoBPutC(sdob, hex[0]);
		sdoBPutC(sdob, hex[1]);
	}
	sdoBPutC(sdob, '"');
	sdoWEndSequence(sdow); // Write out the ']'
	sdow->needComma = true;
	if (sdob->blockSize < sdob->cursor)
		sdob->blockSize = sdob->cursor;
}

/**
 * Internal API
 */
//#define WRBUF_LEN 20
void sdoWriteByteArrayField(SDOW_t *sdow, uint8_t *bufp, int bufSz)
{
	SDOBlock_t *sdob = &sdow->b;
	int index;

	int bufNeeded = binToB64Length(bufSz);

	// mbedtls expect larger size buffer
	bufNeeded += 1;
	// LOG(LOG_ERROR, "bufSz: %d, bufNeeded: %d\n", bufSz, bufNeeded);

	if (bufNeeded) {
		uint8_t *wrBuf = sdoAlloc(bufNeeded * sizeof(uint8_t));
		if (wrBuf) {
			// LOG(LOG_ERROR, "bufp: %p, bufSz: %d, wrBuf: %p\n",
			// bufp,
			// bufSz,
			// wrBuf);

			// Convert the binary to a string
			int strLen =
			    binToB64(bufSz, bufp, 0, bufNeeded, wrBuf, 0);
			// LOG(LOG_ERROR, "strLen: %d\n", strLen);

			_writeComma(sdow);
			sdoBPutC(sdob, '"');
			for (index = 0; index < strLen; index++)
				sdoBPutC(sdob, wrBuf[index]);
			sdoBPutC(sdob, '"');
			sdow->needComma = true;
			if (sdob->blockSize < sdob->cursor)
				sdob->blockSize = sdob->cursor;
			sdoFree(wrBuf);
		}
	}
}

/**
 * Internal API
 */
void sdoWriteByteArray(SDOW_t *sdow, uint8_t *bufp, int bufSz)
{
	sdoWBeginSequence(sdow); // Write out the '['
	if (bufSz) {
		sdoWriteUInt(sdow, bufSz); // Write out the number of bin
					   // characters to come
		_writeComma(sdow);
		sdoWriteByteArrayField(sdow, bufp, bufSz); // "aBzd...==" added
	} else {
		sdoWriteUInt(sdow, 0);
		_writeComma(sdow);
		sdoWriteString(sdow, "");
	}
	sdoWEndSequence(sdow); // Write out the ']'
}

/**
 * Internal API
 */
void sdoWriteByteArrayOneInt(SDOW_t *sdow, uint32_t val1, uint8_t *bufp,
			     int bufSz)
{
	sdoWBeginSequence(sdow);   // Write out the '['
	sdoWriteUInt(sdow, bufSz); // Write out the number bin of characters
	_writeComma(sdow);
	sdoWriteUInt(sdow, val1);
	_writeComma(sdow);
	if (bufSz > 0 && bufp != NULL)
		sdoWriteByteArrayField(sdow, bufp, bufSz); // "aBzd...==" added
	else {
		sdoWriteString(sdow, ""); // Write an empty string
	}
	sdoWEndSequence(sdow); // Write out the ']'
}

/**
 * Internal API
 */
void sdoWriteByteArrayOneIntFirst(SDOW_t *sdow, uint32_t val1, uint8_t *bufp,
				  int bufSz)
{
	sdoWBeginSequence(sdow); // Write out the '['
	sdoWriteUInt(sdow, val1);
	_writeComma(sdow);
	sdoWriteUInt(sdow, bufSz); // Write out the number of bin characters
	_writeComma(sdow);
	if (bufSz > 0 && bufp != NULL) {
		sdoWriteByteArrayField(sdow, bufp, bufSz); // "aBzd...==" added
	} else {
		sdoWriteString(sdow, ""); // Write an empty string
	}
	sdoWEndSequence(sdow); // Write out the ']'
}

/**
 * Internal API used to write 2 arrays used for writing encrypted string.
 * Write "ct". IV, size, cipher text
 */
void sdoWriteByteArrayTwoInt(SDOW_t *sdow, uint8_t *bufIv, uint32_t bufIvSz,
			     uint8_t *bufp, uint32_t bufSz)
{
	sdoWBeginSequence(sdow); /* Write out the '[' */

	if (bufIvSz > 0 && bufIv != NULL) {

		sdoWBeginSequence(sdow);     /* Write out the '[' */
		sdoWriteUInt(sdow, bufIvSz); /* Write out the number IV char */
		_writeComma(sdow);
		sdoWriteByteArrayField(sdow, bufIv, bufIvSz); /* IV data */
		sdoWEndSequence(sdow); /* Write out the ']' */

	} else {
		sdoWriteString(sdow, ""); /* Write an empty string */
	}

	_writeComma(sdow);
	sdoWriteUInt(sdow, bufSz); /* Write out the number bin of characters */
	_writeComma(sdow);

	if (bufSz > 0 && bufp != NULL) {
		sdoWriteByteArrayField(sdow, bufp, bufSz);
	} else {
		sdoWriteString(sdow, ""); /* Write an empty string */
	}
	sdoWEndSequence(sdow); /* Write out the ']' */
}
