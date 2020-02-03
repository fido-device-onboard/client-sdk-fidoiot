/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDOBLOCKIO_H__
#define __SDOBLOCKIO_H__

#include <stdbool.h>
#include <stdint.h>

#define INT2HEX(i) ((i) <= 9 ? '0' + (i) : 'A' - 10 + (i))

typedef struct {
	int cursor;
	int blockMax;
	int blockSize;
	uint8_t *block;
} SDOBlock_t;

typedef struct _SDOR_s {
	SDOBlock_t b;
	uint8_t needComma;
	bool haveBlock;
	int msgType;
	int contentLength;
	int (*receive)(struct _SDOR_s *, int);
	void *receiveData;
} SDOR_t;

typedef int (*SDOReceiveFcnPtr_t)(SDOR_t *, int);

typedef struct _SDOW_s {
	SDOBlock_t b;
	uint8_t needComma;
	int blockLengthFixup;
	int msgType;
	int (*send)(struct _SDOW_s *);
	void *sendData;
} SDOW_t;

#define SDO_FIX_UP_STR "\"0000\""
#define SDO_FIX_UP_TEMPL "\"%04x\""
#define SDO_FIX_UP_LEN 6
#define SDO_BLOCK_READ_SZ 7 // ["XXXX"
#define SDO_BLOCKINC 256
#define SDO_BLOCK_MASK ~255
#define SDO_OK 0
#define SDO_BLOCKLEN_SZ 8
void sdoBlockInit(SDOBlock_t *sdob);
void sdoBlockReset(SDOBlock_t *sdob);
int SDOBPeekc(SDOBlock_t *sdob);
void sdoResizeBlock(SDOBlock_t *sdob, int need);
bool sdoRInit(SDOR_t *sdor, SDOReceiveFcnPtr_t rcv, void *rcvData);
void sdoRFlush(SDOR_t *sdor);
int sdoRPeek(SDOR_t *sdor);
bool sdoRHaveBlock(SDOR_t *sdor);
void sdoRSetHaveBlock(SDOR_t *sdor);
bool sdoRNextBlock(SDOR_t *sdor, uint32_t *typep);
uint8_t *sdoRGetBlockPtr(SDOR_t *sdor, int fromCursor);
uint8_t *sdoWGetBlockPtr(SDOW_t *sdow, int fromCursor);
bool sdoRBeginSequence(SDOR_t *sdor);
bool sdoREndSequence(SDOR_t *sdor);
bool sdoRBeginObject(SDOR_t *sdor);
bool sdoREndObject(SDOR_t *sdor);
uint32_t sdoReadUInt(SDOR_t *sdor);
int sdoReadStringSz(SDOR_t *sdor);
int sdoReadArraySz(SDOR_t *sdor);
int sdoReadArrayNoStateChange(SDOR_t *sdor, uint8_t *buf);
int sdoReadString(SDOR_t *sdor, char *bufp, int bufSz);
int sdoReadTag(SDOR_t *sdor, char *bufp, int bufSz);
bool sdoReadTagFinisher(SDOR_t *sdor);
int sdoReadExpectedTag(SDOR_t *sdor, char *tag);
int sdoReadByteArrayField(SDOR_t *sdor, int b64Sz, uint8_t *bufp, int bufSz);

bool sdoWInit(SDOW_t *sdow);
void sdoWBlockReset(SDOW_t *sdow);
int sdoWNextBlock(SDOW_t *sdow, int type);
int sdoWCreateFixup(SDOW_t *sdow);
void sdoWFixFixup(SDOW_t *sdow, int cursorPosn, int fixup);
void sdoWBeginSequence(SDOW_t *sdow);
void sdoWEndSequence(SDOW_t *sdow);
void sdoWBeginObject(SDOW_t *sdow);
void sdoWEndObject(SDOW_t *sdow);
void sdoWriteTag(SDOW_t *sdow, char *tag);
void sdoWriteTagLen(SDOW_t *sdow, char *tag, int len);
void sdoWriteUInt(SDOW_t *sdow, uint32_t i);
void sdoWriteString(SDOW_t *sdow, const char *s);
void sdoWriteStringLen(SDOW_t *sdow, char *s, int len);
void sdoWriteBigNumField(SDOW_t *sdow, uint8_t *bufp, int bufSz);
void sdoWriteBigNum(SDOW_t *sdow, uint8_t *bufp, int bufSz);
void sdoWriteByteArrayField(SDOW_t *sdow, uint8_t *bufp, int bufSz);
void sdoWriteByteArray(SDOW_t *sdow, uint8_t *bufp, int bufSz);
void sdoWriteByteArrayOneInt(SDOW_t *sdow, uint32_t val1, uint8_t *bufp,
			     int bufSz);
void sdoWriteByteArrayOneIntFirst(SDOW_t *sdow, uint32_t val1, uint8_t *bufp,
				  int bufSz);
void sdoRReadAndIgnoreUntil(SDOR_t *sdor, char expected);
void sdoRReadAndIgnoreUntilEndSequence(SDOR_t *sdor);
void sdoWriteByteArrayTwoInt(SDOW_t *sdow, uint8_t *bufIv, uint32_t bufIvSz,
			     uint8_t *bufp, uint32_t bufSz);

#if 0 // Deprecated
int hexitToInt(int c);
int intToHexit(int v);
int sdoReadBigNumField(SDOR_t *sdor, uint8_t *bufp, int bufSz);
int sdoReadBigNumAsteriskHack(SDOR_t *sdor, uint8_t *bufp, int bufSz,
			      bool *haveAsterisk);
#endif

#endif /*__SDOBLOCKIO_H__ */
