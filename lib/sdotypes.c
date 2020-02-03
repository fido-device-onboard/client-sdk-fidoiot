/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of SDO specific data structures parsing/creating APIs.
 */

#include "crypto_utils.h"
#include "sdoprot.h"
#include "base64.h"
#include "sdotypes.h"
#include "network_al.h"
#include "sdoCryptoApi.h"
#include "util.h"
#include "sdo.h"
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include "safe_lib.h"
#include "snprintf_s.h"
#include "sdodeviceinfo.h"

/**
 * Allocate and Initialize the bits
 * @param b - pointer to initialized bits struct
 * @param byteSz - size of bytes to ve initialized
 * @return bits if initialization in success
 */
SDOBits_t *sdoBitsInit(SDOBits_t *b, int byteSz)
{
	if (!b)
		return NULL;

	if (byteSz > 0) {
		b->bytes = sdoAlloc(byteSz * sizeof(uint8_t));
		if (b->bytes == NULL)
			return NULL;
		b->byteSz = byteSz;
		return b;
	} else {
		if (b->bytes) {
			sdoFree(b->bytes);
			b->bytes = NULL;
		}
		b->byteSz = 0;
	}
	return b;
}

/**
 * Allocote the bytes specified
 * @param byteSz - number of bytes to be initialized
 * @return pointer to the bits allocated if success else NULL
 */
SDOBits_t *sdoBitsAlloc(int byteSz)
{
	SDOBits_t *b = sdoAlloc(sizeof(SDOBits_t));
	if (b == NULL)
		return NULL;

	if (byteSz > 0)
		return sdoBitsInit(b, byteSz);
	else
		return b;
}

/**
 * Allocate the bits and assing with the data specified
 * @param byteSz - number of bytes to be allocated
 * @param data - data to be written to the initialized bits
 * @return pointer to bits if success else NULL
 */
SDOBits_t *sdoBitsAllocWith(int byteSz, uint8_t *data)
{
	SDOBits_t *b = sdoBitsAlloc(byteSz);
	if (b == NULL)
		return NULL;
	if (!sdoBitsFill(&b)) {
		sdoBitsFree(b);
		return NULL;
	}
	if (memcpy_s(b->bytes, b->byteSz, data, b->byteSz) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		sdoBitsFree(b);
		return NULL;
	}
	return b;
}

/**
 * Free the bits specified
 * @param b - pointer to the struct bits that is to be deallocated
 */
void sdoBitsFree(SDOBits_t *b)
{
	if (b) {
		sdoBitsEmpty(b);
		sdoFree(b);
	}
}

/**
 * Free/Nullify the specified bits
 * @param b - pointer to the struct bits
 */
void sdoBitsEmpty(SDOBits_t *b)
{
	if (!b)
		return;
	if (b->bytes) {
		if (b->byteSz && memset_s(b->bytes, b->byteSz, 0))
			LOG(LOG_ERROR, "Failed to clear memory\n");
		sdoFree(b->bytes);
		b->bytes = NULL;
	}
	b->byteSz = 0;
}

/**
 * Clone the bits to a new struct
 * @param b - pointer to the struct bits which has to be cloned
 * @return pointer to the cloned struct bits if success else NULL
 */
SDOBits_t *sdoBitsClone(SDOBits_t *b)
{
	if (!b)
		return NULL;
	return sdoBitsAllocWith(b->byteSz, b->bytes);
}

/**
 * Resize the struct bits with the specified size
 * @param b - pointer to the struct bits
 * @param byteSz - resized value of bits
 * @return true if resized else false
 */
bool sdoBitsResize(SDOBits_t *b, int byteSz)
{
	sdoBitsEmpty(b);
	b->byteSz = byteSz;
	return sdoBitsFill(&b);
}

/**
 * Initialize the struct bits with zero
 * @param bits  - pointer to the struct bits that has to be initialized with
 * zero
 * @return true if set to 0, else false
 */
bool sdoBitsFill(SDOBits_t **bits)
{
	SDOBits_t *b;

	if (!bits || !*bits)
		return false;

	b = *bits;
	if (b->bytes != NULL) {
		sdoFree(b->bytes);
		b->bytes = NULL;
	}
	b->bytes = sdoAlloc(b->byteSz);
	if (b->bytes == NULL)
		return false;
	return true;
}

#if 0
/**
 * Initialize the bits with the specified data
 * @param b - pointer to the struct bits which has to be initialized
 * @param data - data to be initialized
 * @param dataLen - length of the data
 * @return true if initialized else false
 */
bool sdoBitsFillWith(SDOBits_t *b, uint8_t *data, uint32_t dataLen)
{
	b->byteSz = dataLen;
	if (!sdoBitsFill(b))
		return false;
	if (data != NULL && dataLen <= b->byteSz) {
		if (memcpy_s(b->bytes, dataLen, data, dataLen) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			return false;
		}

		return true;
	} else
		return false;
}

/**
 * Resize and initialize with the specified data
 * @param b - pointer to the struct bits
 * @param newByteSz - resized value of struct bits
 * @param data = data to be initialized
 * @return true if success else false
 */
bool sdoBitsResizeWith(SDOBits_t *b, int newByteSz, uint8_t *data)
{
	return sdoBitsFillWith(b, data, newByteSz);
}

/**
 * Check of the struct bits are equal
 * @param b1 - pointer to the first struct bits
 * @param b2 - pointer to the second struct bits
 * @return true if success else false
 */
bool sdoBitsEqual(SDOBits_t *b1, SDOBits_t *b2)
{
	int result_memcmp = 0;
	memcmp_s(b1->bytes, b1->byteSz, b2->bytes, b2->byteSz, &result_memcmp);
	if ((b1->byteSz == b2->byteSz) && (result_memcmp == 0))
		return true;
	else
		return false;
}

/**
 * Iniaialize the struct bits and fill some random data
 * @param b - pointer to the struct bits which has to be initialized
 * @return  0 if success else -1 on failure
 */
int sdoBitsRandomize(SDOBits_t *b)
{
	if ((b->bytes == NULL) || !sdoBitsFill(b))
		return -1;

	return sdoCryptoRandomBytes(b->bytes, b->byteSz);
}
#endif

/**
 * Convert bytes to string
 * @param b - pointer to the struct bits
 * @param typename - string to be appended
 * @param buf - converted string
 * @param bufSz - size of the converted string
 * return pointer to the string if success
 */
char *sdoBitsToString(SDOBits_t *b, char *typename, char *buf, int bufSz)
{
	size_t i;
	int n;
	char *buf0 = buf;
	char hbuf[5];

	if (!b || !typename || !buf)
		return NULL;

	n = snprintf_s_si(buf, bufSz, "[%s[%d]:", typename, (int)b->byteSz);

	if (n < 0) {
		LOG(LOG_ERROR, "snprintf() failed!\n");
		return NULL;
	}

	buf += n;
	bufSz -= n;
	i = 0;
	while (i < b->byteSz && bufSz > 1) {
		// Do it this way to fill up the string completely
		// else the truncated public key will be terminated below.

		if (snprintf_s_i(hbuf, sizeof hbuf, "%02X", b->bytes[i++]) <
		    0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}

		if (strncpy_s(buf, bufSz, hbuf, bufSz) != 0) {
			LOG(LOG_ERROR, "strcpy() failed!\n");
			return NULL;
		}
		n = strnlen_s(buf, bufSz);

		if (!n || n == bufSz) {
			LOG(LOG_ERROR, "strlen() failed!\n");
			return NULL;
		}

		buf += n;
		bufSz -= n;
	}
	if (bufSz > 1) {
		*buf++ = ']';
		*buf++ = 0;
	}
	return buf0;
}

/**
 * Parse single PSI-tuple to get module name, message and value
 * @param psi_tuple - pointer to a single PSI tuple
 * @param psi_len - length of single PSI tuple
 * @param mod_name - name of module retured after parsing PSI tuple
 * @param mod_msg -  module message retured after parsing PSI tuple
 * @param mod_val - module value retured after parsing PSI tuple
 * @param cbReturnVal - Pointer of type int which will be filled with error
 * value.
 * return true if valid PSI-tuple, false otherwise.
 */
bool sdoGetModuleNameMsgValue(char *psi_tuple, int psi_len, char *mod_name,
			      char *mod_msg, char *mod_val, int *cbReturnVal)
{
	if (!psi_tuple || !psi_len || !mod_name || !mod_msg || !mod_val ||
	    !cbReturnVal) {
		LOG(LOG_ERROR, "Invalid input!\n");
		goto err;
	}

	char *rem = NULL;
	int remLen = 0;
	int nameLen, msgLen, valLen;

	nameLen = msgLen = valLen = 0;

	rem = strchr(psi_tuple, ':');

	if (!rem) {
		LOG(LOG_ERROR, "module name not found!\n");
		*cbReturnVal = MESSAGE_BODY_ERROR;
		goto err;
	} else {
		remLen = strnlen_s(rem, SDO_MAX_STR_SIZE);

		if (!remLen || remLen == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Strlen() failed!\n");
			*cbReturnVal = SDO_SI_INTERNAL_ERROR;
			goto err;
		}

		nameLen = psi_len - remLen;

		if (nameLen == 0) {
			LOG(LOG_ERROR, "Module name is empty!\n");
			*cbReturnVal = MESSAGE_BODY_ERROR;
			goto err;
		}

		if (nameLen > SDO_MODULE_NAME_LEN) {
			LOG(LOG_ERROR, "Module max-name-len limit exceeded!\n");
			*cbReturnVal = SDO_SI_CONTENT_ERROR;
			goto err;
		}

		if (strncpy_s(mod_name, nameLen + 1, psi_tuple, nameLen) != 0) {
			*cbReturnVal = SDO_SI_INTERNAL_ERROR;
			LOG(LOG_ERROR, "Strcpy() failed!\n");
			goto err;
		}
		psi_tuple += nameLen;
		psi_len -= nameLen;
	}

	// consuming ':'
	++psi_tuple;
	--psi_len;

	rem = strchr(psi_tuple, '~');

	if (!rem) {
		LOG(LOG_ERROR, "Module message not found!\n");
		*cbReturnVal = MESSAGE_BODY_ERROR;
		goto err;
	} else {
		remLen = strnlen_s(rem, SDO_MAX_STR_SIZE);

		if (!remLen || remLen == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Strlen() failed!\n");
			*cbReturnVal = SDO_SI_INTERNAL_ERROR;
			goto err;
		}

		msgLen = psi_len - remLen;

		if (msgLen == 0) {
			// module msg is not available, copy empty string
			*mod_msg = '\0';
		} else if (msgLen <= SDO_MODULE_MSG_LEN) {
			if (strncpy_s(mod_msg, msgLen + 1, psi_tuple, msgLen) !=
			    0) {
				*cbReturnVal = SDO_SI_INTERNAL_ERROR;
				LOG(LOG_ERROR, "Strcpy() failed!\n");
				goto err;
			}

		} else {
			LOG(LOG_ERROR, "Module max-msg-len limit exceeded!\n");
			*cbReturnVal = SDO_SI_CONTENT_ERROR;
			goto err;
		}
		psi_tuple += msgLen;
		psi_len -= msgLen;
	}

	// consuming '~'
	++rem;
	--remLen;

	if (remLen > 0) {
		if (remLen > SDO_MODULE_VALUE_LEN) {
			LOG(LOG_ERROR, "Module max-val-len limit exceeded!\n");
			*cbReturnVal = SDO_SI_CONTENT_ERROR;
			goto err;
		}

		// module value is available and 'rem' shall contain whole of it
		if (strncpy_s(mod_val, remLen + 1, rem, remLen) != 0) {
			*cbReturnVal = SDO_SI_INTERNAL_ERROR;
			LOG(LOG_ERROR, "Strcpy() failed!\n");
			goto err;
		}
	} else {
		// module value is not available, copy empty string
		*mod_val = '\0';
	}

	return true;

err:
	return false;
}

#if 0
/**
 * Convert string to hexadecimal
 * @param b - pointer to the struct bits
 * @param buf - converted string
 * @param bufSz - size of the converted string
 * return pointer to the converted string
 */
char *sdoBitsToStringHex(SDOBits_t *b, char *buf, int bufSz)
{
	int i, n;
	char *buf0 = buf;
	char hbuf[5];

	i = 0;
	while (i < b->byteSz && bufSz > 1) {
		// Do it this way to fill up the string completely
		// else the truncated public key will be terminated below.

		if (snprintf_s_i(hbuf, sizeof hbuf, "%02X", b->bytes[i++]) <
		    0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}

		if (strncpy_s(buf, bufSz, hbuf, bufSz) != 0) {
			LOG(LOG_ERROR, "strcpy() failed!\n");
			return NULL;
		}
		n = strnlen_s(buf, bufSz);

		if (!n || n == bufSz) {
			LOG(LOG_ERROR, "strlen() failed!\n");
			return NULL;
		}

		buf += n;
		bufSz -= n;
	}
	if (bufSz > 1) {
		*buf++ = 0;
	}
	return buf0;
}

#if 0 // Deprecated
/**
 * Internal API
 */
void SDOBitsWrite(SDOW_t *sdow, SDOBits_t *b)
{
	sdoWriteBigNumField(sdow, b->bytes, b->byteSz);
	//    sdoWriteByteArrayField(sdow, b->bytes, b->byteSz);
}

/**
 * Internal API
 */
bool SDOBitsRead(SDOR_t *sdor, SDOBits_t *b)
{
	if (b->bytes == NULL)
		if (!sdoBitsFill(b))
			return false;
	return sdoReadBigNumField(sdor, b->bytes, b->byteSz) == b->byteSz;
	//    return SDOReadByteArray(sdor, b->bytes, b->byteSz) == b->byteSz;
}
#endif
//==============================================================================
// Byte Array is SDOBits but read and written as base64

/**
 * Internal API
 */
SDOByteArray_t *SDOByteArrayInit(SDOByteArray_t *bn, int byteSz)
{
	return sdoBitsInit(bn, byteSz);
}
#endif

/**
 * Allocate the number of bytes specified
 * @param byteSz - size of the bytes to be allocated
 * @return pointer to the struct bits that is allocated
 */
SDOByteArray_t *sdoByteArrayAlloc(int byteSz)
{
	return sdoBitsAlloc(byteSz);
}

/**
 * Allocate and initialize the bytes
 * @param val - value to the initialized
 * @return pointer to the struct of bits
 */
SDOByteArray_t *sdoByteArrayAllocWithInt(int val)
{
	return sdoBitsAllocWith(sizeof(int), (uint8_t *)&val);
}

/**
 * Allocate the bytes array and assign with the data specified
 * @param ba - data to be assigned
 * @param baLen - size of the data to be assigned
 * @return pointer to the struct of bytes that is allocated and assigned
 */
SDOByteArray_t *sdoByteArrayAllocWithByteArray(uint8_t *ba, int baLen)
{
	return sdoBitsAllocWith(baLen, ba);
}

/**
 * Free the byte array
 * @param ba - pointer to the byte array struct that has to be sdoFree
 */
void sdoByteArrayFree(SDOByteArray_t *ba)
{
	if (ba)
		sdoBitsFree(ba);
}

#if 0
/**
 * Internal API
 */
void SDOByteArrayEmpty(SDOByteArray_t *ba)
{
	sdoBitsEmpty(ba);
}

/**
 * Resize the byte array
 * @param b - pointer to he struct of byte array that has to be resized
 * @param byteSz - value to be resized with
 * @return pointer to the resized byte array struct
 */
bool sdoByteArrayResize(SDOByteArray_t *b, int byteSz)
{
	return sdoBitsResize(b, byteSz);
}

/**
 * Internal API
 */
bool SDOByteArrayResizeWith(SDOByteArray_t *b, int newByteSz, uint8_t *data)
{
	return sdoBitsResizeWith(b, newByteSz, data);
}
#endif

/**
 * Clone the byte array
 * @param bn - byte array to be cloned
 * @return pointet to the cloned byte array struct
 */
SDOByteArray_t *sdoByteArrayClone(SDOByteArray_t *bn)
{
	return sdoBitsClone(bn);
}

#if 0
/**
 * compare the byte array
 * @param bn1 - pointer to the first byte array struct
 * @param bn2 - pointer to the second byte array struct
 * @return true if equal else false
 */
bool SDOByteArrayEqual(SDOByteArray_t *bn1, SDOByteArray_t *bn2)
{
	return sdoBitsEqual(bn1, bn2);
}
#endif

/**
 * Append one byte array onto another and return the resulting byte array
 * @param baA - pointer to the first byte array object
 * @param baB - pointer to the second
 * @return a Byte Array "AB" with B appended after A
 */
SDOByteArray_t *sdoByteArrayAppend(SDOByteArray_t *baA, SDOByteArray_t *baB)
{
	if (!baA || !baB)
		return NULL;

	int bufSzAB = baA->byteSz + baB->byteSz;
	SDOByteArray_t *baAB = sdoByteArrayAlloc(bufSzAB);
	if (!baAB) {
		LOG(LOG_ERROR,
		    "failed to allocate memory for creating byte array\n");
		return NULL;
	}

	if (memcpy_s(&baAB->bytes[0], baA->byteSz, baA->bytes, baA->byteSz) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		sdoByteArrayFree(baAB);
		return NULL;
	}

	if (memcpy_s(&baAB->bytes[baA->byteSz], baB->byteSz, baB->bytes,
		     baB->byteSz) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		sdoByteArrayFree(baAB);
		return NULL;
	}

	return baAB;
}

/**
 * Byte array is represented as {len,"byte array in base64"}
 * @param g - pointer to the byte array struct
 * @param buf - pointer to the output buffer
 * @param bufSz - size of the buffer
 * @return pointer to the buffer
 */
char *sdoByteArrayToString(SDOByteArray_t *g, char *buf, int bufSz)
{
	int obuf_sz = bufSz;
	char *buf0 = buf;
	if (memset_s(buf, bufSz, 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return NULL;
	}

	int charCount = 0;

	if (g->byteSz && g->bytes != NULL) {
		int b64Len = binToB64Length(g->byteSz);

		/* First put out the length followed by a comma. */
		int len = snprintf_s_i(buf, bufSz, "%d,", b64Len);
		buf += len;
		bufSz -= len;

		/* Check to see if we have enough buffer for the conversion. */
		if ((binToB64Length(g->byteSz) + 1) < bufSz) {
			*buf++ = '"';
			bufSz--;
			/* Then the buffer of the base64 representation. */
			charCount = binToB64(g->byteSz, g->bytes, 0, bufSz,
					     (uint8_t *)buf, 0);
			buf += charCount;
			bufSz -= charCount;
			*buf++ = '"';
			bufSz--;
		}
		if ((charCount + len) > obuf_sz - 1) {
			charCount = obuf_sz - 1;
		}
		*buf = 0;
	}
	return buf0;
}

/**
 * Read a base64 byte array, "byte array in base64"
 * @param sdor - data to be read in the form of JSON
 * @param ba - byte array where the data read hase to be written
 * @return the length of the data read and written if success else zero
 */
int sdoByteArrayReadChars(SDOR_t *sdor, SDOByteArray_t *ba)
{
	if (!sdor || !ba)
		return 0;

	if (ba->bytes) {
		sdoFree(ba->bytes);
		ba->bytes = NULL;
	}

	int b64Len = sdoReadStringSz(sdor);
	// LOG(LOG_ERROR, "b64LenReported %d\n", b64Len);
	// Determine the needed length
	int binLen = b64ToBinLength(b64Len);

	LOG(LOG_DEBUG, "Byte Array len %d\n", binLen);

	// DEBUG - added for correct buff allocation
	if (binLen) {
		// Allocate a BPBits for the array
		ba->bytes = sdoAlloc(binLen * sizeof(uint8_t));
		if (!ba->bytes)
			return 0;
		// Now read the byte array
		int resultLen =
		    sdoReadByteArrayField(sdor, b64Len, ba->bytes, binLen);
		ba->byteSz = resultLen;
		return resultLen;
	} else {
		char c;
		sdoReadString(sdor, &c, 1);
		return 0;
	}
}

/**
 * Read a base64 byte array, len,"byte array in base64"
 * @param sdor - data to be read in the form of JSON
 * @param ba - pointer the struct byte array which holds the read data
 * @return size of data read is success else zero
 */
int sdoByteArrayRead(SDOR_t *sdor, SDOByteArray_t *ba)
{
	if (!sdor || !ba)
		return 0;

	/*FIXME: if unnecessary remove it */
	if (ba->bytes) {
		sdoFree(ba->bytes);
		ba->bytes = NULL;
	}

	int binLenReported = sdoReadUInt(sdor);
	// Determine the needed length
	int b64Len = binToB64Length(binLenReported);

	if (b64Len) {

		// LOG(LOG_ERROR, "B64 Array len %d\n", binLenReported);

		// Allocate a BPBits for the array,
		// Allocate 3 bytes extra for max probable decodaed output
		binLenReported += 3;
		ba->bytes = sdoAlloc((binLenReported) * sizeof(uint8_t));
		if (!ba->bytes)
			return 0;
		// Now read the byte array
		int resultLen = sdoReadByteArrayField(sdor, b64Len, ba->bytes,
						      binLenReported);
		ba->byteSz = resultLen;
		return resultLen;
	} else {
		return 0;
	}
}

/**
 * Read a base64 byte array,
 * Format: [[ size of ivdata ,ivdata], size of cipher text, "base64 cipher
 * text"]
 * @param sdor - data to be read in the form of JSON
 * @param ba - byte array where the data read hase to be written
 * @param ctString - byte array where data read for no state change
 * @param ivData - byte array fir iv data
 * @return the size of the data read if seccess else zero
 */

int sdoByteArrayReadWithType(SDOR_t *sdor, SDOByteArray_t *ba,
			     SDOByteArray_t **ctString, uint8_t *ivData)
{
	int ret = 0;
	int binLenReported = 0, b64LenReported = 0, b64LenExpected = 0;
	int ivDataSize;
	uint32_t iv_size_reported = 0;
	int iv_size_64 = -1;

	if (!sdor || !ba || !ivData || !ctString) {
		goto err;
	}

	/* read sequence:
	 * 1. [size of iv, ivData]
	 * 2. size of cipher text
	 * 3. cipher text
	 */
	uint32_t ct_size = sdoReadArraySz(sdor) + 1;

	if ((*ctString != NULL) || (0 == ct_size)) {
		LOG(LOG_ERROR, "Incorrect arguments passed!\n");
		goto err;
	}
	*ctString = sdoByteArrayAlloc(ct_size);

	if (NULL == *ctString) {
		LOG(LOG_ERROR, "Failed to alloc buffer!\n");
		goto err;
	}

	if (sdoReadArrayNoStateChange(sdor, (*ctString)->bytes) >= ct_size) {
		LOG(LOG_ERROR, "Issue with string read\n");
		goto err;
	}

	/* The json object for IV */
	sdoRBeginSequence(sdor);
	/* Get binary length reported */
	iv_size_reported = sdoReadUInt(sdor);

	if (iv_size_reported <= 0 && iv_size_reported > 16) {
		LOG(LOG_ERROR, "Invalid IV reported!\n");
		goto err;
	}

	iv_size_64 = binToB64Length(iv_size_reported);

	/* Read from the array i.e " " */
	if (0 == (ivDataSize = sdoReadByteArrayField(sdor, iv_size_64, ivData,
						     AES_IV))) {
		LOG(LOG_ERROR, "Failed to read the counter value %d %d\n",
		    ivDataSize, iv_size_reported);
		goto err;
	}

	sdoREndSequence(sdor); // e.g.: [16,"8Qy3cBxI7NQ+Ef0XAAAAAA=="]

	/* Get cipher text binary length reported */
	binLenReported = sdoReadUInt(sdor);

	if (binLenReported <= 0) {
		LOG(LOG_ERROR, "Invalid binary length reported!\n");
		goto err;
	}

	/* Get incoming B64 string length (it must be a multiple of 4) */
	b64LenReported = sdoReadStringSz(sdor);

	if ((b64LenReported <= 0) || (b64LenReported % 4 != 0)) {
		LOG(LOG_ERROR, "Invalid input B64 string!\n");
		goto err;
	}

	/* Calculated expected B64 length using binary length reported */
	b64LenExpected = binToB64Length(binLenReported);

	if (b64LenReported != b64LenExpected) {
		LOG(LOG_ERROR, "Incoming B64 string length is not proportional "
			       "to binary length reported!\n");
		goto err;
	}

	/* Allocate required array */
	if (ba->bytes)
		goto err;

	ba->bytes = sdoAlloc(binLenReported * sizeof(uint8_t));

	if (!ba->bytes)
		goto err;

	/* Now read the byte array */
	ret = sdoReadByteArrayField(sdor, b64LenReported, ba->bytes,
				    binLenReported);
	ba->byteSz = ret;
err:
	return ret;
}

/**
 * Byte array is represented as "byte array in base64"
 * @param sdow - pointer to the written data
 * @param ba - pointer to the byte array that holds data to be read from
 */
void sdoByteArrayWriteChars(SDOW_t *sdow, SDOByteArray_t *ba)
{
	sdoWriteByteArrayField(sdow, ba->bytes, ba->byteSz);
}

/**
 * Byte array is represented as {len,"byte array in base64"}
 * @param sdow - pointer to the written data
 * @param ba - pointer to the byte array that holds data to be read from
 */
void SDOByteArrayWrite(SDOW_t *sdow, SDOByteArray_t *ba)
{
	sdoWriteByteArray(sdow, ba->bytes, ba->byteSz);
}

//------------------------------------------------------------------------------
// Bignum Routines
//

#if 0
/**
 * Allocate the struct of type bignum
 */
SDOBignum_t *sdoBigNumAlloc()
{
	SDOBignum_t *bn = sdoAlloc(sizeof(SDOBignum_t));
	if (!bn)
		return NULL;

	bn->sign = BN_POSITIVE;
	bn->value = NULL;
	return bn;
}

/**
 * Free the allocated struct of type bignum
 * @param bn - pointer to the struct of type bignum
 */
void sdoBigNumFree(SDOBignum_t *bn)
{
	sdoBitsFree(bn->value);
	sdoFree(bn);
}
#endif

/**
 * Internal API
 */
// void sdoBigNumFree(SDOBignum_t *bn)
//{
//   sdoBitsFree(bn->value);
//   sdoFree(bn);
//}

#if 0
/**
 * Compare the struct of type bignum
 * @param bn1 - pointer to struct of type bignum1
 * @param bn2 - pointer to struct of type bignum2
 * @return true if equal else false
 */
bool SDOBignumEqual(SDOBignum_t *bn1, SDOBignum_t *bn2)
{
	if (bn1->sign != bn2->sign)
		return false;
	return (sdoBitsEqual(bn1->value, bn2->value));
}

/**
 * Convert bignum to string
 * @param bn - pointer to struct of type bignum
 * @param buf - pointer to the converted string
 * @param bufSz - size of the converted string
 * @return pointer to the converted string
 */
char *SDOBignumToString(SDOBignum_t *bn, char *buf, int bufSz)
{
	return sdoBitsToStringHex(bn->value, buf, bufSz);
}
#endif

//------------------------------------------------------------------------------
// String handler Routines
//

/**
 * Create an empty SDOString_t object
 * @return an allocated empty SDOString_t object
 */
SDOString_t *sdoStringAlloc(void)
{
	return (SDOString_t *)sdoAlloc(sizeof(SDOString_t));
}

/**
 * Create a SDOString_t object from a non zero terminated string
 * @param data - a pointer to the string
 * @param byteSz - the number of characters in the string ( size 0 or more)
 * @return an allocated SDOString_t object containing the string
 */
SDOString_t *sdoStringAllocWith(char *data, int byteSz)
{
	SDOString_t *tempStr = NULL;
	int total_size = byteSz + 1;

	if (!data)
		goto err1;

	tempStr = sdoStringAlloc();
	if (!tempStr)
		goto err1;

	tempStr->bytes = sdoAlloc(total_size * sizeof(char));
	if (tempStr->bytes == NULL)
		goto err2;

	tempStr->byteSz = total_size;
	if (byteSz) {
		if (memcpy_s(tempStr->bytes, total_size, data, byteSz) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed here\n");
			goto err2;
		}
	}
	tempStr->bytes[byteSz] = 0;

	return tempStr;

err2:
	sdoStringFree(tempStr);
err1:
	return NULL;
}

/**
 * Create a SDOString_t object from a zero terminated string
 * @param data - a pointer to a zero terminated string
 * @return an allocated SDOString_t object containing the string
 */
SDOString_t *sdoStringAllocWithStr(char *data)
{
	if (!data)
		return NULL;

	int strSz = strnlen_s(data, SDO_MAX_STR_SIZE);

	if (strSz == SDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "sdoStringAllocWithStr(): data"
			       "is either 'NULL' or 'isn't"
			       "NULL-terminated'\n");
		return NULL;
	}
	return sdoStringAllocWith(data, strSz);
}

/**
 * Free an SDOString_t object, sdoFree any contained buffer as well
 * @param b - the SDOString_t object to be sdoFreed
 * @return none
 */
void sdoStringFree(SDOString_t *b)
{
	if (b) {
		sdoStringInit(b);
		sdoFree(b);
	}
}

/**
 * The same as SDOStringEmpty
 * @param b - the object to have its buffers sdoFreed
 * @return pointer to the empty SDOString object
 */
void sdoStringInit(SDOString_t *b)
{
	if (b->bytes) {
		sdoFree(b->bytes);
		b->bytes = NULL;
	}
	b->byteSz = 0;
}

/**
 * Resize the buffer in a SDOString_t to the new size and
 * return the space filled with zeros
 * sdoFree any already present buffers
 * @param b - the SDOString_t object to be resized
 * @param byteSz - the number of bytes to allocate for the new buffer
 * @return true if successful, false otherwise
 */
bool sdoStringResize(SDOString_t *b, int byteSz)
{
	if (!b)
		return false;

	sdoStringInit(b);
	if (byteSz > 0) {
		b->byteSz = byteSz;
		b->bytes = sdoAlloc(byteSz * sizeof(char));
		if (b->bytes)
			return true;
		else
			return false;
	}
	return true;
}

/**
 * Resize the buffer in a SDOString_t to the new size and
 * return the space filled with zeros
 * sdoFree any already present buffers
 * @param b - the SDOString_t object to be resized
 * @param newByteSz - the number of bytes to allocate for the new buffer
 * @param data - the non zero terminated string to copy
 * @return true if successful, false otherwise
 */
bool sdoStringResizeWith(SDOString_t *b, int newByteSz, char *data)
{
	if (!b || !data)
		return NULL;

	if (sdoStringResize(b, newByteSz + 1)) {
		if (newByteSz > 0)
			if (memcpy_s(b->bytes, newByteSz, data, newByteSz) !=
			    0) {
				LOG(LOG_ERROR, "Memcpy Failed\n");
				sdoFree(b->bytes);
				return false;
			}

		return true;
	} else
		return false;
}

#if LOG_LEVEL == LOG_MAX_LEVEL
/**
 *  Returns a zero terminated string value from the SDOString_t device
 *  @param b - the source SDOString device
 *  @param buf - pointer to a buffer to fill
 *  @param bufSz - the size of the buffer provided at buf
 *  @return pointer to the beginning of the zero terminated string
 */
char *sdoStringToString(SDOString_t *b, char *buf, int bufSz)
{
	if (bufSz >= b->byteSz + 1) {
		if (memcpy_s(buf, b->byteSz, b->bytes, b->byteSz)) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			return NULL;
		}
		buf[b->byteSz + 1] = 0;
	}
	return buf;
}
#endif

/**
 * Read a string from the input buffer
 * The string format is "a string", not zero terminated
 * @param sdor - pointer to the input buffer to parse
 * @param b - the SDOString object to fill
 * @return true oif completed successfully, false otherwise
 */
bool sdoStringRead(SDOR_t *sdor, SDOString_t *b)
{
	if (!sdor || !b)
		return false;

	// Clear the passed SDOString_t object's buffer
	sdoStringInit(b);

	int _len = sdoReadStringSz(sdor);

	if (!sdoStringResize(b, (_len + 1))) {
		LOG(LOG_ERROR, "String Resize failed!, requested str_len %d\n",
		    (_len + 1));
		return false;
	}

	sdoReadString(sdor, b->bytes, b->byteSz);
	return true;
}

#if LOG_LEVEL == LOG_MAX_LEVEL
/* -----------------------------------------------------------------------------
 * GUID routines
 */
/**
 * convert to GUID to string
 * @param g - pointer to the byte array that holds the GUID
 * @param buf - pointer to the converted string
 * @param bufSz - size of the converted string
 * @return pointer to the converted string
 */
char *sdoGuidToString(SDOByteArray_t *g, char *buf, int bufSz)
{
	const char str[] = "[Guid[16]:";
	int i = 0, n = sizeof(str) - 1;
	char *a = (char *)g->bytes;

	/* bufSz >= strlen(str) + SDO_GUID_BYTES + ']' + '\0' */
	if (bufSz < n + SDO_GUID_BYTES + 1 + 1)
		return NULL;

	if (memcpy_s(buf, bufSz, str, n) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return NULL;
	}

	while (i < SDO_GUID_BYTES) {
		buf[n++] = INT2HEX(((*a >> 4) & 0xf));
		buf[n++] = INT2HEX((*a & 0xf));
		i++;
		a++;
	}
	buf[n++] = ']';
	buf[n++] = 0;
	return buf;
}
#endif

/**
 * Write the GID
 * @param sdow - pointer to the struct where the GID is written in JSON format
 * @return none
 */
void sdoGidWrite(SDOW_t *sdow)
{

/*EPID 2.0 supports 128 bit GID*/

// TODO: As per spec GID should be converted into
// networkbyte order, but server is supporting this
// for for now send in little endian
#if 0
	uint32_t htonGid[4];
	uint32_t *gid32;
	/*Convert GID to network byte order*/
	gid32 = (uint32_t *)gid;
	htonGid[0] = sdoHostToNetLong(*gid32);
	gid32++;
	htonGid[1] = sdoHostToNetLong(*gid32);
	gid32++;
	htonGid[2] = sdoHostToNetLong(*gid32);
	gid32++;
	htonGid[3] = sdoHostToNetLong(*gid32);

	/* EPIDInfo eA
	 * [
	 *   epidInfoType(Uint8)  --> 3 for EPID2.0 Non-DAL
	 *   length(Uint16),      --> length of GID (EPID 2.0 supports 128 bit
	 * GID)
	 *   info(ByteArray)      --> ByteArry of GID
	 *  ]
	 *
	 * "eA":[3,16,"GID Bytes"]
	 * */

	/*Write 3 for EPID2.0*/
	//sdoWriteByteArrayOneIntFirst(sdow, SDOEPID_VERSION, (uint8_t *)htonGid,
	//			    sizeof(htonGid));
#endif

	SDOSigInfo_t *eA = sdoGetDeviceSigInfoeA();
	uint8_t *publickey_buf = NULL;
	if (eA && eA->pubkey && eA->pubkey->key1) {
		publickey_buf = (uint8_t *)eA->pubkey->key1->bytes;
	}

	sdoWriteByteArrayOneIntFirst(sdow, SDO_PK_ALGO, publickey_buf,
				     SDO_PK_EA_SIZE);
}

/**
 * Allocate EPID info and initialize to NULL
 * @return null
 */
SDOEPIDInfoeB_t *sdoEPIDInfoEBAllocEmpty(void)
{
	return sdoAlloc(sizeof(SDOEPIDInfoeB_t));
}

/**
 * Allocate Certificate chain and initialize to NULL
 * @return null
 */
SDOCertChain_t *sdoCertChainAllocEmpty(void)
{
	return sdoAlloc(sizeof(SDOCertChain_t));
}

/**
 * Read the Certificate chain
 * @param sdor - pointe to the read EPID information in JSON format
 * @return pointer to the read certificate chain
 */
SDOCertChain_t *sdoCertChainRead(SDOR_t *sdor)
{
	SDOCertChain_t *CertChain = sdoCertChainAllocEmpty();

	if (NULL == CertChain) {
		LOG(LOG_ERROR, "Malloc Failed!\n");
		goto err;
	}

	/* Read the total chain len */
	CertChain->len = sdoReadUInt(sdor);
	if (CertChain->len == 0) {
		LOG(LOG_ERROR, "Invalid Cert chain length reported!\n");
		goto err;
	}

	/* Read the type */
	CertChain->type = sdoReadUInt(sdor);
	if (CertChain->len == 0) {
		LOG(LOG_ERROR, "Invalid Cert chain length reported!\n");
		goto err;
	}

	/* Read the total number of certificate entries */
	CertChain->numEntries = sdoReadUInt(sdor);
	if (CertChain->numEntries == 0) {
		LOG(LOG_ERROR, "Invalid Cert chain num entries reported!\n");
		goto err;
	}

	CertChain->cert = sdoByteArrayAlloc(CertChain->len);
	if (CertChain->cert == 0) {
		LOG(LOG_ERROR,
		    "Invalid number of entries in Cert Chain reported!\n");
		goto err;
	}

	if (!sdoByteArrayRead(sdor, CertChain->cert)) {
		LOG(LOG_ERROR, "Invalid Cert chain received!\n");
		goto err;
	}

	return CertChain;

err:
	if (CertChain)
		sdoFree(CertChain);
	return NULL;
}

/**
 * Read the Dummy EB i.e. [13, 0, ""] sent when ECDSA based device-attestation
 * is used.
 * @param sdor - pointe to the read EPID information in JSON format
 * @return true when successfully read, false in case of any issues.
 */
bool sdoEcdsaDummyEBRead(SDOR_t *sdor)
{
	bool retval = false;
	uint8_t type = 0;
	uint8_t exptype = 0;
	uint8_t len = 0;
	char buf[1] = {0};
	uint8_t temp = 0;

	/* "eB":[13,0,""] */

	if (!sdor)
		goto end;

	if (!sdoRBeginSequence(sdor)) {
		LOG(LOG_ERROR, "No begin Sequence\n");
		goto end;
	}

	exptype = SDO_PK_ALGO;

	type = sdoReadUInt(sdor);
	if (type != exptype) {
		LOG(LOG_ERROR,
		    "Invalid ECDSA pubkey type, expected %d, got %d\n", exptype,
		    type);
		goto end;
	}

	len = sdoReadUInt(sdor);

	// read empty string
	temp = sdoReadString(sdor, buf, len);

	LOG(LOG_DEBUG, "Received ecdsa EB of len: %d\n", temp);

	if (len != 0 || temp != 0) {
		LOG(LOG_ERROR, "Got non-zero length EB in case of ECDSA!\n");
		goto end;
	}

	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		goto end;
	}
	retval = true;

end:
	return retval;
}

/**
 * Read the EPID information
 * @param sdor - pointe to the read EPID information in JSON format
 * @return 0 on success and -1 on failure
 */
int32_t sdoEPIDInfoEBRead(SDOR_t *sdor)
{
	uint8_t type;
	uint16_t sigRLlen;
	uint16_t pubkeylen;
	uint8_t *bSigRL = NULL;
	uint8_t *bPubkey = NULL;
	SDOByteArray_t *sigRL = NULL;
	SDOByteArray_t *pubkey = NULL;

	/*
	 * "eB":[EpidType, len, "EPIDInfo eB ByteArray"]
	 *
	 *EPIDInfo eB
	 * [
	 *     UInt16   sigRLSize,
	 *     BYTE[sigRLSize]	sigRL,
	 *     UInt16	publicKeySize,
	 *     BYTE[publicKeySize]	publicKey
	 * ]
	 * */
	if (!sdor)
		return -1;

	if (!sdoRBeginSequence(sdor))
		return -1;

	type = sdoReadUInt(sdor);
	if (type != SDOEPID_VERSION) {
		LOG(LOG_DEBUG, "Wrong EPID type\n");
		return -1;
	}

	SDOByteArray_t *eB = sdoByteArrayAllocWithInt(0);
	if (!eB)
		return -1;

	if (sdoByteArrayRead(sdor, eB) == 0) {
		goto error;
	}

	sigRLlen = eB->bytes[0] << 8 | eB->bytes[1];

	if (sigRLlen) {
		bSigRL = (uint8_t *)sdoAlloc(sigRLlen);
		if (!bSigRL) {
			goto error;
		}

		if (memcpy_s(bSigRL, sigRLlen, eB->bytes + sizeof(sigRLlen),
			     sigRLlen) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			goto error;
		}
	}

	pubkeylen = eB->bytes[sizeof(sigRLlen) + sigRLlen] << 8 |
		    eB->bytes[sizeof(sigRLlen) + sigRLlen + 1];

	bPubkey = (uint8_t *)sdoAlloc(pubkeylen);
	if (!bPubkey) {
		goto error;
	}

	if (memcpy_s(bPubkey, pubkeylen,
		     eB->bytes + sizeof(sigRLlen) + sigRLlen +
			 sizeof(pubkeylen),
		     pubkeylen) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto error;
	}

	/*TODO: Does byteSz needs to convert to LE ?*/
	LOG(LOG_DEBUG, "Received eB len: %zu SigRLlen :%d pukeylen: %d\n",
	    eB->byteSz, sigRLlen, pubkeylen);

	sigRL = sdoAlloc(sizeof(SDOByteArray_t));
	if (!sigRL)
		goto error;

	pubkey = sdoAlloc(sizeof(SDOByteArray_t));
	if (!pubkey)
		goto error;

	sigRL->bytes = bSigRL;
	sigRL->byteSz = sigRLlen;

	pubkey->bytes = bPubkey;
	pubkey->byteSz = pubkeylen;

	sdoSetDeviceSigInfoeB(sigRL, pubkey);

	sdoByteArrayFree(eB);
	eB = NULL;

	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		goto error;
	}
	return 0;
error:
	if (eB)
		sdoByteArrayFree(eB);
	if (bSigRL)
		sdoFree(bSigRL);
	if (bPubkey)
		sdoFree(bPubkey);
	if (sigRL)
		sdoFree(sigRL);
	if (pubkey)
		sdoFree(pubkey);
	return -1;
}

/**
 * Read the EPID information or do a dummy read for ECDSA
 * @param sdor - pointer to the read location in JSON format
 * @return 0 on success and -1 on failure
 */
int32_t sdoEBRead(SDOR_t *sdor)
{
	SDOSigInfo_t *sig = sdoGetDeviceSigInfoeA();
	if (sig && sig->sigType == SDOEPID_VERSION) {
		return sdoEPIDInfoEBRead(sdor);
	} else {
		int32_t ret = (false == sdoEcdsaDummyEBRead(sdor)) ? -1 : 0;
		return ret;
	}
}

/**
 * Free the EPID information
 * @param EPIDInfo - pointer to the EPID information that has to be sdoFreed
 * @return none
 */
void sdoEPIDInfoEBFree(SDOEPIDInfoeB_t *EPIDInfo)
{
	if (!EPIDInfo)
		return;
	sdoByteArrayFree(EPIDInfo->sigRL);
	sdoByteArrayFree(EPIDInfo->pubkey);
	sdoFree(EPIDInfo);
}

/* -----------------------------------------------------------------------------
 * Nonce routines
 */
/**
 * Initialize Nonce with random data
 * @param n - pointer to the byte array
 * @return none
 */
void sdoNonceInitRand(SDOByteArray_t *n)
{
	sdoCryptoRandomBytes((uint8_t *)n->bytes, n->byteSz);
}

/**
 * compare the two nonce
 * @param n1 - pointer to the first byte array
 * @param n2 - pointer to the second byte array
 * @return true if equal else false
 */
bool sdoNonceEqual(SDOByteArray_t *n1, SDOByteArray_t *n2)
{
	int result_memcmp = 0;
	if (!n1 || !n2)
		return false;

	if (!memcmp_s(n1->bytes, SDO_NONCE_BYTES, n2->bytes, SDO_NONCE_BYTES,
		      &result_memcmp) &&
	    !result_memcmp)
		return true;
	else
		return false;
}

/**
 * convert nonce to string
 * @param n - pointer to the input nonce
 * @param buf - pointer to the converted string
 * @param bufSz - size of the converted string
 * @return pointer to the converted string
 */
char *sdoNonceToString(uint8_t *n, char *buf, int bufSz)
{
	int i = 0, j = 1;
	char *a = (char *)n;

	if (!n || !buf)
		return NULL;

	buf[0] = '[';
	while (i < SDO_NONCE_BYTES) {
		buf[j++] = INT2HEX(((*a >> 4) & 0xf));
		buf[j++] = INT2HEX((*a & 0xf));
		i++;
		a++;
	}
	buf[j++] = ']';
	buf[j++] = 0;
	return buf;
}

//------------------------------------------------------------------------------
// Hash/HMAC Routines
//

/**
 * Allocate and empty hash type
 */
SDOHash_t *sdoHashAllocEmpty(void)
{
	SDOHash_t *hp = sdoAlloc(sizeof(SDOHash_t));
	if (hp == NULL)
		return NULL;
	hp->hashType = SDO_CRYPTO_HASH_TYPE_NONE;
	return hp;
}

/**
 * Allocate byte array of hash type specified
 * @param hashType - type of the hash
 * @param size - size of the byte array to be allocated
 * @return pointer to the allocated hash struct
 */
SDOHash_t *sdoHashAlloc(int hashType, int size)
{
	SDOHash_t *hp = sdoAlloc(sizeof(SDOHash_t));
	if (hp == NULL)
		return NULL;
	hp->hashType = hashType;
	hp->hash = sdoByteArrayAlloc(size);
	if (hp->hash == NULL) {
		sdoFree(hp);
		return NULL;
	}
	return hp;
}

/**
 * Free the allocated struct of type hash type
 * @param hp - pointer to the struct of type hash that is to be sdoFree
 */
void sdoHashFree(SDOHash_t *hp)
{
	if (NULL == hp) {
		return;
	}
	if (hp->hash != NULL) {
		sdoByteArrayFree(hp->hash);
		hp->hash = NULL;
	}
	sdoFree(hp);
}

#if LOG_LEVEL == LOG_MAX_LEVEL
/**
 * Convert hash type to string
 * @param hashType - hash type that has to be converted to string
 * @return the converted string
 */
char *sdoHashTypeToString(int hashType)
{
	static char buf[25];
	switch (hashType) {
	case SDO_CRYPTO_HASH_TYPE_NONE:
		return "NONE";
	case SDO_CRYPTO_HASH_TYPE_SHA_1:
		return "SHA1";
	case SDO_CRYPTO_HASH_TYPE_SHA_256:
		return "SHA256";
	case SDO_CRYPTO_HASH_TYPE_SHA_384:
		return "SHA384";
	case SDO_CRYPTO_HASH_TYPE_SHA_512:
		return "SHA512";
	case SDO_CRYPTO_HMAC_TYPE_SHA_256:
		return "HMAC_SHA256";
	case SDO_CRYPTO_HMAC_TYPE_SHA_512:
		return "HMAC_SHA512";
	case SDO_CRYPTO_HMAC_TYPE_SHA_384:
		return "HMAC_SHA384";
	}
	if (snprintf_s_i(buf, sizeof buf, "-type%u?", hashType) < 0) {
		LOG(LOG_ERROR, "snprintf() failed!\n");
		return NULL;
	}
	return buf;
}

/**
 * convert the hash type to the string
 * @param hp - pointer to the struct if type hash
 * @param buf - pointer to the converted string
 * @param bufSz - size of the converted string
 * @return pointer to the converted string
 */
char *sdoHashToString(SDOHash_t *hp, char *buf, int bufSz)
{
	char name[35];
	char *hashPtr = NULL;

	hashPtr = sdoHashTypeToString(hp->hashType);
	if (hashPtr) {
		if (strncpy_s(name, sizeof name, hashPtr,
			      strnlen_s(hashPtr, sizeof(name))) != 0) {
			LOG(LOG_ERROR, "strcpy() failed!\n");
			return NULL;
		}
		return sdoBitsToString(hp->hash, name, buf, bufSz);
	} else
		return NULL;
}
#endif

/**
 * Read the hash from JSON format
 * @param sdor - input data in JSON format
 * @param hp - pointer to the struct fof type hash
 * @return number of bytes read , 0 if read failed
 */
int sdoHashRead(SDOR_t *sdor, SDOHash_t *hp)
{
	int b64LenReported = 0;
	if (!sdor || !hp)
		return 0;

	if (!sdoRBeginSequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		return 0;
	}

	// LOG(LOG_ERROR, "Reading hash\n");

	// Read the bin character length
	int mbinLenReported = sdoReadUInt(sdor);

	// Read the hash type value
	hp->hashType = sdoReadUInt(sdor);

	// Make sure we have a byte array to resize
	if (hp->hash == NULL) {
		hp->hash = sdoByteArrayAlloc(8);
		if (!hp->hash) {
			LOG(LOG_ERROR, "Alloc failed \n");
			return 0;
		}
	}

	// LOG(LOG_ERROR, "sdoHashRead next char: '%c'\n",
	// sdor->b.block[sdor->b.cursor+1]);

	/* Get incoming B64 string length (it must be a multiple of 4) */
	b64LenReported = sdoReadStringSz(sdor);
	if ((b64LenReported <= 0) || (b64LenReported % 4 != 0)) {
		LOG(LOG_ERROR, "Invalid input B64 string!\n");
		return 0;
	}

	/* Calculated expected B64 length using binary length reported */
	// Calculate b64Len to read the buffer.
	int b64Len = binToB64Length(mbinLenReported);
	if (b64LenReported != b64Len) {
		LOG(LOG_ERROR, "Incoming B64 string length is not proportional "
			       "to binary length reported!\n");
		return 0;
	}

	// TODO: Introduction of a check wud be needed : (b64Len != 0)
	// LOG(LOG_ERROR, "sdoHashRead : %d\n", binLen);
	// Allocate 3 bytes extra for max probable decodaed output
	// Resize the byte array buffer to required length

	if (mbinLenReported &&
	    sdoBitsResize(hp->hash, mbinLenReported + 3) == false) {
		sdoByteArrayFree(hp->hash);
		LOG(LOG_ERROR, "SDOBitsResize failed\n");
		return 0;
	}
	// LOG(LOG_ERROR, "Hash resized to match, len: %d\n",
	// hp->hash->byteSz);

	// Convert buffer from base64 to binary
	int wasRead = sdoReadByteArrayField(sdor, b64Len, hp->hash->bytes,
					    hp->hash->byteSz);

	// LOG(LOG_ERROR, "Byte array read, wasRead : %d, byteSz: %d\n",
	// wasRead, hp->hash->byteSz);
	// char dbuf[128];
	// LOG(LOG_ERROR, "Buf : %s\n", sdoByteArrayToString(hp->hash, dbuf,
	// 128));

	hp->hash->byteSz = wasRead;

	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		return 0;
	}
	return wasRead;
}

/**
 * Write the hash type
 * @param sdow - pointer to the output struct of type JSON message
 * @param hp - pointer to the struct of type hash
 * @return none
 */
void sdoHashWrite(SDOW_t *sdow, SDOHash_t *hp)
{
	sdoWriteByteArrayOneInt(sdow, hp->hashType, hp->hash->bytes,
				hp->hash->byteSz);
}

/**
 * Write out a NULL value hash
 * @param sdow - pointer to the output buffer
 * @return none
 */
void sdoHashNullWrite(SDOW_t *sdow)
{
	if (!sdow)
		return;
	sdoWriteByteArrayOneInt(sdow, SDO_CRYPTO_HASH_TYPE_NONE, NULL, 0);
}

//------------------------------------------------------------------------------
// Key Exchange Routines
//

#if 0
/**
 * Internal API
 */
SDOKeyExchange_t *SDOKeyExAlloc()
{
	return (SDOKeyExchange_t *)sdoByteArrayAlloc(8);
}

/**
 * Internal API
 */
SDOKeyExchange_t *SDOKeyExAllocWith(int size, uint8_t *content)
{
	return sdoByteArrayAllocWithByteArray(content, size);
}
#endif

//------------------------------------------------------------------------------
// IP Address Routines
//

/**
 * Allocate the struct of type IP address
 */
SDOIPAddress_t *sdoIPAddressAlloc(void)
{
	SDOIPAddress_t *sdoip = sdoAlloc(sizeof(SDOIPAddress_t));
	if (sdoip == NULL)
		return NULL;
	if (sdoNullIPAddress(sdoip))
		return sdoip;
	else {
		sdoFree(sdoip);
		return NULL;
	}
}

/**
 * Initialize the struct of type IP with the ipv4 details provided
 * @param sdoip - pointer to the struct if type IP
 * @param ipv4 - ipv4 details that has to be initialized with
 */
void sdoInitIPv4Address(SDOIPAddress_t *sdoip, uint8_t *ipv4)
{
	if (!sdoip || !ipv4)
		return;

	sdoip->length = 4;
	if (memset_s(&sdoip->addr[0], sizeof sdoip->addr, 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return;
	}

	if (memcpy_s(&sdoip->addr[0], sdoip->length, ipv4, sdoip->length) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return;
	}
}

#if 0
/**
 * Internal API
 */
void SDOInitIPv6Address(SDOIPAddress_t *sdoip, uint8_t *ipv6)
{
	sdoip->length = 16;
	memcpy(sdoip->addr, ipv6, sdoip->length);
	// memset(&sdoip->addr, 0, sizeof sdoip->addr - sdoip->length);
}

/**
 * Internal API
 */
int SDOIPAddressToMem(SDOIPAddress_t *sdoip, uint8_t *copyto)
{
	memcpy(copyto, &sdoip->addr[0], sdoip->length);
	return sdoip->length;
}
#endif

/**
 * Reset the IP address
 * @param sdoip - pointer to the struct of type IP address which has to be set
 * to
 * '0'
 */
bool sdoNullIPAddress(SDOIPAddress_t *sdoip)
{
	sdoip->length = 0;
	if (memset_s(&sdoip->addr[0], sizeof sdoip->addr, 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return false;
	} else
		return true;
}

/**
 * Conver the IP address to string
 * @param sdoip - pointer to the struct which holds the IP address
 * @param buf - pointer to the converted string
 * @param bufSz - size of the converted string
 * @return pointer to the converted string
 */
char *sdoIPAddressToString(SDOIPAddress_t *sdoip, char *buf, int bufSz)
{
	int n;
	char *buf0 = buf;

	if (!sdoip || !buf)
		return NULL;

	if (sdoip->length == 4) {
		int temp;
		temp = snprintf_s_i(buf, bufSz, "[IPv4:%u", sdoip->addr[0]);

		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n = temp;

		temp = snprintf_s_i(buf + strnlen_s(buf, bufSz), bufSz, ".%u",
				    sdoip->addr[1]);
		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n += temp;

		temp = snprintf_s_i(buf + strnlen_s(buf, bufSz), bufSz, ".%u",
				    sdoip->addr[2]);
		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n += temp;

		temp = snprintf_s_i(buf + strnlen_s(buf, bufSz), bufSz, ".%u]",
				    sdoip->addr[3]);
		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n += temp;

		buf += n;
		bufSz -= n;
	} else if (sdoip->length == 16) {
		if (strncpy_s(buf, bufSz, "[IPv6", bufSz) != 0) {
			LOG(LOG_ERROR, "strcpy() failed!\n");
			return NULL;
		}
		n = strnlen_s(buf, bufSz);

		if (!n || n == bufSz) {
			LOG(LOG_ERROR, "strlen() failed!\n");
			return NULL;
		}

		buf += n;
		bufSz -= n;
		while (n + 7 < bufSz) {
			int temp;

			temp =
			    snprintf_s_i(buf, bufSz, ":%02X", sdoip->addr[n]);

			if (temp < 0) {
				LOG(LOG_ERROR, "snprintf() failed!\n");
				return NULL;
			}
			n = temp;
			temp = snprintf_s_i(buf, bufSz, "%02X",
					    sdoip->addr[n + 1]);

			if (temp < 0) {
				LOG(LOG_ERROR, "snprintf() failed!\n");
				return NULL;
			}

			n += temp;

			buf += n;
			bufSz -= n;
		}
	} else {
		if (snprintf_s_i(buf, bufSz, "[IP?? len:%u]", sdoip->length) <
		    0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
	}
	return buf0;
}

/**
 * read the IP address
 * @param sdor - read IP address
 * @param sdoip - pointer to the struct which holds the IP information
 * @return true if success else false
 */
bool sdoReadIPAddress(SDOR_t *sdor, SDOIPAddress_t *sdoip)
{
	SDOByteArray_t *IP;

	if (!sdor || !sdoip)
		return false;

	IP = sdoByteArrayAllocWithInt(0);
	if (!IP)
		return false;

	if (!sdoRBeginSequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		sdoByteArrayFree(IP);
		return false;
	}

	if (!sdoByteArrayRead(sdor, IP)) {
		sdoByteArrayFree(IP);
		return false;
	}

	sdoip->length = IP->byteSz;
	if (memcpy_s(&sdoip->addr[0], sdoip->length, IP->bytes, IP->byteSz) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}
	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		return false;
	}
	sdoByteArrayFree(IP);
	return true;
}

/**
 * Wrirte the IP address
 * @param sdow - output to which IP is written to
 * @param sdoip - pointer to the struct of type IP address
 * @return none
 */
void sdoWriteIPAddress(SDOW_t *sdow, SDOIPAddress_t *sdoip)
{
	sdoWriteByteArray(sdow, &sdoip->addr[0], sdoip->length);
}

/**
 * Internal API
 */
#if 0
void SDODNSEmpty(SDODNSName_t *b)
{
	if (b->name) {
		sdoFree(b->name);
		b->name = NULL;
	}
	b->length = 0;
}
#endif

/**
 * Read the DNS information
 * @param sdor - pointer to the input information
 */
char *sdoReadDNS(SDOR_t *sdor)
{
	char *buf;
	int len;

	/* read length of DNS */
	len = sdoReadStringSz(sdor);

	buf = sdoAlloc(len + 1);

	if (!buf)
		return NULL;

	sdoReadString(sdor, buf, len + 1);

	if (len == 0) {
		sdoFree(buf);
		return NULL;
	}

	return buf;
}

/**
 * Write the APPID
 * @param sdow - pointer to the written APPID
 */
void sdoAppIDWrite(SDOW_t *sdow)
{
	/* Swap appid to network endianess if needed */
	// TODO: Change to compilation time byteswap
	uint32_t appid = sdoHostToNetLong(APPID);
	/* AppID is always bytes according specification, so we can hardcode it
	 * here */
	sdoWriteByteArrayOneInt(sdow, SDO_APP_ID_TYPE_BYTES, (uint8_t *)&appid,
				sizeof(appid));
}

//------------------------------------------------------------------------------
// Public Key Routines
//

/**
 * Allocate an empty public key
 */
SDOPublicKey_t *sdoPublicKeyAllocEmpty(void)
{
	return sdoAlloc(sizeof(SDOPublicKey_t));
}

/**
 * Allocate public key and initialize
 * @param pkalg - algorithm to be used for public key
 * @param pkenc - public key encoding type
 * @param pklen - publick key length
 * @param pkey - pointer to the public key
 * @return pointer to the public key
 */
SDOPublicKey_t *sdoPublicKeyAlloc(int pkalg, int pkenc, int pklen,
				  uint8_t *pkey)
{
	SDOPublicKey_t *pk = sdoPublicKeyAllocEmpty();
	if (!pk) {
		LOG(LOG_ERROR, "failed to allocate public key structure\n");
		return NULL;
	}
	pk->pkalg = pkalg;
	pk->pkenc = pkenc;
	pk->key1 = sdoByteArrayAllocWithByteArray(pkey, pklen);
	return pk;
}

/**
 * Clone the public key
 * @param pk 0 pointer to the public key that is to be cloned
 * @return pointer to the cloned public key
 */
SDOPublicKey_t *sdoPublicKeyClone(SDOPublicKey_t *pk)
{
	if (pk == NULL)
		return NULL;

	if (!pk->key1 || !pk->pkenc || !pk->pkalg)
		return NULL;

	SDOPublicKey_t *npk = sdoPublicKeyAlloc(
	    pk->pkalg, pk->pkenc, pk->key1->byteSz, pk->key1->bytes);
	if (!npk) {
		LOG(LOG_ERROR, "failed to alloc public key struct\n");
		return NULL;
	}
	if (pk->key2 != NULL) {
		npk->key2 = sdoByteArrayAllocWithByteArray(pk->key2->bytes,
							   pk->key2->byteSz);
	}
	return npk;
}

/**
 * Compares two public keys
 *
 * @param pk1: poniter to input publickey 1
 * @param pk2: poniter to input publickey 2
 * @return
 *        true if both public keys are same else false.
 */
bool sdoComparePublicKeys(SDOPublicKey_t *pk1, SDOPublicKey_t *pk2)
{
	int result_memcmp = 0;

	if (!pk1 || !pk2)
		return false;

	if (!pk1->key1 || !pk2->key1 || !pk1->pkenc || !pk2->pkenc ||
	    !pk1->pkalg || !pk2->pkalg)
		return false;

	if (pk1->pkalg != pk2->pkalg)
		return false;

	if (pk1->pkenc != pk2->pkenc)
		return false;

	if (memcmp_s(pk1->key1->bytes, pk1->key1->byteSz, pk2->key1->bytes,
		     pk2->key1->byteSz, &result_memcmp) ||
	    result_memcmp)
		return false;

	/* X.509 encoded pubkeys only have key1 parameter */
	if (pk1->key2 && pk2->key2) {
		if (memcmp_s(pk1->key2->bytes, pk1->key2->byteSz,
			     pk2->key2->bytes, pk2->key2->byteSz,
			     &result_memcmp) ||
		    result_memcmp)
			return false;
	}
	return true;
}

/**
 * Free the allocated public key
 * @param pk - pointer to the public key that is to be sdoFreed
 */
void sdoPublicKeyFree(SDOPublicKey_t *pk)
{
	if (!pk)
		return;
	sdoByteArrayFree(pk->key1);
	if (pk->key2) {
		sdoByteArrayFree(pk->key2);
	}
	sdoFree(pk);
}

/**
 * Convert he alggorith to string
 * @param alg - type of the algorithm
 * @return pointer to converted algorith string
 */
char *sdoPKAlgToString(int alg)
{
	static char buf[25];
	switch (alg) {
	case SDO_CRYPTO_PUB_KEY_ALGO_NONE:
		return "AlgNONE";
	case SDO_CRYPTO_PUB_KEY_ALGO_RSA:
		return "AlgRSA";
	case SDO_CRYPTO_PUB_KEY_ALGO_EPID_1_1:
		return "AlgEPID11";
	case SDO_CRYPTO_PUB_KEY_ALGO_EPID_2_0:
		return "AlgEPID20";
	}
	if (snprintf_s_i(buf, sizeof buf, "Alg:%u?", alg) < 0) {
		LOG(LOG_ERROR, "snprintf() failed!\n");
		return NULL;
	}
	return buf;
}

/**
 * Convert the encoding type to string
 * @param enc - type encoding
 * @return pointer to the converted encoding type string
 */
char *sdoPKEncToString(int enc)
{
	static char buf[25];
	switch (enc) {
	case SDO_CRYPTO_PUB_KEY_ENCODING_X509:
		return "EncX509";
	case SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP:
		return "EncRSAMODEXP";
	case SDO_CRYPTO_PUB_KEY_ENCODING_EPID:
		return "EncEPID";
	}
	if (snprintf_s_i(buf, sizeof buf, "Enc:%u?", enc) < 0) {
		LOG(LOG_ERROR, "snprintf() failed!\n");
		return NULL;
	}
	return buf;
}

/**
 * Write a full public key to the output buffer
 * @param sdow - output buffer to hold JSON representation
 * @param pk - pointer to the SDOPublicKey_t object
 * @return none
 */
void sdoPublicKeyWrite(SDOW_t *sdow, SDOPublicKey_t *pk)
{
	if (!sdow)
		return;

	sdoWBeginSequence(sdow);
	if (pk == NULL || pk->key1->byteSz == 0) {
		// Write null key (pknull)
		sdoWriteUInt(sdow, 0);
		sdoWriteUInt(sdow, 0);
		sdoWBeginSequence(sdow);
		sdoWriteUInt(sdow, 0);
		sdoWEndSequence(sdow);
		sdoWEndSequence(sdow);
		return;
	}
	// LOG(LOG_ERROR, "------- pk is %lu bytes long\n",
	// pk->key1->byteSz);
	sdoWriteUInt(sdow, pk->pkalg);
	sdoWriteUInt(sdow, pk->pkenc);
	sdoWriteByteArray(sdow, pk->key1->bytes, pk->key1->byteSz);
	if (pk->pkenc == SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP) {
		sdoWriteByteArray(sdow, pk->key2->bytes, pk->key2->byteSz);
	}
	sdoWEndSequence(sdow);
	// LOG(LOG_ERROR, "SDOWritePublicKeyStub: pklen:%u pkalg:%u pkenc:%u
	// \n",
	// pk->bits.byteSz, pk->pkalg, pk->pkenc);
}

/**
 * Convert the public key to string
 * @param pk - pointer to the public key
 * @param buf - pointer to the converted string
 * @param bufsz - size of the converted string
 * @return pointer to the converted string
 */
char *sdoPublicKeyToString(SDOPublicKey_t *pk, char *buf, int bufsz)
{
	char *buf0 = buf;
	int n = 0;
	char tempChar[20];
	char *charPtr;

	if (!pk || !buf)
		return NULL;

	charPtr = tempChar;

	if (strncpy_s(buf, bufsz, "[SDOPublicKey", bufsz) != 0) {
		LOG(LOG_ERROR, "strcpy() failed!\n");
		return NULL;
	}

	n = strnlen_s(buf, bufsz);

	if (!n || n == bufsz) {
		LOG(LOG_ERROR, "strlen() failed!\n");
		return NULL;
	}

	buf += n;
	bufsz -= n;

	charPtr = sdoPKAlgToString(pk->pkalg);

	if (!charPtr)
		return NULL;

	if (strncpy_s(buf, bufsz, " alg:", bufsz) != 0) {
		LOG(LOG_ERROR, "strcpy() failed!\n");
		return NULL;
	}
	if (strcat_s(buf, bufsz, charPtr) != 0) {
		LOG(LOG_ERROR, "strcat() failed!\n");
		return NULL;
	}
	n = strnlen_s(" alg:", bufsz) + strnlen_s(charPtr, bufsz);

	if (!n || n == bufsz) {
		LOG(LOG_ERROR, "strlen() failed!\n");
		return NULL;
	}

	buf += n;
	bufsz -= n;

	charPtr = sdoPKEncToString(pk->pkenc);

	if (!charPtr)
		return NULL;

	if (strncpy_s(buf, bufsz, " enc:", bufsz) != 0) {
		LOG(LOG_ERROR, "strcpy() failed!\n");
		return NULL;
	}

	if (strcat_s(buf, bufsz, charPtr) != 0) {
		LOG(LOG_ERROR, "strcat() failed!\n");
		return NULL;
	}

	n = strnlen_s(" enc:", bufsz) + strnlen_s(charPtr, bufsz);

	if (!n || n == bufsz) {
		LOG(LOG_ERROR, "strlen() failed!\n");
		return NULL;
	}

	buf += n;
	bufsz -= n;

	if (pk->pkenc == SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP) {
		char strkey1[] = "\nkey1: ";

		if (strcat_s(buf, SDO_MAX_STR_SIZE, strkey1) != 0) {
			LOG(LOG_ERROR,
			    "Owner's PK(RSA_key1) strcat failed !!'\n");
			return NULL;
		}

		n = strnlen_s(strkey1, SDO_MAX_STR_SIZE);
		buf += n;
		bufsz -= n;

		sdoByteArrayToString(pk->key1, buf, bufsz);
		n = strnlen_s(buf, SDO_MAX_STR_SIZE);
		if (!n || n == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR,
			    "Owner's PK(RSA_key1) is either 'NULL' or "
			    "'isn't NULL terminated'\n");
			return NULL;
		}
		buf += n;
		bufsz -= n;

		char strkey2[] = "\nkey2: ";

		if (strcat_s(buf, SDO_MAX_STR_SIZE, strkey2) != 0) {
			LOG(LOG_ERROR,
			    "Owner's PK(RSA_key2) strcat failed !!'\n");
			return NULL;
		}

		n = strnlen_s(strkey2, SDO_MAX_STR_SIZE);
		buf += n;
		bufsz -= n;

		if (pk->key2 != NULL) {
			sdoByteArrayToString(pk->key2, buf, bufsz);
			n = strnlen_s(buf, SDO_MAX_STR_SIZE);

			if (!n || n == SDO_MAX_STR_SIZE) {
				LOG(LOG_ERROR,
				    "Owner's PK(RSA_key2) is either 'NULL' "
				    "or 'isn't NULL terminated'\n");
				return NULL;
			}

			buf += n;
			bufsz -= n;
		} else {
			if (strncpy_s(buf, bufsz, "key2 was NULL", bufsz) !=
			    0) {
				LOG(LOG_ERROR, "strcpy() failed!\n");
				return NULL;
			}

			n = strnlen_s("key2 was NULL", bufsz);

			if (!n || n == bufsz) {
				LOG(LOG_ERROR, "strlen() failed!\n");
				return NULL;
			}

			buf += n;
			bufsz -= n;
		}
	} else {
		sdoByteArrayToString(pk->key1, buf, bufsz);
		n = strnlen_s(buf, SDO_MAX_STR_SIZE);

		if (!n || n == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "buf(non_RSA_key1) is either 'NULL' or "
				       "'isn't NULL terminated'\n");
			return NULL;
		}

		buf += n;
		bufsz -= n;
	}
	if (bufsz > 1) {
		*buf++ = ']';
		*buf = 0;
	}
	return buf0;
}

/**
 * Read the public key information
 * @param sdor - read public key info
 * return pointer to the struct of type public key if success else error code
 */
SDOPublicKey_t *sdoPublicKeyRead(SDOR_t *sdor)
{
	SDOPublicKey_t *pk;
	int pkalg, pkenc;

	if (!sdor)
		return NULL;

	if (!sdoRBeginSequence(sdor))
		goto err;
	pkalg = sdoReadUInt(sdor);
	pkenc = sdoReadUInt(sdor);

	if (!pkalg || !pkenc)
		goto err;

	if (!sdoRBeginSequence(sdor))
		goto err;

	// There will now be one or two Bytearray values
	SDOByteArray_t *baK1 = sdoByteArrayAllocWithInt(0);
	if (!baK1 || (sdoByteArrayRead(sdor, baK1) == 0)) {
		sdoByteArrayFree(baK1);
		goto err;
	}

	pk = sdoPublicKeyAllocEmpty(); // Create a Public Key
	if (!pk) {
		sdoByteArrayFree(baK1);
		goto err;
	}

	pk->pkalg = pkalg;
	pk->pkenc = pkenc;
	pk->key1 = baK1;

	LOG(LOG_DEBUG, "PublicKeyRead Key1 read, %zu bytes\n",
	    pk->key1->byteSz);

	// Check to see if the second key is needed
	// LOG(LOG_ERROR, "PK @ %d Next c '%c'\n", sdor->b.cursor,
	// sdoRPeek(sdor));

	if (sdoRPeek(sdor) != ']') {
		sdor->needComma = true;
		SDOByteArray_t *baK2 = sdoByteArrayAllocWithInt(0);
		// Read second key
		if (!baK2 || sdoByteArrayRead(sdor, baK2) == 0) {
			sdoByteArrayFree(baK2);
			sdoPublicKeyFree(pk);
			goto err;
		} else
			pk->key2 = baK2;

		LOG(LOG_DEBUG, "PublicKeyRead Key2 read, %zu bytes\n",
		    pk->key2->byteSz);
	}
	// LOG(LOG_ERROR, "PK @ %d Next c '%c'\n", sdor->b.cursor,
	// sdoRPeek(sdor));

	if (!sdoREndSequence(sdor))
		LOG(LOG_DEBUG, "Not at end of inner PK sequence\n");
	// LOG(LOG_ERROR, "PK @ %d Next c '%c'\n", sdor->b.cursor,
	// sdoRPeek(sdor));

	if (!sdoREndSequence(sdor))
		LOG(LOG_DEBUG, "Not at end of outer PK sequence\n");
	// LOG(LOG_ERROR, "PK @ %d Next c '%c'\n", sdor->b.cursor,
	// sdoRPeek(sdor));

	sdor->needComma = true;

	LOG(LOG_DEBUG,
	    "PublicKeyRead pkalg: %d. pkenc: %d, key1: %zu, key2: %zu\n",
	    pk->pkalg, pk->pkenc, pk->key1 ? pk->key1->byteSz : 0,
	    pk->key2 ? pk->key2->byteSz : 0);

	return pk;
err:
	sdoRReadAndIgnoreUntilEndSequence(sdor);
	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
	}
	return NULL;
}

//------------------------------------------------------------------------------
// Rendezvous Routines
//

/**
 * Allocate struct of type Rendezvous
 */
SDORendezvous_t *sdoRendezvousAlloc(void)
{
	return sdoAlloc(sizeof(SDORendezvous_t));
}

/**
 * Free the allocated rendezvous struct
 * @param rv - pointer to the struct of type rendezvous
 */
void sdoRendezvousFree(SDORendezvous_t *rv)
{
	if (!rv)
		return;

	if (rv->only != NULL)
		sdoStringFree(rv->only);

	if (rv->ip != NULL)
		sdoFree(rv->ip);

	if (rv->po != NULL)
		sdoFree(rv->po);

	if (rv->pow != NULL)
		sdoFree(rv->pow);

	if (rv->dn != NULL)
		sdoStringFree(rv->dn);

	if (rv->sch != NULL)
		sdoHashFree(rv->sch);

	if (rv->cch != NULL)
		sdoHashFree(rv->cch);

	if (rv->ui != NULL)
		sdoFree(rv->ui);

	if (rv->ss != NULL)
		sdoStringFree(rv->ss);

	if (rv->pw != NULL)
		sdoStringFree(rv->pw);

	if (rv->wsp != NULL)
		sdoStringFree(rv->wsp);

	if (rv->me != NULL)
		sdoStringFree(rv->me);

	if (rv->pr != NULL)
		sdoStringFree(rv->pr);

	if (rv->delaysec != NULL)
		sdoFree(rv->delaysec);

	sdoFree(rv);
}

/**
 * Write a rendezvous object to the output buffer
 * @param sdow - the buffer pointer
 * @param rv - pointer to the rendezvous object to write
 * @return true if written successfully, otherwise false
 */
bool sdoRendezvousWrite(SDOW_t *sdow, SDORendezvous_t *rv)
{
	if (!sdow || !rv)
		return false;

	sdoWBeginSequence(sdow);

	sdow->needComma = false;
	sdoWriteUInt(sdow, rv->numParams);
	sdow->needComma = true;

	sdoWBeginObject(sdow);

	if (rv->only != NULL) {
		sdoWriteTag(sdow, "only");
		sdoWriteStringLen(sdow, rv->only->bytes, rv->only->byteSz);
	}

	if (rv->ip != NULL) {
		sdoWriteTag(sdow, "ip");
		sdoWriteIPAddress(sdow, rv->ip);
	}

	if (rv->po != NULL) {
		sdoWriteTag(sdow, "po");
		sdoWriteUInt(sdow, *rv->po);
	}

	if (rv->pow != NULL) {
		sdoWriteTag(sdow, "pow");
		sdoWriteUInt(sdow, *rv->pow);
	}

	if (rv->dn != NULL) {
		sdoWriteTag(sdow, "dn");
		sdoWriteStringLen(sdow, rv->dn->bytes, rv->dn->byteSz);
	}

	if (rv->sch != NULL) {
		sdoWriteTag(sdow, "sch");
		sdoHashWrite(sdow, rv->sch);
	}

	if (rv->cch != NULL) {
		sdoWriteTag(sdow, "cch");
		sdoHashWrite(sdow, rv->cch);
	}

	if (rv->ui != NULL) {
		sdoWriteTag(sdow, "ui");
		sdoWriteUInt(sdow, *rv->ui);
	}

	if (rv->ss != NULL) {
		sdoWriteTag(sdow, "ss");
		sdoWriteStringLen(sdow, rv->ss->bytes, rv->ss->byteSz);
	}

	if (rv->pw != NULL) {
		sdoWriteTag(sdow, "pw");
		sdoWriteStringLen(sdow, rv->pw->bytes, rv->pw->byteSz);
	}

	if (rv->wsp != NULL) {
		sdoWriteTag(sdow, "wsp");
		sdoWriteStringLen(sdow, rv->wsp->bytes, rv->wsp->byteSz);
	}

	if (rv->me != NULL) {
		sdoWriteTag(sdow, "me");
		sdoWriteStringLen(sdow, rv->me->bytes, rv->me->byteSz);
	}

	if (rv->pr != NULL) {
		sdoWriteTag(sdow, "pr");
		sdoWriteStringLen(sdow, rv->pr->bytes, rv->pr->byteSz);
	}

	if (rv->delaysec != NULL) {
		sdoWriteTag(sdow, "delaysec");
		sdoWriteUInt(sdow, *rv->delaysec);
	}

	sdoWEndObject(sdow);
	sdoWEndSequence(sdow);

	return true;
}

/*
 * This is a lookup on all possible strings
 */
#define BADKEY -1
#define ONLY 1
#define IP 2
#define PO 3
#define POW 4
#define DN 5
#define SCH 6
#define CCH 7
#define UI 8
#define SS 9
#define PW 10
#define WSP 11
#define ME 12
#define PR 13
#define DELAYSEC 14

typedef struct {
	char *key;
	int val;
} t_symstruct;

static t_symstruct lookuptable[] = {{"only", ONLY}, {"ip", IP},
				    {"po", PO},     {"pow", POW},
				    {"dn", DN},     {"sch", SCH},
				    {"cch", CCH},   {"ui", UI},
				    {"ss", SS},     {"pw", PW},
				    {"wsp", WSP},   {"me", ME},
				    {"pr", PR},     {"delaysec", DELAYSEC}};

#define NKEYS (sizeof(lookuptable) / sizeof(t_symstruct))

/**
 * Search the lookuptable for the string passed
 * @param key - key to be searched for
 * @return key if success else error code
 */
int keyfromstring(char *key)
{
	size_t i;
	int res = 1;
	if (!key)
		return BADKEY;

	for (i = 0; i < NKEYS; i++) {
		// t_symstruct *sym = lookuptable + i*sizeof(t_symstruct);
		t_symstruct *sym = &lookuptable[i];
		int symkeylen = strnlen_s(sym->key, SDO_MAX_STR_SIZE);
		if (!symkeylen || symkeylen == SDO_MAX_STR_SIZE) {
			LOG(LOG_DEBUG, "Strnlen Failed");
			continue;
		}
		strcmp_s(sym->key, symkeylen, key, &res);
		if (res == 0) {
			return sym->val;
		}
	}
	LOG(LOG_ERROR, "returns BADKEY\n");

	return BADKEY;
}

/**
 * Read the rendezvous from the input buffer
 * @param sdor - the input buffer object
 * @param rv - pointer to the rendezvous object to fill
 * @return true of read correctly, false otherwise
 */
bool sdoRendezvousRead(SDOR_t *sdor, SDORendezvous_t *rv)
{
	//    SDOBlock_t *sdob = &sdor->b;
	int ret = true;

	if (!sdor || !rv)
		return false;

	if (!sdoRBeginSequence(sdor))
		ret = false;
	int numRvEntries = sdoReadUInt(sdor);

	if (!sdoRBeginObject(sdor))
		ret = false;

	LOG(LOG_DEBUG, "sdoRendezvousRead started\n");

	int index, result;
	size_t keyBufSz = 24;
	char keyBuf[keyBufSz];
	size_t strBufSz = 80;
	char strBuf[strBufSz];

	rv->numParams = 0;

	for (index = 0; index < numRvEntries; index++) {
		if (memset_s(keyBuf, keyBufSz, 0) != 0) {
			LOG(LOG_ERROR, "Memset Failed\n");
			return false;
		}

		int strLen = sdoReadString(sdor, keyBuf, keyBufSz);
		if (strLen == 0 || strLen > (int)keyBufSz)
			ret = false;

		// Parse the values found
		switch (keyfromstring(keyBuf)) {

		case ONLY:
			if (!sdoReadTagFinisher(sdor))
				return false;

			if (memset_s(strBuf, strBufSz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}

			result = sdoReadString(sdor, strBuf, strBufSz);

			if (result == 0 || result > (int)strBufSz)
				return false;

			/*if not for device skip it*/
			int strcmp_result = 0;
			strcmp_s(strBuf, strBufSz, "dev", &strcmp_result);
			if (strcmp_result != 0) {
				sdoRReadAndIgnoreUntilEndSequence(sdor);
				return false;
			}
			rv->only = sdoStringAllocWith(strBuf, result);
			if (!rv->only) {
				LOG(LOG_ERROR, "Rendezvous dev alloc failed\n");
				ret = false;
			}
			break;

		case IP:
			if (!sdoReadTagFinisher(sdor))
				return false;

			rv->ip = sdoIPAddressAlloc();
			if (!rv->ip) {
				LOG(LOG_ERROR, "Rendezvous ip alloc failed\n");
				ret = false;
				break;
			}
			if (sdoReadIPAddress(sdor, rv->ip) != true) {
				LOG(LOG_ERROR, "Read IP Address failed\n");
				ret = false;
			}
			break;

		case PO:
			if (!sdoReadTagFinisher(sdor))
				return false;

			rv->po =
			    sdoAlloc(sizeof(uint32_t)); // Allocate an integer
			if (!rv->po) {
				LOG(LOG_ERROR, "Rendezvous po alloc failed\n");
				ret = false;
				break;
			}
			*rv->po = sdoReadUInt(sdor);
			break;

		/* valid only for OWNER */
		case POW:
			if (!sdoReadTagFinisher(sdor))
				return false;

			rv->pow = sdoAlloc(sizeof(uint32_t));
			if (!rv->pow) {
				LOG(LOG_ERROR, "Rendezvous pow alloc fail\n");
				ret = false;
				break;
			}
			*rv->pow = sdoReadUInt(sdor);
			break;

		case DN:
			if (!sdoReadTagFinisher(sdor))
				return false;

			if (memset_s(strBuf, strBufSz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}

			result = sdoReadString(sdor, strBuf, strBufSz);
			if (result == 0 || result > (int)strBufSz)
				return false;

			rv->dn = sdoStringAllocWith(strBuf, result);
			if (!rv->dn) {
				LOG(LOG_ERROR, "Rendezvous dn alloc failed\n");
				ret = false;
			}
			break;

		case SCH:
			if (!sdoReadTagFinisher(sdor))
				return false;

			rv->sch = sdoHashAllocEmpty();
			if (!rv->sch) {
				LOG(LOG_ERROR, "Rendezvous ss alloc failed\n");
				ret = false;
				break;
			}
			result = sdoHashRead(sdor, rv->sch);
			break;

		case CCH:
			if (!sdoReadTagFinisher(sdor))
				return false;

			rv->cch = sdoHashAllocEmpty();
			if (!rv->cch) {
				LOG(LOG_ERROR, "Rendezvous cch alloc fail\n");
				ret = false;
				break;
			}
			result = sdoHashRead(sdor, rv->cch);
			break;

		case UI:
			if (!sdoReadTagFinisher(sdor))
				return false;

			rv->ui =
			    sdoAlloc(sizeof(uint32_t)); // Allocate an integer
			if (!rv->ui) {
				LOG(LOG_ERROR, "Rendezvous ui alloc failed\n");
				ret = false;
				break;
			}

			*rv->ui = sdoReadUInt(sdor);
			break;

		case SS:
			if (!sdoReadTagFinisher(sdor))
				return false;

			if (memset_s(strBuf, strBufSz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}
			result = sdoReadString(sdor, strBuf, strBufSz);
			if (result == 0 || result > (int)strBufSz)
				return false;

			rv->ss = sdoStringAllocWith(strBuf, result);
			if (!rv->ss) {
				LOG(LOG_ERROR, "Rendezvous ss alloc failed\n");
				ret = false;
			}
			break;

		case PW:
			if (!sdoReadTagFinisher(sdor))
				return false;

			if (memset_s(strBuf, strBufSz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}
			result = sdoReadString(sdor, strBuf, strBufSz);
			if (result == 0 || result > (int)strBufSz)
				return false;

			rv->pw = sdoStringAllocWith(strBuf, result);
			if (!rv->pw) {
				LOG(LOG_ERROR, "Rendezvous pw alloc failed\n");
				ret = false;
			}
			break;

		case WSP:
			if (!sdoReadTagFinisher(sdor))
				return false;

			if (memset_s(strBuf, strBufSz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}
			result = sdoReadString(sdor, strBuf, strBufSz);
			if (result == 0 || result > (int)strBufSz)
				return false;

			rv->wsp = sdoStringAllocWith(strBuf, result);
			if (!rv->wsp) {
				LOG(LOG_ERROR, "Rendezvous wsp alloc fail\n");
				ret = false;
			}
			break;

		case ME:
			if (!sdoReadTagFinisher(sdor))
				return false;

			if (memset_s(strBuf, strBufSz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}
			result = sdoReadString(sdor, strBuf, strBufSz);
			if (result == 0 || result > (int)strBufSz)
				return false;

			rv->me = sdoStringAllocWith(strBuf, result);
			if (!rv->me) {
				LOG(LOG_ERROR, "Rendezvous me alloc failed\n");
				ret = false;
			}
			break;

		case PR:
			if (!sdoReadTagFinisher(sdor))
				return false;

			if (memset_s(strBuf, strBufSz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}

			result = sdoReadString(sdor, strBuf, strBufSz);
			if (result == 0 || result > (int)strBufSz)
				return false;

			rv->pr = sdoStringAllocWith(strBuf, result);
			if (!rv->pr) {
				LOG(LOG_ERROR, "Rendezvous pr alloc failed\n");
				ret = false;
			}
			break;

		case DELAYSEC:
			if (!sdoReadTagFinisher(sdor))
				return false;

			rv->delaysec = sdoAlloc(sizeof(uint32_t));
			if (!rv->delaysec) {
				LOG(LOG_ERROR, "Alloc failed \n");
				return false;
			}
			*rv->delaysec = sdoReadUInt(sdor);
			if (!rv->delaysec) {
				LOG(LOG_ERROR, "Rendezvous ss alloc failed\n");
				ret = false;
			}
			break;

		default:
			LOG(LOG_ERROR,
			    "sdoRendezvousRead : Unknown Entry Type %s\n",
			    keyBuf);
			ret = false; // Abort due to unexpected value for key
			break;
		}
		if (ret == false)
			break;
		rv->numParams++;
	}

	if ((ret == true) && !sdoREndObject(sdor)) {
		LOG(LOG_ERROR, "No End Object\n");
		ret = false;
	}

	if ((ret == true) && !sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		ret = false;
	}

	return ret;
}

#if LOG_LEVEL == LOG_MAX_LEVEL
/**
 * Takes SDORendezvous_t object as input and writes string
 * format data to buffer buf.
 * @param rv - SDORendezvous_t pointer as input buffer.
 * @param buf - char pointer as output buffer buf.
 * @param bufsz - size of buffer buf
 * @return char buffer.
 */
char *sdoRendezvousToString(SDORendezvous_t *rv, char *buf, int bufsz)
{
	char *r = buf;

	sdoIPAddressToString(rv->ip, buf, bufsz);
	int i = strnlen_s(buf, SDO_MAX_STR_SIZE);

	if (!i || i == SDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR,
		    "buf(rv_ip) is either 'NULL' or 'isn't NULL terminated'\n");
		return NULL;
	}

	buf += i;
	bufsz -= i;
	i = snprintf_s_i(buf, bufsz, ":%" PRIu32, *rv->po);

	if (i < 0) {
		LOG(LOG_ERROR, "snprintf() failed!\n");
		return NULL;
	}

	return r;
}
#endif

//------------------------------------------------------------------------------
// RendezvousList Routines
//

/**
 * Allocate an empty SDORendezvousList object to the list.
 * @return an allocated SDORendezvousList object.
 */
SDORendezvousList_t *sdoRendezvousListAlloc(void)
{
	return sdoAlloc(sizeof(SDORendezvousList_t));
}

/**
 * Free all entries  in the list.
 * @param list - the list to sdoFree.
 * @return none
 */
void sdoRendezvousListFree(SDORendezvousList_t *list)
{
	SDORendezvous_t *entry, *next;

	if (list == NULL) {
		return;
	}

	/* Delete all entries. */
	next = entry = list->rvEntries;
	while (entry) {
		next = entry->next;
		sdoRendezvousFree(entry);
		entry = next;
	};

	list->numEntries = 0;
	sdoFree(list);
}

/**
 * Add the rendzvous to the rendzvous list
 * @param list - pointer to the rendzvous list
 * @param rv - pointer to the rendezvous to be added to the list
 * @return number of entries added if success else error code
 */
int sdoRendezvousListAdd(SDORendezvousList_t *list, SDORendezvous_t *rv)
{
	if (list == NULL || rv == NULL)
		return 0;

	LOG(LOG_DEBUG, "Adding to rvlst\n");

	if (list->numEntries == 0) {
		// List empty, add the first entry
		list->rvEntries = rv;
		list->numEntries++;
	} else {
		// already has entries, find the last entry
		SDORendezvous_t *entryPtr, *prevPtr;

		entryPtr = (SDORendezvous_t *)list->rvEntries->next;
		prevPtr = list->rvEntries;
		// Find the last entry
		while (entryPtr != NULL) {
			prevPtr = entryPtr;
			entryPtr = (SDORendezvous_t *)entryPtr->next;
		}
		// Now the entyPtr is pointing to the last entry
		// Add the r entry onto the end
		prevPtr->next = rv;
		list->numEntries++;
	}
	LOG(LOG_DEBUG, "Added to rvlst, %d entries\n", list->numEntries);
	return list->numEntries;
}

/**
 * Function will return the list as per the num passed.
 * @param list - Pointer to the list for the entries.
 * @param num - index of which entry[rventry] to return.
 * @return SDORendezvous_t object.
 */

SDORendezvous_t *sdoRendezvousListGet(SDORendezvousList_t *list, int num)
{
	int index;

	if (list == NULL || list->numEntries == 0 || list->rvEntries == NULL)
		return NULL;

	SDORendezvous_t *entryPtr = list->rvEntries;
	for (index = 0; index < num; index++) {
		entryPtr = entryPtr->next;
	}
	return entryPtr;
}

/**
 * Reads the rendezvous info from the sdor w.r.t the number of entries.
 * @param sdor - Pointer of type SDOR_t as input.
 * @param list- Pointer to the SDORendezvousList_t list to be filled.
 * @return true if reads correctly ,else false
 */

int sdoRendezvousListRead(SDOR_t *sdor, SDORendezvousList_t *list)
{
	if (!sdor || !list)
		return false;

	if (!sdoRBeginSequence(sdor))
		return false;
	// Find out how many entries we should expect
	int numRvs = sdoReadUInt(sdor);
	LOG(LOG_DEBUG, "There should be %d entries in the rvlst\n", numRvs);

	int index;
	for (index = 0; index < numRvs; index++) {
		LOG(LOG_DEBUG, "rvIndex %d\n", index);

		// Read each rv entry and add to the rv list
		SDORendezvous_t *rvEntry = sdoRendezvousAlloc();
		LOG(LOG_DEBUG, "New rv allocated %p\n", rvEntry);

		if (sdoRendezvousRead(sdor, rvEntry))
			sdoRendezvousListAdd(list, rvEntry);
		else {
			sdoRendezvousFree(rvEntry);
		}
	}
	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR,
		    "sdoRendezvousListRead : Final sequence not found\n");
		return false;
	}
	LOG(LOG_DEBUG, "sdoRendezvousListRead read\n");
	return true;
}

/**
 * Writes out the entire Rendezvous list as sequences inside a sequence.
 * @param sdow - Pointer of type sdow to be filled.
 * @param list- Pointer to the SDORendezvousList_t list from which sdow will be
 * filled w.r.t numEntries specified in the list.
 * @return true if writes correctly ,else false
 */

bool sdoRendezvousListWrite(SDOW_t *sdow, SDORendezvousList_t *list)
{
	if (!sdow || !list)
		return false;

	sdoWBeginSequence(sdow);
	sdoWriteUInt(sdow, list->numEntries);

	int index;
	sdow->needComma = true;
	for (index = 0; index < list->numEntries; index++) {
		SDORendezvous_t *entry_Ptr = sdoRendezvousListGet(list, index);
		if (entry_Ptr == NULL) {
			continue;
		}
		sdoRendezvousWrite(sdow, entry_Ptr);
	}
	sdoWEndSequence(sdow);

	return true;
}

//------------------------------------------------------------------------------
// AES Encrypted Message Body Routines
//

/**
 * Allocate an empty AES encrypted Message Body object
 * @return an allocated AES Encrypted Message Body object
 */
SDOEncryptedPacket_t *sdoEncryptedPacketAlloc(void)
{
	return sdoAlloc(sizeof(SDOEncryptedPacket_t));
}

/**
 * Free an AES Encrypted Message Body object
 * @param pkt - the object to sdoFree
 * @return none
 */
void sdoEncryptedPacketFree(SDOEncryptedPacket_t *pkt)
{
	if (pkt == NULL) {
		return;
	}
	sdoByteArrayFree(pkt->emBody);
	sdoHashFree(pkt->hmac);
	sdoByteArrayFree(pkt->ctString);
	sdoFree(pkt);
}

/**
 * Read an Encrypted Message Body object from the SDOR buffer
 * @param sdor - pointer to the character buffer to parse
 * @return a newly allocated SDOEcnryptedPacket object if successful, otherwise
 * NULL
 */
SDOEncryptedPacket_t *sdoEncryptedPacketRead(SDOR_t *sdor)
{
	SDOEncryptedPacket_t *pkt = NULL;

	if (!sdor)
		goto error;

	if (!sdoRBeginObject(sdor)) {
		LOG(LOG_ERROR, "Object beginning not found\n");
		goto error;
	}
	sdor->needComma = false;

	// Expect "ct" tag
	if (!sdoReadExpectedTag(sdor, "ct")) {
		// Very bad, must have the "ct" tag
		LOG(LOG_ERROR, "sdoEncryptedPacketRead : Not a valid "
			       "Encrypted Packet\n");
		goto error;
	}

	if (!sdoRBeginSequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		goto error;
	}

	// Allocate the data structures
	pkt = sdoEncryptedPacketAlloc();
	if (!pkt) {
		LOG(LOG_ERROR, "Out of memory for packet\n");
		goto error;
	}

	pkt->emBody = sdoByteArrayAlloc(0);
	if (!pkt->emBody) {
		LOG(LOG_ERROR, "Out of memory for emBody\n");
		goto error;
	}

	/* Read the buffer and populate the required structs */
	if (!sdoByteArrayReadWithType(sdor, pkt->emBody, &pkt->ctString,
				      pkt->iv)) {
		LOG(LOG_ERROR, "Byte-array read failed!\n");
		goto error;
	}

	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		goto error;
	}

	sdor->needComma = true;

	pkt->hmac = sdoHashAllocEmpty();
	if (!pkt->hmac)
		goto error;

	/* Read the HMAC */
	/* Expect "hmac" tag */
	if (!sdoReadExpectedTag(sdor, "hmac")) {
		/* Very bad, must have the "hmac" tag */
		LOG(LOG_ERROR,
		    "sdoEncryptedPacketRead : Did not find 'hmac' tag\n");
		goto error;
	}

	if (!sdoRBeginSequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		goto error;
	}

	/*number of bytes of hmac */
	uint32_t hmac_size = sdoReadUInt(sdor);

	int b64Len = binToB64Length(hmac_size);

	if (pkt->hmac->hash == NULL) {
		pkt->hmac->hash = sdoByteArrayAlloc(8);
		if (!pkt->hmac->hash) {
			LOG(LOG_ERROR, "Alloc failed \n");
			goto error;
		}
	}

	// Allocate 3 bytes extra for max probable decodaed output
	// Resize the byte array buffer to required length
	if (hmac_size &&
	    sdoBitsResize(pkt->hmac->hash, hmac_size + 3) == false) {
		sdoByteArrayFree(pkt->hmac->hash);
		LOG(LOG_ERROR, "SDOBitsResize failed\n");
		return 0;
	}

	/* Convert buffer from base64 to binary */
	if (0 == sdoReadByteArrayField(sdor, b64Len, pkt->hmac->hash->bytes,
				       pkt->hmac->hash->byteSz)) {
		LOG(LOG_ERROR, "Unable to read hmac\n");
		goto error;
	}

	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		goto error;
	}

	pkt->hmac->hash->byteSz = 32;
	if (!sdoREndObject(sdor)) {
		LOG(LOG_ERROR, "Object end not found\n");
		goto error;
	}

	return pkt;

error:
	sdoEncryptedPacketFree(pkt);
	return NULL;
}

/**
 * Read the IV
 * @param pkt - pointer to the struct of type packet
 * @param ps_iv - pointer to the read IV
 * @param last_pkt - pointer of type SDOEncryptedPacket_t
 * @return true if success else false
 */
bool sdoGetIV(SDOEncryptedPacket_t *pkt, SDOIV_t *ps_iv,
	      SDOEncryptedPacket_t *last_pkt)
{
	uint32_t iv_ctr_ntohl;

	if (!pkt || !ps_iv)
		return false;

	iv_ctr_ntohl = sdoNetToHostLong(ps_iv->ctr_dec);
	if (memcpy_s(pkt->iv, AES_IV, ps_iv->ctr_iv, AES_CTR_IV) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}

	/* Set the last 4 bytes */
	if (memcpy_s(pkt->iv + AES_CTR_IV, AES_IV - AES_CTR_IV, &iv_ctr_ntohl,
		     AES_CTR_IV_COUNTER) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}

	/* Might not be needed if we get ctr in each packet */
	if (last_pkt != NULL)
		ps_iv->ctr_dec += (pkt->emBody->byteSz + last_pkt->offset) /
				  SDO_AES_BLOCK_SIZE;
	else
		ps_iv->ctr_dec += pkt->emBody->byteSz / SDO_AES_BLOCK_SIZE;
	return true;
}

/**
 * Write the IV
 * @param pkt - pointer to the struct of type packet
 * @param ps_iv - pointer to the struct of type IV
 * @param len - written length
 * @return true if success else false
 */
bool sdoWriteIV(SDOEncryptedPacket_t *pkt, SDOIV_t *ps_iv, int len)
{
	uint32_t iv_ctr_ntohl = 0;

	if (!pkt || !ps_iv)
		return false;

	iv_ctr_ntohl = sdoNetToHostLong(ps_iv->ctr_enc);
	if (memcpy_s(pkt->iv, AES_IV, ps_iv->ctr_iv, AES_CTR_IV) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}

	if (memcpy_s(pkt->iv + AES_CTR_IV, AES_IV - AES_CTR_IV, &iv_ctr_ntohl,
		     AES_CTR_IV_COUNTER) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}

	ps_iv->pktCount += len;
	ps_iv->ctr_enc = ps_iv->pktCount / SDO_AES_BLOCK_SIZE;
	return true;
}

/**
 * Write out an Encrypted Message Body object to the sdow buffer
 * @param sdow - Output buffer to write the JASON packet representation
 * @param pkt - the packet to be written out
 * @return none
 */
void sdoEncryptedPacketWrite(SDOW_t *sdow, SDOEncryptedPacket_t *pkt)
{
	if (!sdow || !pkt)
		return;

	sdoWBeginObject(sdow);
	/* Write the Encrypted Message Block data */
	if (pkt->emBody && pkt->emBody->byteSz) {
		sdoWriteTag(sdow, "ct");

		sdoWriteByteArrayTwoInt(sdow, pkt->iv, AES_IV,
					pkt->emBody->bytes,
					pkt->emBody->byteSz);

	} else {
		sdoWriteTag(sdow, "ct");
		sdoWriteString(sdow, "");
	}

	/* Write the Encrypted Message Block HMAC */
	sdoWriteTag(sdow, "hmac");
	if (pkt->hmac != NULL) {

		sdoWriteByteArray(sdow, pkt->hmac->hash->bytes,
				  pkt->hmac->hash->byteSz);

	} else {
		/* HMAC was NULL, do not crash... */
		sdoHashNullWrite(sdow);
	}
	sdoWEndObject(sdow);
}

#if 0
/**
 * Make a string representation of the encrypted packet
 * @param pkt - pointer to the packet to expose
 * @param buf - pointer to the start of the character buffer to fill
 * @param bufsz - the size of the destination buffer
 * @return pointer to the buffer filled
 */
char *SDOEncryptedPacketToString(SDOEncryptedPacket_t *pkt, char *buf, int bufsz)
{
	char *buf0 = buf;
	int n = 0;
	memset(buf, 0, bufsz);

	n = snprintf(buf, bufsz, "[Encrypted Message Body\n");
	buf += n;
	bufsz -= n;

	//    // Write out the start of buffer counter
	//	n = snprintf(buf, bufsz, "blockStart: %d\n", pkt->blockStart);
	//	buf += n; bufsz -= n;

	// Write out the Encrypted Body byte array
	if (pkt->emBody != NULL) {
		char strkey1[] = "Encrypted Body: ";
		strcat(buf, strkey1);
		n = strlen(strkey1);
		buf += n;
		bufsz -= n;

		sdoByteArrayToString(pkt->emBody, buf, bufsz);
		n = strlen(buf);
		buf += n;
		bufsz -= n;
	} else {
		char strkey1[] = "Encrypted Body: NULL";
		strcat(buf, strkey1);
		n = strlen(strkey1);
		buf += n;
		bufsz -= n;
	}

	// Write out the HMAC
	if (pkt->emBody != NULL) {
		char strkey1[] = "\nHMAC of Unencrypted Body: ";
		strcat(buf, strkey1);
		n = strlen(strkey1);
		buf += n;
		bufsz -= n;

		sdoHashToString(pkt->hmac, buf, bufsz);
		n = strlen(buf);
		buf += n;
		bufsz -= n;
	} else {
		char strkey1[] = "\nHMAC of Unencrypted Body: NULL";
		strcat(buf, strkey1);
		n = strlen(strkey1);
		buf += n;
		bufsz -= n;
	}

	if (bufsz > 1) {
		*buf++ = ']';
		*buf = 0;
	}
	return buf0;
}
#endif

/**
 * Take in an EncryptedPacket object and end up with it represented
 * cleartext in the sdor buffer.  This will allow the data to be parsed
 * for its content.
 * @param sdor - pointer to the sdor object to fill
 * @param pkt - Pointer to the Encrypted packet pkt that has to be processed.
 * @param iv - pointer to the IV struct
 * @return true if all goes well, otherwise false
 */
bool sdoEncryptedPacketUnwind(SDOR_t *sdor, SDOEncryptedPacket_t *pkt,
			      SDOIV_t *iv)
{
	bool ret = true;
	SDOString_t *cleartext = NULL;

	// Decrypt the Encrypted Body
	if (!sdor || !pkt || !iv) {
		LOG(LOG_ERROR,
		    "sdoEncryptedPacketUnwind : Invalid Input param\n");
		ret = false;
		goto err;
	}
	cleartext = sdoStringAlloc();

	if (cleartext == NULL) {
		ret = false;
		goto err;
	}

	/* New iv is used for each new decryption which comes from pkt*/
	if (0 != aes_decrypt_packet(pkt, cleartext)) {
		ret = false;
		goto err;
	}

	/* Reset the pointers */
	sdoRFlush(sdor);
	SDOBlock_t *sdob = &sdor->b;

	/* Adjust the buffer for the clear text */
	sdoResizeBlock(sdob, cleartext->byteSz);
	/* Copy the cleartext to the sdor buffer */
	if (memcpy_s(sdob->block, cleartext->byteSz, cleartext->bytes,
		     cleartext->byteSz) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		ret = false;
		goto err;
	}

	sdob->blockSize = cleartext->byteSz;
	sdor->haveBlock = true;
err:
	if (pkt)
		sdoEncryptedPacketFree(pkt);
	if (cleartext)
		sdoStringFree(cleartext);
	return ret;
}

/**
 * Take the cleartext packet contained in the sdow buffer and convert it
 * to an Encrypted Message Body in the sdow buffer
 * @param sdow - pointer to the message buffer
 * @param type - message type
 * @param iv - Pointer to the iv to fill Encrypted Packet pkt.
 * @return true if all goes well, otherwise false
 */
bool sdoEncryptedPacketWindup(SDOW_t *sdow, int type, SDOIV_t *iv)
{
	if (!sdow || !iv)
		return false;

	SDOBlock_t *sdob = &sdow->b;

	SDOEncryptedPacket_t *pkt = sdoEncryptedPacketAlloc();

	if (!pkt) {
		LOG(LOG_ERROR, "Not encrypted\n");
		return false;
	}

	if (0 != aes_encrypt_packet(pkt, sdob->block, sdob->blockSize)) {
		sdoEncryptedPacketFree(pkt);
		return false;
	}

	// At this point we have a valid Encrypted Message Body packet
	// Remake the output buffer, abandoning the cleartext
	sdoWNextBlock(sdow, type);
	sdoEncryptedPacketWrite(sdow, pkt);

	if (pkt)
		sdoEncryptedPacketFree(pkt);

	return true;
}

//------------------------------------------------------------------------------
// Write Signature Routines
//

/**
 * Begin the signature
 * @param sdow - pointe to the output buffer
 * @param sig - pointer to the struct of type signature
 * @param pk - pointer to the struct of type public key
 */
bool sdoBeginWriteSignature(SDOW_t *sdow, SDOSig_t *sig, SDOPublicKey_t *pk)
{
	if (!sdow)
		return false;

	if (memset_s(sig, sizeof *sig, 0)) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return false;
	}
	sig->pk = pk;
	sdoWBeginObject(sdow);
	sdoWriteTag(sdow, "bo");
	sig->sigBlockStart = sdow->b.cursor;
	return true;
}

/**
 * Write the signature to the buffer
 * @param sdow - pointer to the output buffer
 * @param sig - pointer to the struct of type signature
 */
bool sdoEndWriteSignature(SDOW_t *sdow, SDOSig_t *sig)
{
	int sigBlockEnd;
	int sigBlockSz;
	SDOByteArray_t *sigtext = NULL;
	SDOSigInfo_t *eA;
	SDOPublicKey_t *publickey;

	if (!sdow || !sig) {
		LOG(LOG_ERROR, "Invalid arguments\n");
		return false;
	}

	sigBlockEnd = sdow->b.cursor;
	sigBlockSz = sigBlockEnd - sig->sigBlockStart;

	/* Turn the message block into a zero terminated string */
	sdoResizeBlock(&sdow->b, sdow->b.cursor + 1);
	sdow->b.block[sdow->b.cursor] = 0;

	uint8_t *adaptedMessage = sdoAlloc(sigBlockSz);
	if (memcpy_s(adaptedMessage, sigBlockSz,
		     &(sdow->b.block[sig->sigBlockStart]), sigBlockSz) != 0) {
		LOG(LOG_ERROR, "Memcpy failed\n");
		sdoFree(adaptedMessage);
		return false;
	}

	size_t adaptedMessage_len = sigBlockSz;

	if (0 != sdoDeviceSign(adaptedMessage, adaptedMessage_len, &sigtext)) {
		LOG(LOG_ERROR, "ECDSA signing failed!\n");
		sdoFree(adaptedMessage);
		sdoByteArrayFree(sigtext);
		return false;
	}
	hexdump("Adapted message", (char *)adaptedMessage, adaptedMessage_len);

	/* Release the allocated memory */
	sdoFree(adaptedMessage);

	/* ========================================================= */

	/*Write GID to represent EPID public key*/
	sdoWriteTag(sdow, "pk");

	eA = sdoGetDeviceSigInfoeA();
	publickey = eA ? eA->pubkey : NULL;

	sdoPublicKeyWrite(sdow, publickey);
	sdoWriteTag(sdow, "sg");
	sdoWriteByteArray(sdow, sigtext->bytes, sigtext->byteSz);
	sdoWEndObject(sdow);
	sdoBitsFree(sigtext);
	return true;
}

/**
 * HMAC processing start of a block to HMAC
 * @param sdor - pointer to the input buffer
 * @param sigBlockStart - pointer to the signature starting block
 * @return true if proper header present, otherwise false
 */
bool sdoBeginReadHMAC(SDOR_t *sdor, int *sigBlockStart)
{
	if (!sdor)
		return false;

	if (!sdoReadExpectedTag(sdor, "oh")) {
		LOG(LOG_ERROR, "No oh\n");
		return false;
	}
	*sigBlockStart = sdor->b.cursor;

	return true;
}

/**
 * Create the HMAC using our secret
 * @param sdor - input buffer
 * @param hmac - pointer to the hash object to use
 * @param sigBlockStart - pointer to the signature starting block
 * @return true if proper header present, otherwise false
 */
bool sdoEndReadHMAC(SDOR_t *sdor, SDOHash_t **hmac, int sigBlockStart)
{
	// Make the ending calculation for the buffer to sign

	if (!sdor || !hmac)
		return false;

	if (!sdoREndObject(sdor)) {
		return false;
	}
	int sigBlockEnd = sdor->b.cursor;
	int sigBlockSz = sigBlockEnd - sigBlockStart;
	uint8_t *plainText = sdoRGetBlockPtr(sdor, sigBlockStart);

	if (plainText == NULL) {
		LOG(LOG_ERROR, "sdoRGetBlockPtr() returned null, "
			       "sdoEndReadHMAC() failed !!");
		return false;
	}

	// Display the block to be signed
	uint8_t saveByte;
	saveByte = plainText[sigBlockSz];
	plainText[sigBlockSz] = 0;
	LOG(LOG_DEBUG, "sdoEndReadHMAC.plainText: %s\n", plainText);
	plainText[sigBlockSz] = saveByte;
#if !defined(DEVICE_TPM20_ENABLED)
	char buf[256];
	LOG(LOG_DEBUG, "sdoEndReadHMAC.key: %s\n",
	    sdoBitsToString(*getOVKey(), "Secret:", buf, sizeof(buf)) ? buf
								      : "");
#endif
	// Create the HMAC
	*hmac =
	    sdoHashAlloc(SDO_CRYPTO_HMAC_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
	if (!*hmac) {
		return false;
	}

	if (0 != sdoDeviceOVHMAC(plainText, sigBlockSz, (*hmac)->hash->bytes,
				 (*hmac)->hash->byteSz)) {
		sdoHashFree(*hmac);
		return false;
	}

	return true;
}

/**
 * Signature processing.  Call this to mark the place before reading
 * the signature body.  Then call sdoEndReadSignature* afterwards.
 * The same SDOSig_t object must be presented to both procedures.
 *
 * @param sdor - pointer to the input buffer
 * @param sig - pointer to the signature object to use
 * @return true if proper header present, otherwise false
 */
bool sdoBeginReadSignature(SDOR_t *sdor, SDOSig_t *sig)
{
	if (!sdor || !sig)
		return false;

	if (!sdoRBeginObject(sdor))
		return false;
	if (!sdoReadExpectedTag(sdor, "bo"))
		return false;
	sig->sigBlockStart = sdor->b.cursor;
	return true;
}

#if 0
/**
 * Simple Signature processing, yes or no, based on transmitted
 * public key.  The sig pointer must be the same one used for
 * the corresponding BEGIN call
 * @param sdor - pointer to the input buffer
 * @param sig - pointer to the signature object to use
 * @returns true if parsing is correct and signature verifies.
 */
bool sdoEndReadSignature(SDOR_t *sdor, SDOSig_t *sig)
{
	return sdoEndReadSignatureFull(sdor, sig, NULL);
}
#endif

/**
 * Full Signature processing:
 * Any of these may be NULL, in which case it is ignored.
 * @param sdor - input buffer to check
 * @param sig - object holds offset of block start and holds returned signature
 * @param getpk - returns verify public key (caller must sdoFree)
 * @return true if verification successful, otherwise false
 */
bool sdoEndReadSignatureFull(SDOR_t *sdor, SDOSig_t *sig,
			     SDOPublicKey_t **getpk)
{
	// Save buffer at the end of the area to be checked
	int sigBlockEnd;
	int sigBlockSz;
	uint8_t *plainText;
	SDOPublicKey_t *pk;
	bool r = false;
	int ret;

	if (!sdor || !sig || !getpk)
		return false;

	sigBlockEnd = sdor->b.cursor;
	sigBlockSz = sigBlockEnd - sig->sigBlockStart;
	plainText = sdoRGetBlockPtr(sdor, sig->sigBlockStart);

	if (plainText == NULL) {
		LOG(LOG_ERROR, "sdoRGetBlockPtr() returned null, "
			       "sdoEndReadSignatureFull() failed !!");
		return false;
	}

	if (!sdoReadExpectedTag(sdor, "pk"))
		return false;
	// LOG(LOG_ERROR, "this key\n");
	pk = sdoPublicKeyRead(sdor);
	if (pk == NULL) {
		LOG(LOG_ERROR, "sdoEndReadSignatureFull: Could not read \"pk\" "
			       "in signature\n");
		return false;
	}
	// Copy the read public key to the signature object
	sig->pk = pk;

	// LOG(LOG_ERROR, "Next char: '%c'\n", sdoRPeek(sdor));

	if (!sdoReadExpectedTag(sdor, "sg"))
		return false;

	if (!sdoRBeginSequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		return false;
	}
	// These bytes will be thrown away, some issue with zero length
	sig->sg = sdoByteArrayAlloc(1);
	if (!sig->sg) {
		ret = -1;
		goto result;
	}

	// Read the signature to the signature object
	if (!sdoByteArrayRead(sdor, sig->sg)) {
		sdoByteArrayFree(sig->sg);
		ret = -1;
		goto result;
	}
	// LOG(LOG_ERROR, "signature %lu bytes\n", sig->sg->byteSz);

	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		sdoByteArrayFree(sig->sg);
		return false;
	}

	if (!sdoREndObject(sdor)) {
		sdoByteArrayFree(sig->sg);
		return false;
	}

	// Buffer read, all objects consumed, start verify

	// Check the signature
	uint8_t saveByte;
	char buf[1024];
	bool signature_verify = false;

	saveByte = plainText[sigBlockSz];
	plainText[sigBlockSz] = 0;
	LOG(LOG_DEBUG, "sdoEndReadSignature.SigText: %s\n", plainText);
	plainText[sigBlockSz] = saveByte;
	LOG(LOG_DEBUG, "sdoEndReadSignature.PK: %s\n",
	    sdoPublicKeyToString(pk, buf, sizeof buf) ? buf : "");

	ret = sdoOVVerify(plainText, sigBlockSz, sig->sg->bytes,
			  sig->sg->byteSz, pk, &signature_verify);

result:

	if ((ret == 0) && (true == signature_verify)) {
		LOG(LOG_DEBUG, "Signature verifies OK.\n");
		r = true;
	} else {
		LOG(LOG_ERROR, "Signature internal failure, or signature does "
			       "not verify.\n");
		r = false;
	}

	// Return a copy of the data to use or clean up
	if (getpk != NULL) {
		*getpk = sdoPublicKeyClone(pk);
		sdoPublicKeyFree(pk);
	}

	return r;
}

/**
 * Verifies the RSA/ECDSA Signature using provided public key pk.
 * @param plainText - Pointer of type SDOByteArray_t, for generating hash,
 * @param sg - Pointer of type SDOByteArray_t, as signature.
 * @param pk - Pointer of type SDOPublicKey_t, holds the public-key used for
 * verification.
 * @return true if success, else false
 */

bool sdoSignatureVerification(SDOByteArray_t *plainText, SDOByteArray_t *sg,
			      SDOPublicKey_t *pk)
{
	int ret;
	bool signature_verify = false;

	if (!plainText || !sg || !pk || !pk->key1)
		return false;
	if (!plainText->bytes || !sg->bytes)
		return false;

	ret = sdoOVVerify(plainText->bytes, plainText->byteSz, sg->bytes,
			  sg->byteSz, pk, &signature_verify);

	if ((ret == 0) && (true == signature_verify)) {
		LOG(LOG_DEBUG, "Signature verifies OK.\n");
		return true;
	} else {
		LOG(LOG_ERROR, "Signature internal failure, or signature does "
			       "not verify.\n");
		return false;
	}
}

/**
 * Read the pk information
 * @param sdor - pointer to the output buffer
 * @return true if read else flase
 */
bool sdoReadPKNull(SDOR_t *sdor)
{
	if (!sdor)
		return false;

	//"pk":[0,0,[0]]
	if (!sdoReadExpectedTag(sdor, "pk"))
		return false;
	if (!sdoRBeginSequence(sdor))
		return false;

	sdoReadUInt(sdor);
	sdoReadUInt(sdor);

	if (!sdoRBeginSequence(sdor))
		return false;

	sdoReadUInt(sdor);
	if (!sdoREndSequence(sdor))
		return false;

	if (!sdoREndSequence(sdor))
		return false;

	return true;
}

/**
 * Verifies the Signature for ownership voucher using provided public key pk.
 * @param sdor - Pointer of type SDOR_t, holds the signature and plaintext
 * for generating hash.
 * @param sig - Pointer of type SDOSig_t, as signature
 * @param pk - Pointer of type SDOPublicKey_t, holds the key used for
 * verification.
 * @return true if success, else false
 */

bool sdoOVSignatureVerification(SDOR_t *sdor, SDOSig_t *sig, SDOPublicKey_t *pk)
{

	int ret;
	int sigBlockEnd;
	int sigBlockSz;
	uint8_t *plainText;
	bool signature_verify = false;

	if (!sdor || !sig || !pk)
		return false;

	sigBlockEnd = sdor->b.cursor;
	sigBlockSz = sigBlockEnd - sig->sigBlockStart;
	plainText = sdoRGetBlockPtr(sdor, sig->sigBlockStart);

	if (plainText == NULL) {
		LOG(LOG_ERROR, "sdoRGetBlockPtr() returned null, "
			       "sdoOVSignatureVerification() failed !!");
		return false;
	}

	if (!sdoReadPKNull(sdor))
		return false;

	if (!sdoReadExpectedTag(sdor, "sg"))
		return false;

	if (!sdoRBeginSequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		return false;
	}

	sig->sg = sdoByteArrayAlloc(
	    16); // These bytes will be thrown away, some issue with zero length

	if (!sig->sg) {
		LOG(LOG_ERROR, "Alloc failed \n");
		return false;
	}
	// Read the signature to the signature object
	sdoByteArrayRead(sdor, sig->sg);
	// LOG(LOG_ERROR, "signature %lu bytes\n", sig->sg->byteSz);

	if (!sdoREndSequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		return false;
	}

	if (!sdoREndObject(sdor))
		return false;

	ret = sdoOVVerify(plainText, sigBlockSz, sig->sg->bytes,
			  sig->sg->byteSz, pk, &signature_verify);

	if ((ret == 0) && (true == signature_verify)) {
		LOG(LOG_DEBUG, "Signature verifies OK.\n");
		return true;
	} else {
		LOG(LOG_ERROR, "Signature internal failure, or signature does "
			       "not verify.\n");
		return false;
	}
}

//--------------------------------------------------------------------------
// Key Value Pairs
//

/**
 * Allocate the key value
 */
SDOKeyValue_t *sdoKVAlloc(void)
{
	return sdoAlloc(sizeof(SDOKeyValue_t));
}

/**
 * Allocate the key value and initialize with the value provided
 * @param key - pointer to the key
 * @param val - pointer to the struct of type byte array
 * @return pointer to the allocated struct of type key value
 */
SDOKeyValue_t *sdoKVAllocWithArray(char *key, SDOByteArray_t *val)
{
	if (!key || !val)
		return NULL;

	SDOKeyValue_t *kv = sdoKVAlloc();
	if (kv != NULL) {
		int keyLen = strnlen_s(key, SDO_MAX_STR_SIZE);

		if (!keyLen || keyLen == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "sdoKVAllocWithArray(): key is either "
				       "'NULL' or 'isn't"
				       "NULL terminated'\n");
			sdoKVFree(kv);
			return NULL;
		}

		kv->key = sdoStringAllocWith(key, keyLen);
		kv->val = (SDOString_t *)sdoByteArrayAllocWithByteArray(
		    val->bytes, val->byteSz);
		if (kv->key == NULL || kv->val == NULL) {
			sdoKVFree(kv);
			kv = NULL;
		}
	}
	return kv;
}

/**
 * Allocate the key vlaue and initialize with the value provided
 * @param key - pointer to the key
 * @param val - pointer to the input value
 * @return pointer to the allocated key value if success else NULL.
 */
SDOKeyValue_t *sdoKVAllocWithStr(char *key, char *val)
{
	if (!key || !val)
		return NULL;

	SDOKeyValue_t *kv = sdoKVAlloc();
	if (kv != NULL) {
		int keyLen = strnlen_s(key, SDO_MAX_STR_SIZE);

		if (!keyLen || keyLen == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "sdoKVAllocWithStr(): key is either "
				       "'NULL' or 'isn't "
				       "NULL terminated'\n");
			sdoKVFree(kv);
			return NULL;
		}

		kv->key = sdoStringAllocWith(key, keyLen);

		int valLen = strnlen_s(val, SDO_MAX_STR_SIZE);

		if (valLen == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "sdoKVAllocWithStr(): value is either "
				       "'NULL' or 'isn't NULL terminated'\n");
			printf("vallen:%d\t, buf:%s\n", valLen, val);
			sdoKVFree(kv);
			return NULL;
		}

		kv->val = sdoStringAllocWith(val, valLen);
		if (kv->key == NULL || kv->val == NULL) {
			sdoKVFree(kv);
			kv = NULL;
		}
	}
	return kv;
}

/**
 * Free the allcated strutc of type key value
 * @param kv - pointer to the struct of type key value that is to be sdoFree
 */
void sdoKVFree(SDOKeyValue_t *kv)
{
	if (kv->key != NULL)
		sdoStringFree(kv->key);
	if (kv->val != NULL)
		sdoStringFree(kv->val);
	sdoFree(kv);
}

/**
 * Write the key value to the buffer
 * @param sdow - pointer to the output buffer
 * @param kv - pointer to the struct of type key value
 */
void sdoKVWrite(SDOW_t *sdow, SDOKeyValue_t *kv)
{
	sdoWriteTagLen(sdow, kv->key->bytes, kv->key->byteSz);
	sdoWriteStringLen(sdow, kv->val->bytes, kv->val->byteSz);
	sdow->needComma = true;
}

/**
 * Read multiple SvInfo (OSI) Key/Value pairs from the input buffer
 * All Key-value pairs MUST be a null terminated strings.
 * @param sdor - pointer to the input buffer
 * @param moduleList - Global Module List Head Pointer.
 * @param kv - pointer to the SvInfo key/value pair
 * @param cbReturnVal - Pointer of type int which will be filled with CB return
 * value.
 * @return true of read succeeded, false otherwise
 */
bool sdoOsiParsing(SDOR_t *sdor, sdoSdkServiceInfoModuleList_t *moduleList,
		   sdoSdkSiKeyValue *kv, int *cbReturnVal)
{
	int strLen;

	if (!cbReturnVal)
		return false;

	if (!sdor || !kv) {
		*cbReturnVal = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	// loop in to get all the  OSI key value pairs
	// (blockSize-2) is done to skip 2 curly braces to end objects
	// for "sv" tag and "end of Msg 49".

	while (sdor->b.cursor < sdor->b.blockSize - 2) {
		// get len of "key" in KV pair
		strLen = sdoReadStringSz(sdor);

		kv->key = sdoAlloc(strLen + 1); // +1 for null termination

		if (!kv->key) {
			LOG(LOG_ERROR, "Malloc failed!\n");
			return false;
		}

		// read tag "" from KV pair and copy to "kv->key"
		sdoReadTag(sdor, kv->key, strLen + 1);

		// get len of "value" in KV pair
		strLen = sdoReadStringSz(sdor);

		kv->value = sdoAlloc(strLen + 1); // +1 for null termination

		if (!kv->value) {
			LOG(LOG_ERROR, "Malloc failed!\n");
			sdoFree(kv->key);
			return false;
		}

		// read value for above tag and copy into "kv->value"
		sdoReadString(sdor, kv->value, strLen + 1);

		LOG(LOG_DEBUG, "OSI_KV pair:\nKey->%s,Value->%s\n", kv->key,
		    kv->value);

		// call module callback's with appropriate KV pairs
		if (!sdoOsiHandling(moduleList, kv, cbReturnVal)) {
			sdoFree(kv->key);
			sdoFree(kv->value);
			return false;
		}
		// free present KV pair memory
		sdoFree(kv->key);
		sdoFree(kv->value);
	}

	return true;
}

//----------------------------------------------------------------------
// ServiceInfo handling
//

/**
 * Allocate an empty SDOServiceInfo_t object.
 * @return an allocated SDOServiceInfo_t object.
 */

SDOServiceInfo_t *sdoServiceInfoAlloc(void)
{
	return sdoAlloc(sizeof(SDOServiceInfo_t));
}

/**
 * Create a SDOServiceInfo object, by filling the object with key & val
 * passed as parameter.
 * @param val - Value to be mapped to the key, passed as an char pointer.
 * @param key - Pointer to the char buffer key.
 * @return an allocated SDOServiceInfo object containing the key & val.
 */

SDOServiceInfo_t *sdoServiceInfoAllocWith(char *key, char *val)
{
	SDOKeyValue_t *kv;

	SDOServiceInfo_t *si = sdoServiceInfoAlloc();
	if (si == NULL)
		return NULL;
	kv = sdoKVAllocWithStr(key, val);
	if (!kv) {
		sdoServiceInfoFree(si);
		return NULL;
	}
	si->kv = kv;
	si->numKV = 1;
	return si;
}

/**
 * Free an SDOServiceInfo_t object
 * @param si - the object to sdoFree
 * @return none
 */

void sdoServiceInfoFree(SDOServiceInfo_t *si)
{
	SDOKeyValue_t *kv = NULL;
	if (!si)
		return;
	while ((kv = si->kv) != NULL) {
		si->kv = kv->next;
		sdoKVFree(kv);
	}
	sdoFree(si);
}

/**
 * Compares the kv member of si with key parameter and
 * if there is match, return the matched pointer,
 * else last entry in the list.
 * @param si  - Pointer to the SDOServiceInfo_t object si,
 * @param key - Pointer to the char buffer key,
 * @return pointer to SDOKeyValue_t.
 */

SDOKeyValue_t **sdoServiceInfoFetch(SDOServiceInfo_t *si, char *key)
{
	SDOKeyValue_t **kvp, *kv;
	int res = 1;

	for (kvp = &si->kv; (kv = *kvp) != NULL; kvp = &kv->next) {
		int keylen = strnlen_s(key, SDO_MAX_STR_SIZE);
		if (!keylen || keylen == SDO_MAX_STR_SIZE) {
			LOG(LOG_DEBUG, "strlen() failed!\n");
			continue;
		}

		if ((strcasecmp_s(key, keylen, (char *)(kv->key->bytes),
				  &res) == 0) &&
		    res == 0)
			break;
	}
	return kvp;
}
/**
 * Compares the corresponding index associated with kv member of si
 * & keyNum parameter, if there is match, return the matched pointer,
 * else last entry in the list.
 * @param si  - Pointer to the SDOServiceInfo_t object si,
 * @param keyNum - Integer variable determines service request Info number,
 * @return pointer to SDOKeyValue_t.
 */

SDOKeyValue_t **sdoServiceInfoGet(SDOServiceInfo_t *si, int keyNum)
{
	SDOKeyValue_t **kvp, *kv;
	int index;

	for (kvp = &si->kv, index = 0; (kv = *kvp) != NULL;
	     kvp = &kv->next, index++) {
		if (index == keyNum)
			break;
	}
	return kvp;
}
/**
 * si & key are input to the function, it looks for the matching
 * (key, value):
 * if found, update the corresponding si member with val, if memory
 * is not allocated, allocate it.
 * if no matching entry is found, it will add a new entry at the end.
 * @param si  - Pointer to the SDOServiceInfo_t,
 * @param key - Pointer to the char buffer key,
 * @param val - Pointer to the char buffer val, to be updated,
 * @return true if updated correctly else false.
 */

bool sdoServiceInfoAddKVStr(SDOServiceInfo_t *si, char *key, char *val)
{
	SDOKeyValue_t **kvp, *kv;

	if (!si || !key || !val)
		return false;

	kvp = sdoServiceInfoFetch(si, key);
	kv = *kvp;
	if (kv == NULL) {
		// Not found, at end of linked list, add a new entry
		kv = sdoKVAllocWithStr(key, val);
		if (kv == NULL)
			return false;
		*kvp = kv; // Use this pointer to update the next value
		si->numKV++;
		return true;
	} else {
		// Found, update value
		if (kv->val == NULL) {
			// No allocated string present for value, make a new one
			kv->val = sdoStringAllocWithStr(val);
		} else {
			int valLen = strnlen_s(val, SDO_MAX_STR_SIZE);

			if (!valLen || valLen == SDO_MAX_STR_SIZE) {
				LOG(LOG_ERROR, "sdoServiceInfoAddKVStr(): val "
					       "is either 'NULL' or"
					       "'isn't 'NULL-terminating'\n");
				sdoStringFree(kv->val);
				return false;
			}

			// Update the string
			sdoStringResizeWith(kv->val, valLen, val);
		}
	}
	return true;
}
/**
 * Add kvs object of type SDOKeyValue_t to the end of the list(si) if
 * not empty else add it to the head.
 * @param si  - Pointer to the SDOServiceInfo_t list,
 * @param kvs - Pointer to the SDOKeyValue_t kvs, to be added,
 * @return true if updated correctly else false.
 */

bool sdoServiceInfoAddKV(SDOServiceInfo_t *si, SDOKeyValue_t *kvs)
{
	SDOKeyValue_t *kv = NULL;

	if (!si || !kvs)
		return false;

	// Is the list empty?  If it is, add this to the head of the list
	if (si->kv == NULL) {
		si->kv = kvs;
		si->numKV = 1;
		kvs->next = NULL;
	} else {
		// Find the last entry
		for (kv = si->kv; kv->next != NULL; kv = kv->next)
			;
		kv->next = kvs;
		si->numKV++;
		kvs->next = NULL;
	}
	return true;
}

/**
 * Combine SDOKeyValue_t objects into a single string from already built
 * platform DSI list.
 * @param sdow  - Pointer to the output buffer.
 * @param si  - Pointer to the SDOServiceInfo_t list containing all platform
 * DSI's.
 * @return true if combined successfully else false.
 */

bool sdoCombinePlatformDSIs(SDOW_t *sdow, SDOServiceInfo_t *si)
{
	int num = 0;
	bool ret = false;
	SDOKeyValue_t **kvp = NULL;
	SDOKeyValue_t *kv = NULL;

	if (!sdow || !si)
		goto end;

	// fetch all platfrom DSI's one-by-one
	while (num != si->numKV) {
		kvp = sdoServiceInfoGet(si, num);

		kv = *kvp;
		if (!kv || !kv->key || !kv->val) {
			LOG(LOG_ERROR, "Plaform DSI: key-value not found!\n");
			goto end;
		}

		// Write KV pair
		sdoWriteTagLen(sdow, kv->key->bytes, kv->key->byteSz);
		sdoWriteStringLen(sdow, kv->val->bytes, kv->val->byteSz);
		sdow->needComma = true;

		num++;
	}

	ret = true;
end:
	return ret;
}

/**
 * Execute SvInfo Module's callback with the provided svinfo type,
 * @param moduleList - Global Module List Head Pointer.
 * @param type - a valid SvInfo type.
 * @return true if success, false otherwise
 */

bool sdoModExecSvInfotype(sdoSdkServiceInfoModuleList_t *moduleList,
			  sdoSdkSiType type)
{
	while (moduleList) {
		if (moduleList->module.serviceInfoCallback(type, NULL, NULL) !=
		    SDO_SI_SUCCESS) {
			LOG(LOG_DEBUG, "SvInfo: %s's CB Failed for type:%d\n",
			    moduleList->module.moduleName, type);
			return false;
		}
		moduleList = moduleList->next;
	}
	return true;
}

/**
 * Calculation of DSI count for round-trip of modules
 * @param moduleList - Global Module List Head Pointer.
 * @param modMesCount - Pointer of type int which will be filled with count to
 * be added.
 * @param cbReturnVal - Pointer of type int which will be filled with CB return
 * value.
 * @return success if true else false
 */

bool sdoGetDSICount(sdoSdkServiceInfoModuleList_t *moduleList, int *modMesCount,
		    int *cbReturnVal)
{
	int count;

	if (!cbReturnVal)
		return false;

	if (!moduleList) {
		*cbReturnVal = SDO_SI_SUCCESS;
		return true;
	}

	if (moduleList && !modMesCount) {
		*cbReturnVal = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	/*Calculation of DSI count for round-trip of modules*/
	while (moduleList) {
		count = 0;
		// check if module CB is successful
		*cbReturnVal = moduleList->module.serviceInfoCallback(
		    SDO_SI_GET_DSI_COUNT, &count, NULL);
		if (*cbReturnVal != SDO_SI_SUCCESS) {
			LOG(LOG_ERROR, "SvInfo: %s's DSI COUNT CB Failed!\n",
			    moduleList->module.moduleName);
			return false;
		}
		/* populate individual count to the list */
		moduleList->moduleDsiCount = count;

		*modMesCount += count;
		moduleList = moduleList->next;
	}
	// module CB was successful
	*cbReturnVal = SDO_SI_SUCCESS;
	return true;
}

/**
 * Traverse the list for OSI, comparing list with name & calling the appropriate
 * CB.
 * @param moduleList - Global Module List Head Pointer.
 * @param mod_name - Pointer to the mod_name, to be compared with list's modname
 * @param sv_kv - Pointer of type sdoSdkSiKeyValue, holds Module message &
 * value.
 * @param cbReturnVal - Pointer of type int which will be filled with CB return
 * value.
 * @return true if success (module found in list + CB succeed) else false.
 */

bool sdoSupplyModuleOSI(sdoSdkServiceInfoModuleList_t *moduleList,
			char *mod_name, sdoSdkSiKeyValue *sv_kv,
			int *cbReturnVal)
{
	int strcmp_result = 1;
	bool retval = false;

	if (!cbReturnVal)
		return retval;

	if (!sv_kv || !mod_name) {
		*cbReturnVal = SDO_SI_INTERNAL_ERROR;
		return retval;
	}

	retval = true;
	while (moduleList) {
		strcmp_s(moduleList->module.moduleName, SDO_MODULE_NAME_LEN,
			 mod_name, &strcmp_result);
		if (strcmp_result == 0) {
			// check if module CB is successful
			*cbReturnVal = moduleList->module.serviceInfoCallback(
			    SDO_SI_SET_OSI, &(moduleList->moduleOsiIndex),
			    sv_kv);

			if (*cbReturnVal != SDO_SI_SUCCESS) {
				LOG(LOG_ERROR,
				    "SvInfo: %s's CB Failed for type:%d\n",
				    moduleList->module.moduleName,
				    SDO_SI_SET_OSI);
				retval = false;
			}
			// Inc OSI index per module
			moduleList->moduleOsiIndex++;
			break;
		}
		moduleList = moduleList->next;
	}

	return retval;
}

/**
 * Traverse the list for PSI, comparing list with name & calling the appropriate
 * CB.
 * @param moduleList - Global Module List Head Pointer.
 * @param mod_name - Pointer to the mod_name, to be compared with list's modname
 * @param sv_kv - Pointer of type sdoSdkSiKeyValue, holds Module message &
 * value.
 * @param cbReturnVal - Pointer of type int which will be filled with CB return
 * value.
 * @return true if success else false.
 */

bool sdoSupplyModulePSI(sdoSdkServiceInfoModuleList_t *moduleList,
			char *mod_name, sdoSdkSiKeyValue *sv_kv,
			int *cbReturnVal)
{
	int strcmp_result = 1;
	bool retval = false;

	if (!cbReturnVal)
		return retval;

	if (!sv_kv || !mod_name) {
		*cbReturnVal = SDO_SI_INTERNAL_ERROR;
		return retval;
	}

	retval = true;
	while (moduleList) {
		strcmp_s(moduleList->module.moduleName, SDO_MODULE_NAME_LEN,
			 mod_name, &strcmp_result);
		if (strcmp_result == 0) {
			// check if module CB is successful
			*cbReturnVal = moduleList->module.serviceInfoCallback(
			    SDO_SI_SET_PSI, &(moduleList->modulePsiIndex),
			    sv_kv);

			if (*cbReturnVal != SDO_SI_SUCCESS) {
				LOG(LOG_ERROR,
				    "SvInfo: %s's CB Failed for type:%d\n",
				    moduleList->module.moduleName,
				    SDO_SI_SET_PSI);
				retval = false;
			}
			// Inc PSI index per module
			moduleList->modulePsiIndex++;
			break;
		}
		moduleList = moduleList->next;
	}

	return retval;
}

/**
 * Parsing the psi & differentiate string on different delimeters and call the
 * appropriate API's.
 * @param moduleList - Global Module List Head Pointer.
 * @param psi - Pointer to null termincated psi string
 * @param psiLen - length of psi buffer
 * @param cbReturnVal - Pointer of type int which will be filled with CB return
 * value.
 * @return true if success else false.
 */

bool sdoPsiParsing(sdoSdkServiceInfoModuleList_t *moduleList, char *psi,
		   int psiLen, int *cbReturnVal)
{
	if (!cbReturnVal)
		return false;

	if (!moduleList) {
		// No modules.
		*cbReturnVal = SDO_SI_SUCCESS;
		return true;
	}

	char mod_name[SDO_MODULE_NAME_LEN] = {0};
	char mod_message[SDO_MODULE_MSG_LEN] = {0};
	char mod_value[SDO_MODULE_VALUE_LEN] = {0};

	// single PSI tuple
	char *psi_tuple = NULL;
	int psiTupleLen = 0;
	char *notused = NULL;
	// delimiter= ','
	char *del = ",";

	// strtok_s accepts size_t for string length
	size_t len = psiLen - 1; // Buffer size contains ending '\0' char

	// split based on Delimiter
	psi_tuple = strtok_s(psi, &len, del, &notused);

	while (psi_tuple) {
#if LOG_LEVEL == LOG_MAX_LEVEL
		static int i = 0;
		LOG(LOG_DEBUG, "PSI Entry#%d: |%s|\n", i++, psi_tuple);
#endif

		psiTupleLen = strnlen_s(psi_tuple, SDO_MAX_STR_SIZE);

		if (!psiTupleLen || psiTupleLen == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Strlen() failed!\n");
			*cbReturnVal = SDO_SI_INTERNAL_ERROR;
			return false;
		}

		// Get Module name, message and value
		if (!sdoGetModuleNameMsgValue(psi_tuple, psiTupleLen, mod_name,
					      mod_message, mod_value,
					      cbReturnVal)) {
			LOG(LOG_ERROR, "Bad PSI entry: |%s|\n", psi_tuple);
			return false;
		}

		// Fill SI data structure
		sdoSdkSiKeyValue sv_kv;

		sv_kv.key = mod_message;
		sv_kv.value = mod_value;

		// call CB's for PSI
		if (!sdoSupplyModulePSI(moduleList, mod_name, &sv_kv,
					cbReturnVal))
			return false;

		// check for next PSI tuple
		psi_tuple = strtok_s(NULL, &len, del, &notused);
	}

	// module CB's were successful
	*cbReturnVal = SDO_SI_SUCCESS;
	return true;
}

/**
 * Create KeyValue Pair using modName sv_kv key-value pair
 * @param mod_name - Pointer to the char, to be used as a partial key
 * @param sv_kv - Pointer of type sdoSdkSiKeyValue, which holds message & value.
 * @return true if success else false.
 */

bool sdoModDataKV(char *mod_name, sdoSdkSiKeyValue *sv_kv)
{
	// Example : "keypair:pubkey":"sample o/p of pubkey"
	sdoSdkSiKeyValue sv_kv_t;
	if (!mod_name || !sv_kv || !sv_kv->key || !sv_kv->value)
		return false;

	int strlen_name = strnlen_s(mod_name, SDO_MAX_STR_SIZE);
	int strlen_sv_key = strnlen_s(sv_kv->key, SDO_MAX_STR_SIZE);

	if (!strlen_name || !strlen_sv_key ||
	    strlen_sv_key == SDO_MAX_STR_SIZE ||
	    strlen_name == SDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "strlen() failed!\n");
		return false;
	}

	// + 1 is for ':' between mod_name & mod message(sv_kv->key)
	// +1 for terminating null character
	int sv_kv_t_key_size = strlen_name + strlen_sv_key + 2;

	sv_kv_t.key = sdoAlloc(sv_kv_t_key_size);

	if (!sv_kv_t.key) {
		LOG(LOG_ERROR, "Malloc Failed!\n");
		return false;
	}

	if (strcpy_s(sv_kv_t.key, sv_kv_t_key_size, mod_name) != 0) {
		LOG(LOG_ERROR, "strcpy() failed!\n");
		return false;
	}

	sv_kv_t.key[strlen_name] = ':';

	if (strcpy_s(sv_kv_t.key + strlen_name + 1,
		     sv_kv_t_key_size - (strlen_name + 1), sv_kv->key) != 0) {
		LOG(LOG_ERROR, "strcpy() failed!\n");
		return false;
	}

	sv_kv->key = sv_kv_t.key;

	int sv_kv_t_val_size = strnlen_s(sv_kv->value, SDO_MAX_STR_SIZE);
	if (sv_kv_t_val_size == SDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "strlen() failed!\n");
		return false;
	}

	sv_kv_t.value =
	    sdoAlloc(sv_kv_t_val_size + 1); // 1 is for NULL at the end

	if (!sv_kv_t.value) {
		LOG(LOG_ERROR, "Malloc Failed!\n");
		return false;
	}

	if (strcpy_s(sv_kv_t.value, sv_kv_t_val_size + 1, sv_kv->value) != 0) {
		LOG(LOG_ERROR, "strcpy() failed!\n");
		return false;
	}

	sv_kv->value = sv_kv_t.value;
	return true;
}

/**
 * Internal API
 */

bool sdoConstructModuleDSI(sdoSvInfoDsiInfo_t *dsiInfo, sdoSdkSiKeyValue *sv_kv,
			   int *cbReturnVal)
{
	int tempDsiCount;

	if (!cbReturnVal || !dsiInfo)
		return false;

	if (!sv_kv) {
		*cbReturnVal = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	tempDsiCount = dsiInfo->list_dsi->moduleDsiCount;

	/* Finish DSI module-by-module */
	if (dsiInfo->moduleDsiIndex < tempDsiCount) {
		// check if module CB is successful
		*cbReturnVal = dsiInfo->list_dsi->module.serviceInfoCallback(
		    SDO_SI_GET_DSI, &(dsiInfo->moduleDsiIndex), sv_kv);
		if (*cbReturnVal != SDO_SI_SUCCESS) {
			LOG(LOG_ERROR, "SvInfo: %s's DSI CB Failed!\n",
			    dsiInfo->list_dsi->module.moduleName);
			return false;
		}

		if (!sdoModDataKV(dsiInfo->list_dsi->module.moduleName,
				  sv_kv)) {
			*cbReturnVal = SDO_SI_INTERNAL_ERROR;
			return false;
		}
		// Inc ModuleDsiIndex
		dsiInfo->moduleDsiIndex++;
	}

	/* reset module DSI index for next module */
	if (dsiInfo->moduleDsiIndex == tempDsiCount) {
		dsiInfo->moduleDsiIndex = 0;
		dsiInfo->list_dsi = dsiInfo->list_dsi->next;
	}
	*cbReturnVal = SDO_SI_SUCCESS;
	return true;
}

/**
 * Write the key value to the buffer
 * @param sdow - pointer to the output buffer
 * @param sv_kv - pointer to the struct of type key value
 * @return true if success else false
 */
bool sdoModKVWrite(SDOW_t *sdow, sdoSdkSiKeyValue *sv_kv)
{
	int strlen_kv_key = strnlen_s(sv_kv->key, SDO_MAX_STR_SIZE);
	int strlen_kv_value = strnlen_s(sv_kv->value, SDO_MAX_STR_SIZE);

	if (!strlen_kv_key || strlen_kv_key == SDO_MAX_STR_SIZE ||
	    strlen_kv_value == SDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "strlen() failed!\n");
		return false;
	}

	sdoWriteTagLen(sdow, sv_kv->key, strlen_kv_key);
	sdoWriteStringLen(sdow, sv_kv->value, strlen_kv_value);
	sdow->needComma = true;
	return true;
}

/**
 * Free Module Key Value
 * @param sv_kv - the object to free
 * @return none
 */
void sdoSVKeyValueFree(sdoSdkSiKeyValue *sv_kv)
{
	// TODO: ALL free below will change to sdoFree.
	if (sv_kv == NULL)
		return;
	if (sv_kv->key != NULL)
		sdoFree(sv_kv->key);
	if (sv_kv->value != NULL)
		sdoFree(sv_kv->value);
	sdoFree(sv_kv);
}

/**
 * Read a SvInfo (OSI) Key/Value pair from the input buffer
 * The Key and value both  MUST be a null terminated string.
 * @param moduleList - Global Module List Head Pointer.
 * @param sv - pointer to the SvInfo key/value pair
 * @param cbReturnVal - Pointer of type int which will be filled with CB return
 * value.
 * @return true if read succeeded, false otherwise
 */
bool sdoOsiHandling(sdoSdkServiceInfoModuleList_t *moduleList,
		    sdoSdkSiKeyValue *sv, int *cbReturnVal)
{
	char mod_name[SDO_MODULE_NAME_LEN + 1];
	char mod_msg[SDO_MODULE_MSG_LEN + 1];

	if (!cbReturnVal)
		return false;

	if (!sv || !sv->key) {
		*cbReturnVal = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	int osiKeyLen = strnlen_s(sv->key, SDO_MODULE_NAME_LEN);

	if (!osiKeyLen || osiKeyLen > SDO_MODULE_NAME_LEN) {
		LOG(LOG_ERROR,
		    "OSI key is either NULL or isin't NULL terminated!\n");
		*cbReturnVal = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	// get module name and message name from sv->key
	// modulename and message name are separated using :
	char *osiKey = sv->key;
	int i = 0;

	while (':' != osiKey[i]) {
		if (i >= osiKeyLen) {
			*cbReturnVal = MESSAGE_BODY_ERROR;
			return false;
		}

		mod_name[i] = osiKey[i];
		++i;
	}

	mod_name[i] = 0;

	// consume one char for ':'
	++i;

	int j = 0;
	while (i <= osiKeyLen) {
		mod_msg[j++] = osiKey[i++];
	}
	mod_msg[j] = 0;

	if (strcpy_s(sv->key, strnlen_s(mod_msg, SDO_MODULE_MSG_LEN) + 1,
		     mod_msg) != 0) {
		LOG(LOG_ERROR, "Strcpy failed!\n");
		*cbReturnVal = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	if (!sdoSupplyModuleOSI(moduleList, mod_name, sv, cbReturnVal))
		return false;

	*cbReturnVal = SDO_SI_SUCCESS;
	return true;
}

/**
 * SvInfo: Clear the Module PSI and OSI Index for next rounds.
 * @param moduleList - Global Module List Head Pointer.
 * @return none
 */
void sdoSvInfoClearModulePsiOsiIndex(sdoSdkServiceInfoModuleList_t *moduleList)
{
	if (moduleList) {
		while (moduleList) {
			moduleList->modulePsiIndex = 0;
			moduleList->moduleOsiIndex = 0;
			moduleList = moduleList->next;
		}
	}
}

/**
 * Construct the Module List using separator for device service info keys
 * @param moduleList - Global Module List Head Pointer.
 * @param moduleName - Pointer of type char in which List will be copied.
 * @return true if success else false.
 */
bool sdoConstructModuleList(sdoSdkServiceInfoModuleList_t *moduleList,
			    char **moduleName)
{

	if (!moduleName)
		return false;

	// When there are no modules, send empty string
	if (!moduleList) {
		*moduleName = sdoAlloc(1); // 1 is for empty string)
		if (!*moduleName) {
			LOG(LOG_ERROR, "Malloc Failed\n");
			return false;
		}
		return true;
	}

	char *temp = sdoAlloc(SDO_MAX_STR_SIZE);
	if (!temp) {
		LOG(LOG_ERROR, "Malloc Failed\n");
		return false;
	}

	int len = 0;
	int count = 0;
	// Example string: devconfig;keypair
	while (moduleList) {
		if (strcpy_s(temp + count, SDO_MAX_STR_SIZE - count,
			     moduleList->module.moduleName) != 0) {
			LOG(LOG_ERROR, "Strcpy failed!\n");
			sdoFree(temp);
			return false;
		}
		len =
		    strnlen_s(moduleList->module.moduleName, SDO_MAX_STR_SIZE);
		if (!len || len == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Strlen failed!\n");
			sdoFree(temp);
			return false;
		}
		count += len;

		moduleList = moduleList->next;
		if (moduleList) {
			if (strcpy_s(temp + count, SDO_MAX_STR_SIZE - count,
				     SEPARATOR) != 0) {
				LOG(LOG_ERROR, "Strcpy failed!\n");
				sdoFree(temp);
				return false;
			}
			count++; // 1 is for separator
		}
	}
	*moduleName = temp;

	return true;
}

/**
 * Compares two hashes
 *
 * @param hash1: poniter to input hash 1
 * @param hash2: poniter to input hash 2
 * @return
 *        true if both hashes are same else false.
 */
bool sdoCompareHashes(SDOHash_t *hash1, SDOHash_t *hash2)
{
	bool retval = false;
	int result = 1;

	if (!hash1 || !hash2 || !hash1->hash || !hash2->hash ||
	    !hash1->hash->byteSz || !hash1->hash->bytes ||
	    !hash2->hash->byteSz || !hash2->hash->bytes) {
		LOG(LOG_ERROR, "Null arguments!\n");
		goto end;
	}

	if (hash1->hashType != hash2->hashType) {
		LOG(LOG_DEBUG, "Hash types are not same!\n");
		goto end;
	}
	if (memcmp_s(hash1->hash->bytes, hash1->hash->byteSz,
		     hash2->hash->bytes, hash2->hash->byteSz, &result) ||
	    result) {
		LOG(LOG_DEBUG, "Hash contents are not same!\n");
		goto end;
	}

	retval = true;

end:
	return retval;
}

/**
 * Compares two byteArrays
 *
 * @param ba1: poniter to input byteArray 1
 * @param ba2: poniter to input byteArray 2
 * @return
 *        true if both byteArrays are same else false.
 */
bool sdoCompareByteArrays(SDOByteArray_t *ba1, SDOByteArray_t *ba2)
{
	bool retval = false;
	int result = 1;

	if (!ba1 || !ba2 || !ba1->byteSz || !ba1->bytes || !ba2->byteSz ||
	    !ba2->bytes) {
		LOG(LOG_ERROR, "Null arguments!\n");
		goto end;
	}

	if (memcmp_s(ba1->bytes, ba1->byteSz, ba2->bytes, ba2->byteSz,
		     &result) ||
	    result) {
		LOG(LOG_DEBUG, "ByteArray contents are not same!\n");
		goto end;
	}

	retval = true;

end:
	return retval;
}

/**
 * Compares two Rendezvous lists
 *
 * @param rv_list1: poniter to input rv_list 1
 * @param rv_list2: poniter to input rv_list 2
 * @return
 *        true if both rv_lists are same else false.
 */
bool sdoCompareRvLists(SDORendezvousList_t *rv_list1,
		       SDORendezvousList_t *rv_list2)
{
	bool retval = false;

	if (!rv_list1 || !rv_list2) {
		LOG(LOG_ERROR, "Null arguments!\n");
		goto end;
	}

	// FIXME: rv_lists are very unlikely to change, being static scenario,
	// therefore detailed check on rv_list is skipped.
	retval = true;

end:
	return retval;
}
#if 0
    /**
     * Internal API
     */
    void SDOServiceInfoPrint(SDOServiceInfo_t * si)
{
	SDOKeyValue_t *kv;
#define KVBUF_SIZE 32
	char kbuf[KVBUF_SIZE];
	char vbuf[KVBUF_SIZE];

	LOG(LOG_DEBUG, "{#SDOServiceInfo numKV: %u\n", si->numKV);
	for (kv = si->kv; kv; kv = kv->next) {
		LOG(LOG_DEBUG, "    \"%s\":\"%s\"%s\n",
		    sdoStringToString(kv->key, kbuf, KVBUF_SIZE),
		    sdoStringToString(kv->val, vbuf, KVBUF_SIZE),
		    kv->next ? "," : "");
	}
	LOG(LOG_DEBUG, "}\n");
}
#endif
