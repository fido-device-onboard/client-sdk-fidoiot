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
#include "sdoCrypto.h"
#include "util.h"
#include "sdo.h"
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include "safe_lib.h"
#include "snprintf_s.h"
#include "sdodeviceinfo.h"

int keyfromstring(const char *key);

/**
 * Allocate and Initialize the bits
 * @param b - pointer to initialized bits struct
 * @param byte_sz - size of bytes to ve initialized
 * @return bits if initialization in success
 */
sdo_bits_t *sdo_bits_init(sdo_bits_t *b, int byte_sz)
{
	if (!b)
		return NULL;

	if (byte_sz > 0) {
		b->bytes = sdo_alloc(byte_sz * sizeof(uint8_t));
		if (b->bytes == NULL)
			return NULL;
		b->byte_sz = byte_sz;
		return b;
	}

	if (b->bytes) {
		sdo_free(b->bytes);
		b->bytes = NULL;
	}
	b->byte_sz = 0;

	return b;
}

/**
 * Allocote the bytes specified
 * @param byte_sz - number of bytes to be initialized
 * @return pointer to the bits allocated if success else NULL
 */
sdo_bits_t *sdo_bits_alloc(int byte_sz)
{
	sdo_bits_t *b = sdo_alloc(sizeof(sdo_bits_t));

	if (b == NULL)
		return NULL;

	if (byte_sz > 0)
		return sdo_bits_init(b, byte_sz);
	else
		return b;
}

/**
 * Allocate the bits and assing with the data specified
 * @param byte_sz - number of bytes to be allocated
 * @param data - data to be written to the initialized bits
 * @return pointer to bits if success else NULL
 */
sdo_bits_t *sdo_bits_alloc_with(int byte_sz, uint8_t *data)
{
	sdo_bits_t *b = sdo_bits_alloc(byte_sz);

	if (b == NULL)
		return NULL;
	if (!sdo_bits_fill(&b)) {
		sdo_bits_free(b);
		return NULL;
	}
	if (memcpy_s(b->bytes, b->byte_sz, data, b->byte_sz) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		sdo_bits_free(b);
		return NULL;
	}
	return b;
}

/**
 * Free the bits specified
 * @param b - pointer to the struct bits that is to be deallocated
 */
void sdo_bits_free(sdo_bits_t *b)
{
	if (b) {
		sdo_bits_empty(b);
		sdo_free(b);
	}
}

/**
 * Free/Nullify the specified bits
 * @param b - pointer to the struct bits
 */
void sdo_bits_empty(sdo_bits_t *b)
{
	if (!b)
		return;
	if (b->bytes) {
		if (b->byte_sz && memset_s(b->bytes, b->byte_sz, 0))
			LOG(LOG_ERROR, "Failed to clear memory\n");
		sdo_free(b->bytes);
		b->bytes = NULL;
	}
	b->byte_sz = 0;
}

/**
 * Clone the bits to a new struct
 * @param b - pointer to the struct bits which has to be cloned
 * @return pointer to the cloned struct bits if success else NULL
 */
sdo_bits_t *sdo_bits_clone(sdo_bits_t *b)
{
	if (!b)
		return NULL;
	return sdo_bits_alloc_with(b->byte_sz, b->bytes);
}

/**
 * Resize the struct bits with the specified size
 * @param b - pointer to the struct bits
 * @param byte_sz - resized value of bits
 * @return true if resized else false
 */
bool sdo_bits_resize(sdo_bits_t *b, int byte_sz)
{
	sdo_bits_empty(b);
	b->byte_sz = byte_sz;
	return sdo_bits_fill(&b);
}

/**
 * Initialize the struct bits with zero
 * @param bits  - pointer to the struct bits that has to be initialized with
 * zero
 * @return true if set to 0, else false
 */
bool sdo_bits_fill(sdo_bits_t **bits)
{
	sdo_bits_t *b;

	if (!bits || !*bits)
		return false;

	b = *bits;
	if (b->bytes != NULL) {
		sdo_free(b->bytes);
		b->bytes = NULL;
	}
	b->bytes = sdo_alloc(b->byte_sz);
	if (b->bytes == NULL)
		return false;
	return true;
}

#if 0
/**
 * Initialize the bits with the specified data
 * @param b - pointer to the struct bits which has to be initialized
 * @param data - data to be initialized
 * @param data_len - length of the data
 * @return true if initialized else false
 */
bool sdo_bits_fill_with(sdo_bits_t *b, uint8_t *data, uint32_t data_len)
{
	b->byte_sz = data_len;
	if (!sdo_bits_fill(b))
		return false;
	if (data != NULL && data_len <= b->byte_sz) {
		if (memcpy_s(b->bytes, data_len, data, data_len) != 0) {
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
 * @param new_byte_sz - resized value of struct bits
 * @param data = data to be initialized
 * @return true if success else false
 */
bool sdo_bits_resize_with(sdo_bits_t *b, int new_byte_sz, uint8_t *data)
{
	return sdo_bits_fill_with(b, data, new_byte_sz);
}

/**
 * Check of the struct bits are equal
 * @param b1 - pointer to the first struct bits
 * @param b2 - pointer to the second struct bits
 * @return true if success else false
 */
bool sdo_bits_equal(sdo_bits_t *b1, sdo_bits_t *b2)
{
	int result_memcmp = 0;

	memcmp_s(b1->bytes, b1->byte_sz, b2->bytes, b2->byte_sz,
		 &result_memcmp);
	if ((b1->byte_sz == b2->byte_sz) && (result_memcmp == 0)) {
		return true;
	}

	return false;
}

/**
 * Iniaialize the struct bits and fill some random data
 * @param b - pointer to the struct bits which has to be initialized
 * @return  0 if success else -1 on failure
 */
int sdo_bits_randomize(sdo_bits_t *b)
{
	if ((b->bytes == NULL) || !sdo_bits_fill(b))
		return -1;

	return sdo_crypto_random_bytes(b->bytes, b->byte_sz);
}
#endif

/**
 * Convert bytes to string
 * @param b - pointer to the struct bits
 * @param typename - string to be appended
 * @param buf - converted string
 * @param buf_sz - size of the converted string
 * return pointer to the string if success
 */
char *sdo_bits_to_string(sdo_bits_t *b, const char *typename, char *buf,
			 int buf_sz)
{
	size_t i;
	int n;
	char *buf0 = buf;
	char hbuf[5];

	if (!b || !typename || !buf)
		return NULL;

	n = snprintf_s_si(buf, buf_sz, "[%s[%d]:", (char *)typename,
			  (int)b->byte_sz);

	if (n < 0) {
		LOG(LOG_ERROR, "snprintf() failed!\n");
		return NULL;
	}

	buf += n;
	buf_sz -= n;
	i = 0;
	while (i < b->byte_sz && buf_sz > 1) {
		// Do it this way to fill up the string completely
		// else the truncated public key will be terminated below.

		if (snprintf_s_i(hbuf, sizeof(hbuf), "%02X", b->bytes[i++]) <
		    0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}

		if (strncpy_s(buf, buf_sz, hbuf, buf_sz) != 0) {
			LOG(LOG_ERROR, "strcpy() failed!\n");
			return NULL;
		}
		n = strnlen_s(buf, buf_sz);

		if (!n || n == buf_sz) {
			LOG(LOG_ERROR, "strlen() failed!\n");
			return NULL;
		}

		buf += n;
		buf_sz -= n;
	}
	if (buf_sz > 1) {
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
 * @param cb_return_val - Pointer of type int which will be filled with error
 * value.
 * return true if valid PSI-tuple, false otherwise.
 */
bool sdo_get_module_name_msg_value(char *psi_tuple, int psi_len, char *mod_name,
				   char *mod_msg, char *mod_val,
				   int *cb_return_val)
{
	if (!psi_tuple || !psi_len || !mod_name || !mod_msg || !mod_val ||
	    !cb_return_val) {
		LOG(LOG_ERROR, "Invalid input!\n");
		goto err;
	}

	char *rem = NULL;
	int rem_len = 0;
	int name_len, msg_len, val_len;

	name_len = msg_len = val_len = 0;

	rem = strchr(psi_tuple, ':');

	if (!rem) {
		LOG(LOG_ERROR, "module name not found!\n");
		*cb_return_val = MESSAGE_BODY_ERROR;
		goto err;
	} else {
		rem_len = strnlen_s(rem, SDO_MAX_STR_SIZE);

		if (!rem_len || rem_len == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Strlen() failed!\n");
			*cb_return_val = SDO_SI_INTERNAL_ERROR;
			goto err;
		}

		name_len = psi_len - rem_len;

		if (name_len == 0) {
			LOG(LOG_ERROR, "Module name is empty!\n");
			*cb_return_val = MESSAGE_BODY_ERROR;
			goto err;
		}

		if (name_len > SDO_MODULE_NAME_LEN) {
			LOG(LOG_ERROR, "Module max-name-len limit exceeded!\n");
			*cb_return_val = SDO_SI_CONTENT_ERROR;
			goto err;
		}

		if (strncpy_s(mod_name, name_len + 1, psi_tuple, name_len) !=
		    0) {
			*cb_return_val = SDO_SI_INTERNAL_ERROR;
			LOG(LOG_ERROR, "Strcpy() failed!\n");
			goto err;
		}
		psi_tuple += name_len;
		psi_len -= name_len;
	}

	// consuming ':'
	++psi_tuple;
	--psi_len;

	rem = strchr(psi_tuple, '~');

	if (!rem) {
		LOG(LOG_ERROR, "Module message not found!\n");
		*cb_return_val = MESSAGE_BODY_ERROR;
		goto err;
	} else {
		rem_len = strnlen_s(rem, SDO_MAX_STR_SIZE);

		if (!rem_len || rem_len == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Strlen() failed!\n");
			*cb_return_val = SDO_SI_INTERNAL_ERROR;
			goto err;
		}

		msg_len = psi_len - rem_len;

		if (msg_len == 0) {
			// module msg is not available, copy empty string
			*mod_msg = '\0';
		} else if (msg_len <= SDO_MODULE_MSG_LEN) {
			if (strncpy_s(mod_msg, msg_len + 1, psi_tuple,
				      msg_len) != 0) {
				*cb_return_val = SDO_SI_INTERNAL_ERROR;
				LOG(LOG_ERROR, "Strcpy() failed!\n");
				goto err;
			}

		} else {
			LOG(LOG_ERROR, "Module max-msg-len limit exceeded!\n");
			*cb_return_val = SDO_SI_CONTENT_ERROR;
			goto err;
		}
		psi_tuple += msg_len;
		psi_len -= msg_len;
	}

	// consuming '~'
	++rem;
	--rem_len;

	if (rem_len > 0) {
		if (rem_len > SDO_MODULE_VALUE_LEN) {
			LOG(LOG_ERROR, "Module max-val-len limit exceeded!\n");
			*cb_return_val = SDO_SI_CONTENT_ERROR;
			goto err;
		}

		// module value is available and 'rem' shall contain whole of it
		if (strncpy_s(mod_val, rem_len + 1, rem, rem_len) != 0) {
			*cb_return_val = SDO_SI_INTERNAL_ERROR;
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
 * @param buf_sz - size of the converted string
 * return pointer to the converted string
 */
char *sdo_bits_to_string_hex(sdo_bits_t *b, char *buf, int buf_sz)
{
	int i, n;
	char *buf0 = buf;
	char hbuf[5];

	i = 0;
	while (i < b->byte_sz && buf_sz > 1) {
		// Do it this way to fill up the string completely
		// else the truncated public key will be terminated below.

		if (snprintf_s_i(hbuf, sizeof(hbuf), "%02X", b->bytes[i++]) <
		    0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}

		if (strncpy_s(buf, buf_sz, hbuf, buf_sz) != 0) {
			LOG(LOG_ERROR, "strcpy() failed!\n");
			return NULL;
		}
		n = strnlen_s(buf, buf_sz);

		if (!n || n == buf_sz) {
			LOG(LOG_ERROR, "strlen() failed!\n");
			return NULL;
		}

		buf += n;
		buf_sz -= n;
	}
	if (buf_sz > 1) {
		*buf++ = 0;
	}
	return buf0;
}

#if 0 // Deprecated
/**
 * Internal API
 */
void sdo_bits_write(sdow_t *sdow, sdo_bits_t *b)
{
	sdo_write_big_num_field(sdow, b->bytes, b->byte_sz);
	//    sdo_write_byte_array_field(sdow, b->bytes, b->byte_sz);
}

/**
 * Internal API
 */
bool sdo_bits_read(sdor_t *sdor, sdo_bits_t *b)
{
	if (b->bytes == NULL)
		if (!sdo_bits_fill(b))
			return false;
	return sdo_read_big_num_field(sdor, b->bytes, b->byte_sz) == b->byte_sz;
}
#endif
//==============================================================================
// Byte Array is SDOBits but read and written as base64

/**
 * Internal API
 */
sdo_byte_array_t *sdo_byte_array_init(sdo_byte_array_t *bn, int byte_sz)
{
	return sdo_bits_init(bn, byte_sz);
}
#endif

/**
 * Allocate the number of bytes specified
 * @param byte_sz - size of the bytes to be allocated
 * @return pointer to the struct bits that is allocated
 */
sdo_byte_array_t *sdo_byte_array_alloc(int byte_sz)
{
	return sdo_bits_alloc(byte_sz);
}

/**
 * Allocate and initialize the bytes
 * @param val - value to the initialized
 * @return pointer to the struct of bits
 */
sdo_byte_array_t *sdo_byte_array_alloc_with_int(int val)
{
	return sdo_bits_alloc_with(sizeof(int), (uint8_t *)&val);
}

/**
 * Allocate the bytes array and assign with the data specified
 * @param ba - data to be assigned
 * @param ba_len - size of the data to be assigned
 * @return pointer to the struct of bytes that is allocated and assigned
 */
sdo_byte_array_t *sdo_byte_array_alloc_with_byte_array(uint8_t *ba, int ba_len)
{
	return sdo_bits_alloc_with(ba_len, ba);
}

/**
 * Free the byte array
 * @param ba - pointer to the byte array struct that has to be sdo_free
 */
void sdo_byte_array_free(sdo_byte_array_t *ba)
{
	if (ba)
		sdo_bits_free(ba);
}

#if 0
/**
 * Internal API
 */
void sdo_byte_array_empty(sdo_byte_array_t *ba)
{
	sdo_bits_empty(ba);
}

/**
 * Resize the byte array
 * @param b - pointer to he struct of byte array that has to be resized
 * @param byte_sz - value to be resized with
 * @return pointer to the resized byte array struct
 */
bool sdo_byte_array_resize(sdo_byte_array_t *b, int byte_sz)
{
	return sdo_bits_resize(b, byte_sz);
}

/**
 * Internal API
 */
bool sdo_byte_array_resize_with(sdo_byte_array_t *b, int new_byte_sz,
				uint8_t *data)
{
	return sdo_bits_resize_with(b, new_byte_sz, data);
}
#endif

/**
 * Clone the byte array
 * @param bn - byte array to be cloned
 * @return pointet to the cloned byte array struct
 */
sdo_byte_array_t *sdo_byte_array_clone(sdo_byte_array_t *bn)
{
	return sdo_bits_clone(bn);
}

#if 0
/**
 * compare the byte array
 * @param bn1 - pointer to the first byte array struct
 * @param bn2 - pointer to the second byte array struct
 * @return true if equal else false
 */
bool sdo_byte_array_equal(sdo_byte_array_t *bn1, sdo_byte_array_t *bn2)
{
	return sdo_bits_equal(bn1, bn2);
}
#endif

/**
 * Append one byte array onto another and return the resulting byte array
 * @param baA - pointer to the first byte array object
 * @param baB - pointer to the second
 * @return a Byte Array "AB" with B appended after A
 */
sdo_byte_array_t *sdo_byte_array_append(sdo_byte_array_t *baA,
					sdo_byte_array_t *baB)
{
	if (!baA || !baB)
		return NULL;

	int buf_szAB = baA->byte_sz + baB->byte_sz;
	sdo_byte_array_t *baAB = sdo_byte_array_alloc(buf_szAB);

	if (!baAB) {
		LOG(LOG_ERROR,
		    "failed to allocate memory for creating byte array\n");
		return NULL;
	}

	if (memcpy_s(&baAB->bytes[0], baA->byte_sz, baA->bytes, baA->byte_sz) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		sdo_byte_array_free(baAB);
		return NULL;
	}

	if (memcpy_s(&baAB->bytes[baA->byte_sz], baB->byte_sz, baB->bytes,
		     baB->byte_sz) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		sdo_byte_array_free(baAB);
		return NULL;
	}

	return baAB;
}

/**
 * Byte array is represented as {len,"byte array in base64"}
 * @param g - pointer to the byte array struct
 * @param buf - pointer to the output buffer
 * @param buf_sz - size of the buffer
 * @return pointer to the buffer
 */
char *sdo_byte_array_to_string(sdo_byte_array_t *g, char *buf, int buf_sz)
{
	int obuf_sz = buf_sz;
	char *buf0 = buf;

	if (memset_s(buf, buf_sz, 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return NULL;
	}

	int char_count = 0;

	if (g->byte_sz && g->bytes != NULL) {
		int b64Len = bin_toB64Length(g->byte_sz);

		/* First put out the length followed by a comma. */
		int len = snprintf_s_i(buf, buf_sz, "%d,", b64Len);

		buf += len;
		buf_sz -= len;

		/* Check to see if we have enough buffer for the conversion. */
		if ((bin_toB64Length(g->byte_sz) + 1) < buf_sz) {
			*buf++ = '"';
			buf_sz--;
			/* Then the buffer of the base64 representation. */
			char_count = bin_toB64(g->byte_sz, g->bytes, 0, buf_sz,
					       (uint8_t *)buf, 0);
			buf += char_count;
			buf_sz -= char_count;
			*buf++ = '"';
			buf_sz--;
		}
		if ((char_count + len) > obuf_sz - 1) {
			char_count = obuf_sz - 1;
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
int sdo_byte_array_read_chars(sdor_t *sdor, sdo_byte_array_t *ba)
{
	if (!sdor || !ba)
		return 0;

	if (ba->bytes) {
		sdo_free(ba->bytes);
		ba->bytes = NULL;
	}

	int b64Len = sdo_read_string_sz(sdor);
	// LOG(LOG_ERROR, "b64Len_reported %d\n", b64Len);
	// Determine the needed length
	int bin_len = b64To_bin_length(b64Len);

	LOG(LOG_DEBUG, "Byte Array len %d\n", bin_len);

	// DEBUG - added for correct buff allocation
	if (bin_len) {
		// Allocate a BPBits for the array
		ba->bytes = sdo_alloc(bin_len * sizeof(uint8_t));
		if (!ba->bytes)
			return 0;
		// Now read the byte array
		int result_len =
		    sdo_read_byte_array_field(sdor, b64Len, ba->bytes, bin_len);
		ba->byte_sz = result_len;
		return result_len;
	}

	char c;

	sdo_read_string(sdor, &c, 1);
	return 0;
}

/**
 * Read a base64 byte array, len,"byte array in base64"
 * @param sdor - data to be read in the form of JSON
 * @param ba - pointer the struct byte array which holds the read data
 * @return size of data read is success else zero
 */
int sdo_byte_array_read(sdor_t *sdor, sdo_byte_array_t *ba)
{
	if (!sdor || !ba)
		return 0;

	/*FIXME: if unnecessary remove it */
	if (ba->bytes) {
		sdo_free(ba->bytes);
		ba->bytes = NULL;
		ba->byte_sz = 0;
	}

	int bin_len_reported = sdo_read_uint(sdor);
	// Determine the needed length
	int b64Len = bin_toB64Length(bin_len_reported);

	if (b64Len) {

		// LOG(LOG_ERROR, "B64 Array len %d\n", bin_len_reported);

		// Allocate a BPBits for the array,
		// Allocate 3 bytes extra for max probable decodaed output
		bin_len_reported += 3;
		ba->bytes = sdo_alloc((bin_len_reported) * sizeof(uint8_t));
		if (!ba->bytes)
			return 0;
		// Now read the byte array
		int result_len = sdo_read_byte_array_field(
		    sdor, b64Len, ba->bytes, bin_len_reported);
		ba->byte_sz = result_len;
		return result_len;
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
 * @param ct_string - byte array where data read for no state change
 * @param iv_data - byte array fir iv data
 * @return the size of the data read if seccess else zero
 */

int sdo_byte_array_read_with_type(sdor_t *sdor, sdo_byte_array_t *ba,
				  sdo_byte_array_t **ct_string,
				  uint8_t *iv_data)
{
	int ret = 0;
	int bin_len_reported = 0, b64Len_reported = 0, b64Len_expected = 0;
	int iv_data_size;
	uint32_t iv_size_reported = 0;
	int iv_size_64 = -1;

	if (!sdor || !ba || !iv_data || !ct_string) {
		goto err;
	}

	/* read sequence:
	 * 1. [size of iv, iv_data]
	 * 2. size of cipher text
	 * 3. cipher text
	 */
	uint32_t ct_size = sdo_read_array_sz(sdor) + 1;

	if ((*ct_string != NULL) || (0 == ct_size)) {
		LOG(LOG_ERROR, "Incorrect arguments passed!\n");
		goto err;
	}
	*ct_string = sdo_byte_array_alloc(ct_size);

	if (NULL == *ct_string) {
		LOG(LOG_ERROR, "Failed to alloc buffer!\n");
		goto err;
	}

	if ((uint32_t)sdo_read_array_no_state_change(
		sdor, (*ct_string)->bytes) >= ct_size) {
		LOG(LOG_ERROR, "Issue with string read\n");
		goto err;
	}

	/* The json object for IV */
	sdor_begin_sequence(sdor);
	/* Get binary length reported */
	iv_size_reported = sdo_read_uint(sdor);

	if (iv_size_reported <= 0 && iv_size_reported > 16) {
		LOG(LOG_ERROR, "Invalid IV reported!\n");
		goto err;
	}

	iv_size_64 = bin_toB64Length(iv_size_reported);

	/* Read from the array i.e " " */
	iv_data_size = sdo_read_byte_array_field(sdor, iv_size_64,
						  iv_data, AES_IV);
	if (0 == iv_data_size) {
		LOG(LOG_ERROR, "Failed to read the counter value %d %d\n",
		    iv_data_size, iv_size_reported);
		goto err;
	}

	sdor_end_sequence(sdor); // e.g.: [16,"8Qy3c_bxI7NQ+Ef0XAAAAAA=="]

	/* Get cipher text binary length reported */
	bin_len_reported = sdo_read_uint(sdor);

	if (bin_len_reported <= 0) {
		LOG(LOG_ERROR, "Invalid binary length reported!\n");
		goto err;
	}

	/* Get incoming B64 string length (it must be a multiple of 4) */
	b64Len_reported = sdo_read_string_sz(sdor);

	if ((b64Len_reported <= 0) || (b64Len_reported % 4 != 0)) {
		LOG(LOG_ERROR, "Invalid input B64 string!\n");
		goto err;
	}

	/* Calculated expected B64 length using binary length reported */
	b64Len_expected = bin_toB64Length(bin_len_reported);

	if (b64Len_reported != b64Len_expected) {
		LOG(LOG_ERROR, "Incoming B64 string length is not proportional "
			       "to binary length reported!\n");
		goto err;
	}

	/* Allocate required array */
	if (ba->bytes)
		goto err;

	ba->bytes = sdo_alloc(bin_len_reported * sizeof(uint8_t));

	if (!ba->bytes)
		goto err;

	/* Now read the byte array */
	ret = sdo_read_byte_array_field(sdor, b64Len_reported, ba->bytes,
					bin_len_reported);
	ba->byte_sz = ret;
err:
	return ret;
}

/**
 * Byte array is represented as "byte array in base64"
 * @param sdow - pointer to the written data
 * @param ba - pointer to the byte array that holds data to be read from
 */
void sdo_byte_array_write_chars(sdow_t *sdow, sdo_byte_array_t *ba)
{
	sdo_write_byte_array_field(sdow, ba->bytes, ba->byte_sz);
}

/**
 * Byte array is represented as {len,"byte array in base64"}
 * @param sdow - pointer to the written data
 * @param ba - pointer to the byte array that holds data to be read from
 */
void sdo_byte_array_write(sdow_t *sdow, sdo_byte_array_t *ba)
{
	sdo_write_byte_array(sdow, ba->bytes, ba->byte_sz);
}

//------------------------------------------------------------------------------
// Bignum Routines
//

#if 0
/**
 * Allocate the struct of type bignum
 */
sdo_bignum_t *sdo_big_num_alloc()
{
	sdo_bignum_t *bn = sdo_alloc(sizeof(sdo_bignum_t));

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
void sdo_big_num_free(sdo_bignum_t *bn)
{
	sdo_bits_free(bn->value);
	sdo_free(bn);
}
#endif

/**
 * Internal API
 */
// void sdo_big_num_free(sdo_bignum_t *bn)
//{
//   sdo_bits_free(bn->value);
//   sdo_free(bn);
//}

#if 0
/**
 * Compare the struct of type bignum
 * @param bn1 - pointer to struct of type bignum1
 * @param bn2 - pointer to struct of type bignum2
 * @return true if equal else false
 */
bool sdo_bignum_equal(sdo_bignum_t *bn1, sdo_bignum_t *bn2)
{
	if (bn1->sign != bn2->sign)
		return false;
	return sdo_bits_equal(bn1->value, bn2->value);
}

/**
 * Convert bignum to string
 * @param bn - pointer to struct of type bignum
 * @param buf - pointer to the converted string
 * @param buf_sz - size of the converted string
 * @return pointer to the converted string
 */
char *sdo_bignum_to_string(sdo_bignum_t *bn, char *buf, int buf_sz)
{
	return sdo_bits_to_string_hex(bn->value, buf, buf_sz);
}
#endif

//------------------------------------------------------------------------------
// String handler Routines
//

/**
 * Create an empty sdo_string_t object
 * @return an allocated empty sdo_string_t object
 */
sdo_string_t *sdo_string_alloc(void)
{
	return (sdo_string_t *)sdo_alloc(sizeof(sdo_string_t));
}

/**
 * Create a sdo_string_t object from a non zero terminated string
 * @param data - a pointer to the string
 * @param byte_sz - the number of characters in the string ( size 0 or more)
 * @return an allocated sdo_string_t object containing the string
 */
sdo_string_t *sdo_string_alloc_with(const char *data, int byte_sz)
{
	sdo_string_t *temp_str = NULL;
	int total_size = byte_sz + 1;

	if (!data)
		goto err1;

	temp_str = sdo_string_alloc();
	if (!temp_str)
		goto err1;

	temp_str->bytes = sdo_alloc(total_size * sizeof(char));
	if (temp_str->bytes == NULL)
		goto err2;

	temp_str->byte_sz = total_size;
	if (byte_sz) {
		if (memcpy_s(temp_str->bytes, total_size, data, byte_sz) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed here\n");
			goto err2;
		}
	}
	temp_str->bytes[byte_sz] = 0;

	return temp_str;

err2:
	sdo_string_free(temp_str);
err1:
	return NULL;
}

/**
 * Create a sdo_string_t object from a zero terminated string
 * @param data - a pointer to a zero terminated string
 * @return an allocated sdo_string_t object containing the string
 */
sdo_string_t *sdo_string_alloc_with_str(const char *data)
{
	if (!data)
		return NULL;

	int str_sz = strnlen_s(data, SDO_MAX_STR_SIZE);

	if (str_sz == SDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "%s: data"
		    " is either 'NULL' or 'isn't"
		    " NULL-terminated'\n", __func__);
		return NULL;
	}
	return sdo_string_alloc_with(data, str_sz);
}

/**
 * Free an sdo_string_t object, sdo_free any contained buffer as well
 * @param b - the sdo_string_t object to be sdo_freed
 * @return none
 */
void sdo_string_free(sdo_string_t *b)
{
	if (b) {
		sdo_string_init(b);
		sdo_free(b);
	}
}

/**
 * The same as SDOString_empty
 * @param b - the object to have its buffers sdo_freed
 * @return pointer to the empty SDOString object
 */
void sdo_string_init(sdo_string_t *b)
{
	if (b->bytes) {
		sdo_free(b->bytes);
		b->bytes = NULL;
	}
	b->byte_sz = 0;
}

/**
 * Resize the buffer in a sdo_string_t to the new size and
 * return the space filled with zeros
 * sdo_free any already present buffers
 * @param b - the sdo_string_t object to be resized
 * @param byte_sz - the number of bytes to allocate for the new buffer
 * @return true if successful, false otherwise
 */
bool sdo_string_resize(sdo_string_t *b, int byte_sz)
{
	if (!b)
		return false;

	sdo_string_init(b);
	if (byte_sz > 0) {
		b->byte_sz = byte_sz;
		b->bytes = sdo_alloc(byte_sz * sizeof(char));
		if (b->bytes)
			return true;
		else
			return false;
	}
	return true;
}

/**
 * Resize the buffer in a sdo_string_t to the new size and
 * return the space filled with zeros
 * sdo_free any already present buffers
 * @param b - the sdo_string_t object to be resized
 * @param new_byte_sz - the number of bytes to allocate for the new buffer
 * @param data - the non zero terminated string to copy
 * @return true if successful, false otherwise
 */
bool sdo_string_resize_with(sdo_string_t *b, int new_byte_sz, const char *data)
{
	if (!b || !data)
		return NULL;

	if (sdo_string_resize(b, new_byte_sz + 1)) {
		if (new_byte_sz > 0)
			if (memcpy_s(b->bytes, new_byte_sz, data,
				     new_byte_sz) != 0) {
				LOG(LOG_ERROR, "Memcpy Failed\n");
				sdo_free(b->bytes);
				return false;
			}

		return true;
	} else
		return false;
}

#if LOG_LEVEL == LOG_MAX_LEVEL
/**
 *  Returns a zero terminated string value from the sdo_string_t device
 *  @param b - the source SDOString device
 *  @param buf - pointer to a buffer to fill
 *  @param buf_sz - the size of the buffer provided at buf
 *  @return pointer to the beginning of the zero terminated string
 */
char *sdo_string_to_string(sdo_string_t *b, char *buf, int buf_sz)
{
	if (buf_sz >= b->byte_sz + 1) {
		if (memcpy_s(buf, b->byte_sz, b->bytes, b->byte_sz)) {
			LOG(LOG_ERROR, "Memcpy Failed\n");
			return NULL;
		}
		buf[b->byte_sz + 1] = 0;
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
bool sdo_string_read(sdor_t *sdor, sdo_string_t *b)
{
	if (!sdor || !b)
		return false;

	// Clear the passed sdo_string_t object's buffer
	sdo_string_init(b);

	int _len = sdo_read_string_sz(sdor);

	if (!sdo_string_resize(b, (_len + 1))) {
		LOG(LOG_ERROR, "String Resize failed!, requested str_len %d\n",
		    (_len + 1));
		return false;
	}

	sdo_read_string(sdor, b->bytes, b->byte_sz);
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
 * @param buf_sz - size of the converted string
 * @return pointer to the converted string
 */
char *sdo_guid_to_string(sdo_byte_array_t *g, char *buf, int buf_sz)
{
	static const char str[] = "[Guid[16]:";
	int i = 0, n = sizeof(str) - 1;
	char *a = (char *)g->bytes;

	/* buf_sz >= strlen(str) + SDO_GUID_BYTES + ']' + '\0' */
	if (buf_sz < n + SDO_GUID_BYTES + 1 + 1)
		return NULL;

	if (memcpy_s(buf, buf_sz, str, n) != 0) {
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
void sdo_gid_write(sdow_t *sdow)
{
	sdo_write_byte_array_one_int_first(sdow, SDO_PK_ALGO, NULL,
					   SDO_PK_EA_SIZE);
}

/**
 * Allocate Certificate chain and initialize to NULL
 * @return null
 */
sdo_cert_chain_t *sdo_cert_chain_alloc_empty(void)
{
	return sdo_alloc(sizeof(sdo_cert_chain_t));
}

/**
 * Read the Certificate chain
 * @param sdor - pointe to the read EPID information in JSON format
 * @return pointer to the read certificate chain
 */
sdo_cert_chain_t *sdo_cert_chain_read(sdor_t *sdor)
{
	sdo_cert_chain_t *Cert_chain = sdo_cert_chain_alloc_empty();

	if (NULL == Cert_chain) {
		LOG(LOG_ERROR, "Malloc Failed!\n");
		goto err;
	}

	/* Read the total chain len */
	Cert_chain->len = sdo_read_uint(sdor);
	if (Cert_chain->len == 0) {
		LOG(LOG_ERROR, "Invalid Cert chain length reported!\n");
		goto err;
	}

	/* Read the type */
	Cert_chain->type = sdo_read_uint(sdor);
	if (Cert_chain->len == 0) {
		LOG(LOG_ERROR, "Invalid Cert chain length reported!\n");
		goto err;
	}

	/* Read the total number of certificate entries */
	Cert_chain->num_entries = sdo_read_uint(sdor);
	if (Cert_chain->num_entries == 0) {
		LOG(LOG_ERROR, "Invalid Cert chain num entries reported!\n");
		goto err;
	}

	Cert_chain->cert = sdo_byte_array_alloc(Cert_chain->len);
	if (Cert_chain->cert == 0) {
		LOG(LOG_ERROR,
		    "Invalid number of entries in Cert Chain reported!\n");
		goto err;
	}

	if (!sdo_byte_array_read(sdor, Cert_chain->cert)) {
		LOG(LOG_ERROR, "Invalid Cert chain received!\n");
		goto err;
	}

	return Cert_chain;

err:
	if (Cert_chain)
		sdo_free(Cert_chain);
	return NULL;
}

/**
 * Read the Dummy EB i.e. [13, 0, ""] sent when ECDSA based device-attestation
 * is used.
 * @param sdor - pointe to the read EPID information in JSON format
 * @return true when successfully read, false in case of any issues.
 */
bool sdo_ecdsa_dummyEBRead(sdor_t *sdor)
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

	if (!sdor_begin_sequence(sdor)) {
		LOG(LOG_ERROR, "No begin Sequence\n");
		goto end;
	}

	exptype = SDO_PK_ALGO;

	type = sdo_read_uint(sdor);
	if (type != exptype) {
		LOG(LOG_ERROR,
		    "Invalid ECDSA pubkey type, expected %d, got %d\n", exptype,
		    type);
		goto end;
	}

	len = sdo_read_uint(sdor);

	// read empty string
	temp = sdo_read_string(sdor, buf, len);

	LOG(LOG_DEBUG, "Received ecdsa EB of len: %d\n", temp);

	if (len != 0 || temp != 0) {
		LOG(LOG_ERROR, "Got non-zero length EB in case of ECDSA!\n");
		goto end;
	}

	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		goto end;
	}
	retval = true;

end:
	return retval;
}


/**
 * Do a dummy read for ECDSA
 * @param sdor - pointer to the read location in JSON format
 * @return 0 on success and -1 on failure
 */
int32_t sdo_eb_read(sdor_t *sdor)
{
	int32_t ret = (false == sdo_ecdsa_dummyEBRead(sdor)) ? -1 : 0;
	return ret;
}

/* -----------------------------------------------------------------------------
 * Nonce routines
 */
/**
 * Initialize Nonce with random data
 * @param n - pointer to the byte array
 * @return none
 */
void sdo_nonce_init_rand(sdo_byte_array_t *n)
{
	sdo_crypto_random_bytes((uint8_t *)n->bytes, n->byte_sz);
}

/**
 * compare the two nonce
 * @param n1 - pointer to the first byte array
 * @param n2 - pointer to the second byte array
 * @return true if equal else false
 */
bool sdo_nonce_equal(sdo_byte_array_t *n1, sdo_byte_array_t *n2)
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
 * @param buf_sz - size of the converted string
 * @return pointer to the converted string
 */
char *sdo_nonce_to_string(uint8_t *n, char *buf, int buf_sz)
{
	int i = 0, j = 1;
	char *a = (char *)n;

	(void)buf_sz; /* FIXME: Change the signature as its unused */

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
sdo_hash_t *sdo_hash_alloc_empty(void)
{
	sdo_hash_t *hp = sdo_alloc(sizeof(sdo_hash_t));

	if (hp == NULL)
		return NULL;
	hp->hash_type = SDO_CRYPTO_HASH_TYPE_NONE;
	return hp;
}

/**
 * Allocate byte array of hash type specified
 * @param hash_type - type of the hash
 * @param size - size of the byte array to be allocated
 * @return pointer to the allocated hash struct
 */
sdo_hash_t *sdo_hash_alloc(int hash_type, int size)
{
	sdo_hash_t *hp = sdo_alloc(sizeof(sdo_hash_t));

	if (hp == NULL)
		return NULL;
	hp->hash_type = hash_type;
	hp->hash = sdo_byte_array_alloc(size);
	if (hp->hash == NULL) {
		sdo_free(hp);
		return NULL;
	}
	return hp;
}

/**
 * Free the allocated struct of type hash type
 * @param hp - pointer to the struct of type hash that is to be sdo_free
 */
void sdo_hash_free(sdo_hash_t *hp)
{
	if (NULL == hp) {
		return;
	}
	if (hp->hash != NULL) {
		sdo_byte_array_free(hp->hash);
		hp->hash = NULL;
	}
	sdo_free(hp);
}

#if LOG_LEVEL == LOG_MAX_LEVEL
/**
 * Convert hash type to string
 * @param hash_type - hash type that has to be converted to string
 * @return the converted string
 */
char *sdo_hash_type_to_string(int hash_type)
{
	static char buf[25];

	switch (hash_type) {
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
	if (snprintf_s_i(buf, sizeof(buf), "-type%u?", hash_type) < 0) {
		LOG(LOG_ERROR, "snprintf() failed!\n");
		return NULL;
	}
	return buf;
}

/**
 * convert the hash type to the string
 * @param hp - pointer to the struct if type hash
 * @param buf - pointer to the converted string
 * @param buf_sz - size of the converted string
 * @return pointer to the converted string
 */
char *sdo_hash_to_string(sdo_hash_t *hp, char *buf, int buf_sz)
{
	char name[35];
	char *hash_ptr = NULL;

	hash_ptr = sdo_hash_type_to_string(hp->hash_type);
	if (hash_ptr) {
		if (strncpy_s(name, sizeof(name), hash_ptr,
			      strnlen_s(hash_ptr, sizeof(name))) != 0) {
			LOG(LOG_ERROR, "strcpy() failed!\n");
			return NULL;
		}
		return sdo_bits_to_string(hp->hash, name, buf, buf_sz);
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
int sdo_hash_read(sdor_t *sdor, sdo_hash_t *hp)
{
	int b64Len_reported = 0;

	if (!sdor || !hp)
		return 0;

	if (!sdor_begin_sequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		return 0;
	}

	// LOG(LOG_ERROR, "Reading hash\n");

	// Read the bin character length
	int mbin_len_reported = sdo_read_uint(sdor);

	// Read the hash type value
	hp->hash_type = sdo_read_uint(sdor);

	// Make sure we have a byte array to resize
	if (hp->hash == NULL) {
		hp->hash = sdo_byte_array_alloc(8);
		if (!hp->hash) {
			LOG(LOG_ERROR, "Alloc failed\n");
			return 0;
		}
	}

	// LOG(LOG_ERROR, "sdo_hash_read next char: '%c'\n",
	// sdor->b.block[sdor->b.cursor+1]);

	/* Get incoming B64 string length (it must be a multiple of 4) */
	b64Len_reported = sdo_read_string_sz(sdor);
	if ((b64Len_reported <= 0) || (b64Len_reported % 4 != 0)) {
		LOG(LOG_ERROR, "Invalid input B64 string!\n");
		return 0;
	}

	/* Calculated expected B64 length using binary length reported */
	// Calculate b64Len to read the buffer.
	int b64Len = bin_toB64Length(mbin_len_reported);

	if (b64Len_reported != b64Len) {
		LOG(LOG_ERROR, "Incoming B64 string length is not proportional "
			       "to binary length reported!\n");
		return 0;
	}

	// TODO: Introduction of a check wud be needed : (b64Len != 0)
	// LOG(LOG_ERROR, "sdo_hash_read : %d\n", bin_len);
	// Allocate 3 bytes extra for max probable decodaed output
	// Resize the byte array buffer to required length

	if (mbin_len_reported &&
	    sdo_bits_resize(hp->hash, mbin_len_reported + 3) == false) {
		sdo_byte_array_free(hp->hash);
		LOG(LOG_ERROR, "SDOBits_resize failed\n");
		return 0;
	}
	// LOG(LOG_ERROR, "Hash resized to match, len: %d\n",
	// hp->hash->byte_sz);

	// Convert buffer from base64 to binary
	int was_read = sdo_read_byte_array_field(sdor, b64Len, hp->hash->bytes,
						 hp->hash->byte_sz);

	// LOG(LOG_ERROR, "Byte array read, was_read : %d, byte_sz: %d\n",
	// was_read, hp->hash->byte_sz);
	// char dbuf[128];
	// LOG(LOG_ERROR, "Buf : %s\n", sdo_byte_array_to_string(hp->hash, dbuf,
	// 128));

	hp->hash->byte_sz = was_read;

	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		return 0;
	}
	return was_read;
}

/**
 * Write the hash type
 * @param sdow - pointer to the output struct of type JSON message
 * @param hp - pointer to the struct of type hash
 * @return none
 */
void sdo_hash_write(sdow_t *sdow, sdo_hash_t *hp)
{
	sdo_write_byte_array_one_int(sdow, hp->hash_type, hp->hash->bytes,
				     hp->hash->byte_sz);
}

/**
 * Write out a NULL value hash
 * @param sdow - pointer to the output buffer
 * @return none
 */
void sdo_hash_null_write(sdow_t *sdow)
{
	if (!sdow)
		return;
	sdo_write_byte_array_one_int(sdow, SDO_CRYPTO_HASH_TYPE_NONE, NULL, 0);
}

//------------------------------------------------------------------------------
// Key Exchange Routines
//

#if 0
/**
 * Internal API
 */
sdo_key_exchange_t *SDOKey_ex_alloc()
{
	return (sdo_key_exchange_t *)sdo_byte_array_alloc(8);
}

/**
 * Internal API
 */
sdo_key_exchange_t *SDOKey_ex_alloc_with(int size, uint8_t *content)
{
	return sdo_byte_array_alloc_with_byte_array(content, size);
}
#endif

//------------------------------------------------------------------------------
// IP Address Routines
//

/**
 * Allocate the struct of type IP address
 */
sdo_ip_address_t *sdo_ipaddress_alloc(void)
{
	sdo_ip_address_t *sdoip = sdo_alloc(sizeof(sdo_ip_address_t));

	if (sdoip == NULL) {
		return NULL;
	}
	if (sdo_null_ipaddress(sdoip)) {
		return sdoip;
	}

	sdo_free(sdoip);
	return NULL;

}

/**
 * Initialize the struct of type IP with the ipv4 details provided
 * @param sdoip - pointer to the struct if type IP
 * @param ipv4 - ipv4 details that has to be initialized with
 */
void sdo_init_ipv4_address(sdo_ip_address_t *sdoip, uint8_t *ipv4)
{
	if (!sdoip || !ipv4)
		return;

	sdoip->length = 4;
	if (memset_s(&sdoip->addr[0], sizeof(sdoip->addr), 0) != 0) {
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
void sdo_init_ipv6_address(sdo_ip_address_t *sdoip, uint8_t *ipv6)
{
	sdoip->length = 16;
	memcpy(sdoip->addr, ipv6, sdoip->length);
	// memset(&sdoip->addr, 0, sizeof sdoip->addr - sdoip->length);
}

/**
 * Internal API
 */
int sdo_ipaddress_to_mem(sdo_ip_address_t *sdoip, uint8_t *copyto)
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
bool sdo_null_ipaddress(sdo_ip_address_t *sdoip)
{
	sdoip->length = 0;
	if (memset_s(&sdoip->addr[0], sizeof(sdoip->addr), 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return false;
	} else
		return true;
}

/**
 * Conver the IP address to string
 * @param sdoip - pointer to the struct which holds the IP address
 * @param buf - pointer to the converted string
 * @param buf_sz - size of the converted string
 * @return pointer to the converted string
 */
char *sdo_ipaddress_to_string(sdo_ip_address_t *sdoip, char *buf, int buf_sz)
{
	int n;
	char *buf0 = buf;

	if (!sdoip || !buf)
		return NULL;

	if (sdoip->length == 4) {
		int temp;

		temp = snprintf_s_i(buf, buf_sz, "[IPv4:%u", sdoip->addr[0]);

		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n = temp;

		temp = snprintf_s_i(buf + strnlen_s(buf, buf_sz), buf_sz, ".%u",
				    sdoip->addr[1]);
		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n += temp;

		temp = snprintf_s_i(buf + strnlen_s(buf, buf_sz), buf_sz, ".%u",
				    sdoip->addr[2]);
		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n += temp;

		temp = snprintf_s_i(buf + strnlen_s(buf, buf_sz), buf_sz,
				    ".%u]", sdoip->addr[3]);
		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n += temp;

		buf += n;
		buf_sz -= n;
	} else if (sdoip->length == 16) {
		if (strncpy_s(buf, buf_sz, "[IPv6", buf_sz) != 0) {
			LOG(LOG_ERROR, "strcpy() failed!\n");
			return NULL;
		}
		n = strnlen_s(buf, buf_sz);

		if (!n || n == buf_sz) {
			LOG(LOG_ERROR, "strlen() failed!\n");
			return NULL;
		}

		buf += n;
		buf_sz -= n;
		while (n + 7 < buf_sz) {
			int temp;

			temp =
			    snprintf_s_i(buf, buf_sz, ":%02X", sdoip->addr[n]);

			if (temp < 0) {
				LOG(LOG_ERROR, "snprintf() failed!\n");
				return NULL;
			}
			n = temp;
			temp = snprintf_s_i(buf, buf_sz, "%02X",
					    sdoip->addr[n + 1]);

			if (temp < 0) {
				LOG(LOG_ERROR, "snprintf() failed!\n");
				return NULL;
			}

			n += temp;

			buf += n;
			buf_sz -= n;
		}
	} else {
		if (snprintf_s_i(buf, buf_sz, "[IP?? len:%u]", sdoip->length) <
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
bool sdo_read_ipaddress(sdor_t *sdor, sdo_ip_address_t *sdoip)
{
	sdo_byte_array_t *IP;

	if (!sdor || !sdoip)
		return false;

	IP = sdo_byte_array_alloc_with_int(0);
	if (!IP)
		return false;

	if (!sdor_begin_sequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		sdo_byte_array_free(IP);
		return false;
	}

	if (!sdo_byte_array_read(sdor, IP)) {
		sdo_byte_array_free(IP);
		return false;
	}

	sdoip->length = IP->byte_sz;
	if (memcpy_s(&sdoip->addr[0], sdoip->length, IP->bytes, IP->byte_sz) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}
	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		return false;
	}
	sdo_byte_array_free(IP);
	return true;
}

/**
 * Wrirte the IP address
 * @param sdow - output to which IP is written to
 * @param sdoip - pointer to the struct of type IP address
 * @return none
 */
void sdo_write_ipaddress(sdow_t *sdow, sdo_ip_address_t *sdoip)
{
	sdo_write_byte_array(sdow, &sdoip->addr[0], sdoip->length);
}

/**
 * Internal API
 */
#if 0
void SDODNSEmpty(sdo_dns_name_t *b)
{
	if (b->name) {
		sdo_free(b->name);
		b->name = NULL;
	}
	b->length = 0;
}
#endif

/**
 * Read the DNS information
 * @param sdor - pointer to the input information
 */
char *sdo_read_dns(sdor_t *sdor)
{
	char *buf;
	int len;

	/* read length of DNS */
	len = sdo_read_string_sz(sdor);

	buf = sdo_alloc(len + 1);

	if (!buf)
		return NULL;

	sdo_read_string(sdor, buf, len + 1);

	if (len == 0) {
		sdo_free(buf);
		return NULL;
	}

	return buf;
}

/**
 * Write the APPID
 * @param sdow - pointer to the written APPID
 */
void sdo_app_id_write(sdow_t *sdow)
{
	/* Swap appid to network endianess if needed */
	/* TODO: Change to compilation time byteswap */
	uint32_t appid = sdo_host_to_net_long(APPID);
	/* AppID is always bytes according specification, so we can hardcode it
	 * here
	 */
	sdo_write_byte_array_one_int(sdow, SDO_APP_ID_TYPE_BYTES,
				     (uint8_t *)&appid, sizeof(appid));
}

//------------------------------------------------------------------------------
// Public Key Routines
//

/**
 * Allocate an empty public key
 */
sdo_public_key_t *sdo_public_key_alloc_empty(void)
{
	return sdo_alloc(sizeof(sdo_public_key_t));
}

/**
 * Allocate public key and initialize
 * @param pkalg - algorithm to be used for public key
 * @param pkenc - public key encoding type
 * @param pklen - publick key length
 * @param pkey - pointer to the public key
 * @return pointer to the public key
 */
sdo_public_key_t *sdo_public_key_alloc(int pkalg, int pkenc, int pklen,
				       uint8_t *pkey)
{
	sdo_public_key_t *pk = sdo_public_key_alloc_empty();

	if (!pk) {
		LOG(LOG_ERROR, "failed to allocate public key structure\n");
		return NULL;
	}
	pk->pkalg = pkalg;
	pk->pkenc = pkenc;
	pk->key1 = sdo_byte_array_alloc_with_byte_array(pkey, pklen);
	return pk;
}

/**
 * Clone the public key
 * @param pk 0 pointer to the public key that is to be cloned
 * @return pointer to the cloned public key
 */
sdo_public_key_t *sdo_public_key_clone(sdo_public_key_t *pk)
{
	if (pk == NULL)
		return NULL;

	if (!pk->key1 || !pk->pkenc || !pk->pkalg)
		return NULL;

	sdo_public_key_t *npk = sdo_public_key_alloc(
	    pk->pkalg, pk->pkenc, pk->key1->byte_sz, pk->key1->bytes);
	if (!npk) {
		LOG(LOG_ERROR, "failed to alloc public key struct\n");
		return NULL;
	}
	if (pk->key2 != NULL) {
		npk->key2 = sdo_byte_array_alloc_with_byte_array(
		    pk->key2->bytes, pk->key2->byte_sz);
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
bool sdo_compare_public_keys(sdo_public_key_t *pk1, sdo_public_key_t *pk2)
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

	if (memcmp_s(pk1->key1->bytes, pk1->key1->byte_sz, pk2->key1->bytes,
		     pk2->key1->byte_sz, &result_memcmp) ||
	    result_memcmp)
		return false;

	/* X.509 encoded pubkeys only have key1 parameter */
	if (pk1->key2 && pk2->key2) {
		if (memcmp_s(pk1->key2->bytes, pk1->key2->byte_sz,
			     pk2->key2->bytes, pk2->key2->byte_sz,
			     &result_memcmp) ||
		    result_memcmp)
			return false;
	}
	return true;
}

/**
 * Free the allocated public key
 * @param pk - pointer to the public key that is to be sdo_freed
 */
void sdo_public_key_free(sdo_public_key_t *pk)
{
	if (!pk)
		return;
	sdo_byte_array_free(pk->key1);
	if (pk->key2) {
		sdo_byte_array_free(pk->key2);
	}
	sdo_free(pk);
}

/**
 * Convert he alggorith to string
 * @param alg - type of the algorithm
 * @return pointer to converted algorith string
 */
const char *sdo_pk_alg_to_string(int alg)
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
	default:
		return NULL;
	}
	if (snprintf_s_i(buf, sizeof(buf), "Alg:%u?", alg) < 0) {
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
const char *sdo_pk_enc_to_string(int enc)
{
	static char buf[25];

	switch (enc) {
	case SDO_CRYPTO_PUB_KEY_ENCODING_X509:
		return "EncX509";
	case SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP:
		return "EncRSAMODEXP";
	case SDO_CRYPTO_PUB_KEY_ENCODING_EPID:
		return "EncEPID";
	default:
		return NULL;
	}
	if (snprintf_s_i(buf, sizeof(buf), "Enc:%u?", enc) < 0) {
		LOG(LOG_ERROR, "snprintf() failed!\n");
		return NULL;
	}
	return buf;
}

/**
 * Write a full public key to the output buffer
 * @param sdow - output buffer to hold JSON representation
 * @param pk - pointer to the sdo_public_key_t object
 * @return none
 */
void sdo_public_key_write(sdow_t *sdow, sdo_public_key_t *pk)
{
	if (!sdow)
		return;

	sdow_begin_sequence(sdow);
	if (pk == NULL || pk->key1->byte_sz == 0) {
		// Write null key (pknull)
		sdo_writeUInt(sdow, 0);
		sdo_writeUInt(sdow, 0);
		sdow_begin_sequence(sdow);
		sdo_writeUInt(sdow, 0);
		sdow_end_sequence(sdow);
		sdow_end_sequence(sdow);
		return;
	}
	// LOG(LOG_ERROR, "------- pk is %lu bytes long\n",
	// pk->key1->byte_sz);
	sdo_writeUInt(sdow, pk->pkalg);
	sdo_writeUInt(sdow, pk->pkenc);
	sdo_write_byte_array(sdow, pk->key1->bytes, pk->key1->byte_sz);
	if (pk->pkenc == SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP) {
		sdo_write_byte_array(sdow, pk->key2->bytes, pk->key2->byte_sz);
	}
	sdow_end_sequence(sdow);
	// LOG(LOG_ERROR, "SDOWrite_public_key_stub: pklen:%u pkalg:%u pkenc:%u
	// \n",
	// pk->bits.byte_sz, pk->pkalg, pk->pkenc);
}

/**
 * Convert the public key to string
 * @param pk - pointer to the public key
 * @param buf - pointer to the converted string
 * @param bufsz - size of the converted string
 * @return pointer to the converted string
 */
char *sdo_public_key_to_string(sdo_public_key_t *pk, char *buf, int bufsz)
{
	char *buf0 = buf;
	int n = 0;
	char temp_char[20];
	const char *char_ptr;

	if (!pk || !buf)
		return NULL;

	char_ptr = temp_char;

	if (strncpy_s(buf, bufsz, "[SDOPublic_key", bufsz) != 0) {
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

	char_ptr = sdo_pk_alg_to_string(pk->pkalg);

	if (!char_ptr)
		return NULL;

	if (strncpy_s(buf, bufsz, " alg:", bufsz) != 0) {
		LOG(LOG_ERROR, "strcpy() failed!\n");
		return NULL;
	}
	if (strcat_s(buf, bufsz, char_ptr) != 0) {
		LOG(LOG_ERROR, "strcat() failed!\n");
		return NULL;
	}
	n = strnlen_s(" alg:", bufsz) + strnlen_s(char_ptr, bufsz);

	if (!n || n == bufsz) {
		LOG(LOG_ERROR, "strlen() failed!\n");
		return NULL;
	}

	buf += n;
	bufsz -= n;

	char_ptr = sdo_pk_enc_to_string(pk->pkenc);

	if (!char_ptr)
		return NULL;

	if (strncpy_s(buf, bufsz, " enc:", bufsz) != 0) {
		LOG(LOG_ERROR, "strcpy() failed!\n");
		return NULL;
	}

	if (strcat_s(buf, bufsz, char_ptr) != 0) {
		LOG(LOG_ERROR, "strcat() failed!\n");
		return NULL;
	}

	n = strnlen_s(" enc:", bufsz) + strnlen_s(char_ptr, bufsz);

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

		sdo_byte_array_to_string(pk->key1, buf, bufsz);
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
			sdo_byte_array_to_string(pk->key2, buf, bufsz);
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
		sdo_byte_array_to_string(pk->key1, buf, bufsz);
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
sdo_public_key_t *sdo_public_key_read(sdor_t *sdor)
{
	sdo_public_key_t *pk;
	int pkalg, pkenc;

	if (!sdor)
		return NULL;

	if (!sdor_begin_sequence(sdor))
		goto err;
	pkalg = sdo_read_uint(sdor);
	pkenc = sdo_read_uint(sdor);

	if (!pkalg || !pkenc)
		goto err;

	if (!sdor_begin_sequence(sdor))
		goto err;

	// There will now be one or two Bytearray values
	sdo_byte_array_t *baK1 = sdo_byte_array_alloc_with_int(0);

	if (!baK1 || (sdo_byte_array_read(sdor, baK1) == 0)) {
		sdo_byte_array_free(baK1);
		goto err;
	}

	pk = sdo_public_key_alloc_empty(); // Create a Public Key
	if (!pk) {
		sdo_byte_array_free(baK1);
		goto err;
	}

	pk->pkalg = pkalg;
	pk->pkenc = pkenc;
	pk->key1 = baK1;

	LOG(LOG_DEBUG, "Public_key_read Key1 read, %zu bytes\n",
	    pk->key1->byte_sz);

	// Check to see if the second key is needed
	// LOG(LOG_ERROR, "PK @ %d Next c '%c'\n", sdor->b.cursor,
	// sdor_peek(sdor));

	if (sdor_peek(sdor) != ']') {
		sdor->need_comma = true;
		sdo_byte_array_t *baK2 = sdo_byte_array_alloc_with_int(0);
		// Read second key
		if (!baK2 || sdo_byte_array_read(sdor, baK2) == 0) {
			sdo_byte_array_free(baK2);
			sdo_public_key_free(pk);
			goto err;
		} else
			pk->key2 = baK2;

		LOG(LOG_DEBUG, "Public_key_read Key2 read, %zu bytes\n",
		    pk->key2->byte_sz);
	}
	// LOG(LOG_ERROR, "PK @ %d Next c '%c'\n", sdor->b.cursor,
	// sdor_peek(sdor));

	if (!sdor_end_sequence(sdor))
		LOG(LOG_DEBUG, "Not at end of inner PK sequence\n");
	// LOG(LOG_ERROR, "PK @ %d Next c '%c'\n", sdor->b.cursor,
	// sdor_peek(sdor));

	if (!sdor_end_sequence(sdor))
		LOG(LOG_DEBUG, "Not at end of outer PK sequence\n");
	// LOG(LOG_ERROR, "PK @ %d Next c '%c'\n", sdor->b.cursor,
	// sdor_peek(sdor));

	sdor->need_comma = true;

	LOG(LOG_DEBUG,
	    "Public_key_read pkalg: %d. pkenc: %d, key1: %zu, key2: %zu\n",
	    pk->pkalg, pk->pkenc, pk->key1 ? pk->key1->byte_sz : 0,
	    pk->key2 ? pk->key2->byte_sz : 0);

	return pk;
err:
	sdor_read_and_ignore_until_end_sequence(sdor);
	if (!sdor_end_sequence(sdor)) {
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
sdo_rendezvous_t *sdo_rendezvous_alloc(void)
{
	return sdo_alloc(sizeof(sdo_rendezvous_t));
}

/**
 * Free the allocated rendezvous struct
 * @param rv - pointer to the struct of type rendezvous
 */
void sdo_rendezvous_free(sdo_rendezvous_t *rv)
{
	if (!rv)
		return;

	if (rv->only != NULL)
		sdo_string_free(rv->only);

	if (rv->ip != NULL)
		sdo_free(rv->ip);

	if (rv->po != NULL)
		sdo_free(rv->po);

	if (rv->pow != NULL)
		sdo_free(rv->pow);

	if (rv->dn != NULL)
		sdo_string_free(rv->dn);

	if (rv->sch != NULL)
		sdo_hash_free(rv->sch);

	if (rv->cch != NULL)
		sdo_hash_free(rv->cch);

	if (rv->ui != NULL)
		sdo_free(rv->ui);

	if (rv->ss != NULL)
		sdo_string_free(rv->ss);

	if (rv->pw != NULL)
		sdo_string_free(rv->pw);

	if (rv->wsp != NULL)
		sdo_string_free(rv->wsp);

	if (rv->me != NULL)
		sdo_string_free(rv->me);

	if (rv->pr != NULL)
		sdo_string_free(rv->pr);

	if (rv->delaysec != NULL)
		sdo_free(rv->delaysec);

	sdo_free(rv);
}

/**
 * Write a rendezvous object to the output buffer
 * @param sdow - the buffer pointer
 * @param rv - pointer to the rendezvous object to write
 * @return true if written successfully, otherwise false
 */
bool sdo_rendezvous_write(sdow_t *sdow, sdo_rendezvous_t *rv)
{
	if (!sdow || !rv)
		return false;

	sdow_begin_sequence(sdow);

	sdow->need_comma = false;
	sdo_writeUInt(sdow, rv->num_params);
	sdow->need_comma = true;

	sdow_begin_object(sdow);

	if (rv->only != NULL) {
		sdo_write_tag(sdow, "only");
		sdo_write_string_len(sdow, rv->only->bytes, rv->only->byte_sz);
	}

	if (rv->ip != NULL) {
		sdo_write_tag(sdow, "ip");
		sdo_write_ipaddress(sdow, rv->ip);
	}

	if (rv->po != NULL) {
		sdo_write_tag(sdow, "po");
		sdo_writeUInt(sdow, *rv->po);
	}

	if (rv->pow != NULL) {
		sdo_write_tag(sdow, "pow");
		sdo_writeUInt(sdow, *rv->pow);
	}

	if (rv->dn != NULL) {
		sdo_write_tag(sdow, "dn");
		sdo_write_string_len(sdow, rv->dn->bytes, rv->dn->byte_sz);
	}

	if (rv->sch != NULL) {
		sdo_write_tag(sdow, "sch");
		sdo_hash_write(sdow, rv->sch);
	}

	if (rv->cch != NULL) {
		sdo_write_tag(sdow, "cch");
		sdo_hash_write(sdow, rv->cch);
	}

	if (rv->ui != NULL) {
		sdo_write_tag(sdow, "ui");
		sdo_writeUInt(sdow, *rv->ui);
	}

	if (rv->ss != NULL) {
		sdo_write_tag(sdow, "ss");
		sdo_write_string_len(sdow, rv->ss->bytes, rv->ss->byte_sz);
	}

	if (rv->pw != NULL) {
		sdo_write_tag(sdow, "pw");
		sdo_write_string_len(sdow, rv->pw->bytes, rv->pw->byte_sz);
	}

	if (rv->wsp != NULL) {
		sdo_write_tag(sdow, "wsp");
		sdo_write_string_len(sdow, rv->wsp->bytes, rv->wsp->byte_sz);
	}

	if (rv->me != NULL) {
		sdo_write_tag(sdow, "me");
		sdo_write_string_len(sdow, rv->me->bytes, rv->me->byte_sz);
	}

	if (rv->pr != NULL) {
		sdo_write_tag(sdow, "pr");
		sdo_write_string_len(sdow, rv->pr->bytes, rv->pr->byte_sz);
	}

	if (rv->delaysec != NULL) {
		sdo_write_tag(sdow, "delaysec");
		sdo_writeUInt(sdow, *rv->delaysec);
	}

	sdow_end_object(sdow);
	sdow_end_sequence(sdow);

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
	const char *key;
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
int keyfromstring(const char *key)
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
bool sdo_rendezvous_read(sdor_t *sdor, sdo_rendezvous_t *rv)
{
	//    sdo_block_t *sdob = &sdor->b;
	int ret = true;

	if (!sdor || !rv)
		return false;

	if (!sdor_begin_sequence(sdor))
		ret = false;
	int num_rv_entries = sdo_read_uint(sdor);

	if (!sdor_begin_object(sdor))
		ret = false;

	LOG(LOG_DEBUG, "%s started\n", __func__);

	int index, result;
	size_t key_buf_sz = 24;
	char key_buf[key_buf_sz];
	size_t str_buf_sz = 80;
	char str_buf[str_buf_sz];

	rv->num_params = 0;

	for (index = 0; index < num_rv_entries; index++) {
		if (memset_s(key_buf, key_buf_sz, 0) != 0) {
			LOG(LOG_ERROR, "Memset Failed\n");
			return false;
		}

		int str_len = sdo_read_string(sdor, key_buf, key_buf_sz);

		if (str_len == 0 || str_len > (int)key_buf_sz)
			ret = false;

		// Parse the values found
		switch (keyfromstring(key_buf)) {

		case ONLY:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (memset_s(str_buf, str_buf_sz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}

			result = sdo_read_string(sdor, str_buf, str_buf_sz);

			if (result == 0 || result > (int)str_buf_sz)
				return false;

			/*if not for device skip it*/
			int strcmp_result = 0;

			strcmp_s(str_buf, str_buf_sz, "dev", &strcmp_result);
			if (strcmp_result != 0) {
				sdor_read_and_ignore_until_end_sequence(sdor);
				return false;
			}
			if (rv->only) {
				sdo_string_free(rv->only);
			}
			rv->only = sdo_string_alloc_with(str_buf, result);
			if (!rv->only) {
				LOG(LOG_ERROR, "Rendezvous dev alloc failed\n");
				ret = false;
			}
			break;

		case IP:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (rv->ip) {
				sdo_free(rv->ip);
			}

			rv->ip = sdo_ipaddress_alloc();
			if (!rv->ip) {
				LOG(LOG_ERROR, "Rendezvous ip alloc failed\n");
				ret = false;
				break;
			}
			if (sdo_read_ipaddress(sdor, rv->ip) != true) {
				LOG(LOG_ERROR, "Read IP Address failed\n");
				ret = false;
			}
			break;

		case PO:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (rv->po) {
				sdo_free(rv->po);
			}

			rv->po =
			    sdo_alloc(sizeof(uint32_t)); // Allocate an integer
			if (!rv->po) {
				LOG(LOG_ERROR, "Rendezvous po alloc failed\n");
				ret = false;
				break;
			}
			*rv->po = sdo_read_uint(sdor);
			break;

		/* valid only for OWNER */
		case POW:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (rv->pow) {
				sdo_free(rv->pow);
			}

			rv->pow = sdo_alloc(sizeof(uint32_t));
			if (!rv->pow) {
				LOG(LOG_ERROR, "Rendezvous pow alloc fail\n");
				ret = false;
				break;
			}
			*rv->pow = sdo_read_uint(sdor);
			break;

		case DN:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (memset_s(str_buf, str_buf_sz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}

			result = sdo_read_string(sdor, str_buf, str_buf_sz);
			if (result == 0 || result > (int)str_buf_sz)
				return false;

			if (rv->dn) {
				sdo_string_free(rv->dn);
			}

			rv->dn = sdo_string_alloc_with(str_buf, result);
			if (!rv->dn) {
				LOG(LOG_ERROR, "Rendezvous dn alloc failed\n");
				ret = false;
			}
			break;

		case SCH:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (rv->sch) {
				sdo_hash_free(rv->sch);
			}
			rv->sch = sdo_hash_alloc_empty();
			if (!rv->sch) {
				LOG(LOG_ERROR, "Rendezvous ss alloc failed\n");
				ret = false;
				break;
			}
			result = sdo_hash_read(sdor, rv->sch);
			break;

		case CCH:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (rv->cch) {
				sdo_hash_free(rv->cch);
			}

			rv->cch = sdo_hash_alloc_empty();
			if (!rv->cch) {
				LOG(LOG_ERROR, "Rendezvous cch alloc fail\n");
				ret = false;
				break;
			}
			result = sdo_hash_read(sdor, rv->cch);
			break;

		case UI:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (rv->ui) {
				sdo_free(rv->ui);
			}

			rv->ui =
			    sdo_alloc(sizeof(uint32_t)); // Allocate an integer
			if (!rv->ui) {
				LOG(LOG_ERROR, "Rendezvous ui alloc failed\n");
				ret = false;
				break;
			}

			*rv->ui = sdo_read_uint(sdor);
			break;

		case SS:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (memset_s(str_buf, str_buf_sz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}
			result = sdo_read_string(sdor, str_buf, str_buf_sz);
			if (result == 0 || result > (int)str_buf_sz)
				return false;

			if (rv->ss) {
				sdo_string_free(rv->ss);
			}
			rv->ss = sdo_string_alloc_with(str_buf, result);
			if (!rv->ss) {
				LOG(LOG_ERROR, "Rendezvous ss alloc failed\n");
				ret = false;
			}
			break;

		case PW:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (memset_s(str_buf, str_buf_sz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}
			result = sdo_read_string(sdor, str_buf, str_buf_sz);
			if (result == 0 || result > (int)str_buf_sz)
				return false;

			if (rv->pw) {
				sdo_string_free(rv->pw);
			}

			rv->pw = sdo_string_alloc_with(str_buf, result);
			if (!rv->pw) {
				LOG(LOG_ERROR, "Rendezvous pw alloc failed\n");
				ret = false;
			}
			break;

		case WSP:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (memset_s(str_buf, str_buf_sz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}
			result = sdo_read_string(sdor, str_buf, str_buf_sz);
			if (result == 0 || result > (int)str_buf_sz)
				return false;

			if (rv->wsp) {
				sdo_string_free(rv->wsp);
			}

			rv->wsp = sdo_string_alloc_with(str_buf, result);
			if (!rv->wsp) {
				LOG(LOG_ERROR, "Rendezvous wsp alloc fail\n");
				ret = false;
			}
			break;

		case ME:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (memset_s(str_buf, str_buf_sz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}
			result = sdo_read_string(sdor, str_buf, str_buf_sz);
			if (result == 0 || result > (int)str_buf_sz)
				return false;

			if (rv->me) {
				sdo_string_free(rv->me);
			}
			rv->me = sdo_string_alloc_with(str_buf, result);
			if (!rv->me) {
				LOG(LOG_ERROR, "Rendezvous me alloc failed\n");
				ret = false;
			}
			break;

		case PR:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (memset_s(str_buf, str_buf_sz, 0) != 0) {
				LOG(LOG_ERROR, "Memset Failed\n");
				return false;
			}

			result = sdo_read_string(sdor, str_buf, str_buf_sz);
			if (result == 0 || result > (int)str_buf_sz)
				return false;

			if (rv->pr) {
				sdo_string_free(rv->pr);
			}

			rv->pr = sdo_string_alloc_with(str_buf, result);
			if (!rv->pr) {
				LOG(LOG_ERROR, "Rendezvous pr alloc failed\n");
				ret = false;
			}
			break;

		case DELAYSEC:
			if (!sdo_read_tag_finisher(sdor))
				return false;

			if (rv->delaysec) {
				sdo_free(rv->delaysec);
			}

			rv->delaysec = sdo_alloc(sizeof(uint32_t));
			if (!rv->delaysec) {
				LOG(LOG_ERROR, "Alloc failed\n");
				return false;
			}
			*rv->delaysec = sdo_read_uint(sdor);
			if (!rv->delaysec) {
				LOG(LOG_ERROR, "Rendezvous ss alloc failed\n");
				ret = false;
			}
			break;

		default:
			LOG(LOG_ERROR,
			    "%s : Unknown Entry Type %s\n",
			    __func__, key_buf);
			ret = false; // Abort due to unexpected value for key
			break;
		}
		if (ret == false)
			break;
		rv->num_params++;
	}

	if ((ret == true) && !sdor_end_object(sdor)) {
		LOG(LOG_ERROR, "No End Object\n");
		ret = false;
	}

	if ((ret == true) && !sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		ret = false;
	}

	return ret;
}

#if LOG_LEVEL == LOG_MAX_LEVEL
/**
 * Takes sdo_rendezvous_t object as input and writes string
 * format data to buffer buf.
 * @param rv - sdo_rendezvous_t pointer as input buffer.
 * @param buf - char pointer as output buffer buf.
 * @param bufsz - size of buffer buf
 * @return char buffer.
 */
char *sdo_rendezvous_to_string(sdo_rendezvous_t *rv, char *buf, int bufsz)
{
	char *r = buf;

	sdo_ipaddress_to_string(rv->ip, buf, bufsz);
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
// Rendezvous_list Routines
//

/**
 * Allocate an empty SDORendezvous_list object to the list.
 * @return an allocated SDORendezvous_list object.
 */
sdo_rendezvous_list_t *sdo_rendezvous_list_alloc(void)
{
	return sdo_alloc(sizeof(sdo_rendezvous_list_t));
}

/**
 * Free all entries  in the list.
 * @param list - the list to sdo_free.
 * @return none
 */
void sdo_rendezvous_list_free(sdo_rendezvous_list_t *list)
{
	sdo_rendezvous_t *entry, *next;

	if (list == NULL) {
		return;
	}

	/* Delete all entries. */
	next = entry = list->rv_entries;
	while (entry) {
		next = entry->next;
		sdo_rendezvous_free(entry);
		entry = next;
	};

	list->num_entries = 0;
	sdo_free(list);
}

/**
 * Add the rendzvous to the rendzvous list
 * @param list - pointer to the rendzvous list
 * @param rv - pointer to the rendezvous to be added to the list
 * @return number of entries added if success else error code
 */
int sdo_rendezvous_list_add(sdo_rendezvous_list_t *list, sdo_rendezvous_t *rv)
{
	if (list == NULL || rv == NULL)
		return 0;

	LOG(LOG_DEBUG, "Adding to rvlst\n");

	if (list->num_entries == 0) {
		// List empty, add the first entry
		list->rv_entries = rv;
		list->num_entries++;
	} else {
		// already has entries, find the last entry
		sdo_rendezvous_t *entry_ptr, *prev_ptr;

		entry_ptr = (sdo_rendezvous_t *)list->rv_entries->next;
		prev_ptr = list->rv_entries;
		// Find the last entry
		while (entry_ptr != NULL) {
			prev_ptr = entry_ptr;
			entry_ptr = (sdo_rendezvous_t *)entry_ptr->next;
		}
		// Now the enty_ptr is pointing to the last entry
		// Add the r entry onto the end
		prev_ptr->next = rv;
		list->num_entries++;
	}
	LOG(LOG_DEBUG, "Added to rvlst, %d entries\n", list->num_entries);
	return list->num_entries;
}

/**
 * Function will return the list as per the num passed.
 * @param list - Pointer to the list for the entries.
 * @param num - index of which entry[rventry] to return.
 * @return sdo_rendezvous_t object.
 */

sdo_rendezvous_t *sdo_rendezvous_list_get(sdo_rendezvous_list_t *list, int num)
{
	int index;

	if (list == NULL || list->num_entries == 0 || list->rv_entries == NULL)
		return NULL;

	sdo_rendezvous_t *entry_ptr = list->rv_entries;

	for (index = 0; index < num; index++) {
		entry_ptr = entry_ptr->next;
	}
	return entry_ptr;
}

/**
 * Reads the rendezvous info from the sdor w.r.t the number of entries.
 * @param sdor - Pointer of type sdor_t as input.
 * @param list- Pointer to the sdo_rendezvous_list_t list to be filled.
 * @return true if reads correctly ,else false
 */

int sdo_rendezvous_list_read(sdor_t *sdor, sdo_rendezvous_list_t *list)
{
	if (!sdor || !list)
		return false;

	if (!sdor_begin_sequence(sdor))
		return false;
	// Find out how many entries we should expect
	int num_rvs = sdo_read_uint(sdor);

	LOG(LOG_DEBUG, "There should be %d entries in the rvlst\n", num_rvs);

	int index;

	for (index = 0; index < num_rvs; index++) {
		LOG(LOG_DEBUG, "rv_index %d\n", index);

		// Read each rv entry and add to the rv list
		sdo_rendezvous_t *rv_entry = sdo_rendezvous_alloc();

		LOG(LOG_DEBUG, "New rv allocated %p\n", (void *)rv_entry);

		if (sdo_rendezvous_read(sdor, rv_entry))
			sdo_rendezvous_list_add(list, rv_entry);
		else {
			sdo_rendezvous_free(rv_entry);
		}
	}
	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR,
		    "%s : Final sequence not found\n", __func__);
		return false;
	}
	LOG(LOG_DEBUG, "%s read\n", __func__);
	return true;
}

/**
 * Writes out the entire Rendezvous list as sequences inside a sequence.
 * @param sdow - Pointer of type sdow to be filled.
 * @param list- Pointer to the sdo_rendezvous_list_t list from which sdow will
 * be filled w.r.t num_entries specified in the list.
 * @return true if writes correctly ,else false
 */

bool sdo_rendezvous_list_write(sdow_t *sdow, sdo_rendezvous_list_t *list)
{
	if (!sdow || !list)
		return false;

	sdow_begin_sequence(sdow);
	sdo_writeUInt(sdow, list->num_entries);

	int index;

	sdow->need_comma = true;
	for (index = 0; index < list->num_entries; index++) {
		sdo_rendezvous_t *entry_Ptr =
		    sdo_rendezvous_list_get(list, index);
		if (entry_Ptr == NULL) {
			continue;
		}
		sdo_rendezvous_write(sdow, entry_Ptr);
	}
	sdow_end_sequence(sdow);

	return true;
}

//------------------------------------------------------------------------------
// AES Encrypted Message Body Routines
//

/**
 * Allocate an empty AES encrypted Message Body object
 * @return an allocated AES Encrypted Message Body object
 */
sdo_encrypted_packet_t *sdo_encrypted_packet_alloc(void)
{
	return sdo_alloc(sizeof(sdo_encrypted_packet_t));
}

/**
 * Free an AES Encrypted Message Body object
 * @param pkt - the object to sdo_free
 * @return none
 */
void sdo_encrypted_packet_free(sdo_encrypted_packet_t *pkt)
{
	if (pkt == NULL) {
		return;
	}
	sdo_byte_array_free(pkt->em_body);
	sdo_hash_free(pkt->hmac);
	sdo_byte_array_free(pkt->ct_string);
	sdo_free(pkt);
}

/**
 * Read an Encrypted Message Body object from the SDOR buffer
 * @param sdor - pointer to the character buffer to parse
 * @return a newly allocated SDOEcnrypted_packet object if successful, otherwise
 * NULL
 */
sdo_encrypted_packet_t *sdo_encrypted_packet_read(sdor_t *sdor)
{
	sdo_encrypted_packet_t *pkt = NULL;

	if (!sdor)
		goto error;

	if (!sdor_begin_object(sdor)) {
		LOG(LOG_ERROR, "Object beginning not found\n");
		goto error;
	}
	sdor->need_comma = false;

	// Expect "ct" tag
	if (!sdo_read_expected_tag(sdor, "ct")) {
		// Very bad, must have the "ct" tag
		LOG(LOG_ERROR, "%s : Not a valid "
		    "Encrypted Packet\n", __func__);
		goto error;
	}

	if (!sdor_begin_sequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		goto error;
	}

	// Allocate the data structures
	pkt = sdo_encrypted_packet_alloc();
	if (!pkt) {
		LOG(LOG_ERROR, "Out of memory for packet\n");
		goto error;
	}

	pkt->em_body = sdo_byte_array_alloc(0);
	if (!pkt->em_body) {
		LOG(LOG_ERROR, "Out of memory for em_body\n");
		goto error;
	}

	/* Read the buffer and populate the required structs */
	if (!sdo_byte_array_read_with_type(sdor, pkt->em_body, &pkt->ct_string,
					   pkt->iv)) {
		LOG(LOG_ERROR, "Byte-array read failed!\n");
		goto error;
	}

	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		goto error;
	}

	sdor->need_comma = true;

	pkt->hmac = sdo_hash_alloc_empty();
	if (!pkt->hmac)
		goto error;

	/* Read the HMAC */
	/* Expect "hmac" tag */
	if (!sdo_read_expected_tag(sdor, "hmac")) {
		/* Very bad, must have the "hmac" tag */
		LOG(LOG_ERROR,
		    "%s : Did not find 'hmac' tag\n", __func__);
		goto error;
	}

	if (!sdor_begin_sequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		goto error;
	}

	/*number of bytes of hmac */
	uint32_t hmac_size = sdo_read_uint(sdor);

	int b64Len = bin_toB64Length(hmac_size);

	if (pkt->hmac->hash == NULL) {
		pkt->hmac->hash = sdo_byte_array_alloc(8);
		if (!pkt->hmac->hash) {
			LOG(LOG_ERROR, "Alloc failed\n");
			goto error;
		}
	}

	// Allocate 3 bytes extra for max probable decodaed output
	// Resize the byte array buffer to required length
	if (hmac_size &&
	    sdo_bits_resize(pkt->hmac->hash, hmac_size + 3) == false) {
		LOG(LOG_ERROR, "SDOBits_resize failed\n");
		goto error;
	}

	/* Convert buffer from base64 to binary */
	if (0 == sdo_read_byte_array_field(sdor, b64Len, pkt->hmac->hash->bytes,
					   pkt->hmac->hash->byte_sz)) {
		LOG(LOG_ERROR, "Unable to read hmac\n");
		goto error;
	}

	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		goto error;
	}

	pkt->hmac->hash->byte_sz = 32;
	if (!sdor_end_object(sdor)) {
		LOG(LOG_ERROR, "Object end not found\n");
		goto error;
	}

	return pkt;

error:
	sdo_encrypted_packet_free(pkt);
	return NULL;
}

/**
 * Read the IV
 * @param pkt - pointer to the struct of type packet
 * @param ps_iv - pointer to the read IV
 * @param last_pkt - pointer of type sdo_encrypted_packet_t
 * @return true if success else false
 */
bool sdo_get_iv(sdo_encrypted_packet_t *pkt, sdo_iv_t *ps_iv,
		sdo_encrypted_packet_t *last_pkt)
{
	uint32_t iv_ctr_ntohl;

	if (!pkt || !ps_iv)
		return false;

	iv_ctr_ntohl = sdo_net_to_host_long(ps_iv->ctr_dec);
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
		ps_iv->ctr_dec += (pkt->em_body->byte_sz + last_pkt->offset) /
				  SDO_AES_BLOCK_SIZE;
	else
		ps_iv->ctr_dec += pkt->em_body->byte_sz / SDO_AES_BLOCK_SIZE;
	return true;
}

/**
 * Write the IV
 * @param pkt - pointer to the struct of type packet
 * @param ps_iv - pointer to the struct of type IV
 * @param len - written length
 * @return true if success else false
 */
bool sdo_write_iv(sdo_encrypted_packet_t *pkt, sdo_iv_t *ps_iv, int len)
{
	uint32_t iv_ctr_ntohl = 0;

	if (!pkt || !ps_iv)
		return false;

	iv_ctr_ntohl = sdo_net_to_host_long(ps_iv->ctr_enc);
	if (memcpy_s(pkt->iv, AES_IV, ps_iv->ctr_iv, AES_CTR_IV) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}

	if (memcpy_s(pkt->iv + AES_CTR_IV, AES_IV - AES_CTR_IV, &iv_ctr_ntohl,
		     AES_CTR_IV_COUNTER) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}

	ps_iv->pkt_count += len;
	ps_iv->ctr_enc = ps_iv->pkt_count / SDO_AES_BLOCK_SIZE;
	return true;
}

/**
 * Write out an Encrypted Message Body object to the sdow buffer
 * @param sdow - Output buffer to write the JASON packet representation
 * @param pkt - the packet to be written out
 * @return none
 */
void sdo_encrypted_packet_write(sdow_t *sdow, sdo_encrypted_packet_t *pkt)
{
	if (!sdow || !pkt)
		return;

	sdow_begin_object(sdow);
	/* Write the Encrypted Message Block data */
	if (pkt->em_body && pkt->em_body->byte_sz) {
		sdo_write_tag(sdow, "ct");

		sdo_write_byte_array_two_int(sdow, pkt->iv, AES_IV,
					     pkt->em_body->bytes,
					     pkt->em_body->byte_sz);

	} else {
		sdo_write_tag(sdow, "ct");
		sdo_write_string(sdow, "");
	}

	/* Write the Encrypted Message Block HMAC */
	sdo_write_tag(sdow, "hmac");
	if (pkt->hmac != NULL) {

		sdo_write_byte_array(sdow, pkt->hmac->hash->bytes,
				     pkt->hmac->hash->byte_sz);

	} else {
		/* HMAC was NULL, do not crash... */
		sdo_hash_null_write(sdow);
	}
	sdow_end_object(sdow);
}

#if 0
/**
 * Make a string representation of the encrypted packet
 * @param pkt - pointer to the packet to expose
 * @param buf - pointer to the start of the character buffer to fill
 * @param bufsz - the size of the destination buffer
 * @return pointer to the buffer filled
 */
char *sdo_encrypted_packet_to_string(sdo_encrypted_packet_t *pkt, char *buf,
				     int bufsz)
{
	char *buf0 = buf;
	int n = 0;

	memset(buf, 0, bufsz);

	n = snprintf(buf, bufsz, "[Encrypted Message Body\n");
	buf += n;
	bufsz -= n;

	//    // Write out the start of buffer counter
	//	n = snprintf(buf, bufsz, "block_start: %d\n", pkt->block_start);
	//	buf += n; bufsz -= n;

	// Write out the Encrypted Body byte array
	if (pkt->em_body != NULL) {
		char strkey1[] = "Encrypted Body: ";

		strcat(buf, strkey1);
		n = strlen(strkey1);
		buf += n;
		bufsz -= n;

		sdo_byte_array_to_string(pkt->em_body, buf, bufsz);
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
	if (pkt->em_body != NULL) {
		char strkey1[] = "\nHMAC of Unencrypted Body: ";

		strcat(buf, strkey1);
		n = strlen(strkey1);
		buf += n;
		bufsz -= n;

		sdo_hash_to_string(pkt->hmac, buf, bufsz);
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
 * Take in an Encrypted_packet object and end up with it represented
 * cleartext in the sdor buffer.  This will allow the data to be parsed
 * for its content.
 * @param sdor - pointer to the sdor object to fill
 * @param pkt - Pointer to the Encrypted packet pkt that has to be processed.
 * @param iv - pointer to the IV struct
 * @return true if all goes well, otherwise false
 */
bool sdo_encrypted_packet_unwind(sdor_t *sdor, sdo_encrypted_packet_t *pkt,
				 sdo_iv_t *iv)
{
	bool ret = true;
	sdo_string_t *cleartext = NULL;

	// Decrypt the Encrypted Body
	if (!sdor || !pkt || !iv) {
		LOG(LOG_ERROR,
		    "%s : Invalid Input param\n", __func__);
		ret = false;
		goto err;
	}
	cleartext = sdo_string_alloc();

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
	sdor_flush(sdor);
	sdo_block_t *sdob = &sdor->b;

	/* Adjust the buffer for the clear text */
	sdo_resize_block(sdob, cleartext->byte_sz);
	/* Copy the cleartext to the sdor buffer */
	if (memcpy_s(sdob->block, cleartext->byte_sz, cleartext->bytes,
		     cleartext->byte_sz) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		ret = false;
		goto err;
	}

	sdob->block_size = cleartext->byte_sz;
	sdor->have_block = true;
err:
	if (pkt)
		sdo_encrypted_packet_free(pkt);
	if (cleartext)
		sdo_string_free(cleartext);
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
bool sdo_encrypted_packet_windup(sdow_t *sdow, int type, sdo_iv_t *iv)
{
	if (!sdow || !iv)
		return false;

	sdo_block_t *sdob = &sdow->b;

	sdo_encrypted_packet_t *pkt = sdo_encrypted_packet_alloc();

	if (!pkt) {
		LOG(LOG_ERROR, "Not encrypted\n");
		return false;
	}

	if (0 != aes_encrypt_packet(pkt, sdob->block, sdob->block_size)) {
		sdo_encrypted_packet_free(pkt);
		return false;
	}

	// At this point we have a valid Encrypted Message Body packet
	// Remake the output buffer, abandoning the cleartext
	sdow_next_block(sdow, type);
	sdo_encrypted_packet_write(sdow, pkt);

	if (pkt)
		sdo_encrypted_packet_free(pkt);

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
bool sdo_begin_write_signature(sdow_t *sdow, sdo_sig_t *sig,
			       sdo_public_key_t *pk)
{
	if (!sdow)
		return false;

	if (memset_s(sig, sizeof(*sig), 0)) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return false;
	}
	sig->pk = pk;
	sdow_begin_object(sdow);
	sdo_write_tag(sdow, "bo");
	sig->sig_block_start = sdow->b.cursor;
	return true;
}

/**
 * Write the signature to the buffer
 * @param sdow - pointer to the output buffer
 * @param sig - pointer to the struct of type signature
 */
bool sdo_end_write_signature(sdow_t *sdow, sdo_sig_t *sig)
{
	int sig_block_end;
	int sig_block_sz;
	sdo_byte_array_t *sigtext = NULL;
	sdo_public_key_t *publickey;

	if (!sdow || !sig) {
		LOG(LOG_ERROR, "Invalid arguments\n");
		return false;
	}

	sig_block_end = sdow->b.cursor;
	sig_block_sz = sig_block_end - sig->sig_block_start;

	/* Turn the message block into a zero terminated string */
	sdo_resize_block(&sdow->b, sdow->b.cursor + 1);
	sdow->b.block[sdow->b.cursor] = 0;

	uint8_t *adapted_message = sdo_alloc(sig_block_sz);

	if (memcpy_s(adapted_message, sig_block_sz,
		     &(sdow->b.block[sig->sig_block_start]),
		     sig_block_sz) != 0) {
		LOG(LOG_ERROR, "Memcpy failed\n");
		sdo_free(adapted_message);
		return false;
	}

	size_t adapted_message_len = sig_block_sz;

	if (0 !=
	    sdo_device_sign(adapted_message, adapted_message_len, &sigtext)) {
		LOG(LOG_ERROR, "ECDSA signing failed!\n");
		sdo_free(adapted_message);
		sdo_byte_array_free(sigtext);
		return false;
	}
	hexdump("Adapted message", (char *)adapted_message,
		adapted_message_len);

	/* Release the allocated memory */
	sdo_free(adapted_message);

	/* ========================================================= */

	/*Write GID to represent public key*/
	sdo_write_tag(sdow, "pk");

	publickey = NULL;

	sdo_public_key_write(sdow, publickey);
	sdo_write_tag(sdow, "sg");
	sdo_write_byte_array(sdow, sigtext->bytes, sigtext->byte_sz);
	sdow_end_object(sdow);
	sdo_bits_free(sigtext);
	return true;
}

/**
 * HMAC processing start of a block to HMAC
 * @param sdor - pointer to the input buffer
 * @param sig_block_start - pointer to the signature starting block
 * @return true if proper header present, otherwise false
 */
bool sdo_begin_readHMAC(sdor_t *sdor, int *sig_block_start)
{
	if (!sdor)
		return false;

	if (!sdo_read_expected_tag(sdor, "oh")) {
		LOG(LOG_ERROR, "No oh\n");
		return false;
	}
	*sig_block_start = sdor->b.cursor;

	return true;
}

/**
 * Create the HMAC using our secret
 * @param sdor - input buffer
 * @param hmac - pointer to the hash object to use
 * @param sig_block_start - pointer to the signature starting block
 * @return true if proper header present, otherwise false
 */
bool sdo_end_readHMAC(sdor_t *sdor, sdo_hash_t **hmac, int sig_block_start)
{
	// Make the ending calculation for the buffer to sign

	if (!sdor || !hmac)
		return false;

	if (!sdor_end_object(sdor)) {
		return false;
	}
	int sig_block_end = sdor->b.cursor;
	int sig_block_sz = sig_block_end - sig_block_start;
	uint8_t *plain_text = sdor_get_block_ptr(sdor, sig_block_start);

	if (plain_text == NULL) {
		LOG(LOG_ERROR, "sdor_get_block_ptr() returned null, "
		    "%s failed !!", __func__);
		return false;
	}

	// Display the block to be signed
	uint8_t save_byte;

	save_byte = plain_text[sig_block_sz];
	plain_text[sig_block_sz] = 0;
	LOG(LOG_DEBUG, "%s.plain_text: %s\n", __func__, plain_text);
	plain_text[sig_block_sz] = save_byte;
#if !defined(DEVICE_TPM20_ENABLED)
	char buf[256];

	LOG(LOG_DEBUG, "%s: %s\n", __func__,
	    sdo_bits_to_string(*getOVKey(), "Secret:", buf, sizeof(buf)) ? buf
									 : "");
#endif
	// Create the HMAC
	*hmac =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
	if (!*hmac) {
		return false;
	}

	if (0 != sdo_device_ov_hmac(plain_text, sig_block_sz,
				    (*hmac)->hash->bytes,
				    (*hmac)->hash->byte_sz)) {
		sdo_hash_free(*hmac);
		return false;
	}

	return true;
}

/**
 * Signature processing.  Call this to mark the place before reading
 * the signature body.  Then call sdo_end_read_signature* afterwards.
 * The same sdo_sig_t object must be presented to both procedures.
 *
 * @param sdor - pointer to the input buffer
 * @param sig - pointer to the signature object to use
 * @return true if proper header present, otherwise false
 */
bool sdo_begin_read_signature(sdor_t *sdor, sdo_sig_t *sig)
{
	if (!sdor || !sig)
		return false;

	if (!sdor_begin_object(sdor))
		return false;
	if (!sdo_read_expected_tag(sdor, "bo"))
		return false;
	sig->sig_block_start = sdor->b.cursor;
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
bool sdo_end_read_signature(sdor_t *sdor, sdo_sig_t *sig)
{
	return sdo_end_read_signature_full(sdor, sig, NULL);
}
#endif

/**
 * Full Signature processing:
 * Any of these may be NULL, in which case it is ignored.
 * @param sdor - input buffer to check
 * @param sig - object holds offset of block start and holds returned signature
 * @param getpk - returns verify public key (caller must sdo_free)
 * @return true if verification successful, otherwise false
 */
bool sdo_end_read_signature_full(sdor_t *sdor, sdo_sig_t *sig,
				 sdo_public_key_t **getpk)
{
	// Save buffer at the end of the area to be checked
	int sig_block_end;
	int sig_block_sz;
	uint8_t *plain_text;
	sdo_public_key_t *pk;
	bool r = false;
	int ret;

	if (!sdor || !sig || !getpk)
		return false;

	sig_block_end = sdor->b.cursor;
	sig_block_sz = sig_block_end - sig->sig_block_start;
	plain_text = sdor_get_block_ptr(sdor, sig->sig_block_start);

	if (plain_text == NULL) {
		LOG(LOG_ERROR, "sdor_get_block_ptr() returned null, "
		    "%s failed !!", __func__);
		return false;
	}

	if (!sdo_read_expected_tag(sdor, "pk"))
		return false;
	// LOG(LOG_ERROR, "this key\n");
	pk = sdo_public_key_read(sdor);
	if (pk == NULL) {
		LOG(LOG_ERROR,
		    "%s: Could not read \"pk\" "
		    "in signature\n", __func__);
		return false;
	}
	// Copy the read public key to the signature object
	sig->pk = pk;

	// LOG(LOG_ERROR, "Next char: '%c'\n", sdor_peek(sdor));

	if (!sdo_read_expected_tag(sdor, "sg"))
		return false;

	if (!sdor_begin_sequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		return false;
	}
	// These bytes will be thrown away, some issue with zero length
	sig->sg = sdo_byte_array_alloc(1);
	if (!sig->sg) {
		ret = -1;
		goto result;
	}

	// Read the signature to the signature object
	if (!sdo_byte_array_read(sdor, sig->sg)) {
		ret = -1;
		goto result;
	}
	// LOG(LOG_ERROR, "signature %lu bytes\n", sig->sg->byte_sz);

	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		ret = -1;
		goto result;
	}

	if (!sdor_end_object(sdor)) {
		ret = -1;
		goto result;
	}

	// Buffer read, all objects consumed, start verify

	// Check the signature
	uint8_t save_byte;
	char buf[1024];
	bool signature_verify = false;

	save_byte = plain_text[sig_block_sz];
	plain_text[sig_block_sz] = 0;
	LOG(LOG_DEBUG, "sdo_end_read_signature.Sig_text: %s\n", plain_text);
	plain_text[sig_block_sz] = save_byte;
	LOG(LOG_DEBUG, "sdo_end_read_signature.PK: %s\n",
	    sdo_public_key_to_string(pk, buf, sizeof(buf)) ? buf : "");

	ret = sdo_ov_verify(plain_text, sig_block_sz, sig->sg->bytes,
			    sig->sg->byte_sz, pk, &signature_verify);

result:

	if ((ret == 0) && (true == signature_verify)) {
		LOG(LOG_DEBUG, "Signature verifies OK.\n");
		r = true;
	} else {
		LOG(LOG_ERROR, "Signature internal failure, or signature does "
			       "not verify.\n");
		if (ret == -1 && sig->sg) {
			sdo_byte_array_free(sig->sg);
			sig->sg = NULL;
		}
		r = false;
	}

	// Return a copy of the data to use or clean up
	if (getpk != NULL) {
		*getpk = sdo_public_key_clone(pk);
		sdo_public_key_free(pk);
	}

	return r;
}

/**
 * Verifies the RSA/ECDSA Signature using provided public key pk.
 * @param plain_text - Pointer of type sdo_byte_array_t, for generating hash,
 * @param sg - Pointer of type sdo_byte_array_t, as signature.
 * @param pk - Pointer of type sdo_public_key_t, holds the public-key used for
 * verification.
 * @return true if success, else false
 */

bool sdo_signature_verification(sdo_byte_array_t *plain_text,
				sdo_byte_array_t *sg, sdo_public_key_t *pk)
{
	int ret;
	bool signature_verify = false;

	if (!plain_text || !sg || !pk || !pk->key1)
		return false;
	if (!plain_text->bytes || !sg->bytes)
		return false;

	ret = sdo_ov_verify(plain_text->bytes, plain_text->byte_sz, sg->bytes,
			    sg->byte_sz, pk, &signature_verify);

	if ((ret == 0) && (true == signature_verify)) {
		LOG(LOG_DEBUG, "Signature verifies OK.\n");
		return true;
	}

	LOG(LOG_ERROR, "Signature internal failure, or signature does "
	    "not verify.\n");
	return false;
}

/**
 * Read the pk information
 * @param sdor - pointer to the output buffer
 * @return true if read else flase
 */
bool sdo_read_pk_null(sdor_t *sdor)
{
	if (!sdor)
		return false;

	//"pk":[0,0,[0]]
	if (!sdo_read_expected_tag(sdor, "pk"))
		return false;
	if (!sdor_begin_sequence(sdor))
		return false;

	sdo_read_uint(sdor);
	sdo_read_uint(sdor);

	if (!sdor_begin_sequence(sdor))
		return false;

	sdo_read_uint(sdor);
	if (!sdor_end_sequence(sdor))
		return false;

	if (!sdor_end_sequence(sdor))
		return false;

	return true;
}

/**
 * Verifies the Signature for ownership voucher using provided public key pk.
 * @param sdor - Pointer of type sdor_t, holds the signature and plaintext
 * for generating hash.
 * @param sig - Pointer of type sdo_sig_t, as signature
 * @param pk - Pointer of type sdo_public_key_t, holds the key used for
 * verification.
 * @return true if success, else false
 */

bool sdoOVSignature_verification(sdor_t *sdor, sdo_sig_t *sig,
				 sdo_public_key_t *pk)
{

	int ret;
	int sig_block_end;
	int sig_block_sz;
	uint8_t *plain_text;
	bool signature_verify = false;

	if (!sdor || !sig || !pk)
		return false;

	sig_block_end = sdor->b.cursor;
	sig_block_sz = sig_block_end - sig->sig_block_start;
	plain_text = sdor_get_block_ptr(sdor, sig->sig_block_start);

	if (plain_text == NULL) {
		LOG(LOG_ERROR, "sdor_get_block_ptr() returned null, "
		    "%s() failed !!", __func__);
		return false;
	}

	if (!sdo_read_pk_null(sdor))
		return false;

	if (!sdo_read_expected_tag(sdor, "sg"))
		return false;

	if (!sdor_begin_sequence(sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		return false;
	}

	sig->sg = sdo_byte_array_alloc(
	    16); // These bytes will be thrown away, some issue with zero length

	if (!sig->sg) {
		LOG(LOG_ERROR, "Alloc failed\n");
		return false;
	}
	// Read the signature to the signature object
	sdo_byte_array_read(sdor, sig->sg);
	// LOG(LOG_ERROR, "signature %lu bytes\n", sig->sg->byte_sz);

	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "End Sequence not found!\n");
		return false;
	}

	if (!sdor_end_object(sdor))
		return false;

	ret = sdo_ov_verify(plain_text, sig_block_sz, sig->sg->bytes,
			    sig->sg->byte_sz, pk, &signature_verify);

	if ((ret == 0) && (true == signature_verify)) {
		LOG(LOG_DEBUG, "Signature verifies OK.\n");
		return true;
	}

	LOG(LOG_ERROR, "Signature internal failure, or signature does "
	    "not verify.\n");
	return false;
}

//--------------------------------------------------------------------------
// Key Value Pairs
//

/**
 * Allocate the key value
 */
sdo_key_value_t *sdo_kv_alloc(void)
{
	return sdo_alloc(sizeof(sdo_key_value_t));
}

/**
 * Allocate the key value and initialize with the value provided
 * @param key - pointer to the key
 * @param val - pointer to the struct of type byte array
 * @return pointer to the allocated struct of type key value
 */
sdo_key_value_t *sdo_kv_alloc_with_array(const char *key, sdo_byte_array_t *val)
{
	if (!key || !val)
		return NULL;

	sdo_key_value_t *kv = sdo_kv_alloc();

	if (kv != NULL) {
		int key_len = strnlen_s(key, SDO_MAX_STR_SIZE);

		if (!key_len || key_len == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR,
			    "%s(): key is either "
			    "'NULL' or 'isn't "
			    "NULL terminated'\n", __func__);
			sdo_kv_free(kv);
			return NULL;
		}

		kv->key = sdo_string_alloc_with(key, key_len);
		kv->val = (sdo_string_t *)sdo_byte_array_alloc_with_byte_array(
		    val->bytes, val->byte_sz);
		if (kv->key == NULL || kv->val == NULL) {
			sdo_kv_free(kv);
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
sdo_key_value_t *sdo_kv_alloc_with_str(const char *key, const char *val)
{
	if (!key || !val)
		return NULL;

	sdo_key_value_t *kv = sdo_kv_alloc();

	if (kv != NULL) {
		int key_len = strnlen_s(key, SDO_MAX_STR_SIZE);

		if (!key_len || key_len == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "%s(): key is either "
			    "'NULL' or 'isn't "
			    "NULL terminated'\n", __func__);
			sdo_kv_free(kv);
			return NULL;
		}

		kv->key = sdo_string_alloc_with(key, key_len);

		int val_len = strnlen_s(val, SDO_MAX_STR_SIZE);

		if (val_len == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR,
			    "%s(): value is either "
			    "'NULL' or 'isn't NULL terminated'\n", __func__);
			printf("vallen:%d\t, buf:%s\n", val_len, val);
			sdo_kv_free(kv);
			return NULL;
		}

		kv->val = sdo_string_alloc_with(val, val_len);
		if (kv->key == NULL || kv->val == NULL) {
			sdo_kv_free(kv);
			kv = NULL;
		}
	}
	return kv;
}

/**
 * Free the allcated strutc of type key value
 * @param kv - pointer to the struct of type key value that is to be sdo_free
 */
void sdo_kv_free(sdo_key_value_t *kv)
{
	if (kv->key != NULL)
		sdo_string_free(kv->key);
	if (kv->val != NULL)
		sdo_string_free(kv->val);
	sdo_free(kv);
}

/**
 * Write the key value to the buffer
 * @param sdow - pointer to the output buffer
 * @param kv - pointer to the struct of type key value
 */
void sdo_kv_write(sdow_t *sdow, sdo_key_value_t *kv)
{
	sdo_write_tag_len(sdow, kv->key->bytes, kv->key->byte_sz);
	sdo_write_string_len(sdow, kv->val->bytes, kv->val->byte_sz);
	sdow->need_comma = true;
}

/**
 * Read multiple Sv_info (OSI) Key/Value pairs from the input buffer
 * All Key-value pairs MUST be a null terminated strings.
 * @param sdor - pointer to the input buffer
 * @param module_list - Global Module List Head Pointer.
 * @param kv - pointer to the Sv_info key/value pair
 * @param cb_return_val - Pointer of type int which will be filled with CB
 * return value.
 * @return true of read succeeded, false otherwise
 */
bool sdo_osi_parsing(sdor_t *sdor,
		     sdo_sdk_service_info_module_list_t *module_list,
		     sdo_sdk_si_key_value *kv, int *cb_return_val)
{
	int str_len;

	if (!cb_return_val)
		return false;

	if (!sdor || !kv) {
		*cb_return_val = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	// loop in to get all the  OSI key value pairs
	// (block_size-2) is done to skip 2 curly braces to end objects
	// for "sv" tag and "end of Msg 49".

	while (sdor->b.cursor < sdor->b.block_size - 2) {
		// get len of "key" in KV pair
		str_len = sdo_read_string_sz(sdor);

		kv->key = sdo_alloc(str_len + 1); // +1 for null termination

		if (!kv->key) {
			LOG(LOG_ERROR, "Malloc failed!\n");
			return false;
		}

		// read tag "" from KV pair and copy to "kv->key"
		sdo_read_tag(sdor, kv->key, str_len + 1);

		// get len of "value" in KV pair
		str_len = sdo_read_string_sz(sdor);

		kv->value = sdo_alloc(str_len + 1); // +1 for null termination

		if (!kv->value) {
			LOG(LOG_ERROR, "Malloc failed!\n");
			sdo_free(kv->key);
			return false;
		}

		// read value for above tag and copy into "kv->value"
		sdo_read_string(sdor, kv->value, str_len + 1);

		LOG(LOG_DEBUG, "OSI_KV pair:\n_key->%s,Value->%s\n", kv->key,
		    kv->value);

		// call module callback's with appropriate KV pairs
		if (!sdo_osi_handling(module_list, kv, cb_return_val)) {
			sdo_free(kv->key);
			sdo_free(kv->value);
			return false;
		}
		// free present KV pair memory
		sdo_free(kv->key);
		sdo_free(kv->value);
	}

	return true;
}

//----------------------------------------------------------------------
// Service_info handling
//

/**
 * Allocate an empty sdo_service_info_t object.
 * @return an allocated sdo_service_info_t object.
 */

sdo_service_info_t *sdo_service_info_alloc(void)
{
	return sdo_alloc(sizeof(sdo_service_info_t));
}

/**
 * Create a SDOService_info object, by filling the object with key & val
 * passed as parameter.
 * @param val - Value to be mapped to the key, passed as an char pointer.
 * @param key - Pointer to the char buffer key.
 * @return an allocated SDOService_info object containing the key & val.
 */

sdo_service_info_t *sdo_service_info_alloc_with(char *key, char *val)
{
	sdo_key_value_t *kv;

	sdo_service_info_t *si = sdo_service_info_alloc();

	if (si == NULL)
		return NULL;
	kv = sdo_kv_alloc_with_str(key, val);
	if (!kv) {
		sdo_service_info_free(si);
		return NULL;
	}
	si->kv = kv;
	si->numKV = 1;
	return si;
}

/**
 * Free an sdo_service_info_t object
 * @param si - the object to sdo_free
 * @return none
 */

void sdo_service_info_free(sdo_service_info_t *si)
{
	sdo_key_value_t *kv = NULL;

	if (!si)
		return;
	while ((kv = si->kv) != NULL) {
		si->kv = kv->next;
		sdo_kv_free(kv);
	}
	sdo_free(si);
}

/**
 * Compares the kv member of si with key parameter and
 * if there is match, return the matched pointer,
 * else last entry in the list.
 * @param si  - Pointer to the sdo_service_info_t object si,
 * @param key - Pointer to the char buffer key,
 * @return pointer to sdo_key_value_t.
 */

sdo_key_value_t **sdo_service_info_fetch(sdo_service_info_t *si,
					 const char *key)
{
	sdo_key_value_t **kvp, *kv;
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
 * & key_num parameter, if there is match, return the matched pointer,
 * else last entry in the list.
 * @param si  - Pointer to the sdo_service_info_t object si,
 * @param key_num - Integer variable determines service request Info number,
 * @return pointer to sdo_key_value_t.
 */

sdo_key_value_t **sdo_service_info_get(sdo_service_info_t *si, int key_num)
{
	sdo_key_value_t **kvp, *kv;
	int index;

	for (kvp = &si->kv, index = 0; (kv = *kvp) != NULL;
	     kvp = &kv->next, index++) {
		if (index == key_num)
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
 * @param si  - Pointer to the sdo_service_info_t,
 * @param key - Pointer to the char buffer key,
 * @param val - Pointer to the char buffer val, to be updated,
 * @return true if updated correctly else false.
 */

bool sdo_service_info_add_kv_str(sdo_service_info_t *si, const char *key,
				 const char *val)
{
	sdo_key_value_t **kvp, *kv;

	if (!si || !key || !val)
		return false;

	kvp = sdo_service_info_fetch(si, key);
	kv = *kvp;
	if (kv == NULL) {
		 /* Not found, at end of linked list, add a new entry */
		kv = sdo_kv_alloc_with_str(key, val);
		if (kv == NULL)
			return false;
		*kvp = kv;  /* Use this pointer to update the next value */
		si->numKV++;
		return true;
	}

	 /* Found, update value */
	if (kv->val == NULL) {
		 /* No allocated string present for value, make a new one */
		kv->val = sdo_string_alloc_with_str(val);
	} else {
		int val_len = strnlen_s(val, SDO_MAX_STR_SIZE);

		if (!val_len || val_len == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR,
			    "%s(): val "
			    "is either 'NULL' or"
			    "'isn't 'NULL-terminating'\n", __func__);
			sdo_string_free(kv->val);
			return false;
		}

		 /* Update the string */
		sdo_string_resize_with(kv->val, val_len, val);
	}

	return true;
}
/**
 * Add kvs object of type sdo_key_value_t to the end of the list(si) if
 * not empty else add it to the head.
 * @param si  - Pointer to the sdo_service_info_t list,
 * @param kvs - Pointer to the sdo_key_value_t kvs, to be added,
 * @return true if updated correctly else false.
 */

bool sdo_service_info_add_kv(sdo_service_info_t *si, sdo_key_value_t *kvs)
{
	sdo_key_value_t *kv = NULL;

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
 * Combine sdo_key_value_t objects into a single string from already built
 * platform DSI list.
 * @param sdow  - Pointer to the output buffer.
 * @param si  - Pointer to the sdo_service_info_t list containing all platform
 * DSI's.
 * @return true if combined successfully else false.
 */

bool sdo_combine_platform_dsis(sdow_t *sdow, sdo_service_info_t *si)
{
	int num = 0;
	bool ret = false;
	sdo_key_value_t **kvp = NULL;
	sdo_key_value_t *kv = NULL;

	if (!sdow || !si)
		goto end;

	// fetch all platfrom DSI's one-by-one
	while (num != si->numKV) {
		kvp = sdo_service_info_get(si, num);

		kv = *kvp;
		if (!kv || !kv->key || !kv->val) {
			LOG(LOG_ERROR, "Plaform DSI: key-value not found!\n");
			goto end;
		}

		// Write KV pair
		sdo_write_tag_len(sdow, kv->key->bytes, kv->key->byte_sz);
		sdo_write_string_len(sdow, kv->val->bytes, kv->val->byte_sz);
		sdow->need_comma = true;

		num++;
	}

	ret = true;
end:
	return ret;
}

/**
 * Execute Sv_info Module's callback with the provided svinfo type,
 * @param module_list - Global Module List Head Pointer.
 * @param type - a valid Sv_info type.
 * @return true if success, false otherwise
 */

bool sdo_mod_exec_sv_infotype(sdo_sdk_service_info_module_list_t *module_list,
			      sdo_sdk_si_type type)
{
	while (module_list) {
		if (module_list->module.service_info_callback(
			type, NULL, NULL) != SDO_SI_SUCCESS) {
			LOG(LOG_DEBUG, "Sv_info: %s's CB Failed for type:%d\n",
			    module_list->module.module_name, type);
			return false;
		}
		module_list = module_list->next;
	}
	return true;
}

/**
 * Calculation of DSI count for round-trip of modules
 * @param module_list - Global Module List Head Pointer.
 * @param mod_mes_count - Pointer of type int which will be filled with count to
 * be added.
 * @param cb_return_val - Pointer of type int which will be filled with CB
 * return value.
 * @return success if true else false
 */

bool sdo_get_dsi_count(sdo_sdk_service_info_module_list_t *module_list,
		       int *mod_mes_count, int *cb_return_val)
{
	int count;

	if (!cb_return_val)
		return false;

	if (!module_list) {
		*cb_return_val = SDO_SI_SUCCESS;
		return true;
	}

	if (module_list && !mod_mes_count) {
		*cb_return_val = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	/*Calculation of DSI count for round-trip of modules*/
	while (module_list) {
		count = 0;
		// check if module CB is successful
		*cb_return_val = module_list->module.service_info_callback(
		    SDO_SI_GET_DSI_COUNT, &count, NULL);
		if (*cb_return_val != SDO_SI_SUCCESS) {
			LOG(LOG_ERROR, "Sv_info: %s's DSI COUNT CB Failed!\n",
			    module_list->module.module_name);
			return false;
		}
		/* populate individual count to the list */
		module_list->module_dsi_count = count;

		*mod_mes_count += count;
		module_list = module_list->next;
	}
	// module CB was successful
	*cb_return_val = SDO_SI_SUCCESS;
	return true;
}

/**
 * Traverse the list for OSI, comparing list with name & calling the appropriate
 * CB.
 * @param module_list - Global Module List Head Pointer.
 * @param mod_name - Pointer to the mod_name, to be compared with list's modname
 * @param sv_kv - Pointer of type sdo_sdk_si_key_value, holds Module message &
 * value.
 * @param cb_return_val - Pointer of type int which will be filled with CB
 * return value.
 * @return true if success (module found in list + CB succeed) else false.
 */

bool sdo_supply_moduleOSI(sdo_sdk_service_info_module_list_t *module_list,
			  char *mod_name, sdo_sdk_si_key_value *sv_kv,
			  int *cb_return_val)
{
	int strcmp_result = 1;
	bool retval = false;

	if (!cb_return_val)
		return retval;

	if (!sv_kv || !mod_name) {
		*cb_return_val = SDO_SI_INTERNAL_ERROR;
		return retval;
	}

	retval = true;
	while (module_list) {
		strcmp_s(module_list->module.module_name, SDO_MODULE_NAME_LEN,
			 mod_name, &strcmp_result);
		if (strcmp_result == 0) {
			// check if module CB is successful
			*cb_return_val =
			    module_list->module.service_info_callback(
				SDO_SI_SET_OSI,
				&(module_list->module_osi_index), sv_kv);

			if (*cb_return_val != SDO_SI_SUCCESS) {
				LOG(LOG_ERROR,
				    "Sv_info: %s's CB Failed for type:%d\n",
				    module_list->module.module_name,
				    SDO_SI_SET_OSI);
				retval = false;
			}
			// Inc OSI index per module
			module_list->module_osi_index++;
			break;
		}
		module_list = module_list->next;
	}

	return retval;
}

/**
 * Traverse the list for PSI, comparing list with name & calling the appropriate
 * CB.
 * @param module_list - Global Module List Head Pointer.
 * @param mod_name - Pointer to the mod_name, to be compared with list's modname
 * @param sv_kv - Pointer of type sdo_sdk_si_key_value, holds Module message &
 * value.
 * @param cb_return_val - Pointer of type int which will be filled with CB
 * return value.
 * @return true if success else false.
 */

bool sdo_supply_modulePSI(sdo_sdk_service_info_module_list_t *module_list,
			  char *mod_name, sdo_sdk_si_key_value *sv_kv,
			  int *cb_return_val)
{
	int strcmp_result = 1;
	bool retval = false;

	if (!cb_return_val)
		return retval;

	if (!sv_kv || !mod_name) {
		*cb_return_val = SDO_SI_INTERNAL_ERROR;
		return retval;
	}

	retval = true;
	while (module_list) {
		strcmp_s(module_list->module.module_name, SDO_MODULE_NAME_LEN,
			 mod_name, &strcmp_result);
		if (strcmp_result == 0) {
			// check if module CB is successful
			*cb_return_val =
			    module_list->module.service_info_callback(
				SDO_SI_SET_PSI,
				&(module_list->module_psi_index), sv_kv);

			if (*cb_return_val != SDO_SI_SUCCESS) {
				LOG(LOG_ERROR,
				    "Sv_info: %s's CB Failed for type:%d\n",
				    module_list->module.module_name,
				    SDO_SI_SET_PSI);
				retval = false;
			}
			// Inc PSI index per module
			module_list->module_psi_index++;
			break;
		}
		module_list = module_list->next;
	}

	return retval;
}

/**
 * Parsing the psi & differentiate string on different delimeters and call the
 * appropriate API's.
 * @param module_list - Global Module List Head Pointer.
 * @param psi - Pointer to null termincated psi string
 * @param psi_len - length of psi buffer
 * @param cb_return_val - Pointer of type int which will be filled with CB
 * return value.
 * @return true if success else false.
 */

bool sdo_psi_parsing(sdo_sdk_service_info_module_list_t *module_list, char *psi,
		     int psi_len, int *cb_return_val)
{
	if (!cb_return_val)
		return false;

	if (!module_list) {
		// No modules.
		*cb_return_val = SDO_SI_SUCCESS;
		return true;
	}

	char mod_name[SDO_MODULE_NAME_LEN] = {0};
	char mod_message[SDO_MODULE_MSG_LEN] = {0};
	char mod_value[SDO_MODULE_VALUE_LEN] = {0};

	// single PSI tuple
	char *psi_tuple = NULL;
	int psi_tuple_len = 0;
	char *notused = NULL;
	// delimiter= ','
	const char *del = ",";

	// strtok_s accepts size_t for string length
	size_t len = psi_len - 1; // Buffer size contains ending '\0' char

	// split based on Delimiter
	psi_tuple = strtok_s(psi, &len, del, &notused);

	while (psi_tuple) {
#if LOG_LEVEL == LOG_MAX_LEVEL
		static int i;

		LOG(LOG_DEBUG, "PSI Entry#%d: |%s|\n", i++, psi_tuple);
#endif

		psi_tuple_len = strnlen_s(psi_tuple, SDO_MAX_STR_SIZE);

		if (!psi_tuple_len || psi_tuple_len == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Strlen() failed!\n");
			*cb_return_val = SDO_SI_INTERNAL_ERROR;
			return false;
		}

		// Get Module name, message and value
		if (!sdo_get_module_name_msg_value(psi_tuple, psi_tuple_len,
						   mod_name, mod_message,
						   mod_value, cb_return_val)) {
			LOG(LOG_ERROR, "Bad PSI entry: |%s|\n", psi_tuple);
			return false;
		}

		// Fill SI data structure
		sdo_sdk_si_key_value sv_kv;

		sv_kv.key = mod_message;
		sv_kv.value = mod_value;

		// call CB's for PSI
		if (!sdo_supply_modulePSI(module_list, mod_name, &sv_kv,
					  cb_return_val))
			return false;

		// check for next PSI tuple
		psi_tuple = strtok_s(NULL, &len, del, &notused);
	}

	// module CB's were successful
	*cb_return_val = SDO_SI_SUCCESS;
	return true;
}

/**
 * Create Key_value Pair using mod_name sv_kv key-value pair
 * @param mod_name - Pointer to the char, to be used as a partial key
 * @param sv_kv - Pointer of type sdo_sdk_si_key_value, which holds message &
 * value.
 * @return true if success else false.
 */

bool sdo_mod_data_kv(char *mod_name, sdo_sdk_si_key_value *sv_kv)
{
	// Example : "keypair:pubkey":"sample o/p of pubkey"
	sdo_sdk_si_key_value sv_kv_t;

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

	sv_kv_t.key = sdo_alloc(sv_kv_t_key_size);

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
	    sdo_alloc(sv_kv_t_val_size + 1); // 1 is for NULL at the end

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

bool sdo_construct_module_dsi(sdo_sv_info_dsi_info_t *dsi_info,
			      sdo_sdk_si_key_value *sv_kv, int *cb_return_val)
{
	int temp_dsi_count;

	if (!cb_return_val || !dsi_info)
		return false;

	if (!sv_kv) {
		*cb_return_val = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	temp_dsi_count = dsi_info->list_dsi->module_dsi_count;

	/* Finish DSI module-by-module */
	if (dsi_info->module_dsi_index < temp_dsi_count) {
		// check if module CB is successful
		*cb_return_val =
		    dsi_info->list_dsi->module.service_info_callback(
			SDO_SI_GET_DSI, &(dsi_info->module_dsi_index), sv_kv);
		if (*cb_return_val != SDO_SI_SUCCESS) {
			LOG(LOG_ERROR, "Sv_info: %s's DSI CB Failed!\n",
			    dsi_info->list_dsi->module.module_name);
			return false;
		}

		if (!sdo_mod_data_kv(dsi_info->list_dsi->module.module_name,
				     sv_kv)) {
			*cb_return_val = SDO_SI_INTERNAL_ERROR;
			return false;
		}
		// Inc Module_dsi_index
		dsi_info->module_dsi_index++;
	}

	/* reset module DSI index for next module */
	if (dsi_info->module_dsi_index == temp_dsi_count) {
		dsi_info->module_dsi_index = 0;
		dsi_info->list_dsi = dsi_info->list_dsi->next;
	}
	*cb_return_val = SDO_SI_SUCCESS;
	return true;
}

/**
 * Write the key value to the buffer
 * @param sdow - pointer to the output buffer
 * @param sv_kv - pointer to the struct of type key value
 * @return true if success else false
 */
bool sdo_mod_kv_write(sdow_t *sdow, sdo_sdk_si_key_value *sv_kv)
{
	int strlen_kv_key = strnlen_s(sv_kv->key, SDO_MAX_STR_SIZE);
	int strlen_kv_value = strnlen_s(sv_kv->value, SDO_MAX_STR_SIZE);

	if (!strlen_kv_key || strlen_kv_key == SDO_MAX_STR_SIZE ||
	    strlen_kv_value == SDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "strlen() failed!\n");
		return false;
	}

	sdo_write_tag_len(sdow, sv_kv->key, strlen_kv_key);
	sdo_write_string_len(sdow, sv_kv->value, strlen_kv_value);
	sdow->need_comma = true;
	return true;
}

/**
 * Free Module Key Value
 * @param sv_kv - the object to free
 * @return none
 */
void sdo_sv_key_value_free(sdo_sdk_si_key_value *sv_kv)
{
	// TODO: ALL free below will change to sdo_free.
	if (sv_kv == NULL)
		return;
	if (sv_kv->key != NULL)
		sdo_free(sv_kv->key);
	if (sv_kv->value != NULL)
		sdo_free(sv_kv->value);
	sdo_free(sv_kv);
}

/**
 * Read a Sv_info (OSI) Key/Value pair from the input buffer
 * The Key and value both  MUST be a null terminated string.
 * @param module_list - Global Module List Head Pointer.
 * @param sv - pointer to the Sv_info key/value pair
 * @param cb_return_val - Pointer of type int which will be filled with CB
 * return value.
 * @return true if read succeeded, false otherwise
 */
bool sdo_osi_handling(sdo_sdk_service_info_module_list_t *module_list,
		      sdo_sdk_si_key_value *sv, int *cb_return_val)
{
	char mod_name[SDO_MODULE_NAME_LEN + 1];
	char mod_msg[SDO_MODULE_MSG_LEN + 1];

	if (!cb_return_val)
		return false;

	if (!sv || !sv->key) {
		*cb_return_val = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	int osi_key_len = strnlen_s(sv->key, SDO_MODULE_NAME_LEN);

	if (!osi_key_len || osi_key_len > SDO_MODULE_NAME_LEN) {
		LOG(LOG_ERROR,
		    "OSI key is either NULL or isin't NULL terminated!\n");
		*cb_return_val = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	// get module name and message name from sv->key
	// modulename and message name are separated using :
	char *osi_key = sv->key;
	int i = 0;

	while (':' != osi_key[i]) {
		if (i >= osi_key_len) {
			*cb_return_val = MESSAGE_BODY_ERROR;
			return false;
		}

		mod_name[i] = osi_key[i];
		++i;
	}

	mod_name[i] = 0;

	// consume one char for ':'
	++i;

	int j = 0;

	while (i <= osi_key_len) {
		mod_msg[j++] = osi_key[i++];
	}
	mod_msg[j] = 0;

	if (strcpy_s(sv->key, strnlen_s(mod_msg, SDO_MODULE_MSG_LEN) + 1,
		     mod_msg) != 0) {
		LOG(LOG_ERROR, "Strcpy failed!\n");
		*cb_return_val = SDO_SI_INTERNAL_ERROR;
		return false;
	}

	if (!sdo_supply_moduleOSI(module_list, mod_name, sv, cb_return_val))
		return false;

	*cb_return_val = SDO_SI_SUCCESS;
	return true;
}

/**
 * Sv_info: Clear the Module PSI and OSI Index for next rounds.
 * @param module_list - Global Module List Head Pointer.
 * @return none
 */
void sdo_sv_info_clear_module_psi_osi_index(sdo_sdk_service_info_module_list_t
					    *module_list)
{
	if (module_list) {
		while (module_list) {
			module_list->module_psi_index = 0;
			module_list->module_osi_index = 0;
			module_list = module_list->next;
		}
	}
}

/**
 * Construct the Module List using separator for device service info keys
 * @param module_list - Global Module List Head Pointer.
 * @param module_name - Pointer of type char in which List will be copied.
 * @return true if success else false.
 */
bool sdo_construct_module_list(sdo_sdk_service_info_module_list_t *module_list,
			       char **module_name)
{

	if (!module_name)
		return false;

	// When there are no modules, send empty string
	if (!module_list) {
		*module_name = sdo_alloc(1); // 1 is for empty string)
		if (!*module_name) {
			LOG(LOG_ERROR, "Malloc Failed\n");
			return false;
		}
		return true;
	}

	char *temp = sdo_alloc(SDO_MAX_STR_SIZE);

	if (!temp) {
		LOG(LOG_ERROR, "Malloc Failed\n");
		return false;
	}

	int len = 0;
	int count = 0;
	// Example string: devconfig;keypair
	while (module_list) {
		if (strcpy_s(temp + count, SDO_MAX_STR_SIZE - count,
			     module_list->module.module_name) != 0) {
			LOG(LOG_ERROR, "Strcpy failed!\n");
			sdo_free(temp);
			return false;
		}
		len = strnlen_s(module_list->module.module_name,
				SDO_MAX_STR_SIZE);
		if (!len || len == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Strlen failed!\n");
			sdo_free(temp);
			return false;
		}
		count += len;

		module_list = module_list->next;
		if (module_list) {
			if (strcpy_s(temp + count, SDO_MAX_STR_SIZE - count,
				     SEPARATOR) != 0) {
				LOG(LOG_ERROR, "Strcpy failed!\n");
				sdo_free(temp);
				return false;
			}
			count++; // 1 is for separator
		}
	}
	*module_name = temp;

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
bool sdo_compare_hashes(sdo_hash_t *hash1, sdo_hash_t *hash2)
{
	bool retval = false;
	int result = 1;

	if (!hash1 || !hash2 || !hash1->hash || !hash2->hash ||
	    !hash1->hash->byte_sz || !hash1->hash->bytes ||
	    !hash2->hash->byte_sz || !hash2->hash->bytes) {
		LOG(LOG_ERROR, "Null arguments!\n");
		goto end;
	}

	if (hash1->hash_type != hash2->hash_type) {
		LOG(LOG_DEBUG, "Hash types are not same!\n");
		goto end;
	}
	if (memcmp_s(hash1->hash->bytes, hash1->hash->byte_sz,
		     hash2->hash->bytes, hash2->hash->byte_sz, &result) ||
	    result) {
		LOG(LOG_DEBUG, "Hash contents are not same!\n");
		goto end;
	}

	retval = true;

end:
	return retval;
}

/**
 * Compares two byte_arrays
 *
 * @param ba1: poniter to input byte_array 1
 * @param ba2: poniter to input byte_array 2
 * @return
 *        true if both byte_arrays are same else false.
 */
bool sdo_compare_byte_arrays(sdo_byte_array_t *ba1, sdo_byte_array_t *ba2)
{
	bool retval = false;
	int result = 1;

	if (!ba1 || !ba2 || !ba1->byte_sz || !ba1->bytes || !ba2->byte_sz ||
	    !ba2->bytes) {
		LOG(LOG_ERROR, "Null arguments!\n");
		goto end;
	}

	if (memcmp_s(ba1->bytes, ba1->byte_sz, ba2->bytes, ba2->byte_sz,
		     &result) ||
	    result) {
		LOG(LOG_DEBUG, "Byte_array contents are not same!\n");
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
bool sdo_compare_rv_lists(sdo_rendezvous_list_t *rv_list1,
			  sdo_rendezvous_list_t *rv_list2)
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
void sdo_service_info_print(sdo_service_info_t *si)
{
	sdo_key_value_t *kv;
#define KVBUF_SIZE 32
	char kbuf[KVBUF_SIZE];
	char vbuf[KVBUF_SIZE];

	LOG(LOG_DEBUG, "{#SDOService_info numKV: %u\n", si->numKV);
	for (kv = si->kv; kv; kv = kv->next) {
		LOG(LOG_DEBUG, "    \"%s\":\"%s\"%s\n",
		    sdo_string_to_string(kv->key, kbuf, KVBUF_SIZE),
		    sdo_string_to_string(kv->val, vbuf, KVBUF_SIZE),
		    kv->next ? "," : "");
	}
	LOG(LOG_DEBUG, "}\n");
}
#endif
