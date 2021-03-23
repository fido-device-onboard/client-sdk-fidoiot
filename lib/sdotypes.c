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
 * Internal API
 */
bool sdo_byte_array_resize_with(sdo_byte_array_t *b, int new_byte_sz,
				uint8_t *data)
{
	return sdo_bits_resize_with(b, new_byte_sz, data);
}
#endif

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
 * Create sdo_string_t object by allocating memory for the inner buffer
 * with the given size.
 *
 * @return an allocated sdo_string_t object
 */
sdo_string_t *sdo_string_alloc_size(size_t byte_sz) {

	if (byte_sz == 0)
		return NULL;

	// Buffer would store NULL terminated string, adding +1 for '\0'
	int total_size = byte_sz + 1;
	sdo_string_t *s = (sdo_string_t *)sdo_alloc(sizeof(sdo_string_t));
	if (!s)
		return NULL;

	s->bytes = sdo_alloc(total_size * sizeof(char));
	if (!s->bytes) {
		sdo_free(s);
		return NULL;
	}
	// byte_sz contains the number of characters
	s->byte_sz = byte_sz;
	return s;
}

/**
 * Create a sdo_string_t object from a non zero terminated string.
 * @param data - a pointer to the string
 * @param byte_sz - the number of characters in the string ( size 0 or more)
 * @return an allocated sdo_string_t object containing the string
 */
sdo_string_t *sdo_string_alloc_with(const char *data, int byte_sz)
{
	sdo_string_t *temp_str = NULL;
	// Buffer would store NULL terminated string, adding +1 for '\0'
	int total_size = byte_sz + 1;

	if (!data)
		goto err1;

	temp_str = sdo_string_alloc();
	if (!temp_str)
		goto err1;

	temp_str->bytes = sdo_alloc(total_size * sizeof(char));
	if (temp_str->bytes == NULL)
		goto err2;

	// byte_sz contains the number of characters
	temp_str->byte_sz = byte_sz;
	if (byte_sz) {
		if (memcpy_s(temp_str->bytes, total_size, data, byte_sz) != 0) {
			LOG(LOG_ERROR, "Memcpy Failed here\n");
			goto err2;
		}
	}
	temp_str->bytes[byte_sz] = '\0';

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

/**
 * Write the SigInfo of the form:
 * SigInfo = [
 *   sgType: DeviceSgType,
 *   Info: bstr
 * ]
 * @param sdow - pointer to the struct where the GID is to be written.
 * @return true if write is successfull. false, otherwise.
 */
bool sdo_siginfo_write(sdow_t *sdow)
{
	bool ret = false;
	if (!sdow_start_array(sdow, 2)) {
		LOG(LOG_ERROR, "SigInfo: Failed to start array\n");
		return ret;
	}
	if (!sdow_unsigned_int(sdow, SDO_PK_ALGO)) {
		LOG(LOG_ERROR, "SigInfo: Failed to write sgType\n");
		return ret;
	}

	sdo_byte_array_t *empty_byte_array = sdo_byte_array_alloc(0);
	if (!empty_byte_array) {
		LOG(LOG_ERROR, "SigInfo: Byte Array Alloc failed\n");
		return false;
	}

	if (!sdow_byte_string(sdow, empty_byte_array->bytes, empty_byte_array->byte_sz)) {
		LOG(LOG_ERROR, "SigInfo: Failed to write Info\n");
		goto end;
	}

	if (!sdow_end_array(sdow)) {
		LOG(LOG_ERROR, "SigInfo: Failed to end array\n");
		goto end;
	}
	LOG(LOG_DEBUG, "eASigInfo write successfull\n");
	ret = true;
end:
	sdo_byte_array_free(empty_byte_array);
	empty_byte_array = NULL;
	return ret;
}

/**
 * Read the SigInfo of the form:
 * SigInfo = [
 *   sgType: DeviceSgType,
 *   Info: bstr
 * ]
 * @param sdor - pointer to the struct containing GID
 * @return true if write is successfull. false, otherwise.
 */
bool sdo_siginfo_read(sdor_t *sdor)
{
	bool ret = false;
	int type = 0;
	int exptype = 0;
	uint8_t *buf = {0};

	if (!sdor)
		goto end;

	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR, "SigInfo: Failed to start array\n");
		goto end;
	}

	exptype = SDO_PK_ALGO;

	if (!sdor_signed_int(sdor, &type)) {
		LOG(LOG_ERROR, "SigInfo: Failed to read sgType\n");
		goto end;
	}

	if (type != exptype) {
		LOG(LOG_ERROR,
		    "SigInfo: Invalid sgType. Expected %d, Received %d\n", exptype,
		    type);
		goto end;
	}

	size_t info_length = 1;
	if (!sdor_string_length(sdor, &info_length) || info_length != 0) {
		LOG(LOG_ERROR,
		    "SigInfo: Invalid Info length. Expected %d, Received %zu\n", 0,
		    info_length);
		goto end;
	}

	if (!sdor_byte_string(sdor, buf, info_length)) {
		LOG(LOG_ERROR, "SigInfo: Failed to read Info\n");
		goto end;
	}

	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR, "No End Array\n");
		goto end;
	}
	LOG(LOG_DEBUG, "eBSigInfo read successfull\n");
	ret = true;
end:
	sdo_free(buf);
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
	int i = 0;
	char *a = (char *)n;

	(void)buf_sz; /* FIXME: Change the signature as its unused */

	if (!n || !buf)
		return NULL;

	while (i < SDO_NONCE_BYTES) {
		buf[i] = INT2HEX(((*a >> 4) & 0xf));
		buf[++i] = INT2HEX((*a & 0xf));
		++i;
		++a;
	}
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

/**
 * Read the hash of the form:
 * Hash = [
 *   hashtype: uint8,
 *   hash: bstr
 * ]
 * @param sdor - input data in JSON format
 * @param hp - pointer to the struct of type hash
 * @return number of bytes read , 0 if read failed
 */
int sdo_hash_read(sdor_t *sdor, sdo_hash_t *hp)
{

	if (!sdor || !hp)
		return 0;

	size_t num_hash_items = 0;
	if (!sdor_array_length(sdor, &num_hash_items) || num_hash_items != 2) {
		LOG(LOG_ERROR, "Invalid Hash: Invalid number of items\n");
		return 0;
	}
	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR, "Invalid Hash: Start array not found\n");
		return 0;
	}

	// Read the hash type value
	if (!sdor_signed_int(sdor, &hp->hash_type)) {
		LOG(LOG_ERROR, "Invalid Hash: Unable to decode hashtype\n");
		return 0;
	}

	// Read the bin character length
	size_t mbin_len_reported;
	if (!sdor_string_length(sdor, &mbin_len_reported) || mbin_len_reported <= 0) {
		LOG(LOG_ERROR, "Invalid Hash: Unable to decode length of hash!\n");
		return 0;
	}

	// Make sure we have a byte array to resize
	if (hp->hash == NULL) {
		hp->hash = sdo_byte_array_alloc(mbin_len_reported);
		if (!hp->hash) {
			LOG(LOG_ERROR, "Alloc failed\n");
			return 0;
		}
	}

	if (!sdor_byte_string(sdor, hp->hash->bytes, mbin_len_reported)) {
		LOG(LOG_ERROR, "Invalid Hash: Unable to decode hash!\n");
		return 0;
	}
	hp->hash->byte_sz = mbin_len_reported;

	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR, "Invalid Hash: End array not found\n");
		return 0;
	}
	return hp->hash->byte_sz;
}

/**
 * Read the hash of the form:
 * Hash = [
 *   hashtype: uint8,
 *   hash: bstr
 * ]
 * @param sdow - pointer to the output struct of type JSON message
 * @param hp - pointer to the struct of type hash
 * @return bool true if write was successful, false otherwise
 */
bool sdo_hash_write(sdow_t *sdow, sdo_hash_t *hp)
{
	bool ret = false;
	if (!sdow || !hp) {
		return ret;
	}
	if (!sdow_start_array(sdow, 2)) {
		LOG(LOG_ERROR, "Hash write: Failed to start array\n");
		return ret;
	}
	if (!sdow_signed_int(sdow, hp->hash_type)) {
		LOG(LOG_ERROR, "Hash write: Failed to write hashtype\n");
		return ret;
	}
	if (!sdow_byte_string(sdow, hp->hash->bytes, hp->hash->byte_sz)) {
		LOG(LOG_ERROR, "Hash write: Failed to write hash\n");
		return ret;
	}
	if (!sdow_end_array(sdow)) {
		LOG(LOG_ERROR, "Hash write: Failed to end array\n");
		return ret;
	}
	LOG(LOG_DEBUG, "Hash write completed\n");
	ret = true;
	return ret;
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

	size_t ip_length;
	if (!sdor_string_length(sdor, &ip_length) || ip_length != IPV4_ADDR_LEN) {
		LOG(LOG_ERROR, "Invalid IP Address length\n");
		sdo_byte_array_free(IP);
		return false;
	}

	if (!sdor_byte_string(sdor, IP->bytes, ip_length)) {
		sdo_byte_array_free(IP);
		return false;
	}

	sdoip->length = ip_length;
	if (memcpy_s(&sdoip->addr[0], sdoip->length, IP->bytes, ip_length) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}

	sdo_byte_array_free(IP);
	return true;
}

/**
 * Copy the IP Address contents stored in the input sdo_byte_array_t, into
 * the pre-initialized sdo_ip_address_t struct.
 * 
 * @param ip_bytes source byte array containing IP Address and its length to copy
 * @param sdoip pre-initialized IP Address struct as destination
 * @return true if the operation was a success, false otherwise
 */
bool sdo_convert_to_ipaddress(sdo_byte_array_t *ip_bytes, sdo_ip_address_t *sdoip)
{
	if (!ip_bytes || !sdoip)
		return false;

	sdoip->length = ip_bytes->byte_sz;
	if (memcpy_s(&sdoip->addr[0], sdoip->length, ip_bytes->bytes, ip_bytes->byte_sz) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}

	return true;
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
 * Write a full public key to the output buffer
 * PublicKey = [
 *	pkType,
 *	pkEnc,
 *	pkBody
 * ]
 *
 * @param sdow - output buffer to hold CBOR representation
 * @param pk - pointer to the sdo_public_key_t object
 * @return none
 */
bool sdo_public_key_write(sdow_t *sdow, sdo_public_key_t *pk)
{
	if (!sdow)
		return false;

	if (!sdow_start_array(sdow, 3)) {
		LOG(LOG_ERROR, "PublicKey write: Failed to start array.\n");
		return false;
	}
	if (!sdow_signed_int(sdow, pk->pkalg)) {
		LOG(LOG_ERROR, "PublicKey write: Failed to write pkType.\n");
		return false;
	}
	if (!sdow_signed_int(sdow, pk->pkenc)) {
		LOG(LOG_ERROR, "PublicKey write: Failed to write pkEnc.\n");
		return false;
	}
	if (!sdow_byte_string(sdow, pk->key1->bytes, pk->key1->byte_sz)) {
		LOG(LOG_ERROR, "PublicKey write: Failed to write pkBody.\n");
		return false;
	}
	if (!sdow_end_array(sdow)) {
		LOG(LOG_ERROR, "PublicKey write: Failed to end array.\n");
		return false;
	}
	// Write successfull. Return true.
	return true;
}

/**
 * Read the public key information of the form:
 * PublicKey = [
 *	pkType,
 *	pkEnc,
 *	pkBody
 * ]
 * 
 * @param sdor - read public key info
 * return pointer to the struct of type public key if success else error code
 */
sdo_public_key_t *sdo_public_key_read(sdor_t *sdor)
{
	if (!sdor)
		return NULL;

	size_t num_public_key_items, public_key_length = 0;
	sdo_public_key_t *pk = sdo_public_key_alloc_empty(); // Create a Public Key
	if (!pk) {
		goto err;
	}

	if (!sdor_array_length(sdor, &num_public_key_items) || num_public_key_items != 3) {
		LOG(LOG_ERROR, "%s Invalid PublicKey: Array length\n", __func__);
		goto err;
	}
	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR, "%s Invalid PublicKey: Start array not found\n", __func__);
		goto err;
	}
	if (!sdor_signed_int(sdor, &pk->pkalg)) {
		LOG(LOG_ERROR, "%s Invalid PublicKey: Unable to decode pkType\n", __func__);
		goto err;
	}
	if (!sdor_signed_int(sdor, &pk->pkenc)) {
		LOG(LOG_ERROR, "%s Invalid PublicKey: Unable to decode pkEnc\n", __func__);
		goto err;
	}

	if (!sdor_string_length(sdor, &public_key_length) || public_key_length <= 0) {
		LOG(LOG_ERROR, "%s Invalid PublicKey: Unable to decode pkBody length\n", __func__);
	}
	LOG(LOG_DEBUG, "PublicKey.pkBody length: %zu bytes\n", public_key_length);
	pk->key1 = sdo_byte_array_alloc(public_key_length);

	if (!pk->key1 || !sdor_byte_string(sdor, pk->key1->bytes, public_key_length)) {
		LOG(LOG_ERROR, "%s Invalid PublicKey: Unable to decode pkBody\n", __func__);
		sdo_byte_array_free(pk->key1);
		goto err;
	}
	pk->key1->byte_sz = public_key_length;
	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR, "%s Invalid PublicKey: End array not found\n", __func__);
		goto err;
	}
	return pk;
err:
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

	if (rv->dev_only != NULL)
		sdo_free(rv->dev_only);

	if (rv->owner_only != NULL)
		sdo_free(rv->owner_only);

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
		sdo_free(rv->me);

	if (rv->pr != NULL)
		sdo_free(rv->pr);

	if (rv->delaysec != NULL)
		sdo_free(rv->delaysec);

	if (rv->bypass != NULL)
		sdo_free(rv->bypass);

	sdo_free(rv);
}

/** 
 * Write a RendezvousInstr object to the output buffer
 * RendezvousInstr = [
 *   RVVariable,
 *   RVValue
 * ]
 *
 * @param sdow - the buffer pointer
 * @param rv - pointer to the RendezvousInstr object to write
 * @return true if written successfully, otherwise false
 */
bool sdo_rendezvous_write(sdow_t *sdow, sdo_rendezvous_t *rv)
{
	if (!sdow || !rv)
		return false;
	
	if (!sdow_start_array(sdow, rv->num_params)) {
		LOG(LOG_ERROR, "RendezvousInstr: Failed to start array\n");
		return false;
	}

	if (rv->dev_only != NULL && *rv->dev_only == true) {
		if (!sdow_signed_int(sdow, RVDEVONLY)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVDevOnly\n");
			return false;
		}
	}

	if (rv->owner_only != NULL && *rv->owner_only == true) {
		if (!sdow_signed_int(sdow, RVOWNERONLY)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVOwnerOnly\n");
			return false;
		}
	}

	if (rv->ip != NULL) {
		if (!sdow_signed_int(sdow, RVIPADDRESS) ||
			!sdow_byte_string(sdow, (uint8_t *) &rv->ip->addr, rv->ip->length)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVIPAddress\n");
			return false;
		}
	}

	if (rv->po != NULL) {
		if (!sdow_signed_int(sdow, RVDEVPORT) ||
			!sdow_signed_int(sdow, *rv->po)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVDevPort\n");
			return false;
		}
	}

	if (rv->pow != NULL) {
		if (!sdow_unsigned_int(sdow, RVOWNERPORT) ||
			!sdow_signed_int(sdow, *rv->pow)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVOwnerPort\n");
			return false;
		}
	}

	if (rv->dn != NULL) {
		if (!sdow_signed_int(sdow, RVDNS) ||
			!sdow_text_string(sdow, rv->dn->bytes, rv->dn->byte_sz)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVDns\n");
			return false;
		}
	}

	if (rv->sch != NULL) {
		if (!sdow_signed_int(sdow, RVSVCERTHASH) ||
			!sdo_hash_write(sdow, rv->sch)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVSvCertHash\n");
			return false;
		}
	}

	if (rv->cch != NULL) {
		if (!sdow_signed_int(sdow, RVCLCERTHASH) ||
			!sdo_hash_write(sdow, rv->cch)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVClCertHash\n");
			return false;
		}
	}

	if (rv->ui != NULL) {
		if (!sdow_signed_int(sdow, RVUSERINPUT) ||
			!sdow_boolean(sdow, *rv->ui)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVUserInput\n");
			return false;
		}
	}

	if (rv->ss != NULL) {
		if (!sdow_signed_int(sdow, RVWIFISSID) ||
			!sdow_text_string(sdow, rv->ss->bytes, rv->ss->byte_sz)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVWiFiSsid\n");
			return false;
		}
	}

	if (rv->pw != NULL) {
		if (!sdow_signed_int(sdow, RVWIFIPW) ||
			!sdow_text_string(sdow, rv->pw->bytes, rv->pw->byte_sz)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVWifiPw\n");
			return false;
		}
	}

	if (rv->me != NULL) {
		if (!sdow_signed_int(sdow, RVMEDIUM) ||
			!sdow_unsigned_int(sdow, *rv->me)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVMedium\n");
			return false;
		}
	}

	if (rv->pr != NULL) {
		if (!sdow_signed_int(sdow, RVPROTOCOL) ||
			!sdow_unsigned_int(sdow, *rv->pr)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVProtocol\n");
			return false;
		}
	}

	if (rv->delaysec != NULL) {
		if (!sdow_signed_int(sdow, RVDELAYSEC) ||
			!sdow_unsigned_int(sdow, *rv->delaysec)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVDelaysec\n");
			return false;
		}
	}

	if (rv->bypass != NULL && *rv->bypass == true) {
		if (!sdow_signed_int(sdow, RVBYPASS)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVBypass\n");
			return false;
		}
	}

	if (!sdow_end_array(sdow)) {
		LOG(LOG_ERROR, "RendezvousInstr: Failed to end array\n");
		return false;
	}
	return true;
}

/**
 * Read the RendezvousInstr from the input buffer
 * RendezvousInstr = [
 *   RVVariable,
 *   RVValue
 * ]
 *
 * @param sdor - the input buffer object
 * @param rv - pointer to the RendezvousInstr object to fill
 * @return true of read correctly, false otherwise
 */
bool sdo_rendezvous_read(sdor_t *sdor, sdo_rendezvous_t *rv)
{
	int ret = true;

	if (!sdor || !rv)
		return false;

	size_t num_rv_instr_items = 0;
	if (!sdor_array_length(sdor, &num_rv_instr_items) || num_rv_instr_items <= 0) {
		LOG(LOG_ERROR, "RendezvousInstr is empty\n");
		return false;
	}

	LOG(LOG_DEBUG, "%s RendezvousInstr read started\n", __func__);

	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR, "RendezvousInstr start array not found\n");
		return false;
	}
	
	// size_t index;
	size_t key_buf_sz = 24;
	char key_buf[key_buf_sz];
	size_t str_buf_sz = 80;
	char str_buf[str_buf_sz];

	rv->num_params = 0;

	if (memset_s(key_buf, key_buf_sz, 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return false;
	}
	if (memset_s(str_buf, str_buf_sz, 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return false;
	}
	int key;
	if (!sdor_signed_int(sdor, &key)) {
		LOG(LOG_ERROR, "RendezvousInstr key read error\n");
		ret = false;
	}
	// Parse the values found
	switch (key) {
	case RVDEVONLY:
		rv->dev_only = sdo_alloc(sizeof(bool));
		if (!rv->dev_only) {
			LOG(LOG_ERROR, "RVDEVONLY alloc failed\n");
			ret = false;
			break;
		}
		*rv->dev_only = true;
		rv->num_params = 1;
		break;

	case RVOWNERONLY:
		rv->owner_only = sdo_alloc(sizeof(bool));
		if (!rv->owner_only) {
			LOG(LOG_ERROR, "RVOWNERONLY alloc failed\n");
			ret = false;
			break;
		}
		*rv->owner_only = true;
		rv->num_params = 1;
		break;

	case RVIPADDRESS:
		if (rv->ip) {
			sdo_free(rv->ip);
		}

		rv->ip = sdo_ipaddress_alloc();
		if (!rv->ip) {
			LOG(LOG_ERROR, "RVIPADDRESS alloc failed\n");
			ret = false;
			break;
		}
		if (sdo_read_ipaddress(sdor, rv->ip) != true) {
			LOG(LOG_ERROR, "RVIPADDRESS read failed\n");
			ret = false;
		}
		rv->num_params = 2;
		break;

	case RVDEVPORT:

		if (rv->po) {
			sdo_free(rv->po);
		}

		rv->po = sdo_alloc(sizeof(int)); // Allocate an integer
		if (!rv->po) {
			LOG(LOG_ERROR, "RVDEVPORT alloc failed\n");
			ret = false;
			break;
		}
		if (!sdor_signed_int(sdor, rv->po)) {
			LOG(LOG_ERROR, "RVDEVPORT read failed\n");
			ret = false;
		}
		rv->num_params = 2;
		break;

	// valid only for OWNER. parse for validation.
	case RVOWNERPORT:

		if (rv->pow) {
			sdo_free(rv->pow);
		}

		rv->pow = sdo_alloc(sizeof(int));
		if (!rv->pow) {
			LOG(LOG_ERROR, "RVOWNERPORT alloc failed\n");
			ret = false;
			break;
		}
		if (!sdor_signed_int(sdor, rv->pow)) {
			LOG(LOG_ERROR, "RVOWNERPORT read failed\n");
			ret = false;
		}
		rv->num_params = 2;
		break;

	case RVDNS:

		if (!sdor_string_length(sdor, &str_buf_sz)) {
			LOG(LOG_ERROR, "RVDNS length read failed\n");
			return false;
		}

		if (!sdor_text_string(sdor, str_buf, str_buf_sz)) {
			LOG(LOG_ERROR, "RVDNS read failed\n");
			return false;
		}

		if (rv->dn) {
			sdo_string_free(rv->dn);
		}

		rv->dn = sdo_string_alloc_with(str_buf, str_buf_sz);
		if (!rv->dn) {
			LOG(LOG_ERROR, "RVDNS alloc failed\n");
			ret = false;
		}
		rv->num_params = 2;
		break;

	case RVSVCERTHASH:

		if (rv->sch) {
			sdo_hash_free(rv->sch);
		}
		rv->sch = sdo_hash_alloc_empty();
		if (!rv->sch) {
			LOG(LOG_ERROR, "RVSVCERTHASH alloc failed\n");
			ret = false;
			break;
		}
		if (!sdo_hash_read(sdor, rv->sch)) {
			LOG(LOG_ERROR, "RVSVCERTHASH read failed\n");
			ret = false;
		}
		rv->num_params = 2;
		break;

	case RVCLCERTHASH:

		if (rv->cch) {
			sdo_hash_free(rv->cch);
		}

		rv->cch = sdo_hash_alloc_empty();
		if (!rv->cch) {
			LOG(LOG_ERROR, "RVCLCERTHASH alloc failed\n");
			ret = false;
			break;
		}
		if (!sdo_hash_read(sdor, rv->cch)) {
			LOG(LOG_ERROR, "RVSVCERTHASH read failed\n");
			ret = false;
		}
		rv->num_params = 2;
		break;

	case RVUSERINPUT:

		rv->ui = sdo_alloc(sizeof(bool));
		if (!rv->ui) {
			LOG(LOG_ERROR, "RVUSERINPUT alloc failed\n");
			ret = false;
			break;
		}
		if (!sdor_boolean(sdor, rv->ui)) {
			LOG(LOG_ERROR, "RVUSERINPUT read failed\n");
			ret = false;
		}
		rv->num_params = 2;
		break;

	case RVWIFISSID:

		if (!sdor_string_length(sdor, &str_buf_sz)) {
			LOG(LOG_ERROR, "RVWIFISSID length read failed\n");
			ret = false;
		}

		if (sdor_text_string(sdor, str_buf, str_buf_sz)) {
			LOG(LOG_ERROR, "RVWIFISSID length read failed\n");
			return false;
		}

		if (rv->ss) {
			sdo_string_free(rv->ss);
		}
		rv->ss = sdo_string_alloc_with(str_buf, str_buf_sz);
		if (!rv->ss) {
			LOG(LOG_ERROR, "RVWIFISSID alloc failed\n");
			ret = false;
		}
		rv->num_params = 2;
		break;

	case RVWIFIPW:

		if (!sdor_string_length(sdor, &str_buf_sz)) {
			LOG(LOG_ERROR, "RVWIFIPW length read failed\n");
			ret = false;
		}

		if (!sdor_text_string(sdor, str_buf, str_buf_sz)) {
			LOG(LOG_ERROR, "RVWIFIPW read failed\n");
			ret = false;
		}

		if (rv->pw) {
			sdo_string_free(rv->pw);
		}

		rv->pw = sdo_string_alloc_with(str_buf, str_buf_sz);
		if (!rv->pw) {
			LOG(LOG_ERROR, "RVWIFIPW alloc failed\n");
			ret = false;
		}
		rv->num_params = 2;
		break;

	case RVMEDIUM:

		rv->me = sdo_alloc(sizeof(uint64_t));
		if (!sdor_unsigned_int(sdor, rv->me)) {
			LOG(LOG_ERROR, "RVMEDIUM read failed\n");
			ret = false;
		}
		// TO-DO : Parse all possible RVMedium values.
		rv->num_params = 2;
		break;

	case RVPROTOCOL:

		rv->pr = sdo_alloc(sizeof(uint64_t));
		if (!sdor_unsigned_int(sdor, rv->pr)) {
			LOG(LOG_ERROR, "RVPROTOCOL read failed\n");
			ret = false;
		}
		// TO-DO : Parse all possible RVProtocol values.
		rv->num_params = 2;
		break;

	case RVDELAYSEC:

		if (rv->delaysec) {
			sdo_free(rv->delaysec);
		}

		rv->delaysec = sdo_alloc(sizeof(uint64_t));
		if (!rv->delaysec) {
			LOG(LOG_ERROR, "RVDELAYSEC Alloc failed\n");
			return false;
		}
		if (!sdor_unsigned_int(sdor, rv->delaysec) || !rv->delaysec) {
			LOG(LOG_ERROR, "RVDELAYSEC read failed\n");
			ret = false;
		}
		rv->num_params = 2;
		break;

	case RVBYPASS:

		rv->bypass = sdo_alloc(sizeof(bool));
		if (!rv->bypass) {
			LOG(LOG_ERROR, "RVBYPASS alloc failed\n");
			ret = false;
			break;
		}
		*rv->bypass = true;
		rv->num_params = 1;
		break;

	case RVEXTRV:
		// TO-DO: Parse as an array. Implementation is open for now.
		break;

	default:
		LOG(LOG_ERROR,
		    "%s : Invalid RendezvousInstr Entry Type %s\n",
			    __func__, key_buf);
		ret = false; // Abort due to unexpected value for key
		break;
	}

	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR, "RendezvousInstr end array not found\n");
		ret = false;
	}
	LOG(LOG_DEBUG, "%s RendezvousInstr read ended\n", __func__);

	return ret;
}

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
 * Free all entries in the list.
 * @param list - the list to sdo_free.
 * @return none
 */
void sdo_rendezvous_list_free(sdo_rendezvous_list_t *list)
{
	sdo_rendezvous_t *entry, *next;
	sdo_rendezvous_directive_t *directive_entry, *directive_next;

	if (list == NULL) {
		return;
	}

	/* Delete all entries. */
	directive_entry = directive_next = list->rv_directives;
	while (directive_entry) {
		next = entry = directive_entry->rv_entries;
		while (entry) {
			next = entry->next;
			sdo_rendezvous_free(entry);
			entry = next;
		};
		directive_next = directive_entry->next;
		sdo_free(directive_entry);
		directive_entry = directive_next;
	}
	list->num_rv_directives = 0;
	sdo_free(list);
}

/**
 * Add the RendezvousDirective to the RendezvousInfo list
 * @param list - pointer to the RendezvousInfo list
 * @param rv - pointer to the RendezvousDirective to be added to the list
 * @return number of entries added if success else error code
 */
int sdo_rendezvous_directive_add(sdo_rendezvous_list_t *list,
	sdo_rendezvous_directive_t *directive) {
	if (list == NULL || directive == NULL)
		return 0;

	LOG(LOG_DEBUG, "Adding directive to rvlst\n");

	if (list->num_rv_directives == 0) {
		// List empty, add the first entry
		list->rv_directives = directive;
		list->num_rv_directives++;
	} else {
		// already has entries, find the last entry
		sdo_rendezvous_directive_t *entry_ptr = list->rv_directives;
		// Find the last entry
		while (entry_ptr->next != NULL) {
			entry_ptr = (sdo_rendezvous_directive_t *)entry_ptr->next;
		}
		// Now the enty_ptr is pointing to the last entry
		// Add the directive entry onto the end
		entry_ptr->next = directive;
		list->num_rv_directives++;
	}
	LOG(LOG_DEBUG, "Added directive to rvlst, %d entries\n", list->num_rv_directives);
	return list->num_rv_directives;
}

/**
 * Add the RendezvousInstr to the RendezvousDirective struct
 * @param list - pointer to the RendezvousDirective list
 * @param rv - pointer to the RendezvousInstr to be added to the list
 * @return number of entries added if success else error code
 */
int sdo_rendezvous_list_add(sdo_rendezvous_directive_t *directives, sdo_rendezvous_t *rv)
{
	if (directives == NULL || rv == NULL)
		return 0;

	LOG(LOG_DEBUG, "Adding to rvlst\n");

	if (directives->num_entries == 0) {
		// List empty, add the first entry
		directives->rv_entries = rv;
		directives->num_entries++;
	} else {
		// already has entries, find the last entry
		sdo_rendezvous_t *entry_ptr = directives->rv_entries;
		// Find the last entry
		while (entry_ptr->next != NULL) {
			entry_ptr = (sdo_rendezvous_t *)entry_ptr->next;
		}
		// Now the enty_ptr is pointing to the last entry
		// Add the r entry onto the end
		entry_ptr->next = rv;
		directives->num_entries++;
	}
	LOG(LOG_DEBUG, "Added to rvlst, %d entries\n", directives->num_entries);
	return directives->num_entries;
}

/**
 * Function will return the RendezvousDirective as per the num passed.
 * @param list - Pointer to the list for the entries.
 * @param num - index of which entry (RendezvousDirective) to return.
 * @return sdo_rendezvous_directive_t object.
 */
sdo_rendezvous_directive_t *sdo_rendezvous_directive_get(sdo_rendezvous_list_t *list, int num)
{
	int index;

	if (list == NULL || list->rv_directives == NULL)
		return NULL;

	sdo_rendezvous_directive_t *entry_ptr = list->rv_directives;

	for (index = 0; index < num; index++) {
		if (entry_ptr->next != NULL)
			entry_ptr = entry_ptr->next;
		else {
			// this should ideally no happen since for 'num' times,
			// there should be a directive present.
			LOG(LOG_DEBUG, "RendezvousDirective not found for index %d\n", index);
			return NULL;
		}
	}
	return entry_ptr;
}

/**
 * Function will return the RendezvousInstr as per the num passed.
 * @param list - Pointer to the list for the entries.
 * @param num - index of which entry (RendezvousInstr) to return.
 * @return sdo_rendezvous_t object.
 */
sdo_rendezvous_t *sdo_rendezvous_list_get(sdo_rendezvous_directive_t *directive, int num)
{
	int index;

	if (directive == NULL || directive->rv_entries == NULL)
		return NULL;

	sdo_rendezvous_t *entry_ptr = directive->rv_entries;

	for (index = 0; index < num; index++) {
		if (entry_ptr->next != NULL)
			entry_ptr = entry_ptr->next;
		else {
			// this should ideally no happen since for 'num' times,
			// there should be a directive present.
			LOG(LOG_DEBUG, "RendezvousInstr not found for index %d\n", index);
			return NULL;
		}
	}
	return entry_ptr;
}

/**
 * Reads the RendezvousInfo from the sdor w.r.t the number of entries.
 * RendezvousInfo = [
 *   + RendezvousDirective
 * ]
 * RendezvousDirective = [
 *   + RendezvousInstr
 * ]
 * RendezvousInstr = [
 *   RVVariable,
 *   RVValue
 * ]
 * @param sdor - Pointer of type sdor_t as input.
 * @param list- Pointer to the sdo_rendezvous_list_t list to be filled.
 * @return true if reads correctly ,else false
 */

int sdo_rendezvous_list_read(sdor_t *sdor, sdo_rendezvous_list_t *list)
{
	if (!sdor || !list)
		return false;

	// Find out the number of RendezvousDirective(s)
	size_t num_rv_directives = 0;
	if (!sdor_array_length(sdor, &num_rv_directives) || num_rv_directives <= 0) {
		LOG(LOG_ERROR,
		    "%s : No RendezvousDirective(s) found\n", __func__);
		return false;
	}

	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR,
		    "%s : RendezvousInfo start array not found\n", __func__);
		return false;
	}

	LOG(LOG_DEBUG, "There are %zu RendezvousDirective(s) in the RendezvousInfo\n",
		num_rv_directives);

	size_t rv_directive_index;

	for (rv_directive_index = 0; rv_directive_index < num_rv_directives; rv_directive_index++) {
		LOG(LOG_DEBUG, "Processing RendezvousDirective Index %zu\n", rv_directive_index);
		// Find out the number of RendezvousInstr(s)
		size_t num_rv_instr = 0;
		if (!sdor_array_length(sdor, &num_rv_instr) || num_rv_instr <= 0) {
			LOG(LOG_ERROR,
		    	"%s : No RendezvousInstr(s) found\n", __func__);
			return false;
		}

		LOG(LOG_DEBUG, "There are %zu RendezvousInstr(s)\n",
			num_rv_instr);

		if (!sdor_start_array(sdor)) {
			LOG(LOG_ERROR,
		    "%s : RendezvousDirective start array not found\n", __func__);
			return false;
		}

		sdo_rendezvous_directive_t *rv_directive =
			sdo_alloc(sizeof(sdo_rendezvous_directive_t));
		if (!rv_directive) {
			LOG(LOG_ERROR,
		    "%s : RendezvousDirective alloc failed\n", __func__);
			return false;			
		}
		size_t rv_instr_index;
		for (rv_instr_index = 0; rv_instr_index < num_rv_instr; rv_instr_index++) {
			// Read each rv entry and add to the rv list
			LOG(LOG_DEBUG, "Processing RendezvousInstr Index %zu\n", rv_instr_index);

			sdo_rendezvous_t *rv_entry = sdo_rendezvous_alloc();

			LOG(LOG_DEBUG, "New rv allocated %p\n", (void *)rv_entry);

			if (sdo_rendezvous_read(sdor, rv_entry))
				sdo_rendezvous_list_add(rv_directive, rv_entry);
			else {
				sdo_rendezvous_free(rv_entry);
				// TO-DO: free directive here?
				return false;
			}
		}
		if (!sdor_end_array(sdor)) {
			LOG(LOG_ERROR,
		    	"%s : RendezvousDirective end array not found\n", __func__);
		return false;
		}
		sdo_rendezvous_directive_add(list, rv_directive);
	}
	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR,
		    "%s : RendezvousInfo end array not found\n", __func__);
		return false;
	}

	LOG(LOG_DEBUG, "%s read\n", __func__);
	return true;
}

/**
 * Writes out the entire RendezvousInfo list as sequences inside a sequence.
 * RendezvousInfo = [
 *   + RendezvousDirective
 * ]
 * RendezvousDirective = [
 *   + RendezvousInstr
 * ]
 * RendezvousInstr = [
 *   RVVariable,
 *   RVValue
 * ]
 * @param sdow - Pointer of type sdow to be filled.
 * @param list- Pointer to the sdo_rendezvous_list_t list from which sdow will
 * be filled w.r.t num_entries specified in the list.
 * @return true if writes correctly ,else false
 */
bool sdo_rendezvous_list_write(sdow_t *sdow, sdo_rendezvous_list_t *list)
{
	if (!sdow || !list)
		return false;

	sdow_start_array(sdow, list->num_rv_directives);

	int rv_directive_index;
	for (rv_directive_index = 0; rv_directive_index < list->num_rv_directives;
		rv_directive_index++) {
		sdo_rendezvous_directive_t *directive = sdo_rendezvous_directive_get(list, rv_directive_index);
		if (!directive) {
			continue;
		}
		sdow_start_array(sdow, directive->num_entries);
		int rv_instr_index;
		for (rv_instr_index = 0; rv_instr_index < directive->num_entries; rv_instr_index++) {
			sdo_rendezvous_t *entry_Ptr = sdo_rendezvous_list_get(directive, rv_instr_index);
			if (entry_Ptr == NULL) {
				continue;
			}
			sdo_rendezvous_write(sdow, entry_Ptr);
		}
		sdow_end_array(sdow);
	}
	sdow_end_array(sdow);

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
	if (pkt->em_body)
		sdo_byte_array_free(pkt->em_body);
	if (pkt->hmac)
		sdo_hash_free(pkt->hmac);
	if (pkt->ct_string)
		sdo_byte_array_free(pkt->ct_string);
	sdo_free(pkt);
}

/**
 * Read an Encrypted Message Body object from the SDOR buffer.
 * Currently, this parses EncryptedMessage of Composed Type (EncThenMacMessage),
 * that contains an COSE_Encrypt0 (ETMInnerBlock) wrapped by COSE_Mac0 (ETMOuterBlock)
 * ETMOuterBlock = [
 *   protected:   { 1:ETMMacType },		// bstr
 *   unprotected: { }					// empty map
 *   payload:     ETMInnerBlock			// COSE_Encrypt0
 *   hmac:   hmac						// bstr
 * ]
 * ETMInnerBlock = [
 *   protected:   { 1:AESPlainType },	// bstr
 *   unprotected: { 5:AESIV }
 *   payload:     ProtocolMessage
 * ]
 * TO-DO : To be updated later to parse Simple Type.
 * @param sdor - pointer to the character buffer to parse
 * @return a newly allocated SDOEcnrypted_packet object if successful, otherwise
 * NULL
 */
sdo_encrypted_packet_t *sdo_encrypted_packet_read(sdor_t *sdor)
{
	sdo_encrypted_packet_t *pkt = NULL;
	fdo_cose_encrypt0_t *cose_encrypt0 = NULL;
	fdo_cose_mac0_t *cose_mac0 = NULL;

	if (!sdor){
		LOG(LOG_ERROR, "Encrypted Message Read: Invalid SDOR\n");
		goto error;
	}

	pkt = sdo_encrypted_packet_alloc();
	if (!pkt) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to alloc Encrypted structure\n");
		goto error;
	}

	cose_mac0 = sdo_alloc(sizeof(fdo_cose_mac0_t));
	if (!cose_mac0) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to alloc COSE_Mac0\n");
		goto error;
	}
	if (!fdo_cose_mac0_read(sdor, cose_mac0)) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to read COSE_Mac0\n");
		goto error;
	}

	// copy the COSE_Mac0 payload which will be verified against the
	// COSE_Mac0 hmac later
	pkt->ct_string = sdo_byte_array_alloc_with_byte_array(
		cose_mac0->payload->bytes, cose_mac0->payload->byte_sz);
	if (!pkt->ct_string) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to copy Encrypted Payload structure\n");
		goto error;
	}

	// Verify hash/hmac type
	// TO-DO: When implementing Simple Encrypted Message,
	// use the key to differentiate Simple/Composed types.
	int expected_hmac_type = SDO_CRYPTO_HMAC_TYPE_USED;
	if (cose_mac0->protected_header->mac_type != expected_hmac_type) {
		LOG(LOG_ERROR, "Encrypted Message Read: Unexpected HMac Type\n");
		goto error;	
	}
	pkt->hmac = sdo_hash_alloc(cose_mac0->protected_header->mac_type,
		cose_mac0->hmac->byte_sz);	
	if (!pkt->hmac) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to alloc Encrypted Hmac structure\n");
		goto error;
	}
	if (0 != memcpy_s(pkt->hmac->hash->bytes, pkt->hmac->hash->byte_sz,
		cose_mac0->hmac->bytes, cose_mac0->hmac->byte_sz)) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to copy COSE_Mac0.hmac\n");
		goto error;
	}

	// clear the SDOR buffer and push COSE payload into it, essentially reusing the SDOR object.
	sdo_block_reset(&sdor->b);
	sdor->b.block_size = cose_mac0->payload->byte_sz;
	if (0 != memcpy_s(sdor->b.block, sdor->b.block_size,
		cose_mac0->payload->bytes, cose_mac0->payload->byte_sz)) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to copy COSE_Mac0.payload into SDOR\n");
		goto error;
	}
	fdo_cose_mac0_free(cose_mac0);
	cose_mac0 = NULL;

	// initialize the parser once the buffer contains COSE payload to be decoded.
	if (!sdor_parser_init(sdor)) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to initialize SDOR parser\n");
		goto error;
	}

	cose_encrypt0 = sdo_alloc(sizeof(fdo_cose_encrypt0_t));
	if (!cose_encrypt0) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to alloc COSE_Encrypt0\n");
		goto error;
	}
	if (!fdo_cose_encrypt0_read(sdor, cose_encrypt0)) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to read COSE_Encrypt0\n");
		goto error;
	}

	// copy Encrypted payload that will be decrypted later.
	pkt->em_body = sdo_byte_array_alloc_with_byte_array(
		cose_encrypt0->payload->bytes, cose_encrypt0->payload->byte_sz);
	if (!pkt->em_body) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to copy COSE_Encrypt0.Payload\n");
		goto error;
	}

	// copy IV that is used to decrypt the encrypted payload
	if (0 != memcpy_s(&pkt->iv, sizeof(pkt->iv),
		&cose_encrypt0->unprotected_header->aes_iv, sizeof(cose_encrypt0->unprotected_header->aes_iv))) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to copy COSE_Encrypt0.Unprotected.AESIV\n");
		goto error;
	}

	// verify and copy AESPlainType value
	int expected_aes_plain_type = AES_PLAIN_TYPE;
	if (cose_encrypt0->protected_header->aes_plain_type != expected_aes_plain_type) {
		LOG(LOG_ERROR, "Encrypted Message Read: Unexpected AESPlainType\n");
		goto error;
	}
	pkt->aes_plain_type = cose_encrypt0->protected_header->aes_plain_type;

	fdo_cose_encrypt0_free(cose_encrypt0);
	cose_encrypt0 = NULL;
	LOG(LOG_DEBUG, "Encrypted Message Read: Encrypted Message parsed successfully\n");
	return pkt;
error:
	sdo_encrypted_packet_free(pkt);
	if (cose_mac0) {
		fdo_cose_mac0_free(cose_mac0);
		cose_mac0 = NULL;
	}
	if (cose_encrypt0) {
		fdo_cose_encrypt0_free(cose_encrypt0);
		cose_encrypt0 = NULL;
	}
	return NULL;
}

/**
 * Write the ETMInnerBlock stucture (COSE_Encrypt0) in the SDOW buffer using the contents
 * of sdo_encrypted_packet_t.
 * ETMInnerBlock = [
 *   protected:   { 1:AESPlainType },
 *   unprotected: { 5:AESIV }
 *   payload:     ProtocolMessage
 *   signature:   bstr
 *]
 * @param sdow - sdow_t object containing the buffer where CBOR data will be written to
 * @param pkt - sdo_encrypted_packet_t object
 * @return true if write is successfull, false otherwise.
 */
bool fdo_etminnerblock_write(sdow_t *sdow, sdo_encrypted_packet_t *pkt)
{
	if (!sdow || !pkt)
		return false;

	fdo_cose_encrypt0_t *cose_encrypt0 = NULL;

	cose_encrypt0 = fdo_cose_encrypt0_alloc();
	if (!cose_encrypt0) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to alloc COSE_Encrypt0 (ETMInnerBlock)\n");
		goto err;
	}

	// copy the required data into COSE_Encrypt0 object
	cose_encrypt0->protected_header->aes_plain_type = pkt->aes_plain_type;

	if (0 != memcpy_s(&cose_encrypt0->unprotected_header->aes_iv,
		sizeof(cose_encrypt0->unprotected_header->aes_iv),
		&pkt->iv, sizeof(pkt->iv))) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to copy IV\n");
		goto err;
	}
	cose_encrypt0->payload = sdo_byte_array_alloc_with_byte_array(
		pkt->em_body->bytes, pkt->em_body->byte_sz);

	if (!fdo_cose_encrypt0_write(sdow, cose_encrypt0)) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to write COSE_Encrypt0 (ETMInnerBlock)\n");
		goto err;
	}

	// free immediately once used
	fdo_cose_encrypt0_free(cose_encrypt0);
	cose_encrypt0 = NULL;
	return true;
err:
	if (cose_encrypt0) {
		fdo_cose_encrypt0_free(cose_encrypt0);
		cose_encrypt0 = NULL;
	}
	return false;
}

/**
 * Write the ETMOuterBlock stucture (COSE_Mac0) in the SDOW buffer using the contents
 * of sdo_encrypted_packet_t.
 * ETMOuterBlock = [
 *   protected:   bstr .cbor ETMMacType,
 *   unprotected: {},
 *   payload:     bstr .cbor ETMPayloadTag,
 *   hmac:        bstr 
 * ]
 * ETMPayloadTag = ETMInnerBlock
 * @param sdow - sdow_t object containing the buffer where CBOR data will be written to
 * @param pkt - sdo_encrypted_packet_t object
 * @return  true if write is successfull, false otherwise.
 */
bool fdo_etmouterblock_write(sdow_t *sdow, sdo_encrypted_packet_t *pkt)
{
	if (!sdow || !pkt)
		return false;

	fdo_cose_mac0_t *cose_mac0 = sdo_alloc(sizeof(fdo_cose_mac0_t));
	if (!cose_mac0) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to alloc COSE_Sign1 (ETMOuterBlock)\n");
		goto err;
	}
	cose_mac0->protected_header = sdo_alloc(sizeof(fdo_cose_mac0_protected_header_t));
	if (!cose_mac0->protected_header) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to alloc COSE_Mac0 Protected (ETMOuterBlock)\n");
		goto err;
	}
	cose_mac0->protected_header->mac_type = pkt->hmac->hash_type;

	// set the encoded ETMInnerBlock (COSE_Encrypt0) as payload and its HMac into COSE_Mac0
	cose_mac0->payload = sdo_byte_array_alloc_with_byte_array(
		pkt->ct_string->bytes, pkt->ct_string->byte_sz);
	cose_mac0->hmac = sdo_byte_array_alloc_with_byte_array(
		pkt->hmac->hash->bytes, pkt->hmac->hash->byte_sz);

	if (!fdo_cose_mac0_write(sdow, cose_mac0)) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to write COSE_Sign1 (ETMOuterBlock)\n");
		goto err;
	}
	fdo_cose_mac0_free(cose_mac0);
	cose_mac0 = NULL;
	return true;
err:
	if (cose_mac0) {
		fdo_cose_mac0_free(cose_mac0);
		cose_mac0 = NULL;
	}
	return false;
}

/**
 * Take in encrypted data object and end up with it represented
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
	bool ret = false;
	sdo_byte_array_t *cleartext = NULL;

	// Decrypt the Encrypted Body
	if (!sdor || !pkt || !iv) {
		LOG(LOG_ERROR, "Encrypted Message (decrypt): Invalid params\n");
		goto err;
	}

	cleartext = sdo_byte_array_alloc(0);
	if (cleartext == NULL) {
		LOG(LOG_ERROR, "Encrypted Message (decrypt): Failed to alloc clear data\n");
		goto err;
	}

	/* New iv is used for each new decryption which comes from pkt*/
	if (0 != aes_decrypt_packet(pkt, cleartext)) {
		LOG(LOG_ERROR, "Encrypted Message (decrypt): Failed to decrypt\n");
		goto err;
	}

	// clear the SDOR buffer and push decrypted payload into it
	sdo_block_reset(&sdor->b);
	sdor->b.block_size = cleartext->byte_sz;
	if (0 != memcpy_s(sdor->b.block, cleartext->byte_sz,
		cleartext->bytes, cleartext->byte_sz)) {
		LOG(LOG_ERROR, "Encrypted Message (decrypt): Failed to copy\n");
		goto err;
	}

	// initialize the parser once the buffer contains COSE payload to be decoded.
	if (!sdor_parser_init(sdor)) {
		LOG(LOG_ERROR, "Encrypted Message (decrypt): Failed to initialize SDOR parser\n");
		goto err;
	}
	LOG(LOG_DEBUG, "Encrypted Message (decrypt): Decrytion done\n");
	ret = true;
err:
	if (pkt)
		sdo_encrypted_packet_free(pkt);
	if (cleartext)
		sdo_byte_array_free(cleartext);
	return ret;
}

/**
 * Take the cleartext packet contained in the sdow buffer and convert it
 * to an Encrypted Message Body of Composed Type (EncThenMacMessage) in the sdow buffer.
 * It contains an COSE_Encrypt0 (ETMInnerBlock) wrapped by COSE_Mac0 (ETMOuterBlock)
 * ETMOuterBlock = [
 *   protected:   { 1:ETMMacType },		// bstr
 *   unprotected: { }					// empty map
 *   payload:     ETMInnerBlock			// COSE_Encrypt0
 *   hmac:   hmac						// bstr
 * ]
 * ETMInnerBlock = [
 *   protected:   { 1:AESPlainType },	// bstr
 *   unprotected: { 5:AESIV }
 *   payload:     ProtocolMessage
 * ]
 * TO-DO : To be updated later to write Simple Type.
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
	bool ret = false;

	// find the encoded cleartext length
	size_t payload_length = 0;
	if (!sdow_encoded_length(sdow, &payload_length) || payload_length == 0) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to read encoded message length\n");
		return ret;
	}
	sdow->b.block_size = payload_length;

	sdo_encrypted_packet_t *pkt = sdo_encrypted_packet_alloc();
	if (!pkt) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to alloc for Encrypted message struct\n");
		return ret;
	}

	if (0 != aes_encrypt_packet(pkt, sdob->block, payload_length)) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to encrypt\n");
		goto exit;
	}

#if defined AES_PLAIN_TYPE
	pkt->aes_plain_type = AES_PLAIN_TYPE;
#elif
	LOG(LOG_ERROR,
		"Encrypted Message (encrypt): AES_PLAIN_TYPE is undefined\n");
	goto exit;
#endif

	// reset the SDOW block to write COSE_Encrypt0 (ETMInnerBlock)
	// This clears the unencrypted (clear text) as well
	sdo_block_reset(&sdow->b);
	sdow->b.block_size = CBOR_BUFFER_LENGTH;
	if (!sdow_encoder_init(sdow)) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to initialize SDOW encoder\n");
		goto exit;
	}
	// write the ETMInnerBlock containing the cipher text as payload
	if (!fdo_etminnerblock_write(sdow, pkt)) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to write COSE_Encrypt0 (ETMInnerBlock)\n");
		goto exit;
	}

	// update the final encoded length in SDOW
	if (!sdow_encoded_length(sdow, &sdow->b.block_size)) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to read COSE_Encrypt0 ((ETMInnerBlock)) length\n");
		goto exit;		
	}

	// initialize the cipher text array to hold the payload over which HMac will be generated.
	pkt->ct_string = sdo_byte_array_alloc_with_byte_array(sdow->b.block, sdow->b.block_size);
	if (!pkt->ct_string) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to alloc for Encrypted CT structure\n");
		goto exit;
	}

	// reset the SDOW block to prepare for writing COSE_Sign1 (ETMOuterBlock)
	sdo_block_reset(&sdow->b);
	sdow->b.block_size = CBOR_BUFFER_LENGTH;
	if (!sdow_encoder_init(sdow)) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to initialize SDOW encoder\n");
		goto exit;
	}

	// prepare to calculate the HMac over encoded ETMInnerBlock
	pkt->hmac =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);

	if (!pkt->hmac || !pkt->hmac->hash){
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to alloc for HMac\n");
		goto exit;
	}
	if (0 != sdo_to2_hmac(pkt->ct_string->bytes, pkt->ct_string->byte_sz,
			      pkt->hmac->hash->bytes,
			      pkt->hmac->hash->byte_sz)) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to generate HMac\n");
		goto exit;
	}

	// write the final ETMOuetrBlock and the message type
	// This is the message that goes over the network/channel
	sdow_next_block(sdow, type);
	if (!fdo_etmouterblock_write(sdow, pkt)) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to write COSE_Sign1 (ETMOuterBlock)\n");
		goto exit;
	}
	ret = true;
exit:
	if (pkt)
		sdo_encrypted_packet_free(pkt);
	return ret;
}

//------------------------------------------------------------------------------
// Write Signature Routines
//

/**
 * Create an EAT object with memory allocated for Protected header,
 * Unprotected header and Payload.
 * Signature alongwith EATMAROEPREFIX and EATNonce are set to NULL initally, which
 * should be initialized when needed.
 */
fdo_eat_t* fdo_eat_alloc(void) {

	fdo_eat_t *eat = sdo_alloc(sizeof(fdo_eat_t));
	if (!eat) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to alloc\n");
		goto err;
	}
	eat->eat_ph = sdo_alloc(sizeof(fdo_eat_protected_header_t));
	if (!eat->eat_ph) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to alloc Protected Header\n");
		goto err;
	}

	eat->eat_uph = sdo_alloc(sizeof(fdo_eat_unprotected_header_t));
	if (!eat->eat_uph) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to alloc Unprotected header\n");
		goto err;
	}
	eat->eat_uph->eatmaroeprefix = NULL;
	eat->eat_uph->euphnonce = NULL;

	// set the payload and signature to NULL, since there's no use to allocate for them here.
	eat->eat_payload = NULL;
	eat->eat_signature = NULL;
	return eat;
err:
	if (eat)
		fdo_eat_free(eat);
	return NULL;
}

/**
 * Free an EAT object for which memory has been allocated previously.
 */
void fdo_eat_free(fdo_eat_t *eat) {

	if (eat->eat_ph) {
		sdo_free(eat->eat_ph);
	}
	if (eat->eat_uph) {
		if (eat->eat_uph->eatmaroeprefix)
			sdo_byte_array_free(eat->eat_uph->eatmaroeprefix);
		if (eat->eat_uph->euphnonce)
			sdo_byte_array_free(eat->eat_uph->euphnonce);
		sdo_free(eat->eat_uph);
	}
	if (eat->eat_payload) {
		sdo_byte_array_free(eat->eat_payload);
	}
	if (eat->eat_signature) {
		sdo_byte_array_free(eat->eat_signature);
	}
	sdo_free(eat);
	eat = NULL;
}

/**
 * Write an Entity Attestation Token by CBOR encoding the contents of the given EAT object.
 * [
 * protected header,
 * unprotected header,
 * payload,				// bstr
 * signature			// bstr
 * ]
 * @param sdow - sdow_t object holding the buffer where CBOR data will be written to
 * @param eat - fdo_eat_t object that holds the EAT parameters
 * @return true, if write was a success. False otherwise.
 */
bool fdo_eat_write(sdow_t *sdow, fdo_eat_t *eat) {

	if (!sdow_start_array(sdow, 4)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write start array\n");
		return false;
	}

	if (!fdo_eat_write_protected_header(sdow, eat->eat_ph)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write protected header\n");
		return false;
	}

	if (!fdo_eat_write_unprotected_header(sdow, eat->eat_uph)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write unprotected header\n");
		return false;
	}

	if (!sdow_byte_string(sdow, eat->eat_payload->bytes, eat->eat_payload->byte_sz)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write payload\n");
		return false;
	}

	if (!sdow_byte_string(sdow, eat->eat_signature->bytes, eat->eat_signature->byte_sz)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write signature\n");
		return false;
	}

	if (!sdow_end_array(sdow)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write end array\n");
		return false;
	}
	return true;
}

/**
 * Create EAT.EATProtectedHeaders (CBOR map) as CBOR bytes using the given contents.
 * {
 * keyAlg:<key-alg>
 * }
 * Return true, if write was a success. False otherwise.
 */
bool fdo_eat_write_protected_header(sdow_t *sdow, fdo_eat_protected_header_t *eat_ph) {

	bool ret = false;
	sdo_byte_array_t *enc_ph = NULL;

	// create temporary SDOW, use it to create Protected header map and then clear it.
	sdow_t temp_sdow;
	if (!sdow_init(&temp_sdow) || !sdo_block_alloc(&temp_sdow.b) ||
		!sdow_encoder_init(&temp_sdow)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: SDOW Initialization/Allocation failed!\n");
		goto end;
	}

	if (!sdow_start_map(&temp_sdow, 1)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to write start map\n");
		goto end;
	}

	if (!sdow_signed_int(&temp_sdow, FDO_COSE_ALG_KEY)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to write CoseAlg Key\n");
		goto end;
	}

	if (!sdow_signed_int(&temp_sdow, eat_ph->ph_sig_alg)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to write CoseAlg Value\n");
		goto end;
	}

	if (!sdow_end_map(&temp_sdow)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to write end map\n");
		goto end;
	}

	size_t enc_ph_length = 0;
	if (!sdow_encoded_length(&temp_sdow, &enc_ph_length) || enc_ph_length == 0) {
		LOG(LOG_ERROR, "Entity Attestation Token Protected header:: Failed to find encoded length\n");
		goto end;
	}
	temp_sdow.b.block_size = enc_ph_length;
	// Set the encoded payload into buffer
	enc_ph =
		sdo_byte_array_alloc_with_byte_array(temp_sdow.b.block, temp_sdow.b.block_size);
	if (!enc_ph) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to alloc for encoded Protected header\n");
		goto end;
	}

	// finally, wrap the protected header into a bstr
	if (!sdow_byte_string(sdow, enc_ph->bytes, enc_ph->byte_sz)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to write Protected header as bstr\n");
		goto end;
	}
	ret = true;
end:
	sdow_flush(&temp_sdow);
	sdo_free(temp_sdow.b.block);
	if (enc_ph)
		sdo_byte_array_free(enc_ph);
	return ret;
}

/**
 * Create EAT.EATUnprotectedHeaders (CBOR Map) as CBOR bytes using the given contents.
 * {
 * EATMAROEPrefix:<maroe-prefix>,	// optional element
 * EUPHNonce:<nonce>				// optional element
 * }
 * Return true, if write was a success. False otherwise.
 */
bool fdo_eat_write_unprotected_header(sdow_t *sdow, fdo_eat_unprotected_header_t *eat_uph) {
	// calculate the size of map.
	int num_uph_elements = 0;
	if (eat_uph->euphnonce) {
		num_uph_elements++;
	}
	if (eat_uph->eatmaroeprefix) {
		num_uph_elements++;
	}
	if (!sdow_start_map(sdow, num_uph_elements)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Unprotected header: Failed to write start map\n");
		return false;
	}

	// Write EATMAROEPrefix only when its present.
	if (eat_uph->eatmaroeprefix) {
		if (!sdow_signed_int(sdow, FDO_EAT_MAROE_PREFIX_KEY)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token Unprotected header: Failed to write EATMAROEPrefix Key\n");
			return false;
		}

		if (!sdow_byte_string(sdow, eat_uph->eatmaroeprefix->bytes, eat_uph->eatmaroeprefix->byte_sz)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token Unprotected header: Failed to write EATMAROEPrefix value\n");
			return false;
		}
	}

	// Write EUPHNonce only when its present.
	if (eat_uph->euphnonce) {
		if (!sdow_signed_int(sdow, FDO_EAT_EUPHNONCE_KEY)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token Unprotected header: Failed to write EUPHNonce Key\n");
			return false;
		}

		if (!sdow_byte_string(sdow, eat_uph->euphnonce->bytes, eat_uph->euphnonce->byte_sz)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token Unprotected header: Failed to write EUPHNonce Value\n");
			return false;
		}
	}

	if (!sdow_end_map(sdow)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Unprotected header: Failed to write end map\n");
		return false;
	}
	return true;
}

/**
 * Create EAT.EATPayloadBaseMap (CBOR Map) as CBOR bytes using the given contents.
 * Before sending it across, the resulting encoded contents need to be CBOR encoded again
 * into a bstr CBOR type.
 * {
 * EAT-UEID:<ueid>,
 * EAT-NONCE:<nonce>,
 * EAT-FDO:<EATPayloads> // optional element
 * }
 * Return true, if write was a success. False otherwise.
 */
bool fdo_eat_write_payloadbasemap(sdow_t *sdow, fdo_eat_payload_base_map_t *eat_payload) {
	size_t num_payload_elements = 2;
	if (eat_payload->eatpayloads) {
		LOG(LOG_DEBUG,
			"Entity Attestation Token PayloadBaseMap: EATPayload to be written\n");
		num_payload_elements = 3;
	}
	if (!sdow_start_map(sdow, num_payload_elements)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write start map\n");
		return false;
	}

	if (!sdow_signed_int(sdow, FDO_EATUEID_KEY)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write EAT-UEID Key\n");
		return false;
	}

	if (!sdow_byte_string(sdow, eat_payload->eatueid, sizeof(eat_payload->eatueid))) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write EAT-UEID value\n");
		return false;
	}

	if (!sdow_signed_int(sdow, FDO_EATNONCE_KEY)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write EAT-NONCE Key\n");
		return false;
	}

	if (!sdow_byte_string(sdow, eat_payload->eatnonce, sizeof(eat_payload->eatnonce))) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write EAT-NONCE value\n");
		return false;
	}

	if (num_payload_elements == 3) {
		if (!sdow_signed_int(sdow, FDO_EATFDO)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token PayloadBaseMap: Failed to write EAT-FDO Key\n");
			return false;
		}

		// EATPayloads is an array of size 1 as per the usage in the FDO specification.
		if (!sdow_start_array(sdow, 1)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token PayloadBaseMap: Failed to write start array\n");
			return false;
		}
		if (!sdow_byte_string(sdow,
				eat_payload->eatpayloads->bytes, eat_payload->eatpayloads->byte_sz)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token PayloadBaseMap: Failed to write EAT-FDO value\n");
			return false;
		}
		if (!sdow_end_array(sdow)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token PayloadBaseMap: Failed to write end array\n");
			return false;
		}
	}

	if (!sdow_end_map(sdow)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write end map\n");
		return false;
	}
	return true;
}

/**
 * Free the given COSE_Sign1 object for which memory has been allocated previously.
 */
bool fdo_cose_free(fdo_cose_t *cose) {
	if (cose->cose_ph) {
		cose->cose_ph->ph_sig_alg = 0;
		sdo_free(cose->cose_ph);
	}
	if (cose->cose_uph) {
		sdo_public_key_free(cose->cose_uph->cuphowner_public_key);
		sdo_free(cose->cose_uph);
	}
	if (cose->cose_payload) {
		sdo_byte_array_free(cose->cose_payload);
	}
	if (cose->cose_signature) {
		sdo_byte_array_free(cose->cose_signature);
	}
	sdo_free(cose);
	return true;
}

/**
 * Read CoseSignature.COSEProtectedHeaders (CBOR map) into the given fdo_cose_protected_header_t object.
 * {
 * keyAlg:<key-alg>
 * }
 * Return true, if read was a success. False otherwise.
 */
bool fdo_cose_read_protected_header(sdor_t *sdor, fdo_cose_protected_header_t *cose_ph) {

	sdor_t temp_sdor;

	size_t var_length = 0;
	if (!sdor_string_length(sdor, &var_length) ||
		var_length == 0) {
		LOG(LOG_ERROR, "COSE Protected header: Failed to read payload length\n");
		return false;	
	}
	sdo_byte_array_t *ph_as_bstr = sdo_byte_array_alloc(var_length);
	if (!ph_as_bstr) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to alloc for COSE Protected Header as bstr\n");
		return false;
	}
	if (!sdor_byte_string(sdor, ph_as_bstr->bytes, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to read COSE Protected Header as bstr\n");
		goto end;
	}

	// create a temporary SDOR to read (unwrap) the header contents as map
	if (!sdor_init(&temp_sdor) ||
		!sdo_block_alloc_with_size(&temp_sdor.b, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to setup temporary SDOR\n");
		goto end;
	}

	if (0 != memcpy_s(temp_sdor.b.block, temp_sdor.b.block_size,
		ph_as_bstr->bytes, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to copy temporary unwrapped Header content\n");
		goto end;
	}

	if (!sdor_parser_init(&temp_sdor)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to init temporary SDOR parser\n");
		goto end;
	}

	if (!sdor_start_map(&temp_sdor)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to read start map\n");
		goto end;
	}

	int cose_alg_key = 1;
	if (!sdor_signed_int(&temp_sdor, &cose_alg_key) || cose_alg_key != 1) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to read CoseAlg Key\n");
		goto end;
	}

	if (!sdor_signed_int(&temp_sdor, &cose_ph->ph_sig_alg)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to read CoseAlg Value\n");
		goto end;
	}

	if (!sdor_end_map(&temp_sdor)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to read end map\n");
		goto end;
	}
end:
	sdor_flush(&temp_sdor);
	sdo_free(temp_sdor.b.block);
	if (ph_as_bstr)
		sdo_byte_array_free(ph_as_bstr);
	return true;
}

/**
 * Read CoseSignature.COSEUnprotectedHeaders.
 * Reads an empty map if cose_uph is NULL.
 * Reads and pushes the fields CUPHOWNER and CUPHNONCE otherwise.
 * Return true, if read was a success. False otherwise.
 * 
 * TO-DO : Update when Simple Encrypted Message is implemented to parse COSEUnProtFields
 */
bool fdo_cose_read_unprotected_header(sdor_t *sdor, fdo_cose_unprotected_header_t *cose_uph) {

	if (!sdor_start_map(sdor)) {
		LOG(LOG_ERROR,
			"COSE Unprotected header: Failed to read start map\n");
		return false;
	}

	if (cose_uph) {
		int result = 0;
		if (!sdor_signed_int(sdor, &result) || result != FDO_COSE_SIGN1_CUPHOWNERPUBKEY_KEY) {
			LOG(LOG_ERROR,
				"COSE Unprotected header: Failed to read CUPHOWNERPUBKEY key\n");
			return false;
		}
		cose_uph->cuphowner_public_key = sdo_public_key_read(sdor);
		if (!cose_uph->cuphowner_public_key) {
			LOG(LOG_ERROR, "COSE: Failed to read CUPHOWNERPUBKEY value\n");
			return false;
		}

		result = 0;
		if (!sdor_signed_int(sdor, &result) || result != FDO_COSE_SIGN1_CUPHNONCE_KEY) {
			LOG(LOG_ERROR,
				"COSE Unprotected header: Failed to read CUPHNONCE key\n");
			return false;
		}
		if (!sdor_byte_string(sdor, cose_uph->cuphnonce, sizeof(cose_uph->cuphnonce))) {
			LOG(LOG_ERROR,
				"COSE Unprotected header: Failed to read CUPHNONCE value\n");
			return false;			
		}
	}

	if (!sdor_end_map(sdor)) {
		LOG(LOG_ERROR,
			"COSE Unprotected header: Failed to read end map\n");
		return false;
	}
	return true;
}

/**
 * Read the given COSE into the fdo_cose_t parameter.
 * The fdo_cose_t parameter should have memory pre-allocated.
 * However, the internal elements must be un-allocated.
 * The memory allocation for the same would be done in the method.
 * [
 * protected header,
 * unprotected header,
 * payload,				// bstr
 * signature			// bstr
 * ]
 * @param sdor - sdor_t object containing the buffer to read
 * @param cose - fdo_cose_t object that will hold the read COSE_Sign1 parameters
 * @param empty_uph - true if the unprotected header is expected to be empty, false otherwise
 * @return true, if read was a success. False otherwise.
 */
bool fdo_cose_read(sdor_t *sdor, fdo_cose_t *cose, bool empty_uph) {

	size_t num_cose_items = 4;
	if (!sdor_array_length(sdor, &num_cose_items) || num_cose_items != 4) {
		LOG(LOG_ERROR, "COSE: Failed to read/Invalid array length\n");
		return false;		
	}

	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR, "COSE: Failed to read start array\n");
		return false;
	}

	cose->cose_ph = sdo_alloc(sizeof(fdo_cose_protected_header_t));
	if (!cose->cose_ph) {
		LOG(LOG_ERROR, "COSE: Failed to alloc Protected Header\n");
		goto end;
	}
	if (!fdo_cose_read_protected_header(sdor, cose->cose_ph)) {
		LOG(LOG_ERROR, "COSE: Failed to read protected header\n");
		goto end;
	}

	// this is a special case used only for message received from Type 61,
	// since it contains CUPHNONCE and CUPHOWNERPUBKEY
	if (!empty_uph) {
		cose->cose_uph = sdo_alloc(sizeof(fdo_cose_unprotected_header_t));
		if (!cose->cose_uph) {
			LOG(LOG_ERROR, "COSE: Failed to alloc unprotected Header\n");
			goto end;
		}
	}
	if (!fdo_cose_read_unprotected_header(sdor, cose->cose_uph)) {
		LOG(LOG_ERROR, "COSE: Failed to read unprotected header\n");
		goto end;
	}

	size_t var_length = 0;
	if (!sdor_string_length(sdor, &var_length) ||
		var_length == 0) {
		LOG(LOG_ERROR, "COSE: Failed to read payload length\n");
		goto end;	
	}
	cose->cose_payload = sdo_byte_array_alloc(var_length);
	if (!cose->cose_payload) {
		LOG(LOG_ERROR, "COSE: Failed to alloc EATPayload\n");
		goto end;
	}
	if (!sdor_byte_string(sdor, cose->cose_payload->bytes, cose->cose_payload->byte_sz)) {
		LOG(LOG_ERROR, "COSE: Failed to read payload\n");
		goto end;
	}

	var_length = 0;
	if (!sdor_string_length(sdor, &var_length) ||
		var_length == 0) {
		LOG(LOG_ERROR, "COSE: Failed to read signature length\n");
		goto end;	
	}
	cose->cose_signature = sdo_byte_array_alloc(var_length);
	if (!cose->cose_signature) {
		LOG(LOG_ERROR, "COSE: Failed to alloc Signature\n");
		goto end;
	}
	if (!sdor_byte_string(sdor, cose->cose_signature->bytes, cose->cose_signature->byte_sz)) {
		LOG(LOG_ERROR, "COSE: Failed to read signature\n");
		goto end;
	}

	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR, "COSE: Failed to read end array\n");
		goto end;
	}
	return true;

end:
	fdo_cose_free(cose);
	return false;
}

/**
 * Create COSESignature.COSEProtectedHeaders (CBOR map) as CBOR bytes using the given contents.
 * This is wrapped in bstr.
 * {
 * keyAlg:<key-alg>
 * }
 * Return true, if write was a success. False otherwise.
 */
bool fdo_cose_write_protected_header(sdow_t *sdow, fdo_cose_protected_header_t *cose_ph) {

	bool ret = false;
	sdo_byte_array_t *enc_ph = NULL;

	// create temporary SDOW, use it to create Protected header map and then clear it.
	sdow_t temp_sdow;
	if (!sdow_init(&temp_sdow) || !sdo_block_alloc(&temp_sdow.b) ||
		!sdow_encoder_init(&temp_sdow)) {
		LOG(LOG_ERROR, "COSE Protected header: SDOW Initialization/Allocation failed!\n");
		goto end;
	}

	if (!sdow_start_map(&temp_sdow, 1)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to write start map\n");
		goto end;
	}

	if (!sdow_signed_int(&temp_sdow, FDO_COSE_ALG_KEY)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to write CoseAlg Key\n");
		goto end;
	}

	if (!sdow_signed_int(&temp_sdow, cose_ph->ph_sig_alg)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to write CoseAlg Value\n");
		goto end;
	}

	if (!sdow_end_map(&temp_sdow)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to write end map\n");
		goto end;
	}

	size_t enc_ph_length = 0;
	if (!sdow_encoded_length(&temp_sdow, &enc_ph_length) || enc_ph_length == 0) {
		LOG(LOG_ERROR, "COSE Protected header:: Failed to find encoded length\n");
		goto end;
	}
	temp_sdow.b.block_size = enc_ph_length;
	// Set the encoded payload into buffer
	enc_ph =
		sdo_byte_array_alloc_with_byte_array(temp_sdow.b.block, temp_sdow.b.block_size);
	if (!enc_ph) {
		LOG(LOG_ERROR, "COSE Protected header: Failed to alloc for encoded Protected header\n");
		goto end;
	}

	// finally, wrap the protected header into a bstr
	if (!sdow_byte_string(sdow, enc_ph->bytes, enc_ph->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to write Protected header as bstr\n");
		goto end;
	}
	ret = true;
end:
	sdow_flush(&temp_sdow);
	sdo_free(temp_sdow.b.block);
	if (enc_ph)
		sdo_byte_array_free(enc_ph);
	return ret;
}

/**
 * Create COSESignature.COSEUnprotectedHeaders (CBOR empty Map)
 * as CBOR bytes using the given contents.
 *
 * Return true, if write was a success. False otherwise.
 */
bool fdo_cose_write_unprotected_header(sdow_t *sdow) {
	// empty map for now
	if (!sdow_start_map(sdow, 0)) {
		LOG(LOG_ERROR,
			"COSE Unprotected header: Failed to write start map\n");
		return false;
	}

	if (!sdow_end_map(sdow)) {
		LOG(LOG_ERROR,
			"COSE Unprotected header: Failed to write end map\n");
		return false;
	}
	return true;
}

/**
 * Write a COSESignature (COSE_Sign1) object by CBOR encoding the contents of the given cose object.
 * [
 * protected header,
 * unprotected header,
 * payload,				// bstr
 * signature			// bstr
 * ]
 * @param sdow - sdow_t object containing the buffer where CBOR data will be written
 * @param cose - fdo_cose_t object that holds the COSE_Sign1 parameters to encode
 * @return true, if write was a success. False otherwise.
 */
bool fdo_cose_write(sdow_t *sdow, fdo_cose_t *cose) {
	if (!sdow_start_array(sdow, 4)) {
		LOG(LOG_ERROR, "COSE: Failed to write start array\n");
		return false;
	}

	if (!fdo_cose_write_protected_header(sdow, cose->cose_ph)) {
		LOG(LOG_ERROR, "COSE: Failed to write protected header\n");
		return false;
	}

	if (!fdo_cose_write_unprotected_header(sdow)) {
		LOG(LOG_ERROR, "COSE: Failed to write unprotected header\n");
		return false;
	}

	if (!sdow_byte_string(sdow, cose->cose_payload->bytes, cose->cose_payload->byte_sz)) {
		LOG(LOG_ERROR, "COSE: Failed to write payload\n");
		return false;
	}

	if (!sdow_byte_string(sdow, cose->cose_signature->bytes, cose->cose_signature->byte_sz)) {
		LOG(LOG_ERROR, "COSE: Failed to write signature\n");
		return false;
	}

	if (!sdow_end_array(sdow)) {
		LOG(LOG_ERROR, "COSE: Failed to write end array\n");
		return false;
	}
	return true;
}

/**
 * Free the given COSE_Mac0 object for which memory has been allocated previously.
 */
bool fdo_cose_mac0_free(fdo_cose_mac0_t *cose_mac0) {
	if (cose_mac0->protected_header) {
		cose_mac0->protected_header->mac_type = 0;
		sdo_free(cose_mac0->protected_header);
	}
	if (cose_mac0->payload) {
		sdo_byte_array_free(cose_mac0->payload);
	}
	if (cose_mac0->hmac) {
		sdo_byte_array_free(cose_mac0->hmac);
	}
	sdo_free(cose_mac0);
	return true;
}

/**
 * Read Cose_Mac0.protected (CBOR map) into the given fdo_cose_mac0_protected_header_t object.
 * This is wrapped in a bstr.
 * {
 * mac_type:<key-alg>
 * }
 * Return true, if read was a success. False otherwise.
 */
bool fdo_cose_mac0_read_protected_header(sdor_t *sdor,
	fdo_cose_mac0_protected_header_t *protected_header) {

	sdor_t temp_sdor;

	size_t var_length = 0;
	if (!sdor_string_length(sdor, &var_length) ||
		var_length == 0) {
		LOG(LOG_ERROR, "COSE_Mac0 Protected header: Failed to read payload length\n");
		return false;	
	}
	sdo_byte_array_t *ph_as_bstr = sdo_byte_array_alloc(var_length);
	if (!ph_as_bstr) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to alloc for COSE_Mac0 Protected Header as bstr\n");
		return false;
	}
	if (!sdor_byte_string(sdor, ph_as_bstr->bytes, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to read COSE_Mac0 Protected Header as bstr\n");
		goto end;
	}

	// create a temporary SDOR to read (unwrap) the header contents as map
	if (!sdor_init(&temp_sdor) ||
		!sdo_block_alloc_with_size(&temp_sdor.b, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to setup temporary SDOR\n");
		goto end;
	}

	if (0 != memcpy_s(temp_sdor.b.block, temp_sdor.b.block_size,
		ph_as_bstr->bytes, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to copy temporary unwrapped Header content\n");
		goto end;
	}

	if (!sdor_parser_init(&temp_sdor)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to init temporary SDOR parser\n");
		goto end;
	}

	if (!sdor_start_map(&temp_sdor)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to read start map\n");
		goto end;
	}

	int mac_type_key = 1;
	if (!sdor_signed_int(&temp_sdor, &mac_type_key) || mac_type_key != 1) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to read ETMMacType Key\n");
		goto end;
	}

	if (!sdor_signed_int(&temp_sdor, &protected_header->mac_type)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to read ETMMacType Value\n");
		goto end;
	}

	if (!sdor_end_map(&temp_sdor)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to read end map\n");
		goto end;
	}
end:
	sdor_flush(&temp_sdor);
	sdo_free(temp_sdor.b.block);
	if (ph_as_bstr)
		sdo_byte_array_free(ph_as_bstr);
	return true;
}

/**
 * Read Cose_Mac0.unprotected that is an empty map.
 * Return true, if read was a success. False otherwise.
 */
bool fdo_cose_mac0_read_unprotected_header(sdor_t *sdor) {

	if (!sdor_start_map(sdor)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Unprotected header: Failed to read start map\n");
		return false;
	}

	if (!sdor_end_map(sdor)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Unprotected header: Failed to read end map\n");
		return false;
	}
	return true;
}

/**
 * Read the given COSE_Mac0 into the fdo_cose_mac0_t parameter.
 * The fdo_cose_mac0_t parameter should have memory pre-allocated.
 * However, the internal elements must be un-allocated.
 * The memory allocation for the same would be done in the method.
 * [
 * protected header,
 * unprotected header,
 * payload,				// bstr
 * hmac					// bstr
 * ]
 * @param sdor - sdor_t object containing the buffer to read
 * @param cose_mac0 - fdo_cose_mac0_t object that will hold the read COSE_Mac0 parameters
 * @return true, if read was a success. False otherwise.
 */
bool fdo_cose_mac0_read(sdor_t *sdor, fdo_cose_mac0_t *cose_mac0) {

	size_t num_items = 4;
	if (!sdor_array_length(sdor, &num_items) || num_items != 4) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to read/Invalid array length\n");
		return false;		
	}

	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to read start array\n");
		return false;
	}

	cose_mac0->protected_header = sdo_alloc(sizeof(fdo_cose_mac0_protected_header_t));
	if (!cose_mac0->protected_header) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to alloc Protected Header\n");
		goto end;
	}
	if (!fdo_cose_mac0_read_protected_header(sdor, cose_mac0->protected_header)) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to read protected header\n");
		goto end;
	}

	if (!fdo_cose_mac0_read_unprotected_header(sdor)) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to read unprotected header\n");
		goto end;
	}

	size_t var_length = 0;
	if (!sdor_string_length(sdor, &var_length) ||
		var_length == 0) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to read payload length\n");
		goto end;	
	}
	cose_mac0->payload = sdo_byte_array_alloc(var_length);
	if (!cose_mac0->payload) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to alloc ETMPayloadTag\n");
		goto end;
	}
	if (!sdor_byte_string(sdor, cose_mac0->payload->bytes, cose_mac0->payload->byte_sz)) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to read payload\n");
		goto end;
	}

	var_length = 0;
	if (!sdor_string_length(sdor, &var_length) ||
		var_length == 0) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to read hmac bstr length\n");
		goto end;	
	}
	cose_mac0->hmac = sdo_byte_array_alloc(var_length);
	if (!cose_mac0->hmac) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to alloc hmac\n");
		goto end;
	}
	if (!sdor_byte_string(sdor, cose_mac0->hmac->bytes, cose_mac0->hmac->byte_sz)) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to read signature\n");
		goto end;
	}

	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to read end array\n");
		goto end;
	}
	return true;

end:
	fdo_cose_mac0_free(cose_mac0);
	return false;
}

/**
 * Write Cose_Mac0.protected (CBOR map) as given in the fdo_cose_mac0_protected_header_t object.
 * This is wrapped in a bstr.
 * {
 * mac_type:<key-alg>
 * }
 * Return true, if write was a success. False otherwise.
 */
bool fdo_cose_mac0_write_protected_header(sdow_t *sdow,
	fdo_cose_mac0_protected_header_t *protected_header) {

	bool ret = false;
	sdo_byte_array_t *enc_ph = NULL;

	// create temporary SDOW, use it to create Protected header map and then clear it.
	sdow_t temp_sdow;
	if (!sdow_init(&temp_sdow) || !sdo_block_alloc(&temp_sdow.b) ||
		!sdow_encoder_init(&temp_sdow)) {
		LOG(LOG_ERROR, "COSE_Mac0 Protected header: SDOW Initialization/Allocation failed!\n");
		goto end;
	}

	if (!sdow_start_map(&temp_sdow, 1)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to write start map\n");
		goto end;
	}

	if (!sdow_signed_int(&temp_sdow, FDO_COSE_ALG_KEY)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to write CoseAlg Key\n");
		goto end;
	}

	if (!sdow_signed_int(&temp_sdow, protected_header->mac_type)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to write ETMMacType Value\n");
		goto end;
	}

	if (!sdow_end_map(&temp_sdow)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to write end map\n");
		goto end;
	}

	size_t enc_ph_length = 0;
	if (!sdow_encoded_length(&temp_sdow, &enc_ph_length) || enc_ph_length == 0) {
		LOG(LOG_ERROR, "COSE_Mac0 Protected header:: Failed to find encoded length\n");
		goto end;
	}
	temp_sdow.b.block_size = enc_ph_length;
	// Set the encoded payload into buffer
	enc_ph =
		sdo_byte_array_alloc_with_byte_array(temp_sdow.b.block, temp_sdow.b.block_size);
	if (!enc_ph) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to alloc for encoded Protected header\n");
		goto end;
	}

	// finally, wrap the protected header into a bstr
	if (!sdow_byte_string(sdow, enc_ph->bytes, enc_ph->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Protected header: Failed to write Protected header as bstr\n");
		goto end;
	}
	ret = true;
end:
	sdow_flush(&temp_sdow);
	sdo_free(temp_sdow.b.block);
	if (enc_ph)
		sdo_byte_array_free(enc_ph);
	return ret;
}

/**
 * Write Cose_Mac0.unprotected that is an empty map.
 * Return true, if write was a success. False otherwise.
 */
bool fdo_cose_mac0_write_unprotected_header(sdow_t *sdow) {
	// empty map
	if (!sdow_start_map(sdow, 0)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Unprotected header: Failed to write start map\n");
		return false;
	}

	if (!sdow_end_map(sdow)) {
		LOG(LOG_ERROR,
			"COSE_Mac0 Unprotected header: Failed to write end map\n");
		return false;
	}
	return true;
}

/**
 * Write the given fdo_cose_mac0_t parameter into COSE_Mac0 structure
 * [
 * protected header,
 * unprotected header,
 * payload,				// bstr
 * hmac					// bstr
 * ]
 * @param sdow - sdow_t object containing the buffer where CBOR data will be written
 * @param cose_mac0 - fdo_cose_mac0_t object that holds the COSE_Mac0 parameters to encode
 * @return true, if write was a success. False otherwise.
 */
bool fdo_cose_mac0_write(sdow_t *sdow, fdo_cose_mac0_t *cose_mac0) {
	if (!sdow_start_array(sdow, 4)) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to write start array\n");
		return false;
	}

	if (!fdo_cose_mac0_write_protected_header(sdow, cose_mac0->protected_header)) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to write protected header\n");
		return false;
	}

	if (!fdo_cose_mac0_write_unprotected_header(sdow)) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to write unprotected header\n");
		return false;
	}

	if (!sdow_byte_string(sdow, cose_mac0->payload->bytes, cose_mac0->payload->byte_sz)) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to write payload\n");
		return false;
	}

	if (!sdow_byte_string(sdow, cose_mac0->hmac->bytes, cose_mac0->hmac->byte_sz)) {
		LOG(LOG_ERROR, "COSE_Mac0: Failed to write hmac\n");
		return false;
	}

	if (!sdow_end_array(sdow)) {
		LOG(LOG_ERROR, "COSE: Failed to write end array\n");
		return false;
	}
	return true;
}

/**
 * Free the given COSE_Encrypt0 object for which memory has been allocated previously.
 */
bool fdo_cose_encrypt0_free(fdo_cose_encrypt0_t *cose_encrypt0) {
	if (cose_encrypt0->protected_header) {
		cose_encrypt0->protected_header->aes_plain_type = 0;
		sdo_free(cose_encrypt0->protected_header);
	}
	if (cose_encrypt0->unprotected_header) {
		// do memset to 0 here.
		sdo_free(cose_encrypt0->unprotected_header);
	}
	if (cose_encrypt0->payload) {
		sdo_byte_array_free(cose_encrypt0->payload);
	}

	sdo_free(cose_encrypt0);
	cose_encrypt0 = NULL;
	return true;
}

/**
 * Allocate memory and return an object of fdo_cose_encrypt0_t type.
 * Memory is only allocated for protected and unprotected headers.
 * Payload is set to NULL, and should be allocated when needed.
 * 
 * return allocated fdo_cose_encrypt0_t object.
 */
fdo_cose_encrypt0_t* fdo_cose_encrypt0_alloc(void) {
	fdo_cose_encrypt0_t *cose_encrypt0 = sdo_alloc(sizeof(fdo_cose_encrypt0_t));
	if (!cose_encrypt0) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc\n");
		goto err;
	}
	cose_encrypt0->protected_header = sdo_alloc(sizeof(fdo_cose_encrypt0_protected_header_t));
	if (!cose_encrypt0->protected_header) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc Protected Header\n");
		goto err;
	}

	cose_encrypt0->unprotected_header = sdo_alloc(sizeof(fdo_cose_encrypt0_unprotected_header_t));
	if (!cose_encrypt0->unprotected_header) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc Unprotected header\n");
		goto err;
	}

	// set the payload to NULL because of the way we use it.
	cose_encrypt0->payload = NULL;

	return cose_encrypt0;
err:
	if (cose_encrypt0)
		fdo_cose_encrypt0_free(cose_encrypt0);
	return NULL;
}

/**
 * Read Cose_Encrypt0.protected (CBOR map) into the given
 * fdo_cose_encrypt0_protected_header_t object. This is wrapped in a bstr.
 * {
 * aes_plain_type:<key-alg>
 * }
 * Return true, if read was a success. False otherwise.
 */
bool fdo_cose_encrypt0_read_protected_header(sdor_t *sdor,
	fdo_cose_encrypt0_protected_header_t *protected_header) {

	bool ret = false;
	sdor_t temp_sdor;

	size_t var_length = 0;
	if (!sdor_string_length(sdor, &var_length) ||
		var_length == 0) {
		LOG(LOG_ERROR, "COSE_Encrypt0 Protected header: Failed to read length\n");
		return false;	
	}
	sdo_byte_array_t *ph_as_bstr = sdo_byte_array_alloc(var_length);
	if (!ph_as_bstr) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to alloc for bstr\n");
		return false;
	}
	if (!sdor_byte_string(sdor, ph_as_bstr->bytes, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to read as bstr\n");
		goto end;
	}

	// create a temporary SDOR to read (unwrap) the header contents as map
	if (!sdor_init(&temp_sdor) ||
		!sdo_block_alloc_with_size(&temp_sdor.b, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to setup temporary SDOR\n");
		goto end;
	}

	if (0 != memcpy_s(temp_sdor.b.block, temp_sdor.b.block_size,
		ph_as_bstr->bytes, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to copy temporary unwrapped Header content\n");
		goto end;
	}

	if (!sdor_parser_init(&temp_sdor)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to init temporary SDOR parser\n");
		goto end;
	}

	if (!sdor_start_map(&temp_sdor)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to read start map\n");
		goto end;
	}

	int cose_aesplaintype_key = 0;
	if (!sdor_signed_int(&temp_sdor, &cose_aesplaintype_key) ||
		cose_aesplaintype_key != FDO_COSE_ENCRYPT0_AESPLAINTYPE_KEY) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to read AESPlainType Key\n");
		goto end;
	}

	if (!sdor_signed_int(&temp_sdor, &protected_header->aes_plain_type)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to read AESPlainType Value\n");
		goto end;
	}

	if (!sdor_end_map(&temp_sdor)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to read end map\n");
		goto end;
	}
	ret = true;
end:
	sdor_flush(&temp_sdor);
	sdo_free(temp_sdor.b.block);
	if (ph_as_bstr)
		sdo_byte_array_free(ph_as_bstr);
	return ret;
}

/**
 * Read Cose_Encrypt0.unprotected (CBOR map) into the given
 * fdo_cose_encrypt0_unprotected_header_t object.
 * {
 * aes_iv:<IV-16-bytes>
 * }
 * Return true, if read was a success. False otherwise.
 */
bool fdo_cose_encrypt0_read_unprotected_header(sdor_t *sdor,
	fdo_cose_encrypt0_unprotected_header_t *unprotected_header) {
	if (!sdor_start_map(sdor)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to read start map\n");
		return false;
	}

	int cose_aesiv_key = 0;
	if (!sdor_signed_int(sdor, &cose_aesiv_key) ||
		cose_aesiv_key != FDO_COSE_ENCRYPT0_AESIV_KEY) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to read AESIV Key\n");
		return false;
	}

	size_t cose_aesiv_value_length = 0;
	if (!sdor_string_length(sdor, &cose_aesiv_value_length) ||
		cose_aesiv_value_length != sizeof(unprotected_header->aes_iv)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to read AESIV Value\n");
		return false;
	}
	if (!sdor_byte_string(sdor, unprotected_header->aes_iv,
		sizeof(unprotected_header->aes_iv))) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to read AESIV Value\n");
		return false;
	}

	if (!sdor_end_map(sdor)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to read end map\n");
		return false;
	}
	return true;
}

/**
 * Read the given COSE_Encrypt0 into the fdo_cose_encrypt0_t parameter.
 * The fdo_cose_encrypt0_t parameter should have memory pre-allocated.
 * However, the internal elements must be un-allocated.
 * The memory allocation for the same would be done in the method.
 * [
 * protected header,
 * unprotected header,
 * payload,				// bstr
 * ]
 * @param sdor - sdor_t object containing the buffer to read
 * @param cose_encrypt0 - fdo_cose_encrypt0_t object that will hold the read COSE_Encrypt0
 * parameters
 * @return true, if read was a success. False otherwise.
 */
bool fdo_cose_encrypt0_read(sdor_t *sdor, fdo_cose_encrypt0_t *cose_encrypt0) {
	size_t num_cose_items = 3;
	if (!sdor_array_length(sdor, &num_cose_items) || num_cose_items != 3) {
		LOG(LOG_ERROR, "COSE: Failed to read/Invalid array length\n");
		return false;		
	}

	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to read start array\n");
		return false;
	}

	cose_encrypt0->protected_header = sdo_alloc(sizeof(fdo_cose_encrypt0_protected_header_t));
	if (!cose_encrypt0->protected_header) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc Protected Header\n");
		goto end;
	}
	if (!fdo_cose_encrypt0_read_protected_header(sdor, cose_encrypt0->protected_header)) {
		LOG(LOG_ERROR, "COSE: Failed to read protected header\n");
		goto end;
	}

	cose_encrypt0->unprotected_header = sdo_alloc(sizeof(fdo_cose_encrypt0_unprotected_header_t));
	if (!cose_encrypt0->unprotected_header) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc Unprotected Header\n");
		goto end;
	}
	if (!fdo_cose_encrypt0_read_unprotected_header(sdor, cose_encrypt0->unprotected_header)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to read Unprotected header\n");
		goto end;
	}

	size_t payload_length = 0;
	if (!sdor_string_length(sdor, &payload_length) ||
		payload_length == 0) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to read EATpayload length\n");
		goto end;	
	}
	cose_encrypt0->payload = sdo_byte_array_alloc(payload_length);
	if (!cose_encrypt0->payload) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc EATPayload\n");
		goto end;
	}
	if (!sdor_byte_string(sdor, cose_encrypt0->payload->bytes, cose_encrypt0->payload->byte_sz)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to read EATpayload\n");
		goto end;
	}

	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to read end array\n");
		goto end;
	}
	return true;

end:
	fdo_cose_encrypt0_free(cose_encrypt0);
	return false;
}

/**
 * Write the given fdo_cose_encrypt0_protected_header_t object into CBOR encoded
 * Cose_Encrypt0.protected (CBOR map), wrapped in a bstr.
 * {
 * aes_plain_type:<key-alg>
 * }
 * Return true, if write was a success. False otherwise.
 */
bool fdo_cose_encrypt0_write_protected_header(sdow_t *sdow,
	fdo_cose_encrypt0_protected_header_t *protected_header) {

	bool ret = false;
	sdo_byte_array_t *enc_ph = NULL;

	// create temporary SDOW, use it to create Protected header map and then clear it.
	sdow_t temp_sdow;
	if (!sdow_init(&temp_sdow) || !sdo_block_alloc(&temp_sdow.b) ||
		!sdow_encoder_init(&temp_sdow)) {
		LOG(LOG_ERROR, "COSE Protected header: SDOW Initialization/Allocation failed!\n");
		goto end;
	}

	if (!sdow_start_map(&temp_sdow, 1)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to write start map\n");
		goto end;
	}

	if (!sdow_signed_int(&temp_sdow, FDO_COSE_ENCRYPT0_AESPLAINTYPE_KEY)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to write AESPlainType Key\n");
		goto end;
	}

	if (!sdow_signed_int(&temp_sdow, protected_header->aes_plain_type)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to write AESPlainType Value\n");
		goto end;
	}

	if (!sdow_end_map(&temp_sdow)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to write end map\n");
		goto end;
	}

	size_t enc_ph_length = 0;
	if (!sdow_encoded_length(&temp_sdow, &enc_ph_length) || enc_ph_length == 0) {
		LOG(LOG_ERROR, "COSE_Encrypt0 Protected header:: Failed to find encoded length\n");
		goto end;
	}
	temp_sdow.b.block_size = enc_ph_length;
	// Set the encoded payload into buffer
	enc_ph =
		sdo_byte_array_alloc_with_byte_array(temp_sdow.b.block, temp_sdow.b.block_size);
	if (!enc_ph) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to alloc for encoded Protected header\n");
		goto end;
	}

	// finally, wrap the protected header into a bstr
	if (!sdow_byte_string(sdow, enc_ph->bytes, enc_ph->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to write Protected header as bstr\n");
		goto end;
	}
	ret = true;
end:
	sdow_flush(&temp_sdow);
	sdo_free(temp_sdow.b.block);
	if (enc_ph)
		sdo_byte_array_free(enc_ph);
	return ret;
}

/**
 * Write the given fdo_cose_encrypt0_unprotected_header_t object into
 * CBOR encoded Cose_Encrypt0.unprotected (CBOR map).
 * {
 * aes_iv:<IV-16-bytes>
 * }
 * Return true, if write was a success. False otherwise.
 */
bool fdo_cose_encrypt0_write_unprotected_header(sdow_t *sdow,
	fdo_cose_encrypt0_unprotected_header_t *unprotected_header) {
	if (!sdow_start_map(sdow, 1)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to write start map\n");
		return false;
	}

	if (!sdow_signed_int(sdow, FDO_COSE_ENCRYPT0_AESIV_KEY)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to write AESIV Key\n");
		return false;
	}

	if (!sdow_byte_string(sdow, unprotected_header->aes_iv,
		sizeof(unprotected_header->aes_iv))) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to write AESIV Value\n");
		return false;
	}

	if (!sdow_end_map(sdow)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to write end map\n");
		return false;
	}
	return true;
}

/**
 * Write the given fdo_cose_encrypt0_t parameter into CBOR encoded COSE_Encrypt0.
 * [
 * protected header,
 * unprotected header,
 * payload,				// bstr
 * ]
 * @param sdow - sdow_t object holding the buffer where CBOR data will be written to
 * @param cose_encrypt0 - fdo_cose_encrypt0_t object that holds the COSE_Encrypt0 parameters to
 * encode
 * @return true, if write was a success. False otherwise.
 */
bool fdo_cose_encrypt0_write(sdow_t *sdow, fdo_cose_encrypt0_t *cose_encrypt0) {
	if (!sdow_start_array(sdow, 3)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to write start array\n");
		return false;
	}

	if (!fdo_cose_encrypt0_write_protected_header(sdow, cose_encrypt0->protected_header)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to write protected header\n");
		return false;
	}

	if (!fdo_cose_encrypt0_write_unprotected_header(sdow, cose_encrypt0->unprotected_header)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to write unprotected header\n");
		return false;
	}

	if (!sdow_byte_string(sdow, cose_encrypt0->payload->bytes, cose_encrypt0->payload->byte_sz)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to write payload\n");
		return false;
	}

	if (!sdow_end_array(sdow)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to write end array\n");
		return false;
	}
	return true;
}

/**
 * Free the given RVTO2AddrEntry object for which memory has been allocated previously.
 */
void fdo_rvto2addr_entry_free(fdo_rvto2addr_entry_t *rvto2addr_entry) {
	if (rvto2addr_entry->rvip)
		sdo_byte_array_free(rvto2addr_entry->rvip);
	if (rvto2addr_entry->rvdns)
		sdo_string_free(rvto2addr_entry->rvdns);
	sdo_free(rvto2addr_entry);	
}

/**
 * Free the given RVTO2Addr object for which memory has been allocated previously.
 */
void fdo_rvto2addr_free(fdo_rvto2addr_t *rvto2addr) {
	if (rvto2addr) {
		while (rvto2addr->rv_to2addr_entry) {
			fdo_rvto2addr_entry_t *rv_to2addr_entry = rvto2addr->rv_to2addr_entry;
			rvto2addr->rv_to2addr_entry =
				(fdo_rvto2addr_entry_t *) rvto2addr->rv_to2addr_entry->next;
			fdo_rvto2addr_entry_free(rv_to2addr_entry);
		}
		sdo_free(rvto2addr);
	}
}

/**
 * Read RVTO2AddrEntry into the given fdo_rvto2addr_entry_t object.
 * Memory allocation for the internal elements of fdo_rvto2addr_entry_t object
 * will be done in this method.
 * However, the memory must be allocated for fdo_rvto2addr_entry_t object and
 * given to this method.
 * [
 * RVIP,
 * RVDNS,
 * RVPort,
 * RVProtocol
 * ]
 * @param sdor - sdor_t object containing the buffer to read
 * @param rvto2addr_entry - fdo_rvto2addr_entry_t object that will hold the read RVTO2AddrEntry
 * parameters
 * @return true, if read was a success. False otherwise.
 */
bool fdo_rvto2addr_entry_read(sdor_t *sdor, fdo_rvto2addr_entry_t *rvto2addr_entry) {
	size_t num_rvto2addr_entry_items = 0;
	if (!sdor_array_length(sdor, &num_rvto2addr_entry_items) ||
		num_rvto2addr_entry_items != 4) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read/Invalid array length\n");
		return false;
	}

	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read start array\n");
		return false;		
	}
	size_t rvip_length = 0;
	if (!sdor_string_length(sdor, &rvip_length) || rvip_length == 0) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVIP length\n");
		return false;
	}
	rvto2addr_entry->rvip = sdo_byte_array_alloc(rvip_length);
	if (!rvto2addr_entry->rvip) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to alloc RVIP\n");
		return false;
	}
	if (!sdor_byte_string(sdor, rvto2addr_entry->rvip->bytes, rvto2addr_entry->rvip->byte_sz)) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVIP\n");
		return false;
	}

	size_t rvdns_length = 0;
	if (!sdor_string_length(sdor, &rvdns_length) || rvdns_length == 0) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVDNS length\n");
		return false;
	}
	rvto2addr_entry->rvdns = sdo_string_alloc_size(rvdns_length);
	if (!rvto2addr_entry->rvdns) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to alloc RVDNS\n");
		return false;
	}
	
	if (!sdor_text_string(sdor, rvto2addr_entry->rvdns->bytes, rvdns_length)) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVDNS\n");
		return false;
	}
	rvto2addr_entry->rvdns->bytes[rvdns_length] = '\0';

	rvto2addr_entry->rvport = -1;
	if (!sdor_signed_int(sdor, &rvto2addr_entry->rvport) ||
		rvto2addr_entry->rvport == -1) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVPort\n");
		return false;
	}

	rvto2addr_entry->rvprotocol = -1;
	if (!sdor_signed_int(sdor, &rvto2addr_entry->rvprotocol) ||
		rvto2addr_entry->rvprotocol == -1) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVProtocol\n");
		return false;
	}

	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read end array\n");
		goto end;
	}
	return true;
end:
	fdo_rvto2addr_entry_free(rvto2addr_entry);
	return false;
}

/**
 * Read RVTO2Addr into the given fdo_rvto2addr_t object.
 * Memory allocation for the internal elements of fdo_rvto2addr_t object
 * will be done in this method.
 * However, the memory must be allocated for fdo_rvto2addr_y_t object and
 * given to this method.
 * [
 * +RVTO2AddrEntry 		// one or more RVTO2AddrEntry
 * ]
 * @param sdor - sdor_t object containing the buffer to read
 * @param rvto2addr - fdo_rvto2addr_t object that will hold the read RVTO2Addr parameters
 * @return true, if read was a success. False otherwise.
 */
bool fdo_rvto2addr_read(sdor_t *sdor, fdo_rvto2addr_t *rvto2addr) {
	size_t num_rvto2addr_items = 0;
	if (!sdor_array_length(sdor, &num_rvto2addr_items) || num_rvto2addr_items == 0) {
		LOG(LOG_ERROR, "RVTO2Addr: Failed to read/Invalid array length\n");
		return false;
	}

	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR, "RVTO2Addr: Failed to read/Invalid array length\n");
		return false;
	}

	LOG(LOG_DEBUG, "RVTO2Addr: There are %zu RVTO2AddrEntry(s)\n", num_rvto2addr_items);

	rvto2addr->num_rvto2addr = num_rvto2addr_items;
	rvto2addr->rv_to2addr_entry = sdo_alloc(sizeof(fdo_rvto2addr_entry_t));
	if (!rvto2addr->rv_to2addr_entry) {
		LOG(LOG_ERROR, "RVTO2Addr: Failed to alloc RVTO2AddrEntry\n");
		return false;	
	}
	fdo_rvto2addr_entry_t *entry = rvto2addr->rv_to2addr_entry;
	size_t i = 0;
	for (;;) {

		i++;
		if (!fdo_rvto2addr_entry_read(sdor, entry)) {
			LOG(LOG_ERROR, "RVTO2Addr: Failed to read RVTO2AddrEntry\n");
			goto end;
		}
		if (i < num_rvto2addr_items) {
			entry->next = sdo_alloc(sizeof(fdo_rvto2addr_entry_t));
			if (!entry->next) {
				LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read/Invalid array length\n");
				goto end;
			}
			entry = entry->next;
		} else {
			break;
		}
	}
	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR, "RVTO2Addr: Failed to read end array\n");
		goto end;
	}
	return true;

end:
	fdo_rvto2addr_free(rvto2addr);
	return false;
}

/**
 * Verifies the ECDSA Signature using provided public key pk.
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

		kv->str_val = sdo_string_alloc_with(val, val_len);
		if (kv->key == NULL || kv->str_val == NULL) {
			sdo_kv_free(kv);
			kv = NULL;
		}
	}
	return kv;
}

/**
 * Allocate and initialize the key
 * @param key - pointer to the key
 * @return pointer to the allocated key if success else NULL.
 */
sdo_key_value_t *sdo_kv_alloc_key_only(const char *key)
{
	if (!key)
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
		if (kv->key == NULL) {
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
	if (kv->str_val != NULL)
		sdo_string_free(kv->str_val);
	if (kv->bin_val != NULL)
		sdo_byte_array_free(kv->bin_val);
	if (kv->bool_val != NULL)
		sdo_free(kv->bool_val);
	if (kv->int_val != NULL)
		sdo_free(kv->int_val);
	sdo_free(kv);
}

//----------------------------------------------------------------------
// Service_info handling
//

/**
 * Read the CBOR encoded ServiceInfo struct.
 * ServiceInfo = [
 *   *ServiceInfoKeyVal		// one or more ServiceInfoKeyVal
 * ]
 * ServiceInfoKeyVal = [
 *   *ServiceInfoKV			// one or more ServiceInfoKV
 * ]
 * ServiceInfoKV = [
 *   ServiceInfoKey: tstr,
 *   ServiceInfoVal: cborSimpleType
 * ]
 * ServiceInfoKey = moduleName:messageName
 * @param sdor - sdor_t object containing the buffer to read
 * @param module_list - Owner ServiceInfo module list
 * @param cb_return_val - out value to hold the return value from the registered modules.
 * @return true if read was a success, false otherwise
 */
bool fdo_serviceinfo_read(sdor_t *sdor, sdo_sdk_service_info_module_list_t *module_list,
		int *cb_return_val) {

	char *serviceinfokey = NULL;
	char module_name[SDO_MODULE_NAME_LEN];
	char module_message[SDO_MODULE_MSG_LEN];

	size_t num_serviceinfo = 0;
	if (!sdor_array_length(sdor, &num_serviceinfo)) {
		LOG(LOG_ERROR, "ServiceInfo read: Failed to find number of items\n");
		goto exit;
	}
	if (!sdor_start_array(sdor)) {
		LOG(LOG_ERROR, "ServiceInfo read: Failed to start array\n");
		goto exit;
	}
	size_t i;
	for (i = 0; i < num_serviceinfo; i++) {
		size_t num_serviceinfokeyval = 0;
		if (!sdor_array_length(sdor, &num_serviceinfokeyval)) {
				LOG(LOG_ERROR, "ServiceInfoKeyVal read: Failed to find number of items\n");
				goto exit;
		}
		if (!sdor_start_array(sdor)) {
			LOG(LOG_ERROR, "ServiceInfoKeyVal read: Failed to start array\n");
			return false;
		}
		size_t j;
		for (j = 0; j < num_serviceinfokeyval; j++) {
			size_t num_serviceinfokv = 0;
			if (!sdor_array_length(sdor, &num_serviceinfokv) &&
				num_serviceinfokv != 2) {
				LOG(LOG_ERROR, "ServiceInfoKV read: Failed to find number of items\n");
				goto exit;
			}
			if (!sdor_start_array(sdor)) {
				LOG(LOG_ERROR, "ServiceInfoKV read: Failed to start array\n");
				goto exit;
			}

			size_t serviceinfokey_length = 0;
			if (!sdor_string_length(sdor, &serviceinfokey_length)) {
				LOG(LOG_ERROR, "ServiceInfoKV read: Failed to read ServiceInfoKey length\n");
				goto exit;
			}
			serviceinfokey = sdo_alloc(sizeof(char) * serviceinfokey_length);
			if (!serviceinfokey) {
				LOG(LOG_ERROR, "ServiceInfoKV read: Failed to alloc ServiceInfoKey\n");
				goto exit;
			}
			if (!sdor_text_string(sdor, serviceinfokey, serviceinfokey_length)) {
				LOG(LOG_ERROR, "ServiceInfoKV read: Failed to read ServiceInfoKV\n");
				goto exit;
			}

			if (0 != memset_s(&module_name, sizeof(module_name), 0)) {
				LOG(LOG_ERROR, "ServiceInfoKV read: Failed to clear modulename\n");
				goto exit;
			}
			if (0 != memset_s(&module_message, sizeof(module_message), 0)) {
				LOG(LOG_ERROR, "ServiceInfoKV read: Failed to clear modulename\n");
				goto exit;
			}

			// find the index of separator ':' in ServiceInfoKey format of 'moduleName:messageName'
			// copy moduleName:messageName and moduleName:messageName
			size_t index = 0;
			while (':' != serviceinfokey[index]) {
				if (index >= serviceinfokey_length) {
					*cb_return_val = MESSAGE_BODY_ERROR;
					goto exit;
				}

				module_name[index] = serviceinfokey[index];
				++index;
			}
			++index;
			size_t module_name_index = 0;
			while (index < serviceinfokey_length) {
				module_message[module_name_index] = serviceinfokey[index];
				++module_name_index;
				++index;
			}

			if (!fdo_supply_serviceinfoval(sdor, &module_name[0], &module_message[0],
					module_list, cb_return_val)) {
				LOG(LOG_ERROR, "ServiceInfoKV read: Failed to read ServiceInfoVal\n");
				goto exit;
			}

			if (!sdor_end_array(sdor)) {
				LOG(LOG_ERROR, "ServiceInfoKV read: Failed to end array\n");
				goto exit;
			}
			// free the entries for reuse
			sdo_free(serviceinfokey);
		}
		if (!sdor_end_array(sdor)) {
			LOG(LOG_ERROR, "ServiceInfoKeyVal read: Failed to end array\n");
			goto exit;
		}
	}
	if (!sdor_end_array(sdor)) {
		LOG(LOG_ERROR, "ServiceInfo read: Failed to end array\n");
		goto exit;
	}
	return true;
exit:
	if (serviceinfokey) {
		sdo_free(serviceinfokey);
	}
	return false;
}

/**
 * Traverse the Module list to check if the module name is supported and active.
 * If yes, call the registered callback method that processes the ServiceInfoVal
 * within SDOR and return true/false depending on callback's execution.
 * If the module name is not supported, or is not active, skip the ServiceInfoVal
 * and return true.
 * 
 * @param sdor - sdor_t object containing the buffer to read
 * @param module_name - moduleName as received in Owner ServiceInfo
 * @param module_message - messageName as received in Owner ServiceInfo
 * @param module_list - Owner ServiceInfo module list
 * @param cb_return_val - out value to hold the return value from the registered modules.
 * @return true if the operation was a success, false otherwise
 */
bool fdo_supply_serviceinfoval(sdor_t *sdor, char *module_name, char *module_message,
	sdo_sdk_service_info_module_list_t *module_list, int *cb_return_val)
{
	int strcmp_result = 1;
	bool retval = false;
	bool module_name_found = false;
	sdo_sdk_service_info_module_list_t *traverse_list = module_list;

	if (!cb_return_val)
		return retval;

	if (!sdor || !module_name || !module_message) {
		*cb_return_val = SDO_SI_INTERNAL_ERROR;
		return retval;
	}

	while (module_list) {
		strcmp_s(module_list->module.module_name, SDO_MODULE_NAME_LEN,
			 module_name, &strcmp_result);
		if (strcmp_result == 0) {
			// found the module, now check if the message is 'active'
			// if yes, read the value and activate/deactivate the module and return.
			module_name_found = true;
			strcmp_s(module_message, SDO_MODULE_MSG_LEN,
				FDO_MODULE_MESSAGE_ACTIVE, &strcmp_result);
			if (strcmp_result == 0) {
				// TO-DO : PRI sends bool wraped in bstr. Update when PRI is updated.
				size_t active_val_length = 0;
				if (!sdor_string_length(sdor, &active_val_length)) {
					LOG(LOG_ERROR, "ServiceInfoKey: Failed to read module message active length %s\n",
				    	module_list->module.module_name);
					return retval;					
				}
				// to hold 'true' or 'false' as char, hence +1
				uint8_t active_val[active_val_length + 1];
				if (!sdor_byte_string(sdor, &active_val[0], active_val_length)) {
					LOG(LOG_ERROR, "ServiceInfoKey: Failed to read module message active for %s\n",
				    	module_list->module.module_name);
					return retval;
				}
				// null delimeter at last
				active_val[active_val_length] = '\0';
				strcmp_s((char *) &active_val, active_val_length,
			 		"true", &strcmp_result);
				if (strcmp_result == 0) {
					// traverse the list to deactivate every module
					while (traverse_list) {
						traverse_list->module.active = false;
						traverse_list = traverse_list->next;
					}
					// now activate the current module
					module_list->module.active = true;
					LOG(LOG_ERROR, "ServiceInfo: Activated module %s\n",
						module_list->module.module_name);
				}

				retval = true;
				break;
			}
			// if the module is activated by the Owner, only then proceed with processing
			// ServiceInfoVal via callback method
			if (module_list->module.active) {
				// check if module callback is successful
				*cb_return_val = module_list->module.service_info_callback(
					SDO_SI_SET_OSI, sdor, module_message);

				if (*cb_return_val != SDO_SI_SUCCESS) {
					LOG(LOG_ERROR,
						"ServiceInfo: %s's CB Failed for type:%d\n",
						module_list->module.module_name,
						SDO_SI_SET_OSI);
					break;
				}
				retval = true;
			} else {
				LOG(LOG_ERROR, "ServiceInfo: Received ServiceInfo for an inactive module %s\n",
				    module_list->module.module_name);
				// module is present, but is not the active module. skip this ServiceInfoVal
				// TO-DO : Should we throw an error instead?
				sdor_next(sdor);
				retval = true;
			}
			break;
		}
		module_list = module_list->next;
	}
	if (!module_name_found) {
			// module is not present. skip this ServiceInfoVal
			// TO-DO : Should we throw an error instead?
			LOG(LOG_ERROR,
				"ServiceInfo: Received ServiceInfo for an unsupported module %s\n",
			    module_name);
			sdor_next(sdor);
			retval = true;
	}

	return retval;
}

/**
 * Allocate an empty sdo_service_info_t object.
 * @return an allocated sdo_service_info_t object.
 */
sdo_service_info_t *sdo_service_info_alloc(void)
{
	return sdo_alloc(sizeof(sdo_service_info_t));
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
 * if found, update the corresponding si member with string val, if memory
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
	if (kv->str_val == NULL) {
		 /* No allocated string present for value, make a new one */
		kv->str_val = sdo_string_alloc_with_str(val);
	} else {
		int val_len = strnlen_s(val, SDO_MAX_STR_SIZE);

		if (!val_len || val_len == SDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR,
			    "%s(): val "
			    "is either 'NULL' or"
			    "'isn't 'NULL-terminating'\n", __func__);
			sdo_string_free(kv->str_val);
			return false;
		}

		 /* Update the string */
		sdo_string_resize_with(kv->str_val, val_len, val);
	}
	// free other values of other type
	if (kv->bin_val)
		sdo_byte_array_free(kv->bin_val);
	if (kv->int_val)
		sdo_free(kv->int_val);
	if (kv->bool_val)
		sdo_free(kv->bool_val);


	return true;
}

/**
 * si & key are input to the function, it looks for the matching
 * (key, value):
 * if found, update the corresponding si member with byte array val, if memory
 * is not allocated, allocate it.
 * if no matching entry is found, it will add a new entry at the end.
 * @param si  - Pointer to the sdo_service_info_t,
 * @param key - Pointer to the char buffer key,
 * @param val - Pointer to the byte array val, to be updated,
 * @return true if updated correctly else false.
 */
bool sdo_service_info_add_kv_bin(sdo_service_info_t *si, const char *key,
				 const sdo_byte_array_t *val)
{
	sdo_key_value_t **kvp, *kv;

	if (!si || !key || !val)
		return false;

	kvp = sdo_service_info_fetch(si, key);
	kv = *kvp;
	if (kv == NULL) {
		 /* Not found, at end of linked list, add a new entry */
		kv = sdo_kv_alloc_key_only(key);
		if (kv == NULL)
			return false;
		kv->bin_val = sdo_byte_array_alloc_with_byte_array(val->bytes, val->byte_sz);

		*kvp = kv;  /* Use this pointer to update the next value */
		si->numKV++;
		return true;
	}

	 /* Found, free the current and update value */
	if (kv->bin_val) {
		sdo_byte_array_free(kv->bin_val);
	}
	kv->bin_val = sdo_byte_array_alloc_with_byte_array(val->bytes, val->byte_sz);

	// free other values of other type
	if (kv->str_val)
		sdo_string_free(kv->str_val);
	if (kv->int_val)
		sdo_free(kv->int_val);
	if (kv->bool_val)
		sdo_free(kv->bool_val);

	return true;
}

/**
 * si & key are input to the function, it looks for the matching
 * (key, value):
 * if found, update the corresponding si member with boolean val, if memory
 * is not allocated, allocate it.
 * if no matching entry is found, it will add a new entry at the end.
 * @param si  - Pointer to the sdo_service_info_t,
 * @param key - Pointer to the char buffer key,
 * @param val - Pointer to the boolean val, to be updated,
 * @return true if updated correctly else false.
 */
bool sdo_service_info_add_kv_bool(sdo_service_info_t *si, const char *key,
				 bool val)
{
	sdo_key_value_t **kvp, *kv;

	if (!si || !key)
		return false;

	kvp = sdo_service_info_fetch(si, key);
	kv = *kvp;
	if (kv == NULL) {
		 /* Not found, at end of linked list, add a new entry */
		kv = sdo_kv_alloc_key_only(key);
		if (kv == NULL)
			return false;
		kv->bool_val = sdo_alloc(sizeof(bool));
		if (!kv->bool_val) {
			LOG(LOG_ERROR, "Failed to alloc bool Device ServiceInfoVal");
			return false;
		}
		*kv->bool_val = val;
		*kvp = kv;  /* Use this pointer to update the next value */
		si->numKV++;
		return true;
	}

	kv->bool_val = sdo_alloc(sizeof(bool));
	if (!kv->bool_val) {
		LOG(LOG_ERROR, "Failed to alloc bool Device ServiceInfoVal");
		return false;
	}
	*kv->bool_val = val;

	// free any other type of value, if present
	if (kv->str_val)
		sdo_string_free(kv->str_val);
	if (kv->bin_val)
		sdo_byte_array_free(kv->bin_val);
	if (kv->int_val)
		sdo_free(kv->int_val);

	return true;
}

/**
 * si & key are input to the function, it looks for the matching
 * (key, value):
 * if found, update the corresponding si member with integer val, if memory
 * is not allocated, allocate it.
 * if no matching entry is found, it will add a new entry at the end.
 * @param si  - Pointer to the sdo_service_info_t,
 * @param key - Pointer to the char buffer key,
 * @param val - Pointer to the integer val, to be updated,
 * @return true if updated correctly else false.
 */
bool sdo_service_info_add_kv_int(sdo_service_info_t *si, const char *key,
				 int val)
{
	sdo_key_value_t **kvp, *kv;

	if (!si || !key)
		return false;

	kvp = sdo_service_info_fetch(si, key);
	kv = *kvp;
	if (kv == NULL) {
		 /* Not found, at end of linked list, add a new entry */
		kv = sdo_kv_alloc_key_only(key);
		if (kv == NULL)
			return false;
		kv->int_val = sdo_alloc(sizeof(int));
		if (!kv->int_val) {
			LOG(LOG_ERROR, "Failed to alloc int Device ServiceInfoVal");
			return false;
		}
		*kv->int_val = val;
		*kvp = kv;  /* Use this pointer to update the next value */
		si->numKV++;
		return true;
	}

	kv->int_val = sdo_alloc(sizeof(int));
	if (!kv->int_val) {
		LOG(LOG_ERROR, "Failed to alloc int Device ServiceInfoVal");
		return false;
	}
	*kv->int_val = val;

	// free any other type of value, if present
	if (kv->str_val)
		sdo_string_free(kv->str_val);
	if (kv->bin_val)
		sdo_byte_array_free(kv->bin_val);
	if (kv->bool_val)
		sdo_free(kv->bool_val);

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
 * Write the given ServiceInfo struct contents as CBOR.
 * Currently, only used to write 'devmod' Device ServiceInfo module.
 * ServiceInfo = [
 *   *ServiceInfoKeyVal		// one or more ServiceInfoKeyVal
 * ]
 * ServiceInfoKeyVal = [
 *   *ServiceInfoKV			// one or more ServiceInfoKV
 * ]
 * ServiceInfoKV = [
 *   ServiceInfoKey: tstr,
 *   ServiceInfoVal: cborSimpleType
 * ]
 * ServiceInfoKey = moduleName:messageName
 * return true if read was a success, false otherwise
 * 
 * @param sdow - Pointer to the writer.
 * @param si - Pointer to the sdo_service_info_t list containing all platform
 * Device ServiceInfos (only 'devmod' for now).
 * @return true if the opration was a success, false otherwise
 */
bool fdo_serviceinfo_write(sdow_t *sdow, sdo_service_info_t *si)
{
	int num = 0;
	sdo_key_value_t **kvp = NULL;
	sdo_key_value_t *kv = NULL;

	bool ret = false;

	if (!sdow || !si)
		goto end;

	if (!sdow_start_array(sdow, 1)) {
		LOG(LOG_ERROR, "Plaform Device ServiceInfo: Failed to write start array\n");
		goto end;
	}

	if (!sdow_start_array(sdow, si->numKV)) {
		LOG(LOG_ERROR, "Plaform Device ServiceInfoKeyVal: Failed to write start array\n");
		goto end;
	}
	// fetch all platfrom Device ServiceInfo's one-by-one
	while (num != si->numKV) {
		kvp = sdo_service_info_get(si, num);

		kv = *kvp;
		if (!kv || !kv->key) {
			LOG(LOG_ERROR, "Plaform Device ServiceInfo: Key/Value not found\n");
			goto end;
		}

		if (!sdow_start_array(sdow, 2)) {
			LOG(LOG_ERROR, "Plaform Device ServiceInfoKV: Failed to write start array\n");
			goto end;
		}
		// Write KV pair
		if (!sdow_text_string(sdow, kv->key->bytes, kv->key->byte_sz)) {
			LOG(LOG_ERROR, "Plaform Device ServiceInfoKV: Failed to write ServiceInfoKey\n");
			goto end;
		}
		if (kv->str_val) {
			if (!sdow_text_string(sdow, kv->str_val->bytes, kv->str_val->byte_sz)) {
				LOG(LOG_ERROR, "Plaform Device ServiceInfoKV: Failed to write Text ServiceInfoVal\n");
				goto end;
			}
		}
		else if (kv->bin_val) {
			if (!sdow_byte_string(sdow, kv->bin_val->bytes, kv->bin_val->byte_sz)) {
				LOG(LOG_ERROR, "Plaform Device ServiceInfoKV: Failed to write Binary ServiceInfoVal\n");
				goto end;
			}
		}
		else if (kv->bool_val) {
			if (!sdow_boolean(sdow, *kv->bool_val)) {
				LOG(LOG_ERROR, "Plaform Device ServiceInfoKV: Failed to write Bool ServiceInfoVal\n");
				goto end;
			}
		}
		else if (kv->int_val) {
			if (!sdow_signed_int(sdow, *kv->int_val)) {
				LOG(LOG_ERROR, "Plaform Device ServiceInfoKV: Failed to write Int ServiceInfoVal\n");
				goto end;
			}
		} else {
			LOG(LOG_ERROR, "Plaform Device ServiceInfoKV: No ServiceInfoVal found\n");
			goto end;	
		}

		if (!sdow_end_array(sdow)) {
			LOG(LOG_ERROR, "Plaform Device ServiceInfoKV: Failed to write end array\n");
			goto end;
		}
		num++;
	}
	
	if (!sdow_end_array(sdow)) {
		LOG(LOG_ERROR, "Plaform Device ServiceInfoKeyVal: Failed to write end array\n");
		goto end;
	}
	if (!sdow_end_array(sdow)) {
		LOG(LOG_ERROR, "Plaform Device ServiceInfo: Failed to write end array\n");
		goto end;
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

void sdo_log_block(sdo_block_t *sdob) {
	size_t i;
	for (i = 0; i < sdob->block_size; i++) {
		LOG(LOG_INFO, "%02x", sdob->block[i]);
	}
	LOG(LOG_INFO, "\n");
}

