/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of FDO specific data structures parsing/creating APIs.
 */

#include "crypto_utils.h"
#include "fdoprot.h"
#include "fdotypes.h"
#include "network_al.h"
#include "fdoCrypto.h"
#include "util.h"
#include "fdo.h"
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include "safe_lib.h"
#include "snprintf_s.h"
#include "fdodeviceinfo.h"

int keyfromstring(const char *key);

/**
 * Allocate and Initialize the bits
 * @param b - pointer to initialized bits struct
 * @param byte_sz - size of bytes to ve initialized
 * @return bits if initialization in success
 */
fdo_bits_t *fdo_bits_init(fdo_bits_t *b, size_t byte_sz)
{
	if (!b) {
		return NULL;
	}

	if (byte_sz > 0) {
		b->bytes = fdo_alloc(byte_sz * sizeof(uint8_t));
		if (b->bytes == NULL) {
			return NULL;
		}
		b->byte_sz = byte_sz;
		return b;
	}

	if (b->bytes) {
		fdo_free(b->bytes);
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
fdo_bits_t *fdo_bits_alloc(size_t byte_sz)
{
	fdo_bits_t *b = fdo_alloc(sizeof(fdo_bits_t));

	if (b == NULL) {
		return NULL;
	}

	if (byte_sz > 0) {
		return fdo_bits_init(b, byte_sz);
	} else {
		return b;
	}
}

/**
 * Allocate the bits and assing with the data specified
 * @param byte_sz - number of bytes to be allocated
 * @param data - data to be written to the initialized bits
 * @return pointer to bits if success else NULL
 */
fdo_bits_t *fdo_bits_alloc_with(size_t byte_sz, uint8_t *data)
{
	fdo_bits_t *b = fdo_bits_alloc(byte_sz);

	if (b == NULL) {
		return NULL;
	}
	if (!fdo_bits_fill(&b)) {
		fdo_bits_free(b);
		return NULL;
	}
	if (memcpy_s(b->bytes, b->byte_sz, data, b->byte_sz) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		fdo_bits_free(b);
		return NULL;
	}
	return b;
}

/**
 * Free the bits specified
 * @param b - pointer to the struct bits that is to be deallocated
 */
void fdo_bits_free(fdo_bits_t *b)
{
	if (b) {
		fdo_bits_empty(b);
		fdo_free(b);
	}
}

/**
 * Free/Nullify the specified bits
 * @param b - pointer to the struct bits
 */
void fdo_bits_empty(fdo_bits_t *b)
{
	if (!b) {
		return;
	}
	if (b->bytes) {
		if (b->byte_sz && memset_s(b->bytes, b->byte_sz, 0)) {
			LOG(LOG_ERROR, "Failed to clear memory\n");
		}
		fdo_free(b->bytes);
		b->bytes = NULL;
	}
	b->byte_sz = 0;
}

/**
 * Clone the bits to a new struct
 * @param b - pointer to the struct bits which has to be cloned
 * @return pointer to the cloned struct bits if success else NULL
 */
fdo_bits_t *fdo_bits_clone(fdo_bits_t *b)
{
	if (!b) {
		return NULL;
	}
	return fdo_bits_alloc_with(b->byte_sz, b->bytes);
}

/**
 * Resize the struct bits with the specified size
 * @param b - pointer to the struct bits
 * @param byte_sz - resized value of bits
 * @return true if resized else false
 */
bool fdo_bits_resize(fdo_bits_t *b, int byte_sz)
{
	fdo_bits_empty(b);
	b->byte_sz = byte_sz;
	return fdo_bits_fill(&b);
}

/**
 * Initialize the struct bits with zero
 * @param bits  - pointer to the struct bits that has to be initialized with
 * zero
 * @return true if set to 0, else false
 */
bool fdo_bits_fill(fdo_bits_t **bits)
{
	fdo_bits_t *b;

	if (!bits || !*bits) {
		return false;
	}

	b = *bits;
	if (b->bytes != NULL) {
		fdo_free(b->bytes);
		b->bytes = NULL;
	}
	b->bytes = fdo_alloc(b->byte_sz);
	if (b->bytes == NULL) {
		return false;
	}
	return true;
}

/**
 * Allocate the number of bytes specified
 * @param byte_sz - size of the bytes to be allocated
 * @return pointer to the struct bits that is allocated
 */
fdo_byte_array_t *fdo_byte_array_alloc(int byte_sz)
{
	return fdo_bits_alloc(byte_sz);
}

/**
 * Allocate and initialize the bytes
 * @param val - value to the initialized
 * @return pointer to the struct of bits
 */
fdo_byte_array_t *fdo_byte_array_alloc_with_int(int val)
{
	return fdo_bits_alloc_with(sizeof(int), (uint8_t *)&val);
}

/**
 * Allocate the bytes array and assign with the data specified
 * @param ba - data to be assigned
 * @param ba_len - size of the data to be assigned
 * @return pointer to the struct of bytes that is allocated and assigned
 */
fdo_byte_array_t *fdo_byte_array_alloc_with_byte_array(uint8_t *ba, int ba_len)
{
	return fdo_bits_alloc_with(ba_len, ba);
}

/**
 * Free the byte array
 * @param ba - pointer to the byte array struct that has to be fdo_free
 */
void fdo_byte_array_free(fdo_byte_array_t *ba)
{
	if (ba) {
		fdo_bits_free(ba);
	}
}

/**
 * Resize the byte array
 * @param b - pointer to he struct of byte array that has to be resized
 * @param byte_sz - value to be resized with
 * @return pointer to the resized byte array struct
 */
bool fdo_byte_array_resize(fdo_byte_array_t *b, int byte_sz)
{
	return fdo_bits_resize(b, byte_sz);
}

/**
 * Clone the byte array
 * @param bn - byte array to be cloned
 * @return pointet to the cloned byte array struct
 */
fdo_byte_array_t *fdo_byte_array_clone(fdo_byte_array_t *bn)
{
	return fdo_bits_clone(bn);
}

/**
 * Append one byte array onto another and return the resulting byte array
 * @param baA - pointer to the first byte array object
 * @param baB - pointer to the second
 * @return a Byte Array "AB" with B appended after A
 */
fdo_byte_array_t *fdo_byte_array_append(fdo_byte_array_t *baA,
					fdo_byte_array_t *baB)
{
	if (!baA || !baB) {
		return NULL;
	}

	int buf_szAB = baA->byte_sz + baB->byte_sz;
	fdo_byte_array_t *baAB = fdo_byte_array_alloc(buf_szAB);

	if (!baAB) {
		LOG(LOG_ERROR,
		    "failed to allocate memory for creating byte array\n");
		return NULL;
	}

	if (memcpy_s(&baAB->bytes[0], baA->byte_sz, baA->bytes, baA->byte_sz) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		fdo_byte_array_free(baAB);
		return NULL;
	}

	if (memcpy_s(&baAB->bytes[baA->byte_sz], baB->byte_sz, baB->bytes,
		     baB->byte_sz) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		fdo_byte_array_free(baAB);
		return NULL;
	}

	return baAB;
}

//------------------------------------------------------------------------------
// String handler Routines
//

/**
 * Create an empty fdo_string_t object
 * @return an allocated empty fdo_string_t object
 */
fdo_string_t *fdo_string_alloc(void)
{
	return (fdo_string_t *)fdo_alloc(sizeof(fdo_string_t));
}

/**
 * Create fdo_string_t object by allocating memory for the inner buffer
 * with the given size.
 *
 * @return an allocated fdo_string_t object
 */
fdo_string_t *fdo_string_alloc_size(size_t byte_sz) {

	if (byte_sz == 0) {
		return NULL;
	}

	// Buffer would store NULL terminated string, adding +1 for '\0'
	int total_size = byte_sz + 1;
	fdo_string_t *s = (fdo_string_t *)fdo_alloc(sizeof(fdo_string_t));
	if (!s) {
		return NULL;
	}

	s->bytes = fdo_alloc(total_size * sizeof(char));
	if (!s->bytes) {
		fdo_free(s);
		return NULL;
	}
	// byte_sz contains the number of characters
	s->byte_sz = byte_sz;
	return s;
}

/**
 * Create a fdo_string_t object from a non zero terminated string.
 * @param data - a pointer to the string
 * @param byte_sz - the number of characters in the string ( size 0 or more)
 * @return an allocated fdo_string_t object containing the string
 */
fdo_string_t *fdo_string_alloc_with(const char *data, int byte_sz)
{
	fdo_string_t *temp_str = NULL;
	// Buffer would store NULL terminated string, adding +1 for '\0'
	int total_size = byte_sz + 1;

	if (!data) {
		goto err1;
	}

	temp_str = fdo_string_alloc();
	if (!temp_str) {
		goto err1;
	}

	temp_str->bytes = fdo_alloc(total_size * sizeof(char));
	if (temp_str->bytes == NULL) {
		goto err2;
	}

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
	fdo_string_free(temp_str);
err1:
	return NULL;
}

/**
 * Create a fdo_string_t object from a zero terminated string
 * @param data - a pointer to a zero terminated string
 * @return an allocated fdo_string_t object containing the string
 */
fdo_string_t *fdo_string_alloc_with_str(const char *data)
{
	if (!data) {
		return NULL;
	}

	size_t str_sz = strnlen_s(data, FDO_MAX_STR_SIZE);

	if (!str_sz || str_sz == FDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "data is either 'NULL' or 'isn't"
		    " NULL-terminated'\n");
		return NULL;
	}
	return fdo_string_alloc_with(data, str_sz);
}

/**
 * Free an fdo_string_t object, fdo_free any contained buffer as well
 * @param b - the fdo_string_t object to be fdo_freed
 * @return none
 */
void fdo_string_free(fdo_string_t *b)
{
	if (b) {
		fdo_string_init(b);
		fdo_free(b);
	}
}

/**
 * The same as FDOString_empty
 * @param b - the object to have its buffers fdo_freed
 * @return pointer to the empty FDOString object
 */
void fdo_string_init(fdo_string_t *b)
{
	if (b->bytes) {
		fdo_free(b->bytes);
		b->bytes = NULL;
	}
	b->byte_sz = 0;
}

/**
 * Resize the buffer in a fdo_string_t to the new size and
 * return the space filled with zeros
 * fdo_free any already present buffers
 * @param b - the fdo_string_t object to be resized
 * @param byte_sz - the number of bytes to allocate for the new buffer
 * @return true if successful, false otherwise
 */
bool fdo_string_resize(fdo_string_t *b, int byte_sz)
{
	if (!b) {
		return false;
	}

	fdo_string_init(b);
	if (byte_sz > 0) {
		b->byte_sz = byte_sz;
		b->bytes = fdo_alloc(byte_sz * sizeof(char));
		if (b->bytes) {
			return true;
		} else {
			return false;
		}
	}
	return true;
}

/**
 * Resize the buffer in a fdo_string_t to the new size and
 * return the space filled with zeros
 * fdo_free any already present buffers
 * @param b - the fdo_string_t object to be resized
 * @param new_byte_sz - the number of bytes to allocate for the new buffer
 * @param data - the non zero terminated string to copy
 * @return true if successful, false otherwise
 */
bool fdo_string_resize_with(fdo_string_t *b, int new_byte_sz, const char *data)
{
	if (!b || !data) {
		return NULL;
	}

	if (fdo_string_resize(b, new_byte_sz + 1)) {
		if (new_byte_sz > 0) {
			if (memcpy_s(b->bytes, new_byte_sz, data,
				     new_byte_sz) != 0) {
				LOG(LOG_ERROR, "Memcpy Failed\n");
				fdo_free(b->bytes);
				return false;
			}
		}
		return true;
	} else {
		return false;
	}
}

/**
 * Write the SigInfo of the form:
 * SigInfo = [
 *   sgType: DeviceSgType,
 *   Info: bstr
 * ]
 * @param fdow - pointer to the struct where the GID is to be written.
 * @return true if write is successful. false, otherwise.
 */
bool fdo_siginfo_write(fdow_t *fdow)
{
	bool ret = false;
	if (!fdow_start_array(fdow, 2)) {
		LOG(LOG_ERROR, "SigInfo: Failed to start array\n");
		return ret;
	}
	if (!fdow_signed_int(fdow, FDO_SIG_TYPE)) {
		LOG(LOG_ERROR, "SigInfo: Failed to write sgType\n");
		return ret;
	}

	fdo_byte_array_t *empty_byte_array = fdo_byte_array_alloc(0);
	if (!empty_byte_array) {
		LOG(LOG_ERROR, "SigInfo: Byte Array Alloc failed\n");
		return false;
	}

	if (!fdow_byte_string(fdow, empty_byte_array->bytes, empty_byte_array->byte_sz)) {
		LOG(LOG_ERROR, "SigInfo: Failed to write Info\n");
		goto end;
	}

	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "SigInfo: Failed to end array\n");
		goto end;
	}
	LOG(LOG_DEBUG, "eASigInfo write successful\n");
	ret = true;
end:
	fdo_byte_array_free(empty_byte_array);
	empty_byte_array = NULL;
	return ret;
}

/**
 * Read the SigInfo of the form:
 * SigInfo = [
 *   sgType: DeviceSgType,
 *   Info: bstr
 * ]
 * @param fdor - pointer to the struct containing GID
 * @return true if write is successful. false, otherwise.
 */
bool fdo_siginfo_read(fdor_t *fdor)
{
	bool ret = false;
	int type = 0;
	int exptype = 0;
	uint8_t *buf = {0};

	if (!fdor) {
		goto end;
	}

	if (!fdor_start_array(fdor)) {
		LOG(LOG_ERROR, "SigInfo: Failed to start array\n");
		goto end;
	}

	exptype = FDO_SIG_TYPE;

	if (!fdor_signed_int(fdor, &type)) {
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
	if (!fdor_string_length(fdor, &info_length) || info_length != 0) {
		LOG(LOG_ERROR,
		    "SigInfo: Invalid Info length. Expected %d, Received %zu\n", 0,
		    info_length);
		goto end;
	}

	if (!fdor_byte_string(fdor, buf, info_length)) {
		LOG(LOG_ERROR, "SigInfo: Failed to read Info\n");
		goto end;
	}

	if (!fdor_end_array(fdor)) {
		LOG(LOG_ERROR, "No End Array\n");
		goto end;
	}
	LOG(LOG_DEBUG, "eBSigInfo read successful\n");
	ret = true;
end:
	fdo_free(buf);
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
void fdo_nonce_init_rand(fdo_byte_array_t *n)
{
	fdo_crypto_random_bytes((uint8_t *)n->bytes, n->byte_sz);
}

/**
 * compare the two nonce
 * @param n1 - pointer to the first byte array
 * @param n2 - pointer to the second byte array
 * @return true if equal else false
 */
bool fdo_nonce_equal(fdo_byte_array_t *n1, fdo_byte_array_t *n2)
{
	int result_memcmp = 0;

	if (!n1 || !n2) {
		return false;
	}

	if (!memcmp_s(n1->bytes, FDO_NONCE_BYTES, n2->bytes, FDO_NONCE_BYTES,
		      &result_memcmp) &&
	    !result_memcmp) {
		return true;
	} else {
		return false;
	}
}

// -----------------------------------------------------------------------------
// GUID routines
//
/**
 * convert to GUID to string
 * @param g - pointer to the byte array that holds the GUID
 * @param buf - pointer to the converted string
 * @param buf_sz - size of the converted string
 * @return pointer to the converted string
 */
char *fdo_guid_to_string(fdo_byte_array_t *g, char *buf, int buf_sz)
{
	int i = 0;
	int n = 0;
	char *a = NULL;
	char hyphen = '-';

	// buffer size must be (2*16 + 4 + 1), where 2*16 is for holding GUID chars,
	// +4 for holding hyphens and +1 for \0
	// return empty string, in case pre-requisites are not met
	if (!g || !g->bytes || !buf || buf_sz < ((2 * FDO_GUID_BYTES) + 1)) {
		return "";
	}

	a = (char *)g->bytes;
	while (i < FDO_GUID_BYTES) {
		buf[n++] = INT2HEX(((*a >> 4) & 0xf));
		buf[n++] = INT2HEX((*a & 0xf));
		// GUID format: 8-4-4-4-12
		if ((n == 8) || (n == 13) || (n == 18) || (n == 23)) {
			buf[n++] = hyphen;
		}
		i++;
		a++;
	}
	buf[n++] = 0;
	return buf;
}

//------------------------------------------------------------------------------
// Hash/HMAC Routines
//

/**
 * Allocate and empty hash type
 */
fdo_hash_t *fdo_hash_alloc_empty(void)
{
	fdo_hash_t *hp = fdo_alloc(sizeof(fdo_hash_t));

	if (hp == NULL) {
		return NULL;
	}
	hp->hash_type = FDO_CRYPTO_HASH_TYPE_NONE;
	return hp;
}

/**
 * Allocate byte array of hash type specified
 * @param hash_type - type of the hash
 * @param size - size of the byte array to be allocated
 * @return pointer to the allocated hash struct
 */
fdo_hash_t *fdo_hash_alloc(int hash_type, int size)
{
	fdo_hash_t *hp = fdo_alloc(sizeof(fdo_hash_t));

	if (hp == NULL) {
		return NULL;
	}
	hp->hash_type = hash_type;
	hp->hash = fdo_byte_array_alloc(size);
	if (hp->hash == NULL) {
		fdo_free(hp);
		return NULL;
	}
	return hp;
}

/**
 * Free the allocated struct of type hash type
 * @param hp - pointer to the struct of type hash that is to be fdo_free
 */
void fdo_hash_free(fdo_hash_t *hp)
{
	if (NULL == hp) {
		return;
	}
	if (hp->hash != NULL) {
		fdo_byte_array_free(hp->hash);
		hp->hash = NULL;
	}
	fdo_free(hp);
}

/**
 * Read the hash of the form:
 * Hash = [
 *   hashtype: uint8,
 *   hash: bstr
 * ]
 * @param fdor - input data in JSON format
 * @param hp - pointer to the struct of type hash
 * @return number of bytes read , 0 if read failed
 */
int fdo_hash_read(fdor_t *fdor, fdo_hash_t *hp)
{

	if (!fdor || !hp) {
		return 0;
	}

	size_t num_hash_items = 0;
	if (!fdor_array_length(fdor, &num_hash_items) || num_hash_items != 2) {
		LOG(LOG_ERROR, "Invalid Hash: Invalid number of items\n");
		return 0;
	}
	if (!fdor_start_array(fdor)) {
		LOG(LOG_ERROR, "Invalid Hash: Start array not found\n");
		return 0;
	}

	// Read the hash type value
	if (!fdor_signed_int(fdor, &hp->hash_type)) {
		LOG(LOG_ERROR, "Invalid Hash: Unable to decode hashtype\n");
		return 0;
	}

	// Read the bin character length
	size_t mbin_len_reported;
	if (!fdor_string_length(fdor, &mbin_len_reported) || mbin_len_reported <= 0) {
		LOG(LOG_ERROR, "Invalid Hash: Unable to decode length of hash!\n");
		return 0;
	}

	// Make sure we have a byte array to resize
	if (hp->hash == NULL) {
		hp->hash = fdo_byte_array_alloc(mbin_len_reported);
		if (!hp->hash) {
			LOG(LOG_ERROR, "Alloc failed\n");
			return 0;
		}
	}

	if (!fdor_byte_string(fdor, hp->hash->bytes, mbin_len_reported)) {
		LOG(LOG_ERROR, "Invalid Hash: Unable to decode hash!\n");
		return 0;
	}
	hp->hash->byte_sz = mbin_len_reported;

	if (!fdor_end_array(fdor)) {
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
 * @param fdow - pointer to the output struct of type JSON message
 * @param hp - pointer to the struct of type hash
 * @return bool true if write was successful, false otherwise
 */
bool fdo_hash_write(fdow_t *fdow, fdo_hash_t *hp)
{
	bool ret = false;
	if (!fdow || !hp) {
		return ret;
	}
	if (!fdow_start_array(fdow, 2)) {
		LOG(LOG_ERROR, "Hash write: Failed to start array\n");
		return ret;
	}
	if (!fdow_signed_int(fdow, hp->hash_type)) {
		LOG(LOG_ERROR, "Hash write: Failed to write hashtype\n");
		return ret;
	}
	if (!fdow_byte_string(fdow, hp->hash->bytes, hp->hash->byte_sz)) {
		LOG(LOG_ERROR, "Hash write: Failed to write hash\n");
		return ret;
	}
	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "Hash write: Failed to end array\n");
		return ret;
	}
	LOG(LOG_DEBUG, "Hash write completed\n");
	ret = true;
	return ret;
}

//------------------------------------------------------------------------------
// IP Address Routines
//

/**
 * Allocate the struct of type IP address
 */
fdo_ip_address_t *fdo_ipaddress_alloc(void)
{
	fdo_ip_address_t *fdoip = fdo_alloc(sizeof(fdo_ip_address_t));

	if (fdoip == NULL) {
		return NULL;
	}
	if (fdo_null_ipaddress(fdoip)) {
		return fdoip;
	}

	fdo_free(fdoip);
	return NULL;

}

/**
 * Initialize the struct of type IP with the ipv4 details provided
 * @param fdoip - pointer to the struct if type IP
 * @param ipv4 - ipv4 details that has to be initialized with
 */
void fdo_init_ipv4_address(fdo_ip_address_t *fdoip, uint8_t *ipv4)
{
	if (!fdoip || !ipv4) {
		return;
	}

	fdoip->length = 4;
	if (memset_s(&fdoip->addr[0], sizeof(fdoip->addr), 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return;
	}

	if (memcpy_s(&fdoip->addr[0], fdoip->length, ipv4, fdoip->length) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return;
	}
}

/**
 * Reset the IP address
 * @param fdoip - pointer to the struct of type IP address which has to be set
 * to
 * '0'
 */
bool fdo_null_ipaddress(fdo_ip_address_t *fdoip)
{
	fdoip->length = 0;
	if (memset_s(&fdoip->addr[0], sizeof(fdoip->addr), 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return false;
	} else {
		return true;
	}
}

/**
 * Conver the IP address to string
 * @param fdoip - pointer to the struct which holds the IP address
 * @param buf - pointer to the converted string
 * @param buf_sz - size of the converted string
 * @return pointer to the converted string
 */
char *fdo_ipaddress_to_string(fdo_ip_address_t *fdoip, char *buf, int buf_sz)
{
	int n;
	char *buf0 = buf;

	if (!fdoip || !buf) {
		return NULL;
	}

	if (fdoip->length == 4) {
		int temp;

		temp = snprintf_s_i(buf, buf_sz, "[IPv4:%u", fdoip->addr[0]);

		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n = temp;

		temp = snprintf_s_i(buf + strnlen_s(buf, buf_sz), buf_sz, ".%u",
				    fdoip->addr[1]);
		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n += temp;

		temp = snprintf_s_i(buf + strnlen_s(buf, buf_sz), buf_sz, ".%u",
				    fdoip->addr[2]);
		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n += temp;

		temp = snprintf_s_i(buf + strnlen_s(buf, buf_sz), buf_sz,
				    ".%u]", fdoip->addr[3]);
		if (temp < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
		n += temp;

		buf += n;
		buf_sz -= n;
	} else if (fdoip->length == 16) {
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
			    snprintf_s_i(buf, buf_sz, ":%02X", fdoip->addr[n]);

			if (temp < 0) {
				LOG(LOG_ERROR, "snprintf() failed!\n");
				return NULL;
			}
			n = temp;
			temp = snprintf_s_i(buf, buf_sz, "%02X",
					    fdoip->addr[n + 1]);

			if (temp < 0) {
				LOG(LOG_ERROR, "snprintf() failed!\n");
				return NULL;
			}

			n += temp;

			buf += n;
			buf_sz -= n;
		}
	} else {
		if (snprintf_s_i(buf, buf_sz, "[IP?? len:%u]", fdoip->length) <
		    0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return NULL;
		}
	}
	return buf0;
}

/**
 * read the IP address
 * @param fdor - read IP address
 * @param fdoip - pointer to the struct which holds the IP information
 * @return true if success else false
 */
bool fdo_read_ipaddress(fdor_t *fdor, fdo_ip_address_t *fdoip)
{
	fdo_byte_array_t *IP;

	if (!fdor || !fdoip) {
		return false;
	}

	IP = fdo_byte_array_alloc_with_int(0);
	if (!IP) {
		return false;
	}

	size_t ip_length;
	if (!fdor_string_length(fdor, &ip_length) || ip_length != IPV4_ADDR_LEN) {
		LOG(LOG_ERROR, "Invalid IP Address length\n");
		fdo_byte_array_free(IP);
		return false;
	}

	if (!fdor_byte_string(fdor, IP->bytes, ip_length)) {
		fdo_byte_array_free(IP);
		return false;
	}

	fdoip->length = ip_length;
	if (memcpy_s(&fdoip->addr[0], fdoip->length, IP->bytes, ip_length) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}

	fdo_byte_array_free(IP);
	return true;
}

/**
 * Copy the IP Address contents stored in the input fdo_byte_array_t, into
 * the pre-initialized fdo_ip_address_t struct.
 *
 * @param ip_bytes source byte array containing IP Address and its length to copy
 * @param fdoip pre-initialized IP Address struct as destination
 * @return true if the operation was a success, false otherwise
 */
bool fdo_convert_to_ipaddress(fdo_byte_array_t *ip_bytes, fdo_ip_address_t *fdoip)
{
	if (!ip_bytes || !fdoip) {
		return false;
	}

	fdoip->length = ip_bytes->byte_sz;
	if (memcpy_s(&fdoip->addr[0], fdoip->length, ip_bytes->bytes, ip_bytes->byte_sz) !=
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
fdo_public_key_t *fdo_public_key_alloc_empty(void)
{
	return fdo_alloc(sizeof(fdo_public_key_t));
}

/**
 * Allocate public key and initialize
 * @param pkalg - algorithm to be used for public key
 * @param pkenc - public key encoding type
 * @param pklen - publick key length
 * @param pkey - pointer to the public key
 * @return pointer to the public key
 */
fdo_public_key_t *fdo_public_key_alloc(int pkalg, int pkenc, int pklen,
				       uint8_t *pkey)
{
	fdo_public_key_t *pk = fdo_public_key_alloc_empty();

	if (!pk) {
		LOG(LOG_ERROR, "failed to allocate public key structure\n");
		return NULL;
	}
	pk->pkalg = pkalg;
	pk->pkenc = pkenc;
	pk->key1 = fdo_byte_array_alloc_with_byte_array(pkey, pklen);
	return pk;
}

/**
 * Clone the public key
 * @param pk 0 pointer to the public key that is to be cloned
 * @return pointer to the cloned public key
 */
fdo_public_key_t *fdo_public_key_clone(fdo_public_key_t *pk)
{
	if (pk == NULL) {
		return NULL;
	}

	if (!pk->key1 || !pk->pkenc || !pk->pkalg) {
		return NULL;
	}

	fdo_public_key_t *npk = fdo_public_key_alloc(
	    pk->pkalg, pk->pkenc, pk->key1->byte_sz, pk->key1->bytes);
	if (!npk) {
		LOG(LOG_ERROR, "failed to alloc public key struct\n");
		return NULL;
	}
	if (pk->key2 != NULL) {
		npk->key2 = fdo_byte_array_alloc_with_byte_array(
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
bool fdo_compare_public_keys(fdo_public_key_t *pk1, fdo_public_key_t *pk2)
{
	int result_memcmp = 0;

	if (!pk1 || !pk2) {
		return false;
	}

	if (!pk1->key1 || !pk2->key1 || !pk1->pkenc || !pk2->pkenc ||
	    !pk1->pkalg || !pk2->pkalg) {
		return false;
	}

	if (pk1->pkalg != pk2->pkalg) {
		return false;
	}

	if (pk1->pkenc != pk2->pkenc) {
		return false;
	}

	if (memcmp_s(pk1->key1->bytes, pk1->key1->byte_sz, pk2->key1->bytes,
		     pk2->key1->byte_sz, &result_memcmp) ||
	    result_memcmp) {
		return false;
	}

	/* X.509 encoded pubkeys only have key1 parameter */
	if (pk1->key2 && pk2->key2) {
		if (memcmp_s(pk1->key2->bytes, pk1->key2->byte_sz,
			     pk2->key2->bytes, pk2->key2->byte_sz,
			     &result_memcmp) ||
		    result_memcmp) {
			return false;
		}
	}
	return true;
}

/**
 * Free the allocated public key
 * @param pk - pointer to the public key that is to be fdo_freed
 */
void fdo_public_key_free(fdo_public_key_t *pk)
{
	if (!pk) {
		return;
	}
	if (pk->key1) {
		fdo_byte_array_free(pk->key1);
	}
	if (pk->key2) {
		fdo_byte_array_free(pk->key2);
	}
	fdo_free(pk);
}

/**
 * Write a full public key to the output buffer
 * PublicKey = [
 *	pkType,
 *	pkEnc,
 *	pkBody
 * ]
 *
 * @param fdow - output buffer to hold CBOR representation
 * @param pk - pointer to the fdo_public_key_t object
 * @return none
 */
bool fdo_public_key_write(fdow_t *fdow, fdo_public_key_t *pk)
{
	if (!fdow || !pk) {
		return false;
	}

	if (!fdow_start_array(fdow, 3)) {
		LOG(LOG_ERROR, "PublicKey write: Failed to start array.\n");
		return false;
	}
	if (!fdow_signed_int(fdow, pk->pkalg)) {
		LOG(LOG_ERROR, "PublicKey write: Failed to write pkType.\n");
		return false;
	}
	if (!fdow_signed_int(fdow, pk->pkenc)) {
		LOG(LOG_ERROR, "PublicKey write: Failed to write pkEnc.\n");
		return false;
	}
	switch (pk->pkenc)
	{
	case FDO_CRYPTO_PUB_KEY_ENCODING_CRYPTO:
		LOG(LOG_ERROR, "PublicKey write: pkEnc.Crypto is not supported.\n");
		return false;
	case FDO_CRYPTO_PUB_KEY_ENCODING_X509:
		if (!fdow_byte_string(fdow, pk->key1->bytes, pk->key1->byte_sz)) {
			LOG(LOG_ERROR, "PublicKey write: Failed to write in bytes (x509).\n");
			return false;
		}
		break;
	case FDO_CRYPTO_PUB_KEY_ENCODING_X5CHAIN:
		LOG(LOG_ERROR, "PublicKey write: pkEnc.X5CHAIN is not supported.\n");
		return false;
	case FDO_CRYPTO_PUB_KEY_ENCODING_COSEKEY:
		;
		int crv = 0;
		if (!fdow_start_map(fdow, 3)) {
			LOG(LOG_ERROR, "PublicKey write: Failed to start COSEKey Map\n");
			return false;
		}

		if (!fdow_signed_int(fdow, FDO_COSE_ENC_COSEKEY_CURVE_KEY)) {
			LOG(LOG_ERROR, "PublicKey write: Failed to write COSEKey key\n");
			return false;
		}
		crv = pk->pkalg == FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256 ?
			FDO_COSE_ENC_COSEKEY_CRV_EC2_P256 : FDO_COSE_ENC_COSEKEY_CRV_EC2_P384;
		if (!fdow_signed_int(fdow, crv)) {
			LOG(LOG_ERROR,
				"PublicKey write: Failed to write COSEKey Type value\n");
			return false;
		}

		if (!fdow_signed_int(fdow, FDO_COSE_ENC_COSEKEY_ECX_KEY)) {
			LOG(LOG_ERROR, "PublicKey write: Failed to write COSEKey X key\n");
			return false;
		}
		if (!fdow_byte_string(fdow, pk->key1->bytes, pk->key1->byte_sz)) {
			LOG(LOG_ERROR,
				"PublicKey write: Failed to write COSEKey X value\n");
			return false;
		}

		if (!fdow_signed_int(fdow, FDO_COSE_ENC_COSEKEY_ECY_KEY)) {
			LOG(LOG_ERROR, "PublicKey write: Failed to write COSEKey Y key\n");
			return false;
		}
		if (!fdow_byte_string(fdow, pk->key2->bytes, pk->key2->byte_sz)) {
			LOG(LOG_ERROR,
				"PublicKey write: Failed to write COSEKey Y value\n");
			return false;
		}

		if (!fdow_end_map(fdow)) {
			LOG(LOG_ERROR,
				"PublicKey write: Failed to end COSEKey map\n");
			return false;
		}
		break;

	default:
		LOG(LOG_ERROR, "PublicKey write: Invalid pkEnc found\n");
		return false;
	}

	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "PublicKey write: Failed to end array.\n");
		return false;
	}
	// Write successful. Return true.
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
 * @param fdor - read public key info
 * return pointer to the struct of type public key if success else error code
 */
fdo_public_key_t *fdo_public_key_read(fdor_t *fdor)
{
	if (!fdor) {
		return NULL;
	}

	size_t num_public_key_items, public_key_length = 0;
	fdo_public_key_t *pk = fdo_public_key_alloc_empty(); // Create a Public Key
	if (!pk) {
		goto err;
	}

	if (!fdor_array_length(fdor, &num_public_key_items) || num_public_key_items != 3) {
		LOG(LOG_ERROR, "Invalid PublicKey: Array length\n");
		goto err;
	}
	if (!fdor_start_array(fdor)) {
		LOG(LOG_ERROR, "Invalid PublicKey: Start array not found\n");
		goto err;
	}
	if (!fdor_signed_int(fdor, &pk->pkalg) || pk->pkalg != FDO_PK_ALGO) {
		LOG(LOG_ERROR, "Invalid PublicKey: Unable to decode pkType\n");
		goto err;
	}
	if (!fdor_signed_int(fdor, &pk->pkenc)) {
		LOG(LOG_ERROR, "Invalid PublicKey: Unable to decode pkEnc\n");
		goto err;
	}

	switch (pk->pkenc)
	{
	case FDO_CRYPTO_PUB_KEY_ENCODING_CRYPTO:
		LOG(LOG_ERROR, "Invalid PublicKey: pkEnc.Crypto is not supported.\n");
		goto err;
	case FDO_CRYPTO_PUB_KEY_ENCODING_X509:
		if (!fdor_string_length(fdor, &public_key_length) || public_key_length <= 0) {
			LOG(LOG_ERROR, "Invalid PublicKey: Unable to decode pkBody length\n");
			goto err;
		}
		LOG(LOG_DEBUG, "PublicKey.pkBody length: %zu bytes\n", public_key_length);
		pk->key1 = fdo_byte_array_alloc(public_key_length);

		if (!pk->key1 || !fdor_byte_string(fdor, pk->key1->bytes, public_key_length)) {
			LOG(LOG_ERROR, "Invalid PublicKey: Unable to decode pkBody\n");
			goto err;
		}
		pk->key1->byte_sz = public_key_length;
		break;
	case FDO_CRYPTO_PUB_KEY_ENCODING_X5CHAIN:
		LOG(LOG_ERROR, "Invalid PublicKey: pkEnc.X5CHAIN is not supported.\n");
		goto err;
	case FDO_CRYPTO_PUB_KEY_ENCODING_COSEKEY: ;
		size_t map_items = 0;
		int map_key = 0;
		int map_val_int = 0;
		size_t map_val_bytes_sz = 0;
		int exp_crv_val = 0;

#if defined(ECDSA256_DA)
		exp_crv_val = FDO_COSE_ENC_COSEKEY_CRV_EC2_P256;
#else
		exp_crv_val = FDO_COSE_ENC_COSEKEY_CRV_EC2_P384;
#endif

		if (!fdor_map_length(fdor, &map_items) || (map_items != 0 && map_items != 3)) {
			LOG(LOG_ERROR, "Invalid PublicKey: Unable to decode pkBody COSEKey Map length\n");
			goto err;
		}

		if (!fdor_start_map(fdor)) {
			LOG(LOG_ERROR, "Invalid PublicKey: Unable to start pkBody COSEKey Map\n");
			goto err;
		}

		// iterate through the map and look for 2 keys specifically
		// if any other key is found, throw an error
		while (fdor_map_has_more(fdor)) {
			map_key = 0;
			map_val_bytes_sz = 0;
			map_val_int = 0;

			if (!fdor_is_value_signed_int(fdor)) {
				LOG(LOG_ERROR,
					"Invalid PublicKey: Found a non-integer unknown/unsupported COSEKey key.\n");
				goto err;
			}
			if (!fdor_signed_int(fdor, &map_key) || map_key == 0) {
				LOG(LOG_ERROR, "Invalid PublicKey: Failed to read COSEKey key\n");
				goto err;
			}

			if (map_key == FDO_COSE_ENC_COSEKEY_CURVE_KEY) {
				if (!fdor_signed_int(fdor, &map_val_int) || map_val_int != exp_crv_val) {
					LOG(LOG_ERROR,
						"Invalid PublicKey: Failed to read/Invalid COSEKey Type value\n");
					goto err;
				}
			} else if (map_key == FDO_COSE_ENC_COSEKEY_ECX_KEY) {
				if (!fdor_string_length(fdor, &map_val_bytes_sz) || map_val_bytes_sz == 0) {
					if (!fdor_byte_string(fdor, pk->key2->bytes, pk->key2->byte_sz)) {
						LOG(LOG_ERROR,
							"Invalid PublicKey: Failed to read COSEKey X value length\n");
						goto err;
					}
				}
				pk->key1 = fdo_byte_array_alloc(map_val_bytes_sz);
				if (!pk->key1) {
					LOG(LOG_ERROR, "PublicKey1 alloc failed\n");
					goto err;
				}
				if (!fdor_byte_string(fdor, pk->key1->bytes, pk->key1->byte_sz)) {
					LOG(LOG_ERROR,
						"Invalid PublicKey: Failed to read COSEKey X value\n");
					goto err;
				}
			} else if (map_key == FDO_COSE_ENC_COSEKEY_ECY_KEY) {
				if (!fdor_string_length(fdor, &map_val_bytes_sz) || map_val_bytes_sz == 0) {
					if (!fdor_byte_string(fdor, pk->key2->bytes, pk->key2->byte_sz)) {
						LOG(LOG_ERROR,
							"Invalid PublicKey: Failed to read COSEKey Y value length\n");
						goto err;
					}
				}
				pk->key2 = fdo_byte_array_alloc(map_val_bytes_sz);
				if (!pk->key2) {
					LOG(LOG_ERROR, "PublicKey2 alloc failed\n");
					goto err;
				}
				if (!fdor_byte_string(fdor, pk->key2->bytes, pk->key2->byte_sz)) {
					LOG(LOG_ERROR,
						"Invalid PublicKey: Failed to read COSEKey Y value\n");
					goto err;
				}
			} else {
				LOG(LOG_ERROR,
					"Invalid PublicKey: Found unknown/unsupported COSEKey key\n");
				goto err;
			}
		}

		if (!fdor_end_map(fdor)) {
			LOG(LOG_ERROR,
				"Invalid PublicKey: Failed to end COSEKey map\n");
			goto err;
		}
		break;

	default:
		LOG(LOG_ERROR, "Invalid PublicKey: Invalid pkEnc found\n");
		goto err;
	}

	if (!fdor_end_array(fdor)) {
		LOG(LOG_ERROR, "Invalid PublicKey: End array not found\n");
		goto err;
	}
	return pk;
err:
	if (pk) {
		fdo_public_key_free(pk);
	}
	return NULL;
}

//------------------------------------------------------------------------------
// Rendezvous Routines
//

/**
 * Allocate struct of type Rendezvous
 */
fdo_rendezvous_t *fdo_rendezvous_alloc(void)
{
	return fdo_alloc(sizeof(fdo_rendezvous_t));
}

/**
 * Free the allocated rendezvous struct
 * @param rv - pointer to the struct of type rendezvous
 */
void fdo_rendezvous_free(fdo_rendezvous_t *rv)
{
	if (!rv) {
		return;
	}

	if (rv->dev_only != NULL) {
		fdo_free(rv->dev_only);
	}

	if (rv->owner_only != NULL) {
		fdo_free(rv->owner_only);
	}

	if (rv->ip != NULL) {
		fdo_free(rv->ip);
	}

	if (rv->po != NULL) {
		fdo_free(rv->po);
	}

	if (rv->pow != NULL) {
		fdo_free(rv->pow);
	}

	if (rv->dn != NULL) {
		fdo_string_free(rv->dn);
	}

	if (rv->sch != NULL) {
		fdo_hash_free(rv->sch);
	}

	if (rv->cch != NULL) {
		fdo_hash_free(rv->cch);
	}

	if (rv->ui != NULL) {
		fdo_free(rv->ui);
	}

	if (rv->ss != NULL) {
		fdo_string_free(rv->ss);
	}

	if (rv->pw != NULL) {
		fdo_string_free(rv->pw);
	}

	if (rv->wsp != NULL) {
		fdo_string_free(rv->wsp);
	}

	if (rv->me != NULL) {
		fdo_free(rv->me);
	}

	if (rv->pr != NULL) {
		fdo_free(rv->pr);
	}

	if (rv->delaysec != NULL) {
		fdo_free(rv->delaysec);
	}

	if (rv->bypass != NULL) {
		fdo_free(rv->bypass);
	}

	fdo_free(rv);
}

/**
 * Write a RendezvousInstr object to the output buffer
 * RendezvousInstr = [
 *   RVVariable,
 *   RVValue
 * ]
 *
 * @param fdow - the buffer pointer
 * @param rv - pointer to the RendezvousInstr object to write
 * @return true if written successfully, otherwise false
 */
bool fdo_rendezvous_write(fdow_t *fdow, fdo_rendezvous_t *rv)
{
	if (!fdow || !rv) {
		return false;
	}

	bool ret = false;

	// use this temporary FDOW to CBOR-encode RVValue(512 bytes should be enough, update if needed)
	// the resulting RVValue is, then bstr-encoded
	fdow_t temp_fdow = {0};
	if (!fdow_init(&temp_fdow) ||
		!fdo_block_alloc_with_size(&temp_fdow.b, BUFF_SIZE_512_BYTES) ||
		!fdow_encoder_init(&temp_fdow)) {
		LOG(LOG_ERROR,
			"RendezvousInstr: FDOW Initialization/Allocation failed!\n");
		goto end;
	}

	if (!fdow_start_array(fdow, rv->num_params)) {
		LOG(LOG_ERROR, "RendezvousInstr: Failed to start array\n");
		goto end;
	}

	if (rv->dev_only != NULL && *rv->dev_only == true) {
		if (!fdow_signed_int(fdow, RVDEVONLY)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVDevOnly\n");
			goto end;
		}
	}

	if (rv->owner_only != NULL && *rv->owner_only == true) {
		if (!fdow_signed_int(fdow, RVOWNERONLY)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVOwnerOnly\n");
			goto end;
		}
	}

	if (rv->ip != NULL) {
		if (!fdow_signed_int(fdow, RVIPADDRESS) ||
			!fdow_byte_string(&temp_fdow, (uint8_t *) &rv->ip->addr, rv->ip->length)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVIPAddress\n");
			goto end;
		}
	}

	if (rv->po != NULL) {
		if (!fdow_signed_int(fdow, RVDEVPORT) ||
			!fdow_signed_int(&temp_fdow, *rv->po)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVDevPort\n");
			goto end;
		}
	}

	if (rv->pow != NULL) {
		if (!fdow_unsigned_int(fdow, RVOWNERPORT) ||
			!fdow_signed_int(&temp_fdow, *rv->pow)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVOwnerPort\n");
			goto end;
		}
	}

	if (rv->dn != NULL) {
		if (!fdow_signed_int(fdow, RVDNS) ||
			!fdow_text_string(&temp_fdow, rv->dn->bytes, rv->dn->byte_sz)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVDns\n");
			goto end;
		}
	}

	if (rv->sch != NULL) {
		if (!fdow_signed_int(fdow, RVSVCERTHASH) ||
			!fdo_hash_write(&temp_fdow, rv->sch)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVSvCertHash\n");
			goto end;
		}
	}

	if (rv->cch != NULL) {
		if (!fdow_signed_int(fdow, RVCLCERTHASH) ||
			!fdo_hash_write(&temp_fdow, rv->cch)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVClCertHash\n");
			goto end;
		}
	}

	if (rv->ui != NULL) {
		if (!fdow_signed_int(fdow, RVUSERINPUT) ||
			!fdow_boolean(&temp_fdow, *rv->ui)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVUserInput\n");
			goto end;
		}
	}

	if (rv->ss != NULL) {
		if (!fdow_signed_int(fdow, RVWIFISSID) ||
			!fdow_text_string(&temp_fdow, rv->ss->bytes, rv->ss->byte_sz)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVWiFiSsid\n");
			goto end;
		}
	}

	if (rv->pw != NULL) {
		if (!fdow_signed_int(fdow, RVWIFIPW) ||
			!fdow_text_string(&temp_fdow, rv->pw->bytes, rv->pw->byte_sz)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVWifiPw\n");
			goto end;
		}
	}

	if (rv->me != NULL) {
		if (!fdow_signed_int(fdow, RVMEDIUM) ||
			!fdow_unsigned_int(&temp_fdow, *rv->me)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVMedium\n");
			goto end;
		}
	}

	if (rv->pr != NULL) {
		if (!fdow_signed_int(fdow, RVPROTOCOL) ||
			!fdow_unsigned_int(&temp_fdow, *rv->pr)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVProtocol\n");
			goto end;
		}
	}

	if (rv->delaysec != NULL) {
		if (!fdow_signed_int(fdow, RVDELAYSEC) ||
			!fdow_unsigned_int(&temp_fdow, *rv->delaysec)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVDelaysec\n");
			goto end;
		}
	}

	if (rv->bypass != NULL && *rv->bypass == true) {
		if (!fdow_signed_int(fdow, RVBYPASS)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVBypass\n");
			goto end;
		}
	}

	if (rv->num_params == 2) {
		if (!fdow_encoded_length(&temp_fdow, &temp_fdow.b.block_size) ||
			temp_fdow.b.block_size == 0) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to find encoded length\n");
			goto end;
		}
		if (!fdow_byte_string(fdow, temp_fdow.b.block, temp_fdow.b.block_size)) {
			LOG(LOG_ERROR, "RendezvousInstr: Failed to write RVValue\n");
			ret = false;
		}
	}

	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "RendezvousInstr: Failed to end array\n");
		goto end;
	}
	ret = true;
end:
	if (temp_fdow.b.block || temp_fdow.current) {
		fdow_flush(&temp_fdow);
	}
	return ret;
}

/**
 * Read the RendezvousInstr from the input buffer
 * RendezvousInstr = [
 *   RVVariable,
 *   RVValue
 * ]
 *
 * @param fdor - the input buffer object
 * @param rv - pointer to the RendezvousInstr object to fill
 * @return true of read correctly, false otherwise
 */
bool fdo_rendezvous_read(fdor_t *fdor, fdo_rendezvous_t *rv)
{
	int ret = false;
	fdor_t temp_fdor = {0};

	if (!fdor || !rv) {
		return false;
	}

	size_t num_rv_instr_items = 0;
	if (!fdor_array_length(fdor, &num_rv_instr_items) || num_rv_instr_items <= 0) {
		LOG(LOG_ERROR, "RendezvousInstr is empty\n");
		return false;
	}

	if (!fdor_start_array(fdor)) {
		LOG(LOG_ERROR, "RendezvousInstr start array not found\n");
		return false;
	}

	// size_t index;
	size_t key_buf_sz = 24;
	char key_buf[key_buf_sz];
	size_t str_buf_sz = 80;
	char str_buf[str_buf_sz];
	uint8_t *rvvalue = NULL;
	size_t rvvalue_sz = 0;

	rv->num_params = 0;

	if (memset_s(key_buf, key_buf_sz, 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return false;
	}
	if (memset_s(str_buf, str_buf_sz, 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return false;
	}
	// parse RVVariable
	int key;
	if (!fdor_signed_int(fdor, &key)) {
		LOG(LOG_ERROR, "RendezvousInstr RVVariable read error\n");
		return false;
	}

	// bstr-unwrap RVValue, and then parse the same same using temporary FDOR
	// the 3 keys don't have RVValue
	if (key != RVDEVONLY && key != RVOWNERONLY && key != RVBYPASS) {
		if (!fdor_string_length(fdor, &rvvalue_sz) || rvvalue_sz == 0) {
			LOG(LOG_ERROR, "RendezvousInstr RVValue length read error\n");
			return false;
		}
		rvvalue = fdo_alloc(sizeof(uint8_t) * rvvalue_sz);
		if (memset_s(rvvalue, rvvalue_sz, 0) != 0) {
			LOG(LOG_ERROR, "RendezvousInstr RVValue Memset error\n");
			return false;
		}
		if (!fdor_byte_string(fdor, rvvalue, rvvalue_sz)) {
			LOG(LOG_ERROR, "RendezvousInstr RVValue read error\n");
			return false;
		}
	}

	if (rvvalue) {
		if (!fdor_init(&temp_fdor) ||
			!fdo_block_alloc_with_size(&temp_fdor.b, rvvalue_sz)) {
			LOG(LOG_ERROR,
				"Failed to setup temporary FDOR\n");
			goto end;
		}

		if (0 != memcpy_s(temp_fdor.b.block, temp_fdor.b.block_size,
			rvvalue, rvvalue_sz)) {
			LOG(LOG_ERROR,
				"Failed to copy temporary unwrapped Header content\n");
			goto end;
		}

		if (!fdor_parser_init(&temp_fdor)) {
			LOG(LOG_ERROR,
				"Failed to init temporary FDOR parser\n");
			goto end;
		}
	}

	// Parse the values found
	switch (key) {
	case RVDEVONLY:
		rv->dev_only = fdo_alloc(sizeof(bool));
		if (!rv->dev_only) {
			LOG(LOG_ERROR, "RVDEVONLY alloc failed\n");
			goto end;
		}
		*rv->dev_only = true;
		rv->num_params = 1;
		break;

	case RVOWNERONLY:
		rv->owner_only = fdo_alloc(sizeof(bool));
		if (!rv->owner_only) {
			LOG(LOG_ERROR, "RVOWNERONLY alloc failed\n");
			goto end;
		}
		*rv->owner_only = true;
		rv->num_params = 1;
		break;

	case RVIPADDRESS:
		if (rv->ip) {
			fdo_free(rv->ip);
		}

		rv->ip = fdo_ipaddress_alloc();
		if (!rv->ip) {
			LOG(LOG_ERROR, "RVIPADDRESS alloc failed\n");
			goto end;
		}
		if (fdo_read_ipaddress(&temp_fdor, rv->ip) != true) {
			LOG(LOG_ERROR, "RVIPADDRESS read failed\n");
			goto end;
		}
		rv->num_params = 2;
		break;

	case RVDEVPORT:

		if (rv->po) {
			fdo_free(rv->po);
		}

		rv->po = fdo_alloc(sizeof(int)); // Allocate an integer
		if (!rv->po) {
			LOG(LOG_ERROR, "RVDEVPORT alloc failed\n");
			goto end;
		}
		if (!fdor_signed_int(&temp_fdor, rv->po)) {
			LOG(LOG_ERROR, "RVDEVPORT read failed\n");
			goto end;
		}
		rv->num_params = 2;
		break;

	// valid only for OWNER. parse for validation.
	case RVOWNERPORT:

		if (rv->pow) {
			fdo_free(rv->pow);
		}

		rv->pow = fdo_alloc(sizeof(int));
		if (!rv->pow) {
			LOG(LOG_ERROR, "RVOWNERPORT alloc failed\n");
			goto end;
		}
		if (!fdor_signed_int(&temp_fdor, rv->pow)) {
			LOG(LOG_ERROR, "RVOWNERPORT read failed\n");
			goto end;
		}
		rv->num_params = 2;
		break;

	case RVDNS:

		if (!fdor_string_length(&temp_fdor, &str_buf_sz)) {
			LOG(LOG_ERROR, "RVDNS length read failed\n");
			goto end;
		}

		if (!fdor_text_string(&temp_fdor, str_buf, str_buf_sz)) {
			LOG(LOG_ERROR, "RVDNS read failed\n");
			goto end;
		}

		if (rv->dn) {
			fdo_string_free(rv->dn);
		}

		rv->dn = fdo_string_alloc_with(str_buf, str_buf_sz);
		if (!rv->dn) {
			LOG(LOG_ERROR, "RVDNS alloc failed\n");
			goto end;
		}
		rv->num_params = 2;
		break;

	case RVSVCERTHASH:

		if (rv->sch) {
			fdo_hash_free(rv->sch);
		}
		rv->sch = fdo_hash_alloc_empty();
		if (!rv->sch) {
			LOG(LOG_ERROR, "RVSVCERTHASH alloc failed\n");
			goto end;
		}
		if (!fdo_hash_read(&temp_fdor, rv->sch)) {
			LOG(LOG_ERROR, "RVSVCERTHASH read failed\n");
			goto end;
		}
		rv->num_params = 2;
		break;

	case RVCLCERTHASH:

		if (rv->cch) {
			fdo_hash_free(rv->cch);
		}

		rv->cch = fdo_hash_alloc_empty();
		if (!rv->cch) {
			LOG(LOG_ERROR, "RVCLCERTHASH alloc failed\n");
			goto end;
		}
		if (!fdo_hash_read(&temp_fdor, rv->cch)) {
			LOG(LOG_ERROR, "RVSVCERTHASH read failed\n");
			goto end;
		}
		rv->num_params = 2;
		break;

	case RVUSERINPUT:

		rv->ui = fdo_alloc(sizeof(bool));
		if (!rv->ui) {
			LOG(LOG_ERROR, "RVUSERINPUT alloc failed\n");
			goto end;
		}
		if (!fdor_boolean(&temp_fdor, rv->ui)) {
			LOG(LOG_ERROR, "RVUSERINPUT read failed\n");
			goto end;
		}
		rv->num_params = 2;
		break;

	case RVWIFISSID:

		if (!fdor_string_length(&temp_fdor, &str_buf_sz)) {
			LOG(LOG_ERROR, "RVWIFISSID length read failed\n");
			goto end;
		}

		if (fdor_text_string(&temp_fdor, str_buf, str_buf_sz)) {
			LOG(LOG_ERROR, "RVWIFISSID length read failed\n");
			goto end;
		}

		if (rv->ss) {
			fdo_string_free(rv->ss);
		}
		rv->ss = fdo_string_alloc_with(str_buf, str_buf_sz);
		if (!rv->ss) {
			LOG(LOG_ERROR, "RVWIFISSID alloc failed\n");
			goto end;
		}
		rv->num_params = 2;
		break;

	case RVWIFIPW:

		if (!fdor_string_length(&temp_fdor, &str_buf_sz)) {
			LOG(LOG_ERROR, "RVWIFIPW length read failed\n");
			goto end;
		}

		if (!fdor_text_string(&temp_fdor, str_buf, str_buf_sz)) {
			LOG(LOG_ERROR, "RVWIFIPW read failed\n");
			goto end;
		}

		if (rv->pw) {
			fdo_string_free(rv->pw);
		}

		rv->pw = fdo_string_alloc_with(str_buf, str_buf_sz);
		if (!rv->pw) {
			LOG(LOG_ERROR, "RVWIFIPW alloc failed\n");
			goto end;
		}
		rv->num_params = 2;
		break;

	case RVMEDIUM:

		rv->me = fdo_alloc(sizeof(uint64_t));
		if (!fdor_unsigned_int(&temp_fdor, rv->me)) {
			LOG(LOG_ERROR, "RVMEDIUM read failed\n");
			goto end;
		}
		// TO-DO : Parse all possible RVMedium values.
		rv->num_params = 2;
		break;

	case RVPROTOCOL:

		rv->pr = fdo_alloc(sizeof(uint64_t));
		if (!fdor_unsigned_int(&temp_fdor, rv->pr)) {
			LOG(LOG_ERROR, "RVPROTOCOL read failed\n");
			goto end;
		}
		// TO-DO : Parse all possible RVProtocol values.
		rv->num_params = 2;
		break;

	case RVDELAYSEC:

		if (rv->delaysec) {
			fdo_free(rv->delaysec);
		}

		rv->delaysec = fdo_alloc(sizeof(uint64_t));
		if (!rv->delaysec) {
			LOG(LOG_ERROR, "RVDELAYSEC Alloc failed\n");
			goto end;
		}
		if (!fdor_unsigned_int(&temp_fdor, rv->delaysec) || !rv->delaysec) {
			LOG(LOG_ERROR, "RVDELAYSEC read failed\n");
			goto end;
		}
		rv->num_params = 2;
		break;

	case RVBYPASS:

		rv->bypass = fdo_alloc(sizeof(bool));
		if (!rv->bypass) {
			LOG(LOG_ERROR, "RVBYPASS alloc failed\n");
			goto end;
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
		goto end; // Abort due to unexpected value for key
	}

	if (!fdor_end_array(fdor)) {
		LOG(LOG_ERROR, "RendezvousInstr end array not found\n");
		goto end;
	}

	ret = true;

end:
	if (temp_fdor.b.block || temp_fdor.current) {
		fdor_flush(&temp_fdor);
	}
	if (rvvalue) {
		fdo_free(rvvalue);
	}
	return ret;
}

//------------------------------------------------------------------------------
// Rendezvous_list Routines
//

/**
 * Allocate an empty FDORendezvous_list object to the list.
 * @return an allocated FDORendezvous_list object.
 */
fdo_rendezvous_list_t *fdo_rendezvous_list_alloc(void)
{
	return fdo_alloc(sizeof(fdo_rendezvous_list_t));
}

/**
 * Free all entries in the list.
 * @param list - the list to fdo_free.
 * @return none
 */
void fdo_rendezvous_list_free(fdo_rendezvous_list_t *list)
{
	fdo_rendezvous_t *entry, *next;
	fdo_rendezvous_directive_t *directive_entry, *directive_next;

	if (list == NULL) {
		return;
	}

	/* Delete all entries. */
	directive_entry = directive_next = list->rv_directives;
	while (directive_entry) {
		next = entry = directive_entry->rv_entries;
		while (entry) {
			next = entry->next;
			fdo_rendezvous_free(entry);
			entry = next;
		};
		directive_next = directive_entry->next;
		fdo_free(directive_entry);
		directive_entry = directive_next;
	}
	list->num_rv_directives = 0;
	fdo_free(list);
}

/**
 * Add the RendezvousDirective to the RendezvousInfo list
 * @param list - pointer to the RendezvousInfo list
 * @param rv - pointer to the RendezvousDirective to be added to the list
 * @return number of entries added if success else error code
 */
int fdo_rendezvous_directive_add(fdo_rendezvous_list_t *list,
	fdo_rendezvous_directive_t *directive) {
	if (list == NULL || directive == NULL) {
		return 0;
	}

	if (list->num_rv_directives == 0) {
		// List empty, add the first entry
		list->rv_directives = directive;
		list->num_rv_directives++;
	} else {
		// already has entries, find the last entry
		fdo_rendezvous_directive_t *entry_ptr = list->rv_directives;
		// Find the last entry
		while (entry_ptr->next != NULL) {
			entry_ptr = (fdo_rendezvous_directive_t *)entry_ptr->next;
		}
		// Now the enty_ptr is pointing to the last entry
		// Add the directive entry onto the end
		entry_ptr->next = directive;
		list->num_rv_directives++;
	}
	LOG(LOG_DEBUG, "Added RendezvousDirective entry %d\n", list->num_rv_directives);
	return list->num_rv_directives;
}

/**
 * Add the RendezvousInstr to the RendezvousDirective struct
 * @param list - pointer to the RendezvousDirective list
 * @param rv - pointer to the RendezvousInstr to be added to the list
 * @return number of entries added if success else error code
 */
int fdo_rendezvous_list_add(fdo_rendezvous_directive_t *directives, fdo_rendezvous_t *rv)
{
	if (directives == NULL || rv == NULL) {
		return 0;
	}

	if (directives->num_entries == 0) {
		// List empty, add the first entry
		directives->rv_entries = rv;
		directives->num_entries++;
	} else {
		// already has entries, find the last entry
		fdo_rendezvous_t *entry_ptr = directives->rv_entries;
		// Find the last entry
		while (entry_ptr->next != NULL) {
			entry_ptr = (fdo_rendezvous_t *)entry_ptr->next;
		}
		// Now the enty_ptr is pointing to the last entry
		// Add the r entry onto the end
		entry_ptr->next = rv;
		directives->num_entries++;
	}
	LOG(LOG_DEBUG, "Added RendezvousInstr entry %d\n", directives->num_entries);
	return directives->num_entries;
}

/**
 * Function will return the RendezvousDirective as per the num passed.
 * @param list - Pointer to the list for the entries.
 * @param num - index of which entry (RendezvousDirective) to return.
 * @return fdo_rendezvous_directive_t object.
 */
fdo_rendezvous_directive_t *fdo_rendezvous_directive_get(fdo_rendezvous_list_t *list, int num)
{
	int index;

	if (list == NULL || list->rv_directives == NULL) {
		return NULL;
	}

	fdo_rendezvous_directive_t *entry_ptr = list->rv_directives;

	for (index = 0; index < num; index++) {
		if (entry_ptr->next != NULL) {
			entry_ptr = entry_ptr->next;
		} else {
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
 * @return fdo_rendezvous_t object.
 */
fdo_rendezvous_t *fdo_rendezvous_list_get(fdo_rendezvous_directive_t *directive, int num)
{
	int index;

	if (directive == NULL || directive->rv_entries == NULL) {
		return NULL;
	}

	fdo_rendezvous_t *entry_ptr = directive->rv_entries;

	for (index = 0; index < num; index++) {
		if (entry_ptr->next != NULL) {
			entry_ptr = entry_ptr->next;
		} else {
			// this should ideally no happen since for 'num' times,
			// there should be a directive present.
			LOG(LOG_DEBUG, "RendezvousInstr not found for index %d\n", index);
			return NULL;
		}
	}
	return entry_ptr;
}

/**
 * Reads the RendezvousInfo from the fdor w.r.t the number of entries.
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
 * @param fdor - Pointer of type fdor_t as input.
 * @param list- Pointer to the fdo_rendezvous_list_t list to be filled.
 * @return true if reads correctly ,else false
 */

int fdo_rendezvous_list_read(fdor_t *fdor, fdo_rendezvous_list_t *list)
{
	if (!fdor || !list) {
		return false;
	}

	// Find out the number of RendezvousDirective(s)
	size_t num_rv_directives = 0;
	if (!fdor_array_length(fdor, &num_rv_directives) || num_rv_directives <= 0) {
		LOG(LOG_ERROR,
		    "%s : No RendezvousDirective(s) found\n", __func__);
		return false;
	}

	if (!fdor_start_array(fdor)) {
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
		if (!fdor_array_length(fdor, &num_rv_instr) || num_rv_instr <= 0) {
			LOG(LOG_ERROR,
		    	"%s : No RendezvousInstr(s) found\n", __func__);
			return false;
		}

		LOG(LOG_DEBUG, "There are %zu RendezvousInstr(s)\n",
			num_rv_instr);

		if (!fdor_start_array(fdor)) {
			LOG(LOG_ERROR,
		    "%s : RendezvousDirective start array not found\n", __func__);
			return false;
		}

		fdo_rendezvous_directive_t *rv_directive =
			fdo_alloc(sizeof(fdo_rendezvous_directive_t));
		if (!rv_directive) {
			LOG(LOG_ERROR,
		    "%s : RendezvousDirective alloc failed\n", __func__);
			return false;
		}
		size_t rv_instr_index;
		for (rv_instr_index = 0; rv_instr_index < num_rv_instr; rv_instr_index++) {
			// Read each rv entry and add to the rv list
			LOG(LOG_DEBUG, "Processing RendezvousInstr Index %zu\n", rv_instr_index);

			fdo_rendezvous_t *rv_entry = fdo_rendezvous_alloc();

			if (fdo_rendezvous_read(fdor, rv_entry)) {
				fdo_rendezvous_list_add(rv_directive, rv_entry);
			} else {
				fdo_rendezvous_free(rv_entry);
				// TO-DO: free directive here?
				return false;
			}
		}
		if (!fdor_end_array(fdor)) {
			LOG(LOG_ERROR,
		    	"%s : RendezvousDirective end array not found\n", __func__);
			return false;
		}
		fdo_rendezvous_directive_add(list, rv_directive);
	}
	if (!fdor_end_array(fdor)) {
		LOG(LOG_ERROR,
		    "%s : RendezvousInfo end array not found\n", __func__);
		return false;
	}

	LOG(LOG_DEBUG, "RendezvousInfo read completed\n");
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
 * @param fdow - Pointer of type fdow to be filled.
 * @param list- Pointer to the fdo_rendezvous_list_t list from which fdow will
 * be filled w.r.t num_entries specified in the list.
 * @return true if writes correctly ,else false
 */
bool fdo_rendezvous_list_write(fdow_t *fdow, fdo_rendezvous_list_t *list)
{
	if (!fdow || !list) {
		return false;
	}

	if (!fdow_start_array(fdow, list->num_rv_directives)) {
		LOG(LOG_ERROR, "Failed to start array\n");
		return false;
	}

	int rv_directive_index;
	for (rv_directive_index = 0; rv_directive_index < list->num_rv_directives;
		rv_directive_index++) {
		fdo_rendezvous_directive_t *directive = fdo_rendezvous_directive_get(list, rv_directive_index);
		if (!directive) {
			continue;
		}

		if (!fdow_start_array(fdow, directive->num_entries)) {
			LOG(LOG_ERROR, "Failed to start array\n");
			return false;
		}

		int rv_instr_index;
		for (rv_instr_index = 0; rv_instr_index < directive->num_entries; rv_instr_index++) {
			fdo_rendezvous_t *entry_Ptr = fdo_rendezvous_list_get(directive, rv_instr_index);
			if (entry_Ptr == NULL) {
				continue;
			}
			fdo_rendezvous_write(fdow, entry_Ptr);
		}

		if (!fdow_end_array(fdow)) {
			LOG(LOG_ERROR,
		    	"%s : RendezvousInfo end array not found\n", __func__);
			return false;
		}
	}

	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR,
		    "%s : RendezvousInfo end array not found\n", __func__);
		return false;
	}

	return true;
}

//------------------------------------------------------------------------------
// AES Encrypted Message Body Routines
//

/**
 * Allocate an empty AES encrypted Message Body object
 * @return an allocated AES Encrypted Message Body object
 */
fdo_encrypted_packet_t *fdo_encrypted_packet_alloc(void)
{
	return fdo_alloc(sizeof(fdo_encrypted_packet_t));
}

/**
 * Free an AES Encrypted Message Body object
 * @param pkt - the object to fdo_free
 * @return none
 */
void fdo_encrypted_packet_free(fdo_encrypted_packet_t *pkt)
{
	if (pkt == NULL) {
		return;
	}
	if (pkt->em_body) {
		fdo_byte_array_free(pkt->em_body);
	}
	if (pkt->hmac) {
		fdo_hash_free(pkt->hmac);
	}
	if (pkt->ct_string) {
		fdo_byte_array_free(pkt->ct_string);
	}
	fdo_free(pkt);
}

/**
 * Read an Encrypted Message Body object from the FDOR buffer.
 * Currently, this parses EncryptedMessage of Simple Type,
 * that contains an COSE_Encrypt0.
 * ETMOuterBlock = [
 *   protected:   { 1:ETMMacType },		// bstr
 *   unprotected: { 5:IV}				// contains IV
 *   payload:     ETMInnerBlock			// cipher||tag
 * ]
 * @param fdor - pointer to the character buffer to parse
 * @return a newly allocated FDOEcnrypted_packet object if successful, otherwise
 * NULL
 */
fdo_encrypted_packet_t *fdo_encrypted_packet_read(fdor_t *fdor)
{
	fdo_encrypted_packet_t *pkt = NULL;
	fdo_cose_encrypt0_t *cose_encrypt0 = NULL;
	int expected_aes_alg_type = -1;

	if (!fdor){
		LOG(LOG_ERROR, "Encrypted Message Read: Invalid FDOR\n");
		goto err;
	}

	pkt = fdo_encrypted_packet_alloc();
	if (!pkt) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to alloc Encrypted structure\n");
		goto err;
	}

	cose_encrypt0 = fdo_alloc(sizeof(fdo_cose_encrypt0_t));
	if (!cose_encrypt0) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to alloc COSE_Encrypt0\n");
		goto err;
	}
	if (!fdo_cose_encrypt0_read(fdor, cose_encrypt0)) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to read COSE_Encrypt0\n");
		goto err;
	}

	// Encrypted payload that contains cipher||tag
	// Allocate for cipher, discarding the tag length
	pkt->em_body = fdo_byte_array_alloc(cose_encrypt0->payload->byte_sz - sizeof(pkt->tag));
	if (!pkt->em_body) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to copy COSE_Encrypt0.Payload\n");
		goto err;
	}

	// copy the cipher
	if (memcpy_s(pkt->em_body->bytes, pkt->em_body->byte_sz,
		    cose_encrypt0->payload->bytes,
			cose_encrypt0->payload->byte_sz - sizeof(pkt->tag)) != 0) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to copy cipher data\n");
		goto err;
	}

	// copy the tag
	if (0 != memcpy_s(&pkt->tag, sizeof(pkt->tag),
		cose_encrypt0->payload->bytes + pkt->em_body->byte_sz, sizeof(pkt->tag))) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to copy tag\n");
		goto err;
	}

	// copy IV that is used to decrypt the encrypted payload
	// even though the IV buffer length is 16 bytes, the actual IV length is different
	// for GCM vs CCM
	// however, while actually using the IV, only the appropriate length of IV is read/used
	if (0 != memcpy_s(&pkt->iv, sizeof(pkt->iv),
		&cose_encrypt0->unprotected_header->aes_iv, sizeof(cose_encrypt0->unprotected_header->aes_iv))) {
		LOG(LOG_ERROR, "Encrypted Message Read: Failed to copy COSE_Encrypt0.Unprotected.AESIV\n");
		goto err;
	}

#ifdef COSE_ENC_TYPE
	expected_aes_alg_type = COSE_ENC_TYPE;
#else
	LOG(LOG_ERROR, "Encrypted Message Read: Invalid Encryption type\n");
	goto err;
#endif

	if (cose_encrypt0->protected_header->aes_plain_type != expected_aes_alg_type) {
		LOG(LOG_ERROR, "Encrypted Message Read: Unexpected AESPlainType\n");
		goto err;
	}
	pkt->aes_plain_type = cose_encrypt0->protected_header->aes_plain_type;

	fdo_cose_encrypt0_free(cose_encrypt0);
	cose_encrypt0 = NULL;
	LOG(LOG_DEBUG, "Encrypted Message Read: Encrypted Message parsed successfully\n");
	return pkt;
err:
	fdo_encrypted_packet_free(pkt);
	if (cose_encrypt0) {
		fdo_cose_encrypt0_free(cose_encrypt0);
		cose_encrypt0 = NULL;
	}
	return NULL;
}

/**
 * Write the Enc_structure (RFC 8152) used as Addditional Authenticated Data (AAD)
 * for AES GCM/CCM, in the FDOW buffer.
 * Enc_structure = [
 *   context: "Encrypt0"
 *   protected:   { 1:COSEEncType },
 *   external_aad:     bstr
 *]
 * @param fdow - fdow_t object containing the buffer where CBOR data will be written to
 * @param alg_type - COSEEncType value to be used in protected header
 * @return true if write is successful, false otherwise.
 */
bool fdo_aad_write(fdow_t *fdow, int alg_type) {

	bool ret = false;

	if (!fdow) {
		return false;
	}

	char enc_structure_context[9] = "Encrypt0";
	fdo_cose_encrypt0_protected_header_t *protected_header = NULL;
	fdo_byte_array_t *enc_structure_external_aad = NULL;

	if (!fdow_start_array(fdow, 3)) {
		LOG(LOG_ERROR, "Enc_Structure: Failed to write start array\n");
		goto err;
	}

	// context is a constant chosen from a list of available values, as per RFC 8152
	// ignore the NULL terminator in the 'Context' string
	if (!fdow_text_string(fdow, &enc_structure_context[0], sizeof(enc_structure_context) - 1)) {
		LOG(LOG_ERROR, "Enc_Structure: Failed to write Context\n");
		goto err;
	}

	// protected header is the same as "Encrypt0" protected header structure, thus reuse
	protected_header = fdo_alloc(sizeof(fdo_cose_encrypt0_protected_header_t));
	if (!protected_header) {
		LOG(LOG_ERROR, "Enc_Structure: Failed to alloc protected header\n");
		goto err;
	}
	protected_header->aes_plain_type = alg_type;
	if (!fdo_cose_encrypt0_write_protected_header(fdow, protected_header)) {
		LOG(LOG_ERROR, "Enc_Structure: Failed to write protected header\n");
		goto err;
	}

	// external_aad is an empty bstr
	enc_structure_external_aad = fdo_byte_array_alloc(0);
	if (!enc_structure_external_aad) {
		LOG(LOG_ERROR, "Enc_Structure: Failed to alloc external_aad\n");
		goto err;
	}

	if (!fdow_byte_string(fdow, enc_structure_external_aad->bytes,
		enc_structure_external_aad->byte_sz)) {
		LOG(LOG_ERROR, "Enc_Structure: Failed to write external_aad\n");
		goto err;
	}

	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "Enc_Structure: Failed to write end array\n");
		goto err;
	}
	ret = true;
err:
	if (protected_header) {
		fdo_free(protected_header);
		protected_header = NULL;
	}
	if (enc_structure_external_aad) {
		fdo_free(enc_structure_external_aad);
		enc_structure_external_aad = NULL;
	}
	return ret;
}

/**
 * Write the EMBlock stucture (COSE_Encrypt0) in the FDOW buffer using the contents
 * of fdo_encrypted_packet_t.
 * ETMInnerBlock = [
 *   protected:   { 1:COSEEncType },
 *   unprotected: { 5:AESIV }
 *   payload:     ProtocolMessage
 *]
 * @param fdow - fdow_t object containing the buffer where CBOR data will be written to
 * @param pkt - fdo_encrypted_packet_t object
 * @return true if write is successful, false otherwise.
 */
bool fdo_emblock_write(fdow_t *fdow, fdo_encrypted_packet_t *pkt)
{
	if (!fdow || !pkt) {
		return false;
	}

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

	// Allocate for payload that contains cipher||tag
	cose_encrypt0->payload = fdo_byte_array_alloc(pkt->em_body->byte_sz + sizeof(pkt->tag));
	if (!cose_encrypt0->payload) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to alloc COSE_Encrypt0.Payload\n");
		goto err;
	}

	// copy the cipher data
	if (0 != memcpy_s(cose_encrypt0->payload->bytes, pkt->em_body->byte_sz,
			pkt->em_body->bytes, pkt->em_body->byte_sz)) {
		LOG(LOG_ERROR, "Encrypted Message write: Failed to copy cipher data\n");
		goto err;
	}

	// copy the tag
	if (0 != memcpy_s(cose_encrypt0->payload->bytes + pkt->em_body->byte_sz, sizeof(pkt->tag),
		    pkt->tag, sizeof(pkt->tag))) {
		LOG(LOG_ERROR, "Encrypted Message write: Failed to copy tag\n");
		goto err;
	}

	if (!fdo_cose_encrypt0_write(fdow, cose_encrypt0)) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to write COSE_Encrypt0\n");
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
 * Take in encrypted data object and end up with it represented
 * cleartext in the fdor buffer.  This will allow the data to be parsed
 * for its content.
 * @param fdor - pointer to the fdor object to fill
 * @param pkt - Pointer to the Encrypted packet pkt that has to be processed.
 * @return true if all goes well, otherwise false
 */
bool fdo_encrypted_packet_unwind(fdor_t *fdor, fdo_encrypted_packet_t *pkt)
{
	bool ret = false;
	fdo_byte_array_t *cleartext = NULL;
	fdow_t temp_fdow = {0};

	// Decrypt the Encrypted Body
	if (!fdor || !pkt) {
		LOG(LOG_ERROR, "Encrypted Message (decrypt): Invalid params\n");
		return false;
	}

	cleartext = fdo_byte_array_alloc(0);
	if (cleartext == NULL) {
		LOG(LOG_ERROR, "Encrypted Message (decrypt): Failed to alloc clear data\n");
		goto err;
	}

	// create temporary FDOW, use it to create AAD and then clear it.
	if (!fdow_init(&temp_fdow) || !fdo_block_alloc_with_size(&temp_fdow.b, BUFF_SIZE_256_BYTES) ||
		!fdow_encoder_init(&temp_fdow)) {
		LOG(LOG_ERROR,
			"Encrypted Message write: FDOW Initialization/Allocation failed!\n");
		goto err;
	}
	if (!fdo_aad_write(&temp_fdow, pkt->aes_plain_type)) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to generate AAD\n");
		goto err;
	}
	// update the final encoded length in temporary FDOW
	if (!fdow_encoded_length(&temp_fdow, &temp_fdow.b.block_size)) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to read AAD length\n");
		goto err;
	}

	/* New iv is used for each new decryption which comes from pkt*/
	if (0 != aes_decrypt_packet(pkt, cleartext, temp_fdow.b.block, temp_fdow.b.block_size)) {
		LOG(LOG_ERROR, "Encrypted Message (decrypt): Failed to decrypt\n");
		goto err;
	}

	// clear the FDOR buffer and push decrypted payload into it
	fdo_block_reset(&fdor->b);
	fdor->b.block_size = cleartext->byte_sz;
	if (0 != memcpy_s(fdor->b.block, cleartext->byte_sz,
		cleartext->bytes, cleartext->byte_sz)) {
		LOG(LOG_ERROR, "Encrypted Message (decrypt): Failed to copy\n");
		goto err;
	}

	// initialize the parser once the buffer contains COSE payload to be decoded.
	if (!fdor_parser_init(fdor)) {
		LOG(LOG_ERROR, "Encrypted Message (decrypt): Failed to initialize FDOR parser\n");
		goto err;
	}
	LOG(LOG_DEBUG, "Encrypted Message (decrypt): Decryption done\n");
	ret = true;
err:
	if (temp_fdow.b.block || temp_fdow.current) {
		fdow_flush(&temp_fdow);
	}
	if (pkt) {
		fdo_encrypted_packet_free(pkt);
	}
	if (cleartext) {
		fdo_byte_array_free(cleartext);
	}
	return ret;
}

/**
 * Prepare to write Simple EncryptedMessage (Section 4.4 FDO Specification).
 * At the end of this method, structure EMBlock is generated.
 *
 * @param pkt - Pointer to the Encrypted packet pkt that has to be processed.
 * @param fdow - fdow_t object containing the buffer where CBOR data will be written to
 * @param fdow_buff_default_sz - default buffer length of fdow.b.block
 * @return true if all goes well, otherwise false
 */
bool fdo_prep_simple_encrypted_message(fdo_encrypted_packet_t *pkt,
	fdow_t *fdow, size_t fdow_buff_default_sz) {

	bool ret = false;
	// create temporary FDOW, use it to create Protected header map and then clear it.
	fdow_t temp_fdow = {0};

	if (!pkt || ! fdow) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Invalid params\n");
		return false;
	}

	if (!fdow_init(&temp_fdow) || !fdo_block_alloc_with_size(&temp_fdow.b, BUFF_SIZE_256_BYTES) ||
		!fdow_encoder_init(&temp_fdow)) {
		LOG(LOG_ERROR,
			"Encrypted Message write: FDOW Initialization/Allocation failed!\n");
		goto exit;
	}
	if (!fdo_aad_write(&temp_fdow, pkt->aes_plain_type)) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to read COSE_Encrypt0 (EMBlock) length\n");
		goto exit;
	}
	// update the final encoded length in temporary FDOW
	if (!fdow_encoded_length(&temp_fdow, &temp_fdow.b.block_size)) {
		LOG(LOG_ERROR,
			"Encrypted Message write: Failed to read COSE_Encrypt0 (EMBlock) length\n");
		goto exit;
	}

	if (0 != aes_encrypt_packet(pkt, fdow->b.block, fdow->b.block_size, temp_fdow.b.block,
		temp_fdow.b.block_size)) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to encrypt\n");
		goto exit;
	}

	// reset the FDOW block to write EMBlock
	// This clears the unencrypted (clear text) as well
	fdo_block_reset(&fdow->b);
	fdow->b.block_size = fdow_buff_default_sz;
	if (!fdow_encoder_init(fdow)) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to initialize FDOW encoder\n");
		goto exit;
	}

	// write the EMBlock containing the cipher text || tag as payload
	if (!fdo_emblock_write(fdow, pkt)) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to write COSE_Encrypt0 (EMBlock)\n");
		goto exit;
	}
	ret = true;
exit:
	if (temp_fdow.b.block || temp_fdow.current) {
		fdow_flush(&temp_fdow);
	}
	if (!ret) {
		// reset the FDOW block for further writing
		fdo_block_reset(&fdow->b);
		fdow->b.block_size = fdow_buff_default_sz;
		if (!fdow_encoder_init(fdow)) {
			LOG(LOG_ERROR,
				"Encrypted Message (encrypt): Failed to initialize FDOW encoder\n");
		}
	}
	return ret;
}

/**
 * Take the cleartext packet contained in the fdow buffer and convert it
 * to an Encrypted Message Body of Simple Type in the fdow buffer.
 * It contains an COSE_Encrypt0.
 * EMBlock = [
 *   protected:   { 1:ETMMacType },		// bstr
 *   unprotected: { 5 : IV}				// contains IV
 *   payload:     bstr					// cipher||tag
 * ]

 * @param fdow - pointer to the message buffer
 * @param type - message type
 * @return true if all goes well, otherwise false
 */
bool fdo_encrypted_packet_windup(fdow_t *fdow, int type)
{
	if (!fdow) {
		return false;
	}

	fdo_block_t *fdob = &fdow->b;
	bool ret = false;
	// save the default buffer size, set it back at the end
	size_t fdow_buff_default_sz = fdob->block_size;

	// find the encoded cleartext length
	size_t payload_length = 0;
	if (!fdow_encoded_length(fdow, &payload_length) || payload_length == 0) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to read encoded message length\n");
		return ret;
	}
	fdow->b.block_size = payload_length;

	fdo_encrypted_packet_t *pkt = fdo_encrypted_packet_alloc();
	if (!pkt) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to alloc for Encrypted message struct\n");
		return ret;
	}

#if defined(COSE_ENC_TYPE)
	pkt->aes_plain_type = COSE_ENC_TYPE;
	if (!fdo_prep_simple_encrypted_message(pkt, fdow, fdow_buff_default_sz)) {
		LOG(LOG_ERROR,
			"Encrypted Message (encrypt): Failed to generate Simple Encrypted Message\n");
		goto exit;
	}
#else
	LOG(LOG_ERROR,
		"Encrypted Message (encrypt): Invalid AES algorithm type\n");
	goto exit;
#endif

	fdow_next_block(fdow, type);
	ret = true;
exit:
	if (pkt) {
		fdo_encrypted_packet_free(pkt);
	}
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

	fdo_eat_t *eat = fdo_alloc(sizeof(fdo_eat_t));
	if (!eat) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to alloc\n");
		goto err;
	}
	eat->eat_ph = fdo_alloc(sizeof(fdo_eat_protected_header_t));
	if (!eat->eat_ph) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to alloc Protected Header\n");
		goto err;
	}

	eat->eat_uph = fdo_alloc(sizeof(fdo_eat_unprotected_header_t));
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
	if (eat) {
		fdo_eat_free(eat);
	}
	return NULL;
}

/**
 * Free an EAT object for which memory has been allocated previously.
 */
void fdo_eat_free(fdo_eat_t *eat) {

	if (!eat) {
		return;
	}

	if (eat->eat_ph) {
		fdo_free(eat->eat_ph);
	}
	if (eat->eat_uph) {
		if (eat->eat_uph->eatmaroeprefix) {
			fdo_byte_array_free(eat->eat_uph->eatmaroeprefix);
		}
		if (eat->eat_uph->euphnonce) {
			fdo_byte_array_free(eat->eat_uph->euphnonce);
		}
		fdo_free(eat->eat_uph);
	}
	if (eat->eat_payload) {
		fdo_byte_array_free(eat->eat_payload);
	}
	if (eat->eat_signature) {
		fdo_byte_array_free(eat->eat_signature);
	}
	fdo_free(eat);
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
 * @param fdow - fdow_t object holding the buffer where CBOR data will be written to
 * @param eat - fdo_eat_t object that holds the EAT parameters
 * @return true, if write was a success. False otherwise.
 */
bool fdo_eat_write(fdow_t *fdow, fdo_eat_t *eat) {

	if (!fdow || !eat) {
		LOG(LOG_ERROR, "Entity Attestation Token: Invalid params\n");
		return false;
	}

	if (!fdow_tag(fdow, FDO_COSE_TAG_SIGN1)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write Tag\n");
		return false;
	}

	if (!fdow_start_array(fdow, 4)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write start array\n");
		return false;
	}

	if (!fdo_eat_write_protected_header(fdow, eat->eat_ph)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write protected header\n");
		return false;
	}

	if (!fdo_eat_write_unprotected_header(fdow, eat->eat_uph)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write unprotected header\n");
		return false;
	}

	if (!fdow_byte_string(fdow, eat->eat_payload->bytes, eat->eat_payload->byte_sz)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write payload\n");
		return false;
	}

	if (!fdow_byte_string(fdow, eat->eat_signature->bytes, eat->eat_signature->byte_sz)) {
		LOG(LOG_ERROR, "Entity Attestation Token: Failed to write signature\n");
		return false;
	}

	if (!fdow_end_array(fdow)) {
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
bool fdo_eat_write_protected_header(fdow_t *fdow, fdo_eat_protected_header_t *eat_ph) {

	bool ret = false;
	fdo_byte_array_t *enc_ph = NULL;
	// create temporary FDOW, use it to create Protected header map and then clear it.
	fdow_t temp_fdow = {0};

	if (!fdow || !eat_ph) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Invalid params\n");
		return false;
	}

	if (!fdow_init(&temp_fdow) || !fdo_block_alloc_with_size(&temp_fdow.b, BUFF_SIZE_128_BYTES) ||
		!fdow_encoder_init(&temp_fdow)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: FDOW Initialization/Allocation failed!\n");
		goto end;
	}

	if (!fdow_start_map(&temp_fdow, 1)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to write start map\n");
		goto end;
	}

	if (!fdow_signed_int(&temp_fdow, FDO_COSE_ALG_KEY)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to write CoseAlg Key\n");
		goto end;
	}

	if (!fdow_signed_int(&temp_fdow, eat_ph->ph_sig_alg)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to write CoseAlg Value\n");
		goto end;
	}

	if (!fdow_end_map(&temp_fdow)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to write end map\n");
		goto end;
	}

	size_t enc_ph_length = 0;
	if (!fdow_encoded_length(&temp_fdow, &enc_ph_length) || enc_ph_length == 0) {
		LOG(LOG_ERROR, "Entity Attestation Token Protected header:: Failed to find encoded length\n");
		goto end;
	}
	temp_fdow.b.block_size = enc_ph_length;
	// Set the encoded payload into buffer
	enc_ph =
		fdo_byte_array_alloc_with_byte_array(temp_fdow.b.block, temp_fdow.b.block_size);
	if (!enc_ph) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to alloc for encoded Protected header\n");
		goto end;
	}

	// finally, wrap the protected header into a bstr
	if (!fdow_byte_string(fdow, enc_ph->bytes, enc_ph->byte_sz)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Protected header: Failed to write Protected header as bstr\n");
		goto end;
	}
	ret = true;
end:
	if (temp_fdow.b.block || temp_fdow.current) {
		fdow_flush(&temp_fdow);
	}
	if (enc_ph) {
		fdo_byte_array_free(enc_ph);
	}
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
bool fdo_eat_write_unprotected_header(fdow_t *fdow, fdo_eat_unprotected_header_t *eat_uph) {

	if (!fdow || !eat_uph) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Unprotected header: Invalid params\n");
		return false;
	}

	// calculate the size of map.
	int num_uph_elements = 0;
	if (eat_uph->euphnonce) {
		num_uph_elements++;
	}
	if (eat_uph->eatmaroeprefix) {
		num_uph_elements++;
	}
	if (!fdow_start_map(fdow, num_uph_elements)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token Unprotected header: Failed to write start map\n");
		return false;
	}

	// Write EATMAROEPrefix only when its present.
	if (eat_uph->eatmaroeprefix) {
		if (!fdow_signed_int(fdow, FDO_EAT_MAROE_PREFIX_KEY)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token Unprotected header: Failed to write EATMAROEPrefix Key\n");
			return false;
		}

		if (!fdow_byte_string(fdow, eat_uph->eatmaroeprefix->bytes, eat_uph->eatmaroeprefix->byte_sz)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token Unprotected header: Failed to write EATMAROEPrefix value\n");
			return false;
		}
	}

	// Write EUPHNonce only when its present.
	if (eat_uph->euphnonce) {
		if (!fdow_signed_int(fdow, FDO_EAT_EUPHNONCE_KEY)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token Unprotected header: Failed to write EUPHNonce Key\n");
			return false;
		}

		if (!fdow_byte_string(fdow, eat_uph->euphnonce->bytes, eat_uph->euphnonce->byte_sz)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token Unprotected header: Failed to write EUPHNonce Value\n");
			return false;
		}
	}

	if (!fdow_end_map(fdow)) {
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
bool fdo_eat_write_payloadbasemap(fdow_t *fdow, fdo_eat_payload_base_map_t *eat_payload) {

	size_t num_payload_elements = 2;

	if (!fdow) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Invalid params\n");
		return false;
	}

	if (eat_payload->eatpayloads) {
		LOG(LOG_DEBUG,
			"Entity Attestation Token PayloadBaseMap: EATPayload to be written\n");
		num_payload_elements = 3;
	}
	if (!fdow_start_map(fdow, num_payload_elements)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write start map\n");
		return false;
	}

	if (!fdow_signed_int(fdow, FDO_EATUEID_KEY)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write EAT-UEID Key\n");
		return false;
	}

	if (!fdow_byte_string(fdow, eat_payload->eatueid, sizeof(eat_payload->eatueid))) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write EAT-UEID value\n");
		return false;
	}

	if (!fdow_signed_int(fdow, FDO_EATNONCE_KEY)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write EAT-NONCE Key\n");
		return false;
	}

	if (!fdow_byte_string(fdow, eat_payload->eatnonce, sizeof(eat_payload->eatnonce))) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write EAT-NONCE value\n");
		return false;
	}

	if (num_payload_elements == 3) {
		if (!fdow_signed_int(fdow, FDO_EATFDO)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token PayloadBaseMap: Failed to write EAT-FDO Key\n");
			return false;
		}

		// EATPayloads is an array of size 1 as per the usage in the FDO specification.
		if (!fdow_start_array(fdow, 1)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token PayloadBaseMap: Failed to write start array\n");
			return false;
		}
		if (!fdow_byte_string(fdow,
				eat_payload->eatpayloads->bytes, eat_payload->eatpayloads->byte_sz)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token PayloadBaseMap: Failed to write EAT-FDO value\n");
			return false;
		}
		if (!fdow_end_array(fdow)) {
			LOG(LOG_ERROR,
				"Entity Attestation Token PayloadBaseMap: Failed to write end array\n");
			return false;
		}
	}

	if (!fdow_end_map(fdow)) {
		LOG(LOG_ERROR,
			"Entity Attestation Token PayloadBaseMap: Failed to write end map\n");
		return false;
	}
	return true;
}

/**
 * Create Sig_structure of the form:
 * Sig_structure = [
 * context : "Signature1",
 * body_protected : empty_or_serialized_map,	// EAT Protected header as bstr
 * external_aad : bstr,
 * payload : bstr
 * ]
 * Only to be used Sig_sturcture for EAT.
 *
 * @param eat_ph - EAT protected header
 * @param eat_payload - EAT Payload
 * @param external_aad - External AAD. If NULL, empty bstr will be written, else
 * the AAD bytes will be written
 * @param sig_structure - Out buffer to store the constructred CBOR encoded Sig_structure.
 * Memory allocation will be done inside this method, if the operation is successful.
 * It will be NULL otherwise.
 * @return true, if read was a success. False otherwise.
 */
bool fdo_eat_write_sigstructure(fdo_eat_protected_header_t *eat_ph,
	fdo_byte_array_t *eat_payload, fdo_byte_array_t *external_aad,
	fdo_byte_array_t **sig_structure) {

	bool ret = false;
	char context[] = "Signature1";
	fdo_byte_array_t *empty_byte_array = NULL;
	fdow_t temp_fdow = {0};
	size_t enc_length = 0;
	size_t sig_struct_sz = 0;

	if (!eat_ph || !eat_payload || !sig_structure) {
		return false;
	}

	// size of the Sigstruct CBOR encoded buffer
	// provide buffer of 128 bytes for protected header + context + additional CBOR encoding
	if (external_aad) {
		sig_struct_sz = eat_payload->byte_sz + external_aad->byte_sz + BUFF_SIZE_128_BYTES;
	} else {
		sig_struct_sz = eat_payload->byte_sz + BUFF_SIZE_128_BYTES;
	}

	if (!fdow_init(&temp_fdow) || !fdo_block_alloc_with_size(&temp_fdow.b, sig_struct_sz) ||
		!fdow_encoder_init(&temp_fdow)) {
		LOG(LOG_ERROR, "EAT Sig_structure: FDOW Initialization/Allocation failed!\n");
		goto end;
	}

	if (!fdow_start_array(&temp_fdow, 4)) {
		LOG(LOG_ERROR, "EAT Sig_structure: Failed to write start array\n");
		return false;
	}

	if (!fdow_text_string(&temp_fdow, context, sizeof(context) - 1)) {
		LOG(LOG_ERROR, "EAT Sig_structure: Failed to write Context\n");
		return false;
	}

	if (!fdo_eat_write_protected_header(&temp_fdow, eat_ph)) {
		LOG(LOG_ERROR, "EAT Sig_structure: Failed to write protected header\n");
		return false;
	}

	if (external_aad) {
		if (!fdow_byte_string(&temp_fdow, external_aad->bytes, external_aad->byte_sz)) {
			LOG(LOG_ERROR, "EAT Sig_structure: Failed to write external_aad\n");
			goto end;
		}
	} else {
		empty_byte_array = fdo_byte_array_alloc(0);
		if (!empty_byte_array) {
			LOG(LOG_ERROR, "EAT Sig_structure: Byte Array Alloc failed\n");
			return false;
		}

		if (!fdow_byte_string(&temp_fdow, empty_byte_array->bytes, empty_byte_array->byte_sz)) {
			LOG(LOG_ERROR, "EAT Sig_structure: Failed to write external_aad\n");
			goto end;
		}
	}

	if (!fdow_byte_string(&temp_fdow, eat_payload->bytes, eat_payload->byte_sz)) {
		LOG(LOG_ERROR, "EAT Sig_structure: Failed to write payload\n");
		goto end;
	}

	if (!fdow_end_array(&temp_fdow)) {
		LOG(LOG_ERROR, "EAT Sig_structure: Failed to write end array\n");
		goto end;
	}

	enc_length = 0;
	if (!fdow_encoded_length(&temp_fdow, &enc_length) || enc_length == 0) {
		LOG(LOG_ERROR, "EAT Sig_structure: Failed to find encoded length of "
			"Sig_structure array as bstr\n");
		goto end;
	}

	// Alocate and copy the encoded Sig_sturcture bstr
	*sig_structure =
		fdo_byte_array_alloc_with_byte_array(temp_fdow.b.block, enc_length);
	if (!(*sig_structure)) {
		LOG(LOG_ERROR,
			"EAT Sig_structure: Failed to alloc output Sig_structure\n");
		goto end;
	}

	ret = true;
end:
	if (empty_byte_array) {
		fdo_byte_array_free(empty_byte_array);
	}
	if (temp_fdow.b.block || temp_fdow.current) {
		fdow_flush(&temp_fdow);
	}
	return ret;
}

/**
 * Free the given COSE_Sign1 object for which memory has been allocated previously.
 */
void fdo_cose_free(fdo_cose_t *cose) {
	if (!cose) {
		return;
	}
	if (cose->cose_ph) {
		cose->cose_ph->ph_sig_alg = 0;
		fdo_free(cose->cose_ph);
	}
	if (cose->cose_uph) {
		fdo_public_key_free(cose->cose_uph->cuphowner_public_key);
		fdo_free(cose->cose_uph);
	}
	if (cose->cose_payload) {
		fdo_byte_array_free(cose->cose_payload);
	}
	if (cose->cose_signature) {
		fdo_byte_array_free(cose->cose_signature);
	}
	fdo_free(cose);
}

/**
 * Read CoseSignature.COSEProtectedHeaders (CBOR map) into the given fdo_cose_protected_header_t object.
 * {
 * keyAlg:<key-alg>
 * }
 * Return true, if read was a success. False otherwise.
 */
bool fdo_cose_read_protected_header(fdor_t *fdor, fdo_cose_protected_header_t *cose_ph) {

	if (!fdor || !cose_ph) {
		LOG(LOG_ERROR, "COSE Protected header: Invalid params\n");
		return false;
	}

	fdor_t temp_fdor;
	if (memset_s(&temp_fdor, sizeof(fdor_t), 0) != 0) {
		LOG(LOG_ERROR, "COSE Protected header: Failed to intialize temporary FDOR\n");
		return false;
	}

	size_t var_length = 0;
	if (!fdor_string_length(fdor, &var_length) ||
		var_length == 0) {
		LOG(LOG_ERROR, "COSE Protected header: Failed to read payload length\n");
		return false;
	}
	fdo_byte_array_t *ph_as_bstr = fdo_byte_array_alloc(var_length);
	if (!ph_as_bstr) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to alloc for COSE Protected Header as bstr\n");
		return false;
	}
	if (!fdor_byte_string(fdor, ph_as_bstr->bytes, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to read COSE Protected Header as bstr\n");
		goto end;
	}

	// create a temporary FDOR to read (unwrap) the header contents as map
	if (!fdor_init(&temp_fdor) ||
		!fdo_block_alloc_with_size(&temp_fdor.b, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to setup temporary FDOR\n");
		goto end;
	}

	if (0 != memcpy_s(temp_fdor.b.block, temp_fdor.b.block_size,
		ph_as_bstr->bytes, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to copy temporary unwrapped Header content\n");
		goto end;
	}

	if (!fdor_parser_init(&temp_fdor)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to init temporary FDOR parser\n");
		goto end;
	}

	if (!fdor_start_map(&temp_fdor)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to read start map\n");
		goto end;
	}

	int cose_alg_key = 1;
	if (!fdor_signed_int(&temp_fdor, &cose_alg_key) || cose_alg_key != 1) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to read CoseAlg Key\n");
		goto end;
	}

	if (!fdor_signed_int(&temp_fdor, &cose_ph->ph_sig_alg)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to read CoseAlg Value\n");
		goto end;
	}

	if (!fdor_end_map(&temp_fdor)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to read end map\n");
		goto end;
	}
end:
	fdor_flush(&temp_fdor);
	fdo_free(temp_fdor.b.block);
	if (ph_as_bstr) {
		fdo_byte_array_free(ph_as_bstr);
	}
	return true;
}

/**
 * Read CoseSignature.COSEUnprotectedHeaders.
 * Reads an empty map if cose_uph is NULL.
 * Reads and pushes the fields CUPHOWNER and CUPHNONCE otherwise.
 * Return true, if read was a success. False otherwise.
 */
bool fdo_cose_read_unprotected_header(fdor_t *fdor, fdo_cose_unprotected_header_t *cose_uph) {

	int result = 0;
	size_t map_items = 0;

	if (!fdor) {
		LOG(LOG_ERROR, "COSE Unprotected header: Invalid params\n");
		return false;
	}

	if (!fdor_map_length(fdor, &map_items) || (map_items != 0 && map_items != 2)) {
		LOG(LOG_ERROR,
			"COSE Unprotected header: Invalid map length.\n");
		return false;
	}

	// either the header is expected to ne non-NULL and hold 2 items, or
	// the header is expected to be NULL and hold 0 items
	// anything else means that the expectation from the header is not fulfilled, or
	// the method is not called with correct parameters
	if ((cose_uph && map_items != 2) || (!cose_uph && map_items != 0)) {
		LOG(LOG_ERROR,
			"COSE Unprotected header: Unexpected map parameters.\n");
		return false;
	}

	if (!fdor_start_map(fdor)) {
		LOG(LOG_ERROR,
			"COSE Unprotected header: Failed to read start map\n");
		return false;
	}

	// if unprotected header is not an empty map, it will contain 2 items (key-value pairs)
	if (cose_uph && map_items == 2) {
		// iterate through the map and look for 2 keys specifically
		// if any other key is found, throw an error
		while (fdor_map_has_more(fdor)) {
			if (!fdor_is_value_signed_int(fdor)) {
				LOG(LOG_ERROR,
					"COSE Unprotected header: Found a non-integer unknown/unsupported key.\n");
				return false;
			}
			result = 0;
			if (!fdor_signed_int(fdor, &result) || result == 0) {
				LOG(LOG_ERROR,
					"COSE Unprotected header: Failed to read key\n");
				return false;
			}
			if (result == FDO_COSE_SIGN1_CUPHOWNERPUBKEY_KEY) {
				cose_uph->cuphowner_public_key = fdo_public_key_read(fdor);
				if (!cose_uph->cuphowner_public_key) {
					LOG(LOG_ERROR, "COSE: Failed to read CUPHOWNERPUBKEY value\n");
					return false;
				}
			} else if (result == FDO_COSE_SIGN1_CUPHNONCE_KEY) {
				if (!fdor_byte_string(fdor, cose_uph->cuphnonce, sizeof(cose_uph->cuphnonce))) {
					LOG(LOG_ERROR,
						"COSE Unprotected header: Failed to read CUPHNONCE value\n");
					return false;
				}
			} else {
				LOG(LOG_ERROR,
					"COSE Unprotected header: Found unknown/unsupported key\n");
				return false;
			}
		}
	}

	if (!fdor_end_map(fdor)) {
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
 * @param fdor - fdor_t object containing the buffer to read
 * @param cose - fdo_cose_t object that will hold the read COSE_Sign1 parameters
 * @param empty_uph - true if the unprotected header is expected to be empty, false otherwise
 * @return true, if read was a success. False otherwise.
 */
bool fdo_cose_read(fdor_t *fdor, fdo_cose_t *cose, bool empty_uph) {

	if (!fdor || !cose) {
		LOG(LOG_ERROR, "COSE: Invalid params\n");
		return false;
	}

	size_t num_cose_items = 4;
	uint64_t tag = 0;

	if (!fdor_tag(fdor, &tag) || tag != FDO_COSE_TAG_SIGN1) {
		LOG(LOG_ERROR, "COSE: Failed to read/Invalid Tag\n");
		return false;
	}

	if (!fdor_array_length(fdor, &num_cose_items) || num_cose_items != 4) {
		LOG(LOG_ERROR, "COSE: Failed to read/Invalid array length\n");
		return false;
	}

	if (!fdor_start_array(fdor)) {
		LOG(LOG_ERROR, "COSE: Failed to read start array\n");
		return false;
	}

	cose->cose_ph = fdo_alloc(sizeof(fdo_cose_protected_header_t));
	if (!cose->cose_ph) {
		LOG(LOG_ERROR, "COSE: Failed to alloc Protected Header\n");
		goto end;
	}
	if (!fdo_cose_read_protected_header(fdor, cose->cose_ph)) {
		LOG(LOG_ERROR, "COSE: Failed to read protected header\n");
		goto end;
	}

	// this is a special case used only for message received from Type 61,
	// since it contains CUPHNONCE and CUPHOWNERPUBKEY
	if (!empty_uph) {
		cose->cose_uph = fdo_alloc(sizeof(fdo_cose_unprotected_header_t));
		if (!cose->cose_uph) {
			LOG(LOG_ERROR, "COSE: Failed to alloc unprotected Header\n");
			goto end;
		}
	}
	if (!fdo_cose_read_unprotected_header(fdor, cose->cose_uph)) {
		LOG(LOG_ERROR, "COSE: Failed to read unprotected header\n");
		goto end;
	}

	size_t var_length = 0;
	if (!fdor_string_length(fdor, &var_length) ||
		var_length == 0) {
		LOG(LOG_ERROR, "COSE: Failed to read payload length\n");
		goto end;
	}
	cose->cose_payload = fdo_byte_array_alloc(var_length);
	if (!cose->cose_payload) {
		LOG(LOG_ERROR, "COSE: Failed to alloc EATPayload\n");
		goto end;
	}
	if (!fdor_byte_string(fdor, cose->cose_payload->bytes, cose->cose_payload->byte_sz)) {
		LOG(LOG_ERROR, "COSE: Failed to read payload\n");
		goto end;
	}

	var_length = 0;
	if (!fdor_string_length(fdor, &var_length) ||
		var_length == 0) {
		LOG(LOG_ERROR, "COSE: Failed to read signature length\n");
		goto end;
	}
	cose->cose_signature = fdo_byte_array_alloc(var_length);
	if (!cose->cose_signature) {
		LOG(LOG_ERROR, "COSE: Failed to alloc Signature\n");
		goto end;
	}
	if (!fdor_byte_string(fdor, cose->cose_signature->bytes, cose->cose_signature->byte_sz)) {
		LOG(LOG_ERROR, "COSE: Failed to read signature\n");
		goto end;
	}

	if (!fdor_end_array(fdor)) {
		LOG(LOG_ERROR, "COSE: Failed to read end array\n");
		goto end;
	}
	return true;

end:
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
bool fdo_cose_write_protected_header(fdow_t *fdow, fdo_cose_protected_header_t *cose_ph) {

	bool ret = false;
	fdo_byte_array_t *enc_ph = NULL;
	// create temporary FDOW, use it to create Protected header map and then clear it.
	fdow_t temp_fdow = {0};

	if (!fdow || !cose_ph) {
		LOG(LOG_ERROR, "COSE Protected header: Invalid params\n");
		return false;
	}

	if (!fdow_init(&temp_fdow) || !fdo_block_alloc_with_size(&temp_fdow.b, BUFF_SIZE_128_BYTES) ||
		!fdow_encoder_init(&temp_fdow)) {
		LOG(LOG_ERROR, "COSE Protected header: FDOW Initialization/Allocation failed!\n");
		goto end;
	}

	if (!fdow_start_map(&temp_fdow, 1)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to write start map\n");
		goto end;
	}

	if (!fdow_signed_int(&temp_fdow, FDO_COSE_ALG_KEY)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to write CoseAlg Key\n");
		goto end;
	}

	if (!fdow_signed_int(&temp_fdow, cose_ph->ph_sig_alg)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to write CoseAlg Value\n");
		goto end;
	}

	if (!fdow_end_map(&temp_fdow)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to write end map\n");
		goto end;
	}

	size_t enc_ph_length = 0;
	if (!fdow_encoded_length(&temp_fdow, &enc_ph_length) || enc_ph_length == 0) {
		LOG(LOG_ERROR, "COSE Protected header:: Failed to find encoded length\n");
		goto end;
	}
	temp_fdow.b.block_size = enc_ph_length;
	// Set the encoded payload into buffer
	enc_ph =
		fdo_byte_array_alloc_with_byte_array(temp_fdow.b.block, temp_fdow.b.block_size);
	if (!enc_ph) {
		LOG(LOG_ERROR, "COSE Protected header: Failed to alloc for encoded Protected header\n");
		goto end;
	}

	// finally, wrap the protected header into a bstr
	if (!fdow_byte_string(fdow, enc_ph->bytes, enc_ph->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE Protected header: Failed to write Protected header as bstr\n");
		goto end;
	}
	ret = true;
end:
	if (temp_fdow.b.block || temp_fdow.current) {
		fdow_flush(&temp_fdow);
	}
	if (enc_ph) {
		fdo_byte_array_free(enc_ph);
	}
	return ret;
}

/**
 * Create COSESignature.COSEUnprotectedHeaders (CBOR empty Map)
 * as CBOR bytes using the given contents.
 *
 * Return true, if write was a success. False otherwise.
 */
bool fdo_cose_write_unprotected_header(fdow_t *fdow) {
	if (!fdow) {
		LOG(LOG_ERROR,
			"COSE Unprotected header: Invalid params\n");
		return false;
	}

	// empty map for now
	if (!fdow_start_map(fdow, 0)) {
		LOG(LOG_ERROR,
			"COSE Unprotected header: Failed to write start map\n");
		return false;
	}

	if (!fdow_end_map(fdow)) {
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
 * @param fdow - fdow_t object containing the buffer where CBOR data will be written
 * @param cose - fdo_cose_t object that holds the COSE_Sign1 parameters to encode
 * @return true, if write was a success. False otherwise.
 */
bool fdo_cose_write(fdow_t *fdow, fdo_cose_t *cose) {
	if (!fdow || !cose) {
		LOG(LOG_ERROR, "COSE: Invalid params\n");
		return false;
	}

	if (!fdow_tag(fdow, FDO_COSE_TAG_SIGN1)) {
		LOG(LOG_ERROR, "COSE: Failed to write Tag\n");
		return false;
	}

	if (!fdow_start_array(fdow, 4)) {
		LOG(LOG_ERROR, "COSE: Failed to write start array\n");
		return false;
	}

	if (!fdo_cose_write_protected_header(fdow, cose->cose_ph)) {
		LOG(LOG_ERROR, "COSE: Failed to write protected header\n");
		return false;
	}

	if (!fdo_cose_write_unprotected_header(fdow)) {
		LOG(LOG_ERROR, "COSE: Failed to write unprotected header\n");
		return false;
	}

	if (!fdow_byte_string(fdow, cose->cose_payload->bytes, cose->cose_payload->byte_sz)) {
		LOG(LOG_ERROR, "COSE: Failed to write payload\n");
		return false;
	}

	if (!fdow_byte_string(fdow, cose->cose_signature->bytes, cose->cose_signature->byte_sz)) {
		LOG(LOG_ERROR, "COSE: Failed to write signature\n");
		return false;
	}

	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "COSE: Failed to write end array\n");
		return false;
	}
	return true;
}

/**
 * Create Sig_structure of the form:
 * Sig_structure = [
 * context : "Signature1",
 * body_protected : empty_or_serialized_map,	// COSE Protected header as bstr
 * external_aad : bstr,
 * payload : bstr
 * ]
 * Only to be used Sig_sturcture for COSE.
 *
 * @param cose_ph - COSE protected header
 * @param cose_payload - COSE Payload
 * @param external_aad - External AAD. If NULL, empty bstr will be written, else
 * the AAD bytes will be written
 * @param sig_structure - Out buffer to store the constructred CBOR encoded Sig_structure.
 * Memory allocation will be done inside this method, if the operation is successful.
 * It will be NULL otherwise.
 * @return true, if read was a success. False otherwise.
 */
bool fdo_cose_write_sigstructure(fdo_cose_protected_header_t *cose_ph,
	fdo_byte_array_t *cose_payload, fdo_byte_array_t *external_aad,
	fdo_byte_array_t **sig_structure) {

	bool ret = false;
	char context[] = "Signature1";
	fdo_byte_array_t *empty_byte_array = NULL;
	fdow_t temp_fdow = {0};
	size_t enc_length = 0;
	size_t sig_struct_sz = 0;

	if (!cose_ph || !cose_payload || !sig_structure) {
		return false;
	}

	// size of the Sigstruct CBOR encoded buffer
	// provide buffer of 128 bytes for protected header + context + additional CBOR encoding
	if (external_aad) {
		sig_struct_sz = cose_payload->byte_sz + external_aad->byte_sz + BUFF_SIZE_128_BYTES;
	} else {
		sig_struct_sz = cose_payload->byte_sz + BUFF_SIZE_128_BYTES;
	}

	if (!fdow_init(&temp_fdow) || !fdo_block_alloc_with_size(&temp_fdow.b, sig_struct_sz) ||
		!fdow_encoder_init(&temp_fdow)) {
		LOG(LOG_ERROR, "COSE Sig_structure: FDOW Initialization/Allocation failed!\n");
		goto end;
	}

	if (!fdow_start_array(&temp_fdow, 4)) {
		LOG(LOG_ERROR, "COSE Sig_structure: Failed to write start array\n");
		return false;
	}

	if (!fdow_text_string(&temp_fdow, context, sizeof(context) - 1)) {
		LOG(LOG_ERROR, "COSE Sig_structure: Failed to write Context\n");
		return false;
	}

	if (!fdo_cose_write_protected_header(&temp_fdow, cose_ph)) {
		LOG(LOG_ERROR, "COSE Sig_structure: Failed to write protected header\n");
		return false;
	}

	if (external_aad) {
		if (!fdow_byte_string(&temp_fdow, external_aad->bytes, external_aad->byte_sz)) {
			LOG(LOG_ERROR, "COSE Sig_structure: Failed to write external_aad\n");
			goto end;
		}
	} else {
		empty_byte_array = fdo_byte_array_alloc(0);
		if (!empty_byte_array) {
			LOG(LOG_ERROR, "COSE Sig_structure: Byte Array Alloc failed\n");
			return false;
		}

		if (!fdow_byte_string(&temp_fdow, empty_byte_array->bytes, empty_byte_array->byte_sz)) {
			LOG(LOG_ERROR, "COSE Sig_structure: Failed to write external_aad\n");
			goto end;
		}
	}

	if (!fdow_byte_string(&temp_fdow, cose_payload->bytes, cose_payload->byte_sz)) {
		LOG(LOG_ERROR, "COSE Sig_structure: Failed to write payload\n");
		goto end;
	}

	if (!fdow_end_array(&temp_fdow)) {
		LOG(LOG_ERROR, "COSE Sig_structure: Failed to write end array\n");
		goto end;
	}

	enc_length = 0;
	if (!fdow_encoded_length(&temp_fdow, &enc_length) || enc_length == 0) {
		LOG(LOG_ERROR, "COSE Sig_structure: Failed to find encoded length of "
			"Sig_structure array as bstr\n");
		goto end;
	}

	// Alocate and copy the encoded Sig_sturcture bstr
	*sig_structure =
		fdo_byte_array_alloc_with_byte_array(temp_fdow.b.block, enc_length);
	if (!(*sig_structure)) {
		LOG(LOG_ERROR,
			"COSE Sig_structure: Failed to alloc output Sig_structure\n");
		goto end;
	}

	ret = true;
end:
	if (empty_byte_array) {
		fdo_byte_array_free(empty_byte_array);
	}
	if (temp_fdow.b.block || temp_fdow.current) {
		fdow_flush(&temp_fdow);
	}
	return ret;
}

/**
 * Free the given COSE_Encrypt0 object for which memory has been allocated previously.
 */
void fdo_cose_encrypt0_free(fdo_cose_encrypt0_t *cose_encrypt0) {
	if (!cose_encrypt0) {
		return;
	}
	if (cose_encrypt0->protected_header) {
		cose_encrypt0->protected_header->aes_plain_type = 0;
		fdo_free(cose_encrypt0->protected_header);
	}
	if (cose_encrypt0->unprotected_header) {
		fdo_free(cose_encrypt0->unprotected_header);
	}
	if (cose_encrypt0->payload) {
		fdo_byte_array_free(cose_encrypt0->payload);
	}

	fdo_free(cose_encrypt0);
	cose_encrypt0 = NULL;
}

/**
 * Allocate memory and return an object of fdo_cose_encrypt0_t type.
 * Memory is only allocated for protected and unprotected headers.
 * Payload is set to NULL, and should be allocated when needed.
 *
 * return allocated fdo_cose_encrypt0_t object.
 */
fdo_cose_encrypt0_t* fdo_cose_encrypt0_alloc(void) {
	fdo_cose_encrypt0_t *cose_encrypt0 = fdo_alloc(sizeof(fdo_cose_encrypt0_t));
	if (!cose_encrypt0) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc\n");
		goto err;
	}
	cose_encrypt0->protected_header = fdo_alloc(sizeof(fdo_cose_encrypt0_protected_header_t));
	if (!cose_encrypt0->protected_header) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc Protected Header\n");
		goto err;
	}

	cose_encrypt0->unprotected_header = fdo_alloc(sizeof(fdo_cose_encrypt0_unprotected_header_t));
	if (!cose_encrypt0->unprotected_header) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc Unprotected header\n");
		goto err;
	}

	// set the payload to NULL because of the way we use it.
	cose_encrypt0->payload = NULL;

	return cose_encrypt0;
err:
	if (cose_encrypt0) {
		fdo_cose_encrypt0_free(cose_encrypt0);
	}
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
bool fdo_cose_encrypt0_read_protected_header(fdor_t *fdor,
	fdo_cose_encrypt0_protected_header_t *protected_header) {

	bool ret = false;
	fdor_t temp_fdor;
	if (memset_s(&temp_fdor, sizeof(fdor_t), 0) != 0) {
		LOG(LOG_ERROR, "COSE_Encrypt0 Protected header: Failed to intialize temporary FDOR\n");
		return false;
	}

	size_t var_length = 0;
	if (!fdor_string_length(fdor, &var_length) ||
		var_length == 0) {
		LOG(LOG_ERROR, "COSE_Encrypt0 Protected header: Failed to read length\n");
		return false;
	}
	fdo_byte_array_t *ph_as_bstr = fdo_byte_array_alloc(var_length);
	if (!ph_as_bstr) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to alloc for bstr\n");
		return false;
	}
	if (!fdor_byte_string(fdor, ph_as_bstr->bytes, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to read as bstr\n");
		goto end;
	}

	// create a temporary FDOR to read (unwrap) the header contents as map
	if (!fdor_init(&temp_fdor) ||
		!fdo_block_alloc_with_size(&temp_fdor.b, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to setup temporary FDOR\n");
		goto end;
	}

	if (0 != memcpy_s(temp_fdor.b.block, temp_fdor.b.block_size,
		ph_as_bstr->bytes, ph_as_bstr->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to copy temporary unwrapped Header content\n");
		goto end;
	}

	if (!fdor_parser_init(&temp_fdor)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to init temporary FDOR parser\n");
		goto end;
	}

	if (!fdor_start_map(&temp_fdor)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to read start map\n");
		goto end;
	}

	int cose_aesplaintype_key = 0;
	if (!fdor_signed_int(&temp_fdor, &cose_aesplaintype_key) ||
		cose_aesplaintype_key != FDO_COSE_ENCRYPT0_AESPLAINTYPE_KEY) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to read AESPlainType Key\n");
		goto end;
	}

	if (!fdor_signed_int(&temp_fdor, &protected_header->aes_plain_type)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to read AESPlainType Value\n");
		goto end;
	}

	if (!fdor_end_map(&temp_fdor)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to read end map\n");
		goto end;
	}
	ret = true;
end:
	fdor_flush(&temp_fdor);
	fdo_free(temp_fdor.b.block);
	if (ph_as_bstr) {
		fdo_byte_array_free(ph_as_bstr);
	}
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
bool fdo_cose_encrypt0_read_unprotected_header(fdor_t *fdor,
	fdo_cose_encrypt0_unprotected_header_t *unprotected_header) {
	if (!fdor_start_map(fdor)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to read start map\n");
		return false;
	}

	int cose_aesiv_key = 0;
	if (!fdor_signed_int(fdor, &cose_aesiv_key) ||
		cose_aesiv_key != FDO_COSE_ENCRYPT0_AESIV_KEY) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to read AESIV Key\n");
		return false;
	}

	size_t cose_aesiv_value_length = 0;
	if (!fdor_string_length(fdor, &cose_aesiv_value_length) ||
		cose_aesiv_value_length != sizeof(unprotected_header->aes_iv)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to read AESIV Value\n");
		return false;
	}
	if (!fdor_byte_string(fdor, unprotected_header->aes_iv,
		sizeof(unprotected_header->aes_iv))) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to read AESIV Value\n");
		return false;
	}

	if (!fdor_end_map(fdor)) {
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
 * @param fdor - fdor_t object containing the buffer to read
 * @param cose_encrypt0 - fdo_cose_encrypt0_t object that will hold the read COSE_Encrypt0
 * parameters
 * @return true, if read was a success. False otherwise.
 */
bool fdo_cose_encrypt0_read(fdor_t *fdor, fdo_cose_encrypt0_t *cose_encrypt0) {
	size_t num_cose_items = 3;
	uint64_t tag = 0;

	if (!fdor || !cose_encrypt0) {
		LOG(LOG_ERROR, "COSE: Invalid params\n");
		return false;
	}

	if (!fdor_tag(fdor, &tag) || tag != FDO_COSE_TAG_ENCRYPT0) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to read/Invalid Tag\n");
		return false;
	}

	if (!fdor_array_length(fdor, &num_cose_items) || num_cose_items != 3) {
		LOG(LOG_ERROR, "COSE: Failed to read/Invalid array length\n");
		return false;
	}

	if (!fdor_start_array(fdor)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to read start array\n");
		return false;
	}

	cose_encrypt0->protected_header = fdo_alloc(sizeof(fdo_cose_encrypt0_protected_header_t));
	if (!cose_encrypt0->protected_header) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc Protected Header\n");
		goto end;
	}
	if (!fdo_cose_encrypt0_read_protected_header(fdor, cose_encrypt0->protected_header)) {
		LOG(LOG_ERROR, "COSE: Failed to read protected header\n");
		goto end;
	}

	cose_encrypt0->unprotected_header = fdo_alloc(sizeof(fdo_cose_encrypt0_unprotected_header_t));
	if (!cose_encrypt0->unprotected_header) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc Unprotected Header\n");
		goto end;
	}
	if (!fdo_cose_encrypt0_read_unprotected_header(fdor, cose_encrypt0->unprotected_header)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to read Unprotected header\n");
		goto end;
	}

	size_t payload_length = 0;
	if (!fdor_string_length(fdor, &payload_length) ||
		payload_length == 0) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to read EATpayload length\n");
		goto end;
	}
	cose_encrypt0->payload = fdo_byte_array_alloc(payload_length);
	if (!cose_encrypt0->payload) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to alloc EATPayload\n");
		goto end;
	}
	if (!fdor_byte_string(fdor, cose_encrypt0->payload->bytes, cose_encrypt0->payload->byte_sz)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to read EATpayload\n");
		goto end;
	}

	if (!fdor_end_array(fdor)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to read end array\n");
		goto end;
	}
	return true;

end:
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
bool fdo_cose_encrypt0_write_protected_header(fdow_t *fdow,
	fdo_cose_encrypt0_protected_header_t *protected_header) {

	bool ret = false;
	fdo_byte_array_t *enc_ph = NULL;
	// create temporary FDOW, use it to create Protected header map and then clear it.
	fdow_t temp_fdow = {0};

	if (!fdow || !protected_header) {
		LOG(LOG_ERROR, "COSE Protected header: Invalid params\n");
		return false;
	}

	if (!fdow_init(&temp_fdow) || !fdo_block_alloc_with_size(&temp_fdow.b, BUFF_SIZE_128_BYTES) ||
		!fdow_encoder_init(&temp_fdow)) {
		LOG(LOG_ERROR, "COSE Protected header: FDOW Initialization/Allocation failed!\n");
		goto end;
	}

	if (!fdow_start_map(&temp_fdow, 1)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to write start map\n");
		goto end;
	}

	if (!fdow_signed_int(&temp_fdow, FDO_COSE_ENCRYPT0_AESPLAINTYPE_KEY)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to write AESPlainType Key\n");
		goto end;
	}

	if (!fdow_signed_int(&temp_fdow, protected_header->aes_plain_type)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to write AESPlainType Value\n");
		goto end;
	}

	if (!fdow_end_map(&temp_fdow)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to write end map\n");
		goto end;
	}

	size_t enc_ph_length = 0;
	if (!fdow_encoded_length(&temp_fdow, &enc_ph_length) || enc_ph_length == 0) {
		LOG(LOG_ERROR, "COSE_Encrypt0 Protected header:: Failed to find encoded length\n");
		goto end;
	}
	temp_fdow.b.block_size = enc_ph_length;
	// Set the encoded payload into buffer
	enc_ph =
		fdo_byte_array_alloc_with_byte_array(temp_fdow.b.block, temp_fdow.b.block_size);
	if (!enc_ph) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to alloc for encoded Protected header\n");
		goto end;
	}

	// finally, wrap the protected header into a bstr
	if (!fdow_byte_string(fdow, enc_ph->bytes, enc_ph->byte_sz)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Protected header: Failed to write Protected header as bstr\n");
		goto end;
	}
	ret = true;
end:
	if (temp_fdow.b.block || temp_fdow.current) {
		fdow_flush(&temp_fdow);
	}
	if (enc_ph) {
		fdo_byte_array_free(enc_ph);
	}
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
bool fdo_cose_encrypt0_write_unprotected_header(fdow_t *fdow,
	fdo_cose_encrypt0_unprotected_header_t *unprotected_header) {
	if (!fdow_start_map(fdow, 1)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to write start map\n");
		return false;
	}

	if (!fdow_signed_int(fdow, FDO_COSE_ENCRYPT0_AESIV_KEY)) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to write AESIV Key\n");
		return false;
	}

	if (!fdow_byte_string(fdow, unprotected_header->aes_iv,
		sizeof(unprotected_header->aes_iv))) {
		LOG(LOG_ERROR,
			"COSE_Encrypt0 Unprotected header: Failed to write AESIV Value\n");
		return false;
	}

	if (!fdow_end_map(fdow)) {
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
 * @param fdow - fdow_t object holding the buffer where CBOR data will be written to
 * @param cose_encrypt0 - fdo_cose_encrypt0_t object that holds the COSE_Encrypt0 parameters to
 * encode
 * @return true, if write was a success. False otherwise.
 */
bool fdo_cose_encrypt0_write(fdow_t *fdow, fdo_cose_encrypt0_t *cose_encrypt0) {

	if (!fdow_tag(fdow, FDO_COSE_TAG_ENCRYPT0)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to write Tag\n");
		return false;
	}

	if (!fdow_start_array(fdow, 3)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to write start array\n");
		return false;
	}

	if (!fdo_cose_encrypt0_write_protected_header(fdow, cose_encrypt0->protected_header)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to write protected header\n");
		return false;
	}

	if (!fdo_cose_encrypt0_write_unprotected_header(fdow, cose_encrypt0->unprotected_header)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to write unprotected header\n");
		return false;
	}

	if (!fdow_byte_string(fdow, cose_encrypt0->payload->bytes, cose_encrypt0->payload->byte_sz)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to write payload\n");
		return false;
	}

	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "COSE_Encrypt0: Failed to write end array\n");
		return false;
	}
	return true;
}

/**
 * Free the given RVTO2AddrEntry object for which memory has been allocated previously.
 */
void fdo_rvto2addr_entry_free(fdo_rvto2addr_entry_t *rvto2addr_entry) {
	if (rvto2addr_entry->rvip) {
		fdo_byte_array_free(rvto2addr_entry->rvip);
	}
	if (rvto2addr_entry->rvdns) {
		fdo_string_free(rvto2addr_entry->rvdns);
	}
	fdo_free(rvto2addr_entry);
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
		fdo_free(rvto2addr);
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
 * @param fdor - fdor_t object containing the buffer to read
 * @param rvto2addr_entry - fdo_rvto2addr_entry_t object that will hold the read RVTO2AddrEntry
 * parameters
 * @return true, if read was a success. False otherwise.
 */
bool fdo_rvto2addr_entry_read(fdor_t *fdor, fdo_rvto2addr_entry_t *rvto2addr_entry) {
	size_t num_rvto2addr_entry_items = 0;
	size_t rvip_length = 0;
	size_t rvdns_length = 0;

	if (!fdor_array_length(fdor, &num_rvto2addr_entry_items) ||
		num_rvto2addr_entry_items != 4) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read/Invalid array length\n");
		return false;
	}

	if (!fdor_start_array(fdor)) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read start array\n");
		return false;
	}

	if (fdor_is_value_null(fdor) || !fdor_string_length(fdor, &rvip_length) || rvip_length == 0) {
		if (!fdor_next(fdor)) {
			LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to skip NULL RVIP\n");
			return false;
		}
	} else {
		rvip_length = 0;
		if (!fdor_string_length(fdor, &rvip_length) || rvip_length == 0) {
			LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVIP length\n");
			return false;
		}
		rvto2addr_entry->rvip = fdo_byte_array_alloc(rvip_length);
		if (!rvto2addr_entry->rvip) {
			LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to alloc RVIP\n");
			return false;
		}
		if (!fdor_byte_string(fdor, rvto2addr_entry->rvip->bytes, rvto2addr_entry->rvip->byte_sz)) {
			LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVIP\n");
			return false;
		}
	}

	if (fdor_is_value_null(fdor) || !fdor_string_length(fdor, &rvdns_length) || rvdns_length == 0) {
		if (!fdor_next(fdor)) {
			LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to skip NULL RVDNS\n");
			return false;
		}
	} else {
		rvdns_length = 0;
		if (!fdor_string_length(fdor, &rvdns_length) || rvdns_length == 0) {
			LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVDNS length\n");
			return false;
		}
		rvto2addr_entry->rvdns = fdo_string_alloc_size(rvdns_length);
		if (!rvto2addr_entry->rvdns) {
			LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to alloc RVDNS\n");
			return false;
		}

		if (!fdor_text_string(fdor, rvto2addr_entry->rvdns->bytes, rvdns_length)) {
			LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVDNS\n");
			return false;
		}
		rvto2addr_entry->rvdns->bytes[rvdns_length] = '\0';
	}

	if (!rvto2addr_entry->rvip && !rvto2addr_entry->rvdns) {
		LOG(LOG_ERROR, "RVTO2AddrEntry: Both RVIP and RVDNS can not be NULL\n");
			return false;
	} else {
		rvto2addr_entry->rvport = -1;
		if (!fdor_signed_int(fdor, &rvto2addr_entry->rvport) ||
			rvto2addr_entry->rvport == -1) {
			LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVPort\n");
			return false;
		}

		rvto2addr_entry->rvprotocol = -1;
		if (!fdor_signed_int(fdor, &rvto2addr_entry->rvprotocol) ||
			rvto2addr_entry->rvprotocol == -1) {
			LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read RVProtocol\n");
			return false;
		}

		if (!fdor_end_array(fdor)) {
			LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read end array\n");
			goto end;
		}
		return true;
	}
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
 * @param fdor - fdor_t object containing the buffer to read
 * @param rvto2addr - fdo_rvto2addr_t object that will hold the read RVTO2Addr parameters
 * @return true, if read was a success. False otherwise.
 */
bool fdo_rvto2addr_read(fdor_t *fdor, fdo_rvto2addr_t *rvto2addr) {
	size_t num_rvto2addr_items = 0;
	if (!fdor_array_length(fdor, &num_rvto2addr_items) || num_rvto2addr_items == 0) {
		LOG(LOG_ERROR, "RVTO2Addr: Failed to read/Invalid array length\n");
		return false;
	}

	if (!fdor_start_array(fdor)) {
		LOG(LOG_ERROR, "RVTO2Addr: Failed to read/Invalid array length\n");
		return false;
	}

	LOG(LOG_DEBUG, "RVTO2Addr: There are %zu RVTO2AddrEntry(s)\n", num_rvto2addr_items);

	rvto2addr->num_rvto2addr = num_rvto2addr_items;
	rvto2addr->rv_to2addr_entry = fdo_alloc(sizeof(fdo_rvto2addr_entry_t));
	if (!rvto2addr->rv_to2addr_entry) {
		LOG(LOG_ERROR, "RVTO2Addr: Failed to alloc RVTO2AddrEntry\n");
		return false;
	}
	fdo_rvto2addr_entry_t *entry = rvto2addr->rv_to2addr_entry;
	size_t i = 0;
	for (;;) {

		i++;
		if (!fdo_rvto2addr_entry_read(fdor, entry)) {
			LOG(LOG_ERROR, "RVTO2Addr: Failed to read RVTO2AddrEntry\n");
			goto end;
		}
		if (i < num_rvto2addr_items) {
			entry->next = fdo_alloc(sizeof(fdo_rvto2addr_entry_t));
			if (!entry->next) {
				LOG(LOG_ERROR, "RVTO2AddrEntry: Failed to read/Invalid array length\n");
				goto end;
			}
			entry = entry->next;
		} else {
			break;
		}
	}
	if (!fdor_end_array(fdor)) {
		LOG(LOG_ERROR, "RVTO2Addr: Failed to read end array\n");
		goto end;
	}
	return true;

end:
	if (rvto2addr->rv_to2addr_entry) {
		fdo_free(rvto2addr->rv_to2addr_entry);
	}
	return false;
}

/**
 * Verifies the ECDSA Signature using provided public key pk.
 * @param plain_text - Pointer of type fdo_byte_array_t, for generating hash,
 * @param sg - Pointer of type fdo_byte_array_t, as signature.
 * @param pk - Pointer of type fdo_public_key_t, holds the public-key used for
 * verification.
 * @return true if success, else false
 */

bool fdo_signature_verification(fdo_byte_array_t *plain_text,
				fdo_byte_array_t *sg, fdo_public_key_t *pk)
{
	int ret;
	bool signature_verify = false;

	if (!plain_text || !sg || !pk || !pk->key1) {
		return false;
	}
	if (!plain_text->bytes || !sg->bytes) {
		return false;
	}

	ret = fdo_ov_verify(plain_text->bytes, plain_text->byte_sz, sg->bytes,
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
fdo_key_value_t *fdo_kv_alloc(void)
{
	return fdo_alloc(sizeof(fdo_key_value_t));
}

/**
 * Allocate the key vlaue and initialize with the value provided
 * @param key - pointer to the key
 * @param val - pointer to the input value
 * @return pointer to the allocated key value if success else NULL.
 */
fdo_key_value_t *fdo_kv_alloc_with_str(const char *key, const char *val)
{
	if (!key || !val) {
		return NULL;
	}

	fdo_key_value_t *kv = fdo_kv_alloc();

	if (kv != NULL) {
		int key_len = strnlen_s(key, FDO_MAX_STR_SIZE);

		if (!key_len || key_len == FDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "%s(): key is either "
			    "'NULL' or 'isn't "
			    "NULL terminated'\n", __func__);
			fdo_kv_free(kv);
			return NULL;
		}

		kv->key = fdo_string_alloc_with(key, key_len);

		int val_len = strnlen_s(val, FDO_MAX_STR_SIZE);

		if (val_len == FDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR,
			    "%s(): value is either "
			    "'NULL' or 'isn't NULL terminated'\n", __func__);
			printf("vallen:%d\t, buf:%s\n", val_len, val);
			fdo_kv_free(kv);
			return NULL;
		}

		kv->str_val = fdo_string_alloc_with(val, val_len);
		if (kv->key == NULL || kv->str_val == NULL) {
			fdo_kv_free(kv);
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
fdo_key_value_t *fdo_kv_alloc_key_only(const char *key)
{
	if (!key) {
		return NULL;
	}

	fdo_key_value_t *kv = fdo_kv_alloc();

	if (kv != NULL) {
		int key_len = strnlen_s(key, FDO_MAX_STR_SIZE);

		if (!key_len || key_len == FDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "%s(): key is either "
			    "'NULL' or 'isn't "
			    "NULL terminated'\n", __func__);
			fdo_kv_free(kv);
			return NULL;
		}

		kv->key = fdo_string_alloc_with(key, key_len);
		if (kv->key == NULL) {
			fdo_kv_free(kv);
			kv = NULL;
		}
	}
	return kv;
}

/**
 * Free the allcated strutc of type key value
 * @param kv - pointer to the struct of type key value that is to be fdo_free
 */
void fdo_kv_free(fdo_key_value_t *kv)
{
	if (kv->key != NULL) {
		fdo_string_free(kv->key);
	}
	if (kv->str_val != NULL) {
		fdo_string_free(kv->str_val);
	}
	if (kv->bin_val != NULL) {
		fdo_byte_array_free(kv->bin_val);
	}
	if (kv->bool_val != NULL) {
		fdo_free(kv->bool_val);
	}
	if (kv->int_val != NULL) {
		fdo_free(kv->int_val);
	}
	fdo_free(kv);
}

//----------------------------------------------------------------------
// Service_info handling
//

/**
 * Read the CBOR encoded ServiceInfo struct.
 * ServiceInfo = [
 *   *ServiceInfoKV	// one or more ServiceInfoKV
 * ]
 * ServiceInfoKV = [
 *   ServiceInfoKey: tstr,
 *   ServiceInfoVal: bstr, cborSimpleType within
 * ]
 * ServiceInfoKey = moduleName:messageName
 * @param fdor - fdor_t object containing the buffer to read
 * @param module_list - Owner ServiceInfo module list
 * @param cb_return_val - out value to hold the return value from the registered modules.
 * @param serviceinfo_invalid_modnames - Structure to store list of unsupported module names
 * for which an access request was made by the Owner.
 * @return true if read was a success, false otherwise
 */
bool fdo_serviceinfo_read(fdor_t *fdor, fdo_sdk_service_info_module_list_t *module_list,
		int *cb_return_val, fdo_sv_invalid_modnames_t **serviceinfo_invalid_modnames) {

	bool ret = false;
	char *serviceinfokey = NULL;
	fdo_byte_array_t *serviceinfoval = NULL;
	char module_name[FDO_MODULE_NAME_LEN] = {0};
	char module_message[FDO_MODULE_MSG_LEN] = {0};
	size_t num_serviceinfokv = 0;

	if (!fdor || !module_list || !cb_return_val) {
		LOG(LOG_ERROR, "ServiceInfo read: Invalid params\n");
		return false;
	}

	if (!fdor_array_length(fdor, &num_serviceinfokv)) {
		LOG(LOG_ERROR, "ServiceInfo read: Failed to find number of items\n");
		goto exit;
	}
	if (!fdor_start_array(fdor)) {
		LOG(LOG_ERROR, "ServiceInfo read: Failed to start array\n");
		goto exit;
	}
	size_t i;
	for (i = 0; i < num_serviceinfokv; i++) {
		// ServiceInfoKV must contain 2 items: Key and Val
		size_t num_serviceinfokv_items = 0;
		if (!fdor_array_length(fdor, &num_serviceinfokv_items) ||
			num_serviceinfokv_items != 2) {
			LOG(LOG_ERROR, "ServiceInfoKV read: Invalid number of items\n");
			goto exit;
		}
		if (!fdor_start_array(fdor)) {
			LOG(LOG_ERROR, "ServiceInfoKV read: Failed to start array\n");
			goto exit;
		}

		size_t serviceinfokey_length = 0;
		size_t serviceinfoval_length = 0;
		if (!fdor_string_length(fdor, &serviceinfokey_length)) {
			LOG(LOG_ERROR, "ServiceInfoKV read: Failed to read ServiceInfoKey length\n");
			goto exit;
		}
		if (serviceinfokey_length == 0 ||
			serviceinfokey_length >= FDO_MODULE_NAME_LEN + FDO_MODULE_MSG_LEN) {
			LOG(LOG_ERROR, "ServiceInfoKV read: Received module name and message "
				"length is invalid\n");
			goto exit;
		}

		serviceinfokey = fdo_alloc(sizeof(char) * serviceinfokey_length);
		if (!serviceinfokey) {
			LOG(LOG_ERROR, "ServiceInfoKV read: Failed to alloc ServiceInfoKey\n");
			goto exit;
			}
		if (!fdor_text_string(fdor, serviceinfokey, serviceinfokey_length)) {
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
		if (serviceinfokey[index] == ':') {
			LOG(LOG_ERROR, "ServiceInfoKV read: Invalid ServiceInfoKey\n");
			*cb_return_val = MESSAGE_BODY_ERROR;
			goto exit;
		}
		while (':' != serviceinfokey[index]) {
			if (index >= sizeof(module_name) - 1) {
				LOG(LOG_ERROR, "ServiceInfoKV read: Invalid ServiceInfoKey\n");
				*cb_return_val = MESSAGE_BODY_ERROR;
				goto exit;
			}

			module_name[index] = serviceinfokey[index];
			++index;
		}
		++index;
		size_t module_msg_index = 0;
		if (serviceinfokey_length - index >= sizeof(module_message) - 1) {
			LOG(LOG_ERROR, "ServiceInfoKV read: Invalid ServiceInfoKey\n");
			*cb_return_val = MESSAGE_BODY_ERROR;
			goto exit;
		}
		while (index < serviceinfokey_length) {
			module_message[module_msg_index] = serviceinfokey[index];
			++module_msg_index;
			++index;
		}

		// start parsing ServiceInfoVal now
		if (!fdor_string_length(fdor, &serviceinfoval_length)) {
			LOG(LOG_ERROR, "ServiceInfoKV read: Failed to read ServiceInfoKey length\n");
			goto exit;
		}

		serviceinfoval = fdo_byte_array_alloc(serviceinfoval_length);
		if (!serviceinfoval) {
			LOG(LOG_ERROR,
				"ServiceInfoKV read: Failed to alloc ServiceInfoVal\n");
			goto exit;
		}

		if (!fdor_byte_string(fdor, serviceinfoval->bytes, serviceinfoval->byte_sz)) {
			LOG(LOG_ERROR, "ServiceInfoKV read: Failed to read ServiceInfoVal\n");
			goto exit;
		}

		if (!fdor_end_array(fdor)) {
			LOG(LOG_ERROR, "ServiceInfoKV read: Failed to end array\n");
			goto exit;
		}

		if (!fdo_supply_serviceinfoval(&module_name[0], &module_message[0],
				serviceinfoval, module_list, cb_return_val)) {
			LOG(LOG_ERROR, "ServiceInfoKV read: Failed to read ServiceInfoVal\n");
			goto exit;
		}

		// free the entries for reuse
		fdo_free(serviceinfokey);
		fdo_byte_array_free(serviceinfoval);
		serviceinfoval = NULL;
		if (*cb_return_val == FDO_SI_INVALID_MOD_ERROR) {
			if (!fdo_serviceinfo_invalid_modname_add(module_name,
				serviceinfo_invalid_modnames)) {
				LOG(LOG_ERROR, "ServiceInfoKV read: Failed to add invalid module name\n");
				goto exit;
			}
		}
	}
	if (!fdor_end_array(fdor)) {
		LOG(LOG_ERROR, "ServiceInfo read: Failed to end array\n");
		goto exit;
	}

	ret = true;
exit:
	if (serviceinfokey) {
		fdo_free(serviceinfokey);
	}
	if (serviceinfoval) {
		fdo_byte_array_free(serviceinfoval);
		serviceinfoval = NULL;
	}
	return ret;
}

/**
 * Traverse through the structure containing the list of unsupported/invalid module names
 * as accessed by the Owner, and add the given module name to the end of the list.
 *
 * @param module_name - Name of the unsupported module.
 * @param serviceinfo_invalid_modnames - Structure to store list of unsupported module names
 * for which an access request was made by the Owner.
 * @return true if operations was a success, false otherwise
 */
bool fdo_serviceinfo_invalid_modname_add(char *module_name,
	fdo_sv_invalid_modnames_t **serviceinfo_invalid_modnames) {

	int strcmp_diff = 0;
	size_t modname_sz_rcv = 0;
	fdo_sv_invalid_modnames_t *temp_next = NULL;
	fdo_sv_invalid_modnames_t *temp_current = NULL;

	if (!module_name || !serviceinfo_invalid_modnames) {
		return false;
	}

	// 1st module name being allocated
	if (!(*serviceinfo_invalid_modnames)) {
		*serviceinfo_invalid_modnames = fdo_alloc(sizeof(fdo_sv_invalid_modnames_t));
		if (!(*serviceinfo_invalid_modnames)) {
			LOG(LOG_ERROR,
				"Failed to alloc for unsupported modules\n");
			return false;
		}
		temp_current = *serviceinfo_invalid_modnames;
	} else {
		// serach for the key that equals to module_name
		// if found, don't add it to the list,
		// else add it to the end of the list
		temp_next = *serviceinfo_invalid_modnames;
		while (temp_next) {

			modname_sz_rcv = strnlen_s(temp_next->bytes,
				FDO_MODULE_NAME_LEN);
			if (modname_sz_rcv == 0 || modname_sz_rcv == FDO_MODULE_NAME_LEN) {
				LOG(LOG_ERROR, "Module name may not be NULL-terminated\n");
				return false;
			}

			if (0 != strcmp_s(temp_next->bytes,
					modname_sz_rcv, module_name, &strcmp_diff)) {
					LOG(LOG_ERROR,
						"Failed to compare module names for unsupported modules\n");
					return false;
			}
			if (0 == strcmp_diff) {
				return true;
			}

			temp_current = temp_next;
			temp_next = temp_next->next;
		}
		temp_current->next = fdo_alloc(sizeof(fdo_sv_invalid_modnames_t));
		if (!temp_current->next) {
			LOG(LOG_ERROR,
				"Failed to alloc for unsupported modules\n");
			return false;
		}
	}

	if (0 != strncpy_s(temp_current->bytes,
		FDO_MODULE_NAME_LEN, module_name, FDO_MODULE_NAME_LEN)) {
		LOG(LOG_ERROR,
			"Failed to copy unsupported module name\n");
		return false;
	}
	return true;
}

/**
 * Traverse through the structure containing the list of unsupported/invalid module names
 * as accessed by the Owner, and free them one-by-one. The structure itself is not freed.
 *
 * @param serviceinfo_invalid_modnames - Structure that contains the list of unsupported module
 * names to be freed.
 */
void fdo_serviceinfo_invalid_modname_free(
	fdo_sv_invalid_modnames_t *serviceinfo_invalid_modnames) {

	fdo_sv_invalid_modnames_t *next = NULL;
	fdo_sv_invalid_modnames_t *current = NULL;

	if (!serviceinfo_invalid_modnames) {
		return;
	}

	current = next = serviceinfo_invalid_modnames;
	while (current) {
		next = current->next;
		fdo_free(current);
		current = next;
	}
}

/**
 * Traverse the Module list to check if the module name is supported and active.
 * If yes, call the registered callback method that processes the ServiceInfoVal
 * and return true/false depending on callback's execution.
 * If the module name is not supported, set cb_return_val to 'FDO_SI_INVALID_MOD_ERROR'
 * and return true.
 * If the module name is not active, skip the ServiceInfoVal and return true.
 *
 * @param module_name - moduleName as received in Owner ServiceInfo
 * @param module_message - messageName as received in Owner ServiceInfo
 * @param module_val - moduleVal (bstr-unwrapped) as received in Owner ServiceInfo
 * @param module_list - Owner ServiceInfo module list
 * @param cb_return_val - out value to hold the return value from the registered modules.
 * @return true if the operation was a success, false otherwise
 */
bool fdo_supply_serviceinfoval(char *module_name, char *module_message,
	fdo_byte_array_t *module_val,
	fdo_sdk_service_info_module_list_t *module_list, int *cb_return_val)
{
	int strcmp_result = 1;
	bool retval = false;
	bool module_name_found = false;
	bool active = false;
	fdo_sdk_service_info_module_list_t *traverse_list = module_list;
	fdor_t temp_fdor = {0};

	if (!cb_return_val) {
		return retval;
	}

	if (!module_name || !module_message || !module_val) {
		*cb_return_val = FDO_SI_INTERNAL_ERROR;
		return retval;
	}

	// create a temporary FDOR to read the received unwrapped (cbor.any) ServiceInfoVal
	if (!fdor_init(&temp_fdor) ||
		!fdo_block_alloc_with_size(&temp_fdor.b, module_val->byte_sz)) {
		LOG(LOG_ERROR, "ServiceInfo - Failed to setup temporary FDOR\n");
		goto end;
	}

	if (0 != memcpy_s(temp_fdor.b.block, temp_fdor.b.block_size,
		module_val->bytes, module_val->byte_sz)) {
		LOG(LOG_ERROR, "ServiceInfo - Failed to copy buffer into temporary FDOR\n");
		goto end;
	}

	if (!fdor_parser_init(&temp_fdor)) {
		printf("ServiceInfo - Failed to perform init FDOR parser\n");
		goto end;
	}

	while (module_list) {
		strcmp_s(module_list->module.module_name, FDO_MODULE_NAME_LEN,
			 module_name, &strcmp_result);
		if (strcmp_result == 0) {
			// found the module, now check if the message is 'active'
			// if yes, read the value and activate/deactivate the module and return.
			module_name_found = true;
			strcmp_s(module_message, FDO_MODULE_MSG_LEN,
				FDO_MODULE_MESSAGE_ACTIVE, &strcmp_result);
			if (strcmp_result == 0) {
				if (!fdor_boolean(&temp_fdor, &active)) {
					LOG(LOG_ERROR, "ServiceInfoKey: Failed to read module message active %s\n",
				    	module_list->module.module_name);
					goto end;
				}

				if (active) {
					// traverse the list to deactivate every module
					while (traverse_list) {
						traverse_list->module.active = false;
						traverse_list = traverse_list->next;
					}
					// now activate the current module
					module_list->module.active = active;
					LOG(LOG_INFO, "ServiceInfo: Activated module %s\n",
						module_list->module.module_name);
				} else {
					// now de-activate the current module
					module_list->module.active = active;
					LOG(LOG_INFO, "ServiceInfo: De-activated module %s\n",
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
					FDO_SI_SET_OSI, module_message, module_val->bytes,
					&module_val->byte_sz, NULL, NULL, NULL, 0);

				if (*cb_return_val != FDO_SI_SUCCESS) {
					LOG(LOG_ERROR,
						"ServiceInfo: %s's CB Failed for type:%d\n",
						module_list->module.module_name,
						FDO_SI_SET_OSI);
					break;
				}
				retval = true;
			} else {
				LOG(LOG_ERROR, "ServiceInfo: Received ServiceInfo for an inactive module %s\n",
				    module_list->module.module_name);
				// module is present, but is not the active module. skip this ServiceInfoVal
				if (!fdor_next(&temp_fdor)) {
					LOG(LOG_DEBUG,"ServiceInfo: Failed to skip active module\n");
					goto end;
				}
				retval = true;
			}
			break;
		}
		module_list = module_list->next;
	}
	if (!module_name_found) {
			// module is not present. skip this ServiceInfoVal and
			// set cb_return_val to 'FDO_SI_INVALID_MOD_ERROR'
			LOG(LOG_ERROR,
				"ServiceInfo: Received ServiceInfo for an unsupported module %s\n",
			    module_name);
			if (!fdor_next(&temp_fdor)) {
					LOG(LOG_DEBUG,"ServiceInfo: Failed to skip unsupported module\n");
					goto end;
			}
			*cb_return_val = FDO_SI_INVALID_MOD_ERROR;
			retval = true;
	}

end:
	if (temp_fdor.b.block || temp_fdor.current) {
		fdor_flush(&temp_fdor);
	}
	return retval;
}

/**
 * Deactivate all modules in the given module_list by setting 'active' to false.
 *
 * @param module_list - Owner ServiceInfo module list
 */
bool fdo_serviceinfo_deactivate_modules(fdo_sdk_service_info_module_list_t *module_list) {

	if (!module_list) {
		return false;
	}
	fdo_sdk_service_info_module_list_t *traverse_list = module_list;
	while (traverse_list) {
		traverse_list->module.active = false;
		traverse_list = traverse_list->next;
	}
	return true;
}

/**
 * Allocate an empty fdo_service_info_t object.
 * @return an allocated fdo_service_info_t object.
 */
fdo_service_info_t *fdo_service_info_alloc(void)
{
	return fdo_alloc(sizeof(fdo_service_info_t));
}

/**
 * Free an fdo_service_info_t object
 * @param si - the object to fdo_free
 * @return none
 */
void fdo_service_info_free(fdo_service_info_t *si)
{
	fdo_key_value_t *kv = NULL;

	if (!si) {
		return;
	}
	while ((kv = si->kv) != NULL) {
		si->kv = kv->next;
		fdo_kv_free(kv);
		kv = NULL;
	}
	fdo_free(si);
	si = NULL;
}

/**
 * Compares the kv member of si with key parameter and
 * if there is match, return the matched pointer,
 * else last entry in the list.
 * @param si  - Pointer to the fdo_service_info_t object si,
 * @param key - Pointer to the char buffer key,
 * @return pointer to fdo_key_value_t.
 */
fdo_key_value_t **fdo_service_info_fetch(fdo_service_info_t *si,
					 const char *key)
{
	fdo_key_value_t **kvp = NULL, *kv = NULL;
	int res = 1;

	for (kvp = &si->kv; (kv = *kvp) != NULL; kvp = &kv->next) {
		int keylen = strnlen_s(key, FDO_MAX_STR_SIZE);

		if (!keylen || keylen == FDO_MAX_STR_SIZE) {
			LOG(LOG_DEBUG, "strlen() failed!\n");
			continue;
		}

		if ((strcasecmp_s(key, keylen, (char *)(kv->key->bytes),
				  &res) == 0) &&
		    res == 0) {
			break;
		}
	}
	return kvp;
}
/**
 * Compares the corresponding index associated with kv member of si
 * & key_num parameter, if there is match, return the matched pointer,
 * else last entry in the list.
 * @param si  - Pointer to the fdo_service_info_t object si,
 * @param key_num - Integer variable determines service request Info number,
 * @return pointer to fdo_key_value_t.
 */
fdo_key_value_t **fdo_service_info_get(fdo_service_info_t *si, int key_num)
{
	fdo_key_value_t **kvp = NULL, *kv = NULL;
	int index;

	for (kvp = &si->kv, index = 0; (kv = *kvp) != NULL;
	     kvp = &kv->next, index++) {
		if (index == key_num) {
			break;
		}
	}
	return kvp;
}

/**
 * si & key are input to the function, it looks for the matching
 * (key, value):
 * if found, update the corresponding si member with string val, if memory
 * is not allocated, allocate it.
 * if no matching entry is found, it will add a new entry at the end.
 * @param si  - Pointer to the fdo_service_info_t,
 * @param key - Pointer to the char buffer key,
 * @param val - Pointer to the char buffer val, to be updated,
 * @return true if updated correctly else false.
 */
bool fdo_service_info_add_kv_str(fdo_service_info_t *si, const char *key,
				 const char *val)
{
	fdo_key_value_t **kvp = NULL, *kv = NULL;

	if (!si || !key || !val) {
		return false;
	}

	kvp = fdo_service_info_fetch(si, key);
	kv = *kvp;
	if (kv == NULL) {
		 /* Not found, at end of linked list, add a new entry */
		kv = fdo_kv_alloc_with_str(key, val);
		if (kv == NULL) {
			return false;
		}
		*kvp = kv;  /* Use this pointer to update the next value */
		si->numKV++;
		return true;
	}

	 /* Found, update value */
	if (kv->str_val == NULL) {
		 /* No allocated string present for value, make a new one */
		kv->str_val = fdo_string_alloc_with_str(val);
	} else {
		int val_len = strnlen_s(val, FDO_MAX_STR_SIZE);

		if (!val_len || val_len == FDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR,
			    "%s(): val "
			    "is either 'NULL' or"
			    "'isn't 'NULL-terminating'\n", __func__);
			fdo_string_free(kv->str_val);
			return false;
		}

		 /* Update the string */
		fdo_string_resize_with(kv->str_val, val_len, val);
	}
	// free other values of other type
	if (kv->bin_val) {
		fdo_byte_array_free(kv->bin_val);
	}
	if (kv->int_val) {
		fdo_free(kv->int_val);
	}
	if (kv->bool_val) {
		fdo_free(kv->bool_val);
	}

	return true;
}

/**
 * si & key are input to the function, it looks for the matching
 * (key, value):
 * if found, update the corresponding si member with byte array val, if memory
 * is not allocated, allocate it.
 * if no matching entry is found, it will add a new entry at the end.
 * @param si  - Pointer to the fdo_service_info_t,
 * @param key - Pointer to the char buffer key,
 * @param val - Pointer to the byte array val, to be updated,
 * @return true if updated correctly else false.
 */
bool fdo_service_info_add_kv_bin(fdo_service_info_t *si, const char *key,
				 const fdo_byte_array_t *val)
{
	fdo_key_value_t **kvp = NULL, *kv = NULL;

	if (!si || !key || !val) {
		return false;
	}

	kvp = fdo_service_info_fetch(si, key);
	kv = *kvp;
	if (kv == NULL) {
		 /* Not found, at end of linked list, add a new entry */
		kv = fdo_kv_alloc_key_only(key);
		if (kv == NULL) {
			return false;
		}
		kv->bin_val = fdo_byte_array_alloc_with_byte_array(val->bytes, val->byte_sz);

		*kvp = kv;  /* Use this pointer to update the next value */
		si->numKV++;
		return true;
	}

	 /* Found, free the current and update value */
	if (kv->bin_val) {
		fdo_byte_array_free(kv->bin_val);
	}
	kv->bin_val = fdo_byte_array_alloc_with_byte_array(val->bytes, val->byte_sz);

	// free other values of other type
	if (kv->str_val) {
		fdo_string_free(kv->str_val);
	}
	if (kv->int_val) {
		fdo_free(kv->int_val);
	}
	if (kv->bool_val) {
		fdo_free(kv->bool_val);
	}

	return true;
}

/**
 * si & key are input to the function, it looks for the matching
 * (key, value):
 * if found, update the corresponding si member with boolean val, if memory
 * is not allocated, allocate it.
 * if no matching entry is found, it will add a new entry at the end.
 * @param si  - Pointer to the fdo_service_info_t,
 * @param key - Pointer to the char buffer key,
 * @param val - Pointer to the boolean val, to be updated,
 * @return true if updated correctly else false.
 */
bool fdo_service_info_add_kv_bool(fdo_service_info_t *si, const char *key,
				 bool val)
{
	fdo_key_value_t **kvp = NULL, *kv = NULL;

	if (!si || !key) {
		return false;
	}

	kvp = fdo_service_info_fetch(si, key);
	kv = *kvp;
	if (kv == NULL) {
		 /* Not found, at end of linked list, add a new entry */
		kv = fdo_kv_alloc_key_only(key);
		if (kv == NULL) {
			return false;
		}
		kv->bool_val = fdo_alloc(sizeof(bool));
		if (!kv->bool_val) {
			LOG(LOG_ERROR, "Failed to alloc bool Device ServiceInfoVal");
			return false;
		}
		*kv->bool_val = val;
		*kvp = kv;  /* Use this pointer to update the next value */
		si->numKV++;
		return true;
	}

	kv->bool_val = fdo_alloc(sizeof(bool));
	if (!kv->bool_val) {
		LOG(LOG_ERROR, "Failed to alloc bool Device ServiceInfoVal");
		return false;
	}
	*kv->bool_val = val;

	// free any other type of value, if present
	if (kv->str_val) {
		fdo_string_free(kv->str_val);
	}
	if (kv->bin_val) {
		fdo_byte_array_free(kv->bin_val);
	}
	if (kv->int_val) {
		fdo_free(kv->int_val);
	}

	return true;
}

/**
 * si & key are input to the function, it looks for the matching
 * (key, value):
 * if found, update the corresponding si member with integer val, if memory
 * is not allocated, allocate it.
 * if no matching entry is found, it will add a new entry at the end.
 * @param si  - Pointer to the fdo_service_info_t,
 * @param key - Pointer to the char buffer key,
 * @param val - Pointer to the integer val, to be updated,
 * @return true if updated correctly else false.
 */
bool fdo_service_info_add_kv_int(fdo_service_info_t *si, const char *key,
				 int val)
{
	fdo_key_value_t **kvp = NULL, *kv = NULL;

	if (!si || !key) {
		return false;
	}

	kvp = fdo_service_info_fetch(si, key);
	kv = *kvp;
	if (kv == NULL) {
		 /* Not found, at end of linked list, add a new entry */
		kv = fdo_kv_alloc_key_only(key);
		if (kv == NULL) {
			return false;
		}
		kv->int_val = fdo_alloc(sizeof(int));
		if (!kv->int_val) {
			LOG(LOG_ERROR, "Failed to alloc int Device ServiceInfoVal");
			return false;
		}
		*kv->int_val = val;
		*kvp = kv;  /* Use this pointer to update the next value */
		si->numKV++;
		return true;
	}

	kv->int_val = fdo_alloc(sizeof(int));
	if (!kv->int_val) {
		LOG(LOG_ERROR, "Failed to alloc int Device ServiceInfoVal");
		return false;
	}
	*kv->int_val = val;

	// free any other type of value, if present
	if (kv->str_val) {
		fdo_string_free(kv->str_val);
	}
	if (kv->bin_val) {
		fdo_byte_array_free(kv->bin_val);
	}
	if (kv->bool_val) {
		fdo_free(kv->bool_val);
	}

	return true;
}

/**
 * Add kvs object of type fdo_key_value_t to the end of the list(si) if
 * not empty else add it to the head.
 * @param si  - Pointer to the fdo_service_info_t list,
 * @param kvs - Pointer to the fdo_key_value_t kvs, to be added,
 * @return true if updated correctly else false.
 */
bool fdo_service_info_add_kv(fdo_service_info_t *si, fdo_key_value_t *kvs)
{
	fdo_key_value_t *kv = NULL;

	if (!si || !kvs) {
		return false;
	}

	// Is the list empty?  If it is, add this to the head of the list
	if (si->kv == NULL) {
		si->kv = kvs;
		si->numKV = 1;
		kvs->next = NULL;
	} else {
		// Find the last entry
		for (kv = si->kv; kv->next != NULL; kv = kv->next) {
			// Iterate till the last entry
		}
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
 *   *ServiceInfoKV		// one or more ServiceInfoKV
 * ]
 * ServiceInfoKV = [
 *   ServiceInfoKey: tstr,
 *   ServiceInfoVal: bstr (wraps any cborSimpleType)
 * ]
 * ServiceInfoKey = moduleName:messageName
 * return true if read was a success, false otherwise
 *
 * @param fdow - Pointer to the writer.
 * @param si - Pointer to the fdo_service_info_t list containing all platform
 * Device ServiceInfos.
 * @param mtu - MTU value to be used.
 * @return true if the opration was a success, false otherwise
 */
bool fdo_serviceinfo_write(fdow_t *fdow, fdo_service_info_t *si, size_t mtu)
{
	size_t num = 0;

	bool ret = false;

	if (!fdow || !si || mtu == 0) {
		goto end;
	}

	if (!fdow_start_array(fdow, si->sv_index_end - si->sv_index_begin)) {
		LOG(LOG_ERROR, "Platform Device ServiceInfo: Failed to write start array\n");
		goto end;
	}
	num = si->sv_index_begin;
	// fetch all platfrom Device ServiceInfo's one-by-one
	while (num != si->sv_index_end) {
		if (!fdo_serviceinfo_kv_write(fdow, si, num, mtu)) {
			LOG(LOG_ERROR, "Platform Device ServiceInfo: Failed to write ServiceInfoKV\n");
			goto end;
		}
		num++;
	}

	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "Platform Device ServiceInfo: Failed to write end array\n");
		goto end;
	}
	ret = true;
end:
	return ret;
}

/**
 * Write the given ServiceInfoKV contents as CBOR.
 * ServiceInfoKV = [
 *   ServiceInfoKey: tstr,
 *   ServiceInfoVal: bstr (wraps any cborSimpleType)
 * ]
 * ServiceInfoKey = moduleName:messageName
 *
 * @param fdow - Pointer to the writer.
 * @param si - Pointer to the fdo_service_info_t list containing all platform
 * Device ServiceInfos.
 * @param num - Index of the ServiceInfoKV to write
 * @param mtu - MTU value to be used.
 *
 * @return true if the opration was a success, false otherwise
 */
bool fdo_serviceinfo_kv_write(fdow_t *fdow, fdo_service_info_t *si, size_t num, size_t mtu)
{
	fdo_key_value_t **kvp = NULL;
	fdo_key_value_t *kv = NULL;
	int strcmp_diff = 0;
	fdow_t temp_fdow = {0};

	bool ret = false;

	if (!fdow || !si) {
		goto end;
	}

	kvp = fdo_service_info_get(si, num);

	kv = *kvp;
	if (!kv || !kv->key) {
		LOG(LOG_ERROR, "Platform Device ServiceInfo: Key/Value not found\n");
		goto end;
	}

	// create temporary FDOW, use it to encode ServiceInfoVal array and then clear it.
	if (!fdow_init(&temp_fdow) || !fdo_block_alloc_with_size(&temp_fdow.b, mtu) ||
		!fdow_encoder_init(&temp_fdow)) {
		LOG(LOG_ERROR,
			"Platform Device ServiceInfo: FDOW Initialization/Allocation failed!\n");
		goto end;
	}

	// start writing ServiceInfoKV
	if (!fdow_start_array(fdow, 2)) {
		LOG(LOG_ERROR, "Platform Device ServiceInfoKV: Failed to write start array\n");
		goto end;
	}

	if (!fdow_text_string(fdow, kv->key->bytes, kv->key->byte_sz)) {
		LOG(LOG_ERROR, "Platform Device ServiceInfoKV: Failed to write ServiceInfoKey\n");
		goto end;
	}

	if (0 != strcmp_s(kv->key->bytes, kv->key->byte_sz, "devmod:modules", &strcmp_diff)) {
		LOG(LOG_ERROR, "Platform Device ServiceInfoKV: Failed to compare\n");
		goto end;
	}
	if (strcmp_diff == 0) {
		// write value "[1,1,"fdo_sys"]" for "devmod:modules" ServiceInfoKey
		// TO-DO: Update this when multi-module support is added.
		if (!fdo_serviceinfo_modules_list_write(&temp_fdow)) {
			LOG(LOG_ERROR, "Platform Device ServiceInfoKeyVal: Failed to write modules\n");
			goto end;
		}
	} else {

		// CBOR-encode the appropriate ServiceInfoVal using temporary FDOW
		if (kv->str_val) {
			if (!fdow_text_string(&temp_fdow, kv->str_val->bytes,
				si->sv_val_index == 0 ? (size_t) kv->str_val->byte_sz : si->sv_val_index)) {
				LOG(LOG_ERROR, "Platform Device ServiceInfoKV: Failed to write Text ServiceInfoVal\n");
				goto end;
			}
		} else if (kv->bin_val) {
			if (!fdow_byte_string(&temp_fdow, kv->bin_val->bytes,
				si->sv_val_index == 0 ? kv->bin_val->byte_sz : si->sv_val_index)) {
				LOG(LOG_ERROR, "Platform Device ServiceInfoKV: Failed to write Binary ServiceInfoVal\n");
				goto end;
			}
		} else if (kv->bool_val) {
			if (!fdow_boolean(&temp_fdow, *kv->bool_val)) {
				LOG(LOG_ERROR, "Platform Device ServiceInfoKV: Failed to write Bool ServiceInfoVal\n");
				goto end;
			}
		} else if (kv->int_val) {
			if (!fdow_signed_int(&temp_fdow, *kv->int_val)) {
				LOG(LOG_ERROR, "Platform Device ServiceInfoKV: Failed to write Int ServiceInfoVal\n");
				goto end;
			}
		} else {
			LOG(LOG_ERROR, "Platform Device ServiceInfoKV: No ServiceInfoVal found\n");
			goto end;
		}
	}

	if (!fdow_encoded_length(&temp_fdow, &temp_fdow.b.block_size)) {
		LOG(LOG_ERROR, "Platform Device ServiceInfoKV: Failed to get encoded length\n");
		goto end;
	}

	// Now, wrap the CBOR-encoded ServiceInfoVal at temporary FDOW, into a bstr
	if (!fdow_byte_string(fdow, temp_fdow.b.block, temp_fdow.b.block_size)) {
		LOG(LOG_ERROR,
			"Platform Device ServiceInfoKV: Failed to write ServiceInfoVal as bstr\n");
		goto end;
	}

	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "Platform Device ServiceInfoKV: Failed to write end array\n");
		goto end;
	}
	ret = true;
end:
	if (temp_fdow.b.block || temp_fdow.current) {
		fdow_flush(&temp_fdow);
	}
	return ret;
}

/**
 * Write the key 'devmod:modules' with value of form [int, int, text,....]
 * into the given FDOW object. Currently, it only writes 1 ServiceInfo module name
 * 'fdo_sys', i.e [1,1,"fdo_sys"].
 * @param fdow - Pointer to the writer.
 */
bool fdo_serviceinfo_modules_list_write(fdow_t *fdow) {

	bool ret = false;
	char module_value[8] = "fdo_sys";

	if (!fdow_start_array(fdow, 3)) {
		LOG(LOG_ERROR,
			"Platform Device ServiceInfoKV: Failed to start ServiceInfoVal (modules) array\n");
		goto end;
	}
	if (!fdow_signed_int(fdow, 1)) {
		LOG(LOG_ERROR,
			"Platform Device ServiceInfoKV: Failed to write ServiceInfoVal (modules) nummodules\n");
		goto end;
	}
	if (!fdow_signed_int(fdow, 1)) {
		LOG(LOG_ERROR,
			"Platform Device ServiceInfoKV: Failed to write ServiceInfoVal (modules) return count\n");
		goto end;
	}
	if (!fdow_text_string(fdow, module_value, strnlen_s(module_value, FDO_MAX_STR_SIZE))) {
		LOG(LOG_ERROR,
			"Platform Device ServiceInfoKV: Failed to write ServiceInfoVal (modules) module name\n");
		goto end;
	}
	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "Platform Device ServiceInfoKV: Failed to end array\n");
		goto end;
	}
	ret = true;
end:
	return ret;
}

/**
 * Return bool value representing whether any external ServiceInfo module has message to
 * send in the NEXT iteration. This determines the TO2.DeviceServiceInfo.IsMoreServiceInfo value
 * for any currently active module.
 *
 * @param fdow - Pointer to the writer.
 * @param module_list - Pointer to the ServiceInfo module list containing all
 * Device ServiceInfos modules.
 * @param mtu - MTU to be used for fitting the values.
 * @param is_more - Out parameter (Pointer) that will store the callback's value for
 * TO2.DeviceServiceInfo.IsMoreServiceInfo.
 *
 * @return true the operation was a success, false otherwise.
 */
bool fdo_serviceinfo_external_mod_is_more(fdow_t *fdow,
	fdo_sdk_service_info_module_list_t *module_list, size_t mtu, bool *is_more) {

	if (!fdow || !module_list || !is_more) {
		return false;
	}
	fdo_sdk_service_info_module_list_t *traverse_list = module_list;
	bool more = false;

	while (traverse_list) {
		if (traverse_list->module.active &&
			traverse_list->module.service_info_callback(
			FDO_SI_IS_MORE_DSI, NULL, NULL, NULL, NULL, NULL, &more, mtu) != FDO_SI_SUCCESS) {
			LOG(LOG_DEBUG, "Sv_info: %s's CB Failed for type:%d\n",
			    traverse_list->module.module_name, FDO_SI_HAS_MORE_DSI);
			return false;
		}
		if (more) {
			*is_more = more;
			return more;
		}
		traverse_list = traverse_list->next;
	}
	return true;
}

/**
 * Return a module reference that has some ServiceInfo to be sent NOW/immediately,
 * by making callbacks to each active module, to determine whether the module
 * has something to send immediately.
 *
 * @param fdow - Pointer to the writer.
 * @param module_list - Pointer to the ServiceInfo module list containing all
 * Device ServiceInfos modules.
 * @param mtu - MTU to be used for fitting the values.
 *
 * @return Pointer to/module reference (fdo_sdk_service_info_module *) if there is any module
 * that has ServiceInfo to send NOW/immediately, else return NULL.
 */
fdo_sdk_service_info_module* fdo_serviceinfo_get_external_mod_to_write(fdow_t *fdow,
	fdo_sdk_service_info_module_list_t *module_list, size_t mtu) {

	if (!fdow || !module_list) {
		return NULL;
	}
	fdo_sdk_service_info_module_list_t *traverse_list = module_list;
	bool has_more = false;

	while (traverse_list) {
		if (traverse_list->module.active &&
			traverse_list->module.service_info_callback(
			FDO_SI_HAS_MORE_DSI, NULL, NULL, NULL, NULL, &has_more, NULL, mtu) != FDO_SI_SUCCESS) {
			LOG(LOG_DEBUG, "Sv_info: %s's CB Failed for type:%d\n",
			    traverse_list->module.module_name, FDO_SI_HAS_MORE_DSI);
			return NULL;
		}
		if (has_more) {
			return &(traverse_list->module);
		}
		traverse_list = traverse_list->next;
	}
	return NULL;
}

/**
 * Given an active ServiceInfo module, invoke the callback on the same,
 * to get the number of ServiceInfoKVs and CBOR-encoded ServiceInfoVal to be sent.
 * Use the same to then write the 'ServiceInfo' structure.
 *
 * NOTE: This currently writes ONLY 1 ServiceInfoKV inside ServiceInfo array.
 * This can be extended to write multiple ServiceInfoKVs, but would require us
 * to fit those within MTU here (similar to devmod + unsupported module mtu fitting).
 *
 * @param fdow - Pointer to the writer.
 * @param ext_serviceinfo - Pointer to store CBOR-encoded ServiceInfoVal from the module.
 * @param module - Pointer to the ServiceInfo module list containing all
 * Device ServiceInfos modules.
 * @param mtu - MTU to be used for fitting the values.
 *
 * @return Return true if the operation was successful, else return false.
 */
bool fdo_serviceinfo_external_mod_write(fdow_t *fdow,
	fdo_byte_array_t *ext_serviceinfo,
	fdo_sdk_service_info_module *module,
	size_t mtu) {

	char serviceinfokv_key[FDO_MODULE_NAME_LEN + FDO_MODULE_MSG_LEN + 1] = {0};
	char module_message[FDO_MODULE_MSG_LEN] = {0};
	size_t module_name_sz = 0;
	size_t module_message_sz = 0;

	if (!fdow || !ext_serviceinfo || !module || !module->active) {
		return false;
	}

	// clear for immmediate usage and use ext_serviceinfo.byte_sz to store the final length
	if (memset_s(ext_serviceinfo->bytes, ext_serviceinfo->byte_sz, 0)) {
		LOG(LOG_ERROR,
			"Device ServiceInfoKV: Failed to clear memory for external ServiceInfoVal\n");
		return false;
	}
	// get the CBOR-encoded ServiceInfoVal from the external module
	if (module->service_info_callback(FDO_SI_GET_DSI, &module_message[0],
		ext_serviceinfo->bytes, &ext_serviceinfo->byte_sz,
		NULL, NULL, NULL, mtu) != FDO_SI_SUCCESS) {
		LOG(LOG_DEBUG, "Sv_info: %s's CB Failed for type:%d\n",
			module->module_name, FDO_SI_GET_DSI);
		return false;
	}

	// create 'modulename:modulemessage'
	module_name_sz = strnlen_s(module->module_name, sizeof(module->module_name));
	if (memcpy_s(&serviceinfokv_key[0], module_name_sz,
		module->module_name, module_name_sz) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}
	serviceinfokv_key[module_name_sz] = ':';
	// finally form "modulename:modulemessage" by appending 'modulemessage'
	module_message_sz = strnlen_s(module_message, sizeof(module_message));
	if (memcpy_s(&serviceinfokv_key[module_name_sz + 1], module_message_sz,
		module_message, module_message_sz) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return false;
	}
	serviceinfokv_key[module_name_sz + 1 + module_message_sz] = '\0';

	// start writing ServiceInfo array
	if (!fdow_start_array(fdow, 1)) {
		LOG(LOG_ERROR, "Device ServiceInfo: Failed to write start ServiceInfo array\n");
		return false;
	}

	// now start writing ServiceInfoKV array
	if (!fdow_start_array(fdow, 2)) {
		LOG(LOG_ERROR, "Device ServiceInfoKV: Failed to write start ServiceInfoKV array\n");
		return false;
	}

	// Write ServiceInfoKey
	if (!fdow_text_string(fdow, serviceinfokv_key, module_name_sz + 1 + module_message_sz)) {
		LOG(LOG_ERROR, "Device ServiceInfoKV: Failed to write ServiceInfoKey\n");
		return false;
	}

	// bstr-wrap ServiceInfoVal
	if (!fdow_byte_string(fdow, ext_serviceinfo->bytes, ext_serviceinfo->byte_sz)) {
		LOG(LOG_ERROR, "Device ServiceInfoKV: Failed to write ServiceInfoVal as bstr\n");
		return false;
	}

	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "Device ServiceInfo: Failed to write ServiceInfoKV end array\n");
		return false;
	}

	if (!fdow_end_array(fdow)) {
		LOG(LOG_ERROR, "Device ServiceInfo: Failed to write ServiceInfo end array\n");
		return false;
	}
	return true;
}

/**
 * Fit as many ServiceInfo as possible in the given MTU.
 * The key-values are CBOR encoded once to decide how many
 * key-value pairs (partial/complete), can be fitted within the
 * current message as per MTU.
 * NOTE: Might need to be updated when multiple Device ServiceInfo module
 * aupport is added, since this operation might be module-specific (TO-DO).
 *
 * @param fdow - FDOW writer to be used for encoding
 * @param si - Pointer to the fdo_service_info_t list containing all platform
 * Device ServiceInfos.
 * @param mtu - MTU to be used for fitting the values
* @return Return true if operation was successful, else return false.
 */
bool fdo_serviceinfo_fit_mtu(fdow_t *fdow, fdo_service_info_t *si, size_t mtu) {

	bool ret = false;
	fdo_key_value_t *kv = NULL;
	fdo_key_value_t **kvp = NULL;

	size_t num = 0;
	size_t encoded_length = 0;
	size_t fit_so_far = 0;

	if (!fdow || !si) {
		return false;
	}

	num = si->sv_index_end;
	si->sv_index_begin = si->sv_index_end;

	// just start writing the ServiceInfo till numKV, but don't end it
	// since it does not matter in finding out encoded length,
	// and is not going to be used for any other purposes
	if (!fdow_start_array(fdow, si->numKV)) {
		LOG(LOG_ERROR, "Failed to write start array\n");
		goto end;
	}

	// fetch all Device ServiceInfo's one-by-one
	while (num != si->numKV) {

		encoded_length = 0;
		if (!fdo_serviceinfo_kv_write(fdow, si, num, mtu)) {
			LOG(LOG_ERROR, "Failed to write ServiceInfoKV\n");
			goto end;
		}
		if (!fdow_encoded_length(fdow, &encoded_length) || encoded_length == 0) {
			LOG(LOG_ERROR, "Failed to read ServiceInfoKV length\n");
			goto end;
		}
		if (encoded_length >= mtu) {
			// this key-value does not fit within the MTU
			// now, check if atleast the key fits with some room for value
			kvp = fdo_service_info_get(si, num);
			kv = *kvp;
			if ((fit_so_far + kv->key->byte_sz + 10) < mtu) {
				// the key fits and atleast 10 bytes of value fits
				// the difference gives the exact length exceeding the MTU
				// for the given key and partial value
				si->sv_val_index = encoded_length - mtu;
				si->sv_index_end++;
				ret = true;
				goto end;
			} else {
				// key and partial value cannot be fit within the MTU,
				// ignore this key and value, return
				si->sv_val_index = 0;
				ret = true;
				goto end;
			}
		} else {
			// both key and value fit within the MTU
			si->sv_index_end++;
			si->sv_val_index = 0;
			fit_so_far = encoded_length;
		}
		num++;
	}
	ret = true;
end:
	while (fdow->current->previous) {
		// recursively move to previous and free current
		// this is done because we cannot close the arrays created initially
		fdow->current = fdow->current->previous;
		fdo_free(fdow->current->next);
	}
	return ret;
}

/**
 * Execute Sv_info Module's callback with the provided svinfo type,
 * @param module_list - Global Module List Head Pointer.
 * @param type - a valid Sv_info type.
 * @return true if success, false otherwise
 */
bool fdo_mod_exec_sv_infotype(fdo_sdk_service_info_module_list_t *module_list,
			      fdo_sdk_si_type type)
{
	while (module_list) {
		if (module_list->module.service_info_callback(
			type, NULL, NULL, NULL, NULL, NULL, NULL, 0) != FDO_SI_SUCCESS) {
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
void fdo_sv_info_clear_module_psi_osi_index(fdo_sdk_service_info_module_list_t
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
bool fdo_compare_hashes(fdo_hash_t *hash1, fdo_hash_t *hash2)
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
bool fdo_compare_byte_arrays(fdo_byte_array_t *ba1, fdo_byte_array_t *ba2)
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
bool fdo_compare_rv_lists(fdo_rendezvous_list_t *rv_list1,
			  fdo_rendezvous_list_t *rv_list2)
{
	bool retval = false;
	int rv_directive_index = 0;
	int rv_instr_index = 0;
	fdo_rendezvous_list_t *rv_list1_traverse = rv_list1;
	fdo_rendezvous_list_t *rv_list2_traverse = rv_list2;

	if (!rv_list1_traverse || !rv_list2_traverse) {
		LOG(LOG_ERROR, "Received NULL arguments\n");
		goto end;
	}

	if (rv_list1_traverse->num_rv_directives != rv_list2_traverse->num_rv_directives) {
		LOG(LOG_ERROR, "Number of RendezvousDirective(s) do not match\n");
		goto end;
	}
	while (rv_directive_index < rv_list1_traverse->num_rv_directives &&
		rv_directive_index < rv_list2_traverse->num_rv_directives) {
		fdo_rendezvous_directive_t *directive1 =
			fdo_rendezvous_directive_get(rv_list1_traverse, rv_directive_index);
		fdo_rendezvous_directive_t *directive2 =
			fdo_rendezvous_directive_get(rv_list2_traverse, rv_directive_index);
		if (!directive1 || !directive2) {
			LOG(LOG_ERROR, "One of the RendezvousDirective(s) is empty\n");
			goto end;
		}
		rv_instr_index = 0;
		while (rv_instr_index < directive1->num_entries &&
			rv_instr_index < directive2->num_entries) {
			fdo_rendezvous_t *entry_ptr1 =
				fdo_rendezvous_list_get(directive1, rv_instr_index);
			fdo_rendezvous_t *entry_ptr2 =
				fdo_rendezvous_list_get(directive2, rv_instr_index);
			if ((!entry_ptr1 || !entry_ptr2)) {
				LOG(LOG_ERROR, "One of the RendezvousInstr(s) is empty\n");
				goto end;
			}
			if (!fdo_rendezvous_instr_compare(entry_ptr1, entry_ptr2)) {
				LOG(LOG_ERROR, "One of the RendezvousInstr(s) is empty\n");
				goto end;
			}
			rv_instr_index++;
		}
		rv_directive_index++;
	}
	retval = true;
end:
	return retval;
}

/**
 * Compare the given RendezvousInstr(s) represented by the two fdo_rendezvous_t, with one another.
 *
 * @param entry1: pointer to input first fdo_rendezvous_t object
 * @param entry2: pointer to input second fdo_rendezvous_t object
 * @return
 *        true if both RendexvousInstr(s) are same else false.
 */
bool fdo_rendezvous_instr_compare(fdo_rendezvous_t *entry1, fdo_rendezvous_t *entry2) {

	int memcmp_diff = -1;

	if (!entry1 || !entry2) {
		LOG(LOG_ERROR, "Received NULL arguments\n");
		return false;
	}

	if (entry1->dev_only != NULL && entry2->dev_only != NULL &&
		*entry1->dev_only ==  *entry2->dev_only) {
		return true;
	}

	if (entry1->owner_only != NULL && entry2->owner_only != NULL &&
		*entry1->owner_only ==  *entry2->owner_only) {
		return true;
	}

	if (entry1->ip != NULL && entry2->ip != NULL) {
		if (!memcmp_s(entry1->ip->addr, entry1->ip->length,
			entry2->ip->addr,entry1->ip->length, &memcmp_diff) &&
	    	!memcmp_diff) {
			return true;
		} else {
			return false;
		}
	}

	if (entry1->po != NULL && entry2->po != NULL &&
		*entry1->po ==  *entry2->po) {
		return true;
	}

	if (entry1->pow != NULL && entry2->pow != NULL &&
		*entry1->pow ==  *entry2->pow) {
		return true;
	}

	if (entry1->dn != NULL && entry2->dn != NULL &&
		entry1->dn->byte_sz == entry2->dn->byte_sz &&
		0 == strncmp(entry1->dn->bytes, entry2->dn->bytes, entry1->dn->byte_sz)) {
		return true;
	}

	if (entry1->sch != NULL && entry2->sch != NULL &&
		fdo_compare_hashes(entry1->sch, entry2->sch)) {
		return true;
	}

	if (entry1->cch != NULL && entry2->cch != NULL &&
		fdo_compare_hashes(entry1->cch, entry2->cch)) {
		return true;
	}

	if (entry1->ui != NULL && entry2->ui != NULL &&
		*entry1->ui ==  *entry2->ui) {
		return true;
	}

	if (entry1->ss != NULL && entry2->ss != NULL &&
		entry1->ss->byte_sz == entry2->ss->byte_sz &&
		0 == strncmp(entry1->ss->bytes, entry2->ss->bytes, entry1->ss->byte_sz)) {
		return true;
	}

	if (entry1->pw != NULL && entry2->pw != NULL &&
		entry1->pw->byte_sz == entry2->pw->byte_sz &&
		0 == strncmp(entry1->pw->bytes, entry2->pw->bytes, entry1->pw->byte_sz)) {
		return true;
	}

	if (entry1->me != NULL && entry2->me != NULL &&
		*entry1->me ==  *entry2->me) {
		return true;
	}

	if (entry1->pr != NULL && entry2->pr != NULL &&
		*entry1->pr ==  *entry2->pr) {
		return true;
	}

	if (entry1->delaysec != NULL && entry2->delaysec != NULL &&
		*entry1->delaysec ==  *entry2->delaysec) {
		return true;
	}

	if (entry1->bypass != NULL && entry2->bypass != NULL &&
		*entry1->bypass ==  *entry2->bypass) {
		return true;
	}

	LOG(LOG_ERROR, "RendezvousInstr: Received invalid RVVariable to compare\n");
	return false;
}

void fdo_log_block(fdo_block_t *fdob) {
	size_t i;
	for (i = 0; i < fdob->block_size; i++) {
		LOG(LOG_DEBUGNTS, "%02x", fdob->block[i]);
	}
	LOG(LOG_DEBUGNTS, "\n");
}

