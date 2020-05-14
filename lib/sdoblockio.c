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
bool _read_expected_char(sdor_t *sdor, char expected);
bool _read_comma(sdor_t *sdor);
// bool _read_expected_charNC(sdor_t *sdor, char expected);
void _padstring(sdow_t *sdow, const char *s, int len, bool escape);
void _writespecialchar(sdow_t *sdow, char c);

// These are intended to be inlined...
void sdo_skipC(sdo_block_t *sdob);
void sdoBPutC(sdo_block_t *sdob, char c);
int sdob_getc(sdo_block_t *sdob, char *c);

int sdob_peekc(sdo_block_t *sdob)
{
	if ((NULL == sdob->block) || (sdob->cursor >= sdob->block_size)) {
		return -1;
	}
	return sdob->block[sdob->cursor];
}

/**
 * Internal API
 */
int sdob_getc(sdo_block_t *sdob, char *c)
{
	if ((NULL == sdob->block) || (sdob->cursor >= sdob->block_size)) {
		c = "";
		return -1;
	}
        *c = (char)sdob->block[sdob->cursor++];
	return 0;
}

/**
 * Internal API
 */
void sdo_skipC(sdo_block_t *sdob)
{
	if (sdob->cursor < sdob->block_size)
		sdob->cursor++;
}

/**
 * Internal API
 */
void sdoBPutC(sdo_block_t *sdob, char c)
{
	if (sdob->cursor >= sdob->block_max)
		sdo_resize_block(sdob, sdob->block_max + 1);
	sdob->block[sdob->cursor++] = c;
}

/**
 * Internal API
 */
void sdo_block_init(sdo_block_t *sdob)
{
	if (sdob->block != NULL)
		sdo_free(sdob->block);
	sdob->block = NULL;
	sdob->block_max = 0;
	sdo_block_reset(sdob);
}

/**
 * Internal API
 */
void sdo_block_reset(sdo_block_t *sdob)
{
	if (sdob) {
		sdob->cursor = 0;
		sdob->block_size = 0;
	}
}

#if 0 // deprecated
/**
 * Internal API
 */
int hexit_to_int(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	LOG(LOG_ERROR, "SDO: expected hex digit, got %c\n", c);
	return 0;

}

/**
 * Internal API
 */
int int_to_hexit(int v)
{
	v &= 0xf;
	return v + (v <= 9 ? '0' : 'a' - 10);
}
#endif

/**
 * Internal API
 */
void sdo_resize_block(sdo_block_t *sdob, int need)
{
	if (need > sdob->block_max) {
		int new_size = (need + SDO_BLOCKINC - 1) & SDO_BLOCK_MASK;

		sdob->block = realloc(sdob->block, new_size);
		sdob->block_max = new_size;

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
 * @param rcv_data - Pointer to received file data.
 *
 * @return
 *        return 0 on success. -ve value on failure.
 */
bool sdor_init(sdor_t *sdor, SDOReceive_fcn_ptr_t rcv, void *rcv_data)
{
	if (memset_s(sdor, sizeof(*sdor), 0) != 0) {
		LOG(LOG_ERROR, "SDOR memset() failed!\n");
		return false;
	}

	sdo_block_init(&sdor->b);

	sdor->receive = rcv;
	sdor->receive_data = rcv_data;
	sdor->have_block = false;

	return true;
}

/**
 * Internal API
 */
int sdor_peek(sdor_t *sdor)
{
	sdo_block_t *sdob = &sdor->b;

	return sdob_peekc(sdob);
}

/**
 * Internal API
 */
void sdor_flush(sdor_t *sdor)
{
	sdo_block_t *sdob = &sdor->b;

	sdo_block_reset(sdob);
	sdor->need_comma = false;
	sdor->have_block = false;
}

/**
 * Internal API
 */
bool sdor_have_block(sdor_t *sdor)
{
	return sdor->have_block;
}

/**
 * Internal API
 */
void sdor_set_have_block(sdor_t *sdor)
{
	sdor->have_block = true;
}

/**
 * Internal API
 */
bool sdor_next_block(sdor_t *sdor, uint32_t *typep)
{
	if (!sdor->have_block)
		return false;

	*typep = sdor->msg_type;
	//	sdor_begin_object(sdor);
	return true;
}

/**
 * Internal API
 */
uint8_t *sdor_get_block_ptr(sdor_t *sdor, int from_cursor)
{
	if (from_cursor < 0)
		from_cursor = sdor->b.cursor;
	if (from_cursor > sdor->b.block_size) {
		LOG(LOG_ERROR, "%s(%u) is too big\n",
		    __func__, from_cursor);
		return NULL;
	}
	return &sdor->b.block[from_cursor];
}

/**
 * Internal API
 */
uint8_t *sdow_get_block_ptr(sdow_t *sdow, int from_cursor)
{
	if (from_cursor < 0)
		from_cursor = sdow->b.cursor;
	if (from_cursor > sdow->b.block_size) {
		LOG(LOG_ERROR, "%s(%u) is too big\n",
		    __func__, from_cursor);
		return NULL;
	}
	return &sdow->b.block[from_cursor];
}

/**
 * Internal API
 */
bool _read_expected_char(sdor_t *sdor, char expected)
{
	char c;
	int ret_value = sdob_getc(&sdor->b, &c);

	if ((0 != ret_value) || (c != expected)) {
		LOG(LOG_ERROR, "expected '%c' at cursor %u, got '%c'.\n",
		    expected, sdor->b.cursor - 1, c);
		return false;
	}
	return true;
}

/**
 * Internal API
 */
bool _read_comma(sdor_t *sdor)
{
	if (sdor->need_comma) {
		sdor->need_comma = false;
		return _read_expected_char(sdor, ',');
	}
	return true;
}

/**
 * Internal API
 */
static bool _read_expected_char_comma_before(sdor_t *sdor, char expected)
{
	int r;

	if (!_read_comma(sdor)) {
		LOG(LOG_ERROR, "we were expecting , here!\n");
		return false;
	}

	r = _read_expected_char(sdor, expected);
	sdor->need_comma = false;
	return r;
}

/**
 * Internal API
 */
static bool _read_expected_char_comma_after(sdor_t *sdor, char expected)
{
	int r = _read_expected_char(sdor, expected);

	sdor->need_comma = true;
	return r;
}

/**
 * Internal API
 */
bool sdor_begin_sequence(sdor_t *sdor)
{
	return _read_expected_char_comma_before(sdor, '[');
}

/**
 * Internal API
 */
bool sdor_end_sequence(sdor_t *sdor)
{
	return _read_expected_char_comma_after(sdor, ']');
}

/**
 * Internal API
 */
bool sdor_begin_object(sdor_t *sdor)
{
	return _read_expected_char_comma_before(sdor, '{');
}

/**
 * Internal API
 */
bool sdor_end_object(sdor_t *sdor)
{
	return _read_expected_char_comma_after(sdor, '}');
}

/**
 * Internal API
 */
void sdor_read_and_ignore_until(sdor_t *sdor, char expected)
{
	char c;
	int ret_value;

	while (1) {
		ret_value = sdob_getc(&sdor->b, &c);
		if (0 == ret_value && expected != c && c != '\0')
			continue;
		break;
	}
}

/**
 * Internal API
 */
void sdor_read_and_ignore_until_end_sequence(sdor_t *sdor)
{
	sdor_read_and_ignore_until(sdor, ']');
	sdor->need_comma = true;
}

/**
 * Internal API
 */
uint32_t sdo_read_uint(sdor_t *sdor)
{
	uint32_t r = 0;
	int c;
	sdo_block_t *sdob = &sdor->b;

	if (!_read_comma(sdor))
		LOG(LOG_ERROR, "we were expecting , here!\n");

	while ((c = sdob_peekc(sdob)) != -1 && c >= '0' && c <= '9') {
		sdo_skipC(sdob);
		r = (r * 10) + (c - '0');
	}
	sdor->need_comma = true;
	return r;
}

/**
 * Internal API
 */
int sdo_read_string_sz(sdor_t *sdor)
{
	int n, save_cursor;
	bool save_need_comma;
	char c;

	save_need_comma = sdor->need_comma;
	save_cursor = sdor->b.cursor;
	n = sdo_read_string(sdor, &c, 1);
	sdor->b.cursor = save_cursor;
	sdor->need_comma = save_need_comma;
	return n;
}

/**
 * Internal API
 * Read the complete array block without changing the cursor and
 * return the size required. i.e "[" to "]"
 */
int sdo_read_array_sz(sdor_t *sdor)
{
	int save_cursor;
	bool save_need_comma;
	char c;
	int32_t size_of_buffer = 0;
	bool ct_end_wait = false;
	int ret_value;

	save_need_comma = sdor->need_comma;
	save_cursor = sdor->b.cursor;
	sdor->b.cursor--;
	while (1) {
		ret_value = sdob_getc(&sdor->b , &c);
		if (-1 == ret_value) {
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

	sdor->b.cursor = save_cursor;
	sdor->need_comma = save_need_comma;
	return size_of_buffer;
}

/**
 * Internal API
 * Read the complete array block without changing the cursor and
 * return the size populated in the buf. i.e "[" to "]"
 */
int sdo_read_array_no_state_change(sdor_t *sdor, uint8_t *buf)
{
	int save_cursor;
	bool save_need_comma;
	char c;
	int32_t size_of_buffer = 0;
	bool ct_end_wait = false;
	int ret_value;

	save_need_comma = sdor->need_comma;
	save_cursor = sdor->b.cursor;
	sdor->b.cursor--;
	while (1) {
		ret_value = sdob_getc(&sdor->b, &c);
		if (-1 == ret_value) {
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

	sdor->b.cursor = save_cursor;
	sdor->need_comma = save_need_comma;
	return size_of_buffer;
}

/**
 * Internal API
 */
int sdo_read_string(sdor_t *sdor, char *bufp, int buf_sz)
{
	int n;
	char c;
	char *limit = bufp + (buf_sz - 1);
	sdo_block_t *sdob = &sdor->b;
	int ret_value;

	if (!_read_comma(sdor)) {
		LOG(LOG_ERROR, "we were expecting , here!\n");
		return 0;
	}

	if (!_read_expected_char(sdor, '"')) {
		LOG(LOG_ERROR, "Expected char read is not \"\n");
		return 0;
	}

	n = 0;
	ret_value = sdob_getc(sdob, &c);
	while (c != '"' && ret_value != -1) {
		++n;
		if (bufp < limit)
			*bufp++ = c;
		ret_value = sdob_getc(sdob, &c);
	}
	*bufp = 0;
	sdor->need_comma = true;
	return n;
}

/**
 * Internal API
 */
int sdo_read_tag(sdor_t *sdor, char *bufp, int buf_sz)
{
	int n = sdo_read_string(sdor, bufp, buf_sz);

	if (!_read_expected_char(sdor, ':')) {
		LOG(LOG_ERROR, "Expected char read is not :\n");
		return 0;
	}

	sdor->need_comma = false;
	return n;
}

/**
 * Internal API
 */
bool sdo_read_tag_finisher(sdor_t *sdor)
{
	sdor->need_comma = false;
	return _read_expected_char(sdor, ':');
}

/**
 * Internal API
 */
int sdo_read_expected_tag(sdor_t *sdor, const char *tag)
{
	char buf[SDO_TAG_MAX_LEN] = {0};
	int strcmp_result = 0;

	sdo_read_tag(sdor, &buf[0], sizeof(buf));
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
int sdo_read_big_num_field(sdor_t *sdor, uint8_t *bufp, int buf_sz)
{
	return sdo_read_big_num_asterisk_hack(sdor, bufp, buf_sz, NULL);
}

/**
 * Internal API
 */
int sdo_read_big_num_asterisk_hack(sdor_t *sdor, uint8_t *bufp, int buf_sz,
			      bool *have_asterisk)
{
	int n, c, v;
	uint8_t *limit = bufp + buf_sz;
	sdo_block_t *sdob = &sdor->b;
	int ret_value

	if (!_read_comma(sdor)) {
		LOG(LOG_ERROR, "we were expecting , here!\n");
		return 0;
	}

	if (!_read_expected_char(sdor, '"')) {
		LOG(LOG_ERROR, "Expected char read is not \"\n");
		return 0;
	}

	n = 0;
	v = 0;
	ret_value = sdob_getc(sdob, &c);
	while (c != '"' && ret_value != -1) {
		if (n == 0 && have_asterisk != NULL && c == '*') {
			*have_asterisk = true;
			c = '0';
		}
		if ((n & 1) == 0) {
			v = hexit_to_int(c) << 4;
		} else {
			v += hexit_to_int(c);
			if (bufp < limit)
				*bufp++ = v;
		}
		++n;
		ret_value = sdob_getc(sdob, &c);
	}
	sdor->need_comma = true;
	return n >> 1;
}
#endif

/**
 * Reads a byte array base64 into the buffer provided
 */
int sdo_read_byte_array_field(sdor_t *sdor, int b64Sz, uint8_t *bufp,
			      int buf_sz)
{
	int converted = 0;

	if (!_read_comma(sdor)) {
		LOG(LOG_ERROR, "we were expecting , here!\n");
		goto err;
	}

	// LOG(LOG_ERROR, "SDORead_byte_array\n");
	if (!_read_expected_char(sdor, '"'))
		goto err;

	converted = b64To_bin((size_t)b64Sz, sdor->b.block, sdor->b.cursor,
			      (size_t)buf_sz, bufp, 0);

	if (converted == -1) {
		LOG(LOG_ERROR, "Base64 string is invalid!\n");
		goto err;
	}
	sdor->b.cursor += b64Sz;

	if (!_read_expected_char(sdor, '"'))
		goto err;

	sdor->need_comma = true;

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
bool sdow_init(sdow_t *sdow)
{
	if (memset_s(sdow, sizeof(*sdow), 0) != 0) {
		LOG(LOG_ERROR, "SDOW memset() failed!\n");
		return false;
	}

	sdo_block_init(&sdow->b);

	return true;
}

/**
 * Internal API
 */
void sdow_block_reset(sdow_t *sdow)
{
	sdo_block_t *sdob = &sdow->b;

	sdob->cursor = sdob->block_size = 0;
	sdow->need_comma = false;
}

/**
 * Internal API
 */
int sdow_next_block(sdow_t *sdow, int type)
{
	sdow_block_reset(sdow);
	sdow->msg_type = type;
	return true;
}

/**
 * Internal API
 */
static void _write_comma(sdow_t *sdow)
{
	sdo_block_t *sdob = &sdow->b;

	if (sdow->need_comma) {
		sdow->need_comma = false;
		sdoBPutC(sdob, ',');
		if (sdob->block_size < sdob->cursor)
			sdob->block_size = sdob->cursor;
	}
}

/**
 * Write a string to the block, extending block and converting
 * special characters.  Does NOT handle commas.
 */
void _padstring(sdow_t *sdow, const char *s, int len, bool escape)
{
	sdo_block_t *sdob = &sdow->b;
	char ucode[10], *ucs;
	unsigned char c;

	while (len-- != 0 && (c = (unsigned char)*s++) != 0) {
		if (escape &&
		    (c < 0x20 || c > 0x7d || c == '[' || c == ']' || c == '"' ||
		     c == '\\' || c == '{' || c == '}' || c == '&')) {

			if (snprintf_s_i(ucode, sizeof(ucode), "\\u%04x", c) <
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
	if (sdob->block_size < sdob->cursor)
		sdob->block_size = sdob->cursor;
}

/**
 * Internal API
 */
void _writespecialchar(sdow_t *sdow, char c)
{
	sdo_block_t *sdob = &sdow->b;

	_write_comma(sdow);
	sdoBPutC(sdob, c);
	sdow->need_comma = false;
	if (sdob->block_size < sdob->cursor)
		sdob->block_size = sdob->cursor;
}

/**
 * Internal API
 */
void sdow_begin_sequence(sdow_t *sdow)
{
	_writespecialchar(sdow, '[');
}

/**
 * Internal API
 */
void sdow_end_sequence(sdow_t *sdow)
{
	sdow->need_comma = false;
	_writespecialchar(sdow, ']');
	sdow->need_comma = true;
}

/**
 * Internal API
 */
void sdow_begin_object(sdow_t *sdow)
{
	_writespecialchar(sdow, '{');
}

/**
 * Internal API
 */
void sdow_end_object(sdow_t *sdow)
{
	sdow->need_comma = false;
	_writespecialchar(sdow, '}');
	sdow->need_comma = true;
}

/**
 * Internal API
 */
void sdo_write_tag(sdow_t *sdow, const char *tag)
{
	sdo_write_string(sdow, tag);
	sdow->need_comma = false;
	_writespecialchar(sdow, ':');
}

/**
 * Internal API
 */
void sdo_write_tag_len(sdow_t *sdow, const char *tag, int len)
{
	sdo_write_string_len(sdow, tag, len);
	sdow->need_comma = false;
	_writespecialchar(sdow, ':');
}

/**
 * Internal API
 */
void sdo_writeUInt(sdow_t *sdow, uint32_t i)
{
	sdo_block_t *sdob = &sdow->b;
	char num[20] = {0};

	_write_comma(sdow);
	if (snprintf_s_i(num, sizeof(num), "%u", i) < 0) {
		LOG(LOG_ERROR, "snprintf() failed!\n");
		return;
	}
	_padstring(sdow, num, -1, false);
	sdow->need_comma = true;
	if (sdob->block_size < sdob->cursor)
		sdob->block_size = sdob->cursor;
}

/**
 * Internal API
 */
void sdo_write_string(sdow_t *sdow, const char *s)
{
	sdo_block_t *sdob = &sdow->b;

	_write_comma(sdow);
	sdoBPutC(sdob, '"');
	_padstring(sdow, s, -1, true);
	sdoBPutC(sdob, '"');
	sdow->need_comma = true;
	if (sdob->block_size < sdob->cursor)
		sdob->block_size = sdob->cursor;
}

/**
 * Internal API
 */
void sdo_write_string_len(sdow_t *sdow, const char *s, int len)
{
	sdo_block_t *sdob = &sdow->b;

	_write_comma(sdow);
	sdoBPutC(sdob, '"');
	_padstring(sdow, s, len, true);
	sdoBPutC(sdob, '"');
	sdow->need_comma = true;
	if (sdob->block_size < sdob->cursor)
		sdob->block_size = sdob->cursor;
}
#if 0
/**
 * Internal API
 */
// This is base16 as it should be
void sdo_write_big_num_field(sdow_t *sdow, uint8_t *bufp, int buf_sz)
{
	sdo_block_t *sdob = &sdow->b;
	char hex[3];

	_write_comma(sdow);
	sdoBPutC(sdob, '"');
	while (buf_sz-- > 0) {
		if (snprintf_s_i(hex, sizeof(hex), "%02X", *bufp++) < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return;
		}
		sdoBPutC(sdob, hex[0]);
		sdoBPutC(sdob, hex[1]);
	}
	sdoBPutC(sdob, '"');
	sdow->need_comma = true;
	if (sdob->block_size < sdob->cursor)
		sdob->block_size = sdob->cursor;
}
#endif
/**
 * Internal API
 * This is base16 as it should be
 */
void sdo_write_big_num(sdow_t *sdow, uint8_t *bufp, int buf_sz)
{
	sdo_block_t *sdob = &sdow->b;
	char hex[3];

	sdow_begin_sequence(sdow); // Write out the '['
	sdo_writeUInt(sdow, buf_sz);
	_write_comma(sdow);
	sdoBPutC(sdob, '"');
	while (buf_sz-- > 0) {
		if (snprintf_s_i(hex, sizeof(hex), "%02X", *bufp++) < 0) {
			LOG(LOG_ERROR, "snprintf() failed!\n");
			return;
		}
		sdoBPutC(sdob, hex[0]);
		sdoBPutC(sdob, hex[1]);
	}
	sdoBPutC(sdob, '"');
	sdow_end_sequence(sdow); // Write out the ']'
	sdow->need_comma = true;
	if (sdob->block_size < sdob->cursor)
		sdob->block_size = sdob->cursor;
}

/**
 * Internal API
 */
//#define WRBUF_LEN 20
void sdo_write_byte_array_field(sdow_t *sdow, uint8_t *bufp, int buf_sz)
{
	sdo_block_t *sdob = &sdow->b;
	int index;

	int buf_needed = bin_toB64Length(buf_sz);

	// mbedtls expect larger size buffer
	buf_needed += 1;
	// LOG(LOG_ERROR, "buf_sz: %d, buf_needed: %d\n", buf_sz, buf_needed);

	if (buf_needed) {
		uint8_t *wr_buf = sdo_alloc(buf_needed * sizeof(uint8_t));

		if (wr_buf) {
			// LOG(LOG_ERROR, "bufp: %p, buf_sz: %d, wr_buf: %p\n",
			// bufp,
			// buf_sz,
			// wr_buf);

			// Convert the binary to a string
			int str_len =
			    bin_toB64(buf_sz, bufp, 0, buf_needed, wr_buf, 0);
			// LOG(LOG_ERROR, "str_len: %d\n", str_len);

			_write_comma(sdow);
			sdoBPutC(sdob, '"');
			for (index = 0; index < str_len; index++)
				sdoBPutC(sdob, wr_buf[index]);
			sdoBPutC(sdob, '"');
			sdow->need_comma = true;
			if (sdob->block_size < sdob->cursor)
				sdob->block_size = sdob->cursor;
			sdo_free(wr_buf);
		}
	}
}

/**
 * Internal API
 */
void sdo_write_byte_array(sdow_t *sdow, uint8_t *bufp, int buf_sz)
{
	sdow_begin_sequence(sdow); // Write out the '['
	if (buf_sz) {
		sdo_writeUInt(sdow, buf_sz); // Write out the number of bin
					     // characters to come
		_write_comma(sdow);
		sdo_write_byte_array_field(sdow, bufp,
					   buf_sz); // "a_bzd...==" added
	} else {
		sdo_writeUInt(sdow, 0);
		_write_comma(sdow);
		sdo_write_string(sdow, "");
	}
	sdow_end_sequence(sdow); // Write out the ']'
}

/**
 * Internal API
 */
void sdo_write_byte_array_one_int(sdow_t *sdow, uint32_t val1, uint8_t *bufp,
				  int buf_sz)
{
	sdow_begin_sequence(sdow);   // Write out the '['
	sdo_writeUInt(sdow, buf_sz); // Write out the number bin of characters
	_write_comma(sdow);
	sdo_writeUInt(sdow, val1);
	_write_comma(sdow);
	if (buf_sz > 0 && bufp != NULL)
		sdo_write_byte_array_field(sdow, bufp,
					   buf_sz); // "a_bzd...==" added
	else {
		sdo_write_string(sdow, ""); // Write an empty string
	}
	sdow_end_sequence(sdow); // Write out the ']'
}

/**
 * Internal API
 */
void sdo_write_byte_array_one_int_first(sdow_t *sdow, uint32_t val1,
					uint8_t *bufp, int buf_sz)
{
	sdow_begin_sequence(sdow); // Write out the '['
	sdo_writeUInt(sdow, val1);
	_write_comma(sdow);
	sdo_writeUInt(sdow, buf_sz); // Write out the number of bin characters
	_write_comma(sdow);
	if (buf_sz > 0 && bufp != NULL) {
		sdo_write_byte_array_field(sdow, bufp,
					   buf_sz); // "a_bzd...==" added
	} else {
		sdo_write_string(sdow, ""); // Write an empty string
	}
	sdow_end_sequence(sdow); // Write out the ']'
}

/**
 * Internal API used to write 2 arrays used for writing encrypted string.
 * Write "ct". IV, size, cipher text
 */
void sdo_write_byte_array_two_int(sdow_t *sdow, uint8_t *buf_iv,
				  uint32_t buf_iv_sz, uint8_t *bufp,
				  uint32_t buf_sz)
{
	sdow_begin_sequence(sdow); /* Write out the '[' */

	if (buf_iv_sz > 0 && buf_iv != NULL) {

		sdow_begin_sequence(sdow); /* Write out the '[' */
		sdo_writeUInt(sdow,
			      buf_iv_sz); /* Write out the number IV char */
		_write_comma(sdow);
		sdo_write_byte_array_field(sdow, buf_iv,
					   buf_iv_sz); /* IV data */
		sdow_end_sequence(sdow);	       /* Write out the ']' */

	} else {
		sdo_write_string(sdow, ""); /* Write an empty string */
	}

	_write_comma(sdow);
	sdo_writeUInt(sdow,
		      buf_sz); /* Write out the number bin of characters */
	_write_comma(sdow);

	if (buf_sz > 0 && bufp != NULL) {
		sdo_write_byte_array_field(sdow, bufp, buf_sz);
	} else {
		sdo_write_string(sdow, ""); /* Write an empty string */
	}
	sdow_end_sequence(sdow); /* Write out the ']' */
}
