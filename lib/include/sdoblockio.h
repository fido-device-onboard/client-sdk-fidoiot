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
	int block_max;
	int block_size;
	uint8_t *block;
} sdo_block_t;

typedef struct _SDOR_s {
	sdo_block_t b;
	uint8_t need_comma;
	bool have_block;
	int msg_type;
	int content_length;
	int (*receive)(struct _SDOR_s *, int);
	void *receive_data;
} sdor_t;

typedef int (*SDOReceive_fcn_ptr_t)(sdor_t *, int);

typedef struct _SDOW_s {
	sdo_block_t b;
	uint8_t need_comma;
	int block_length_fixup;
	int msg_type;
	int (*send)(struct _SDOW_s *);
	void *send_data;
} sdow_t;

#define SDO_FIX_UP_STR "\"0000\""
#define SDO_FIX_UP_TEMPL "\"%04x\""
#define SDO_FIX_UP_LEN 6
#define SDO_BLOCK_READ_SZ 7 // ["XXXX"
#define SDO_BLOCKINC 256
#define SDO_BLOCK_MASK ~255
#define SDO_OK 0
#define SDO_BLOCKLEN_SZ 8
void sdo_block_init(sdo_block_t *sdob);
void sdo_block_reset(sdo_block_t *sdob);
int sdob_peekc(sdo_block_t *sdob);
void sdo_resize_block(sdo_block_t *sdob, int need);
bool sdor_init(sdor_t *sdor, SDOReceive_fcn_ptr_t rcv, void *rcv_data);
void sdor_flush(sdor_t *sdor);
int sdor_peek(sdor_t *sdor);
bool sdor_have_block(sdor_t *sdor);
void sdor_set_have_block(sdor_t *sdor);
bool sdor_next_block(sdor_t *sdor, uint32_t *typep);
uint8_t *sdor_get_block_ptr(sdor_t *sdor, int from_cursor);
uint8_t *sdow_get_block_ptr(sdow_t *sdow, int from_cursor);
bool sdor_begin_sequence(sdor_t *sdor);
bool sdor_end_sequence(sdor_t *sdor);
bool sdor_begin_object(sdor_t *sdor);
bool sdor_end_object(sdor_t *sdor);
uint32_t sdo_read_uint(sdor_t *sdor);
int sdo_read_string_sz(sdor_t *sdor);
int sdo_read_array_sz(sdor_t *sdor);
int sdo_read_array_no_state_change(sdor_t *sdor, uint8_t *buf);
int sdo_read_string(sdor_t *sdor, char *bufp, int buf_sz);
int sdo_read_tag(sdor_t *sdor, char *bufp, int buf_sz);
bool sdo_read_tag_finisher(sdor_t *sdor);
int sdo_read_expected_tag(sdor_t *sdor, const char *tag);
int sdo_read_byte_array_field(sdor_t *sdor, int b64Sz, uint8_t *bufp,
			      int buf_sz);

bool sdow_init(sdow_t *sdow);
void sdow_block_reset(sdow_t *sdow);
int sdow_next_block(sdow_t *sdow, int type);
int sdow_create_fixup(sdow_t *sdow);
void sdow_fix_fixup(sdow_t *sdow, int cursor_posn, int fixup);
void sdow_begin_sequence(sdow_t *sdow);
void sdow_end_sequence(sdow_t *sdow);
void sdow_begin_object(sdow_t *sdow);
void sdow_end_object(sdow_t *sdow);
void sdo_write_tag(sdow_t *sdow, const char *tag);
void sdo_write_tag_len(sdow_t *sdow, const char *tag, int len);
void sdo_writeUInt(sdow_t *sdow, uint32_t i);
void sdo_write_string(sdow_t *sdow, const char *s);
void sdo_write_string_len(sdow_t *sdow, const char *s, int len);
void sdo_write_big_num_field(sdow_t *sdow, uint8_t *bufp, int buf_sz);
void sdo_write_big_num(sdow_t *sdow, uint8_t *bufp, int buf_sz);
void sdo_write_byte_array_field(sdow_t *sdow, uint8_t *bufp, int buf_sz);
void sdo_write_byte_array(sdow_t *sdow, uint8_t *bufp, int buf_sz);
void sdo_write_byte_array_one_int(sdow_t *sdow, uint32_t val1, uint8_t *bufp,
				  int buf_sz);
void sdo_write_byte_array_one_int_first(sdow_t *sdow, uint32_t val1,
					uint8_t *bufp, int buf_sz);
void sdor_read_and_ignore_until(sdor_t *sdor, char expected);
void sdor_read_and_ignore_until_end_sequence(sdor_t *sdor);
void sdo_write_byte_array_two_int(sdow_t *sdow, uint8_t *buf_iv,
				  uint32_t buf_iv_sz, uint8_t *bufp,
				  uint32_t buf_sz);

#if 0 // Deprecated
int hexit_to_int(int c);
int int_to_hexit(int v);
int sdo_read_big_num_field(sdor_t *sdor, uint8_t *bufp, int buf_sz);
int sdo_read_big_num_asterisk_hack(sdor_t *sdor, uint8_t *bufp, int buf_sz,
			      bool *have_asterisk);
#endif

#endif /*__SDOBLOCKIO_H__ */
