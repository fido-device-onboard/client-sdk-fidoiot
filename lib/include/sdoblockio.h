/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDOBLOCKIO_H__
#define __SDOBLOCKIO_H__

#include <stdbool.h>
#include <stdint.h>
#include "cbor.h"

#define INT2HEX(i) ((i) <= 9 ? '0' + (i) : 'A' - 10 + (i))

// a typical buffer and its associated size
typedef struct {
	size_t block_size;
	uint8_t *block;
} sdo_block_t;

// Helper struct that encodes values into CBOR using TinyCBOR's CborEncoder.
// the self-typed next pointer is used to go inside a container and encode.
// the self-typed previous pointer is used to come out of a container once encoding is done.
typedef struct _SDOW_CBOR_ENCODER {
	CborEncoder cbor_encoder;
	struct _SDOW_CBOR_ENCODER *next;
	struct _SDOW_CBOR_ENCODER *previous;
} sdow_cbor_encoder_t;

// Helper struct that decodes CBOR data using TinyCBOR's CborValue.
// the self-typed next pointer is used to go inside a container and decode.
// the self-typed previous pointer is used to come out of a container once decoding is done.
typedef struct _SDOR_CBOR_DECODER {
	CborValue cbor_value;
	struct _SDOR_CBOR_DECODER *next;
	struct _SDOR_CBOR_DECODER *previous;
} sdor_cbor_decoder_t;

// SDO Reader (SDOR) struct that handles the CBOR decode operation using the _SDOR_CBOR_DECODER struct
// and TinyCBOR's CborParser, finally placing the CBOR-decoded data and its size into
// sdo_block_t struct.
// have_block signifies if there's more data to be decoded while the msg_type signifies
// SDO type (Type 1x/3x/6x/255)
typedef struct _SDOR_s {
	sdo_block_t b;
	int msg_type;
	bool have_block;
	CborParser cbor_parser;
	sdor_cbor_decoder_t *current;
} sdor_t;

typedef int (*SDOReceive_fcn_ptr_t)(sdor_t *, int);

// SDO Writer (SDOW) struct that handles the CBOR encode operation using the _SDOR_CBOR_ENCODER struct,
// It CBOR-encodes the data present in sdo_block_t struct.
// msg_type signifies SDO type (Type 1x/3x/6x/255)
typedef struct _SDOW_s {
	sdo_block_t b;
	int msg_type;
	sdow_cbor_encoder_t *current;
} sdow_t;


#define CBOR_BUFFER_LENGTH 2048

#define SDO_FIX_UP_STR "\"0000\""
#define SDO_FIX_UP_TEMPL "\"%04x\""
#define SDO_FIX_UP_LEN 6
#define SDO_BLOCK_READ_SZ 7 // ["XXXX"
#define SDO_BLOCKINC 256
#define SDO_BLOCK_MASK ~255
#define SDO_OK 0
#define SDO_BLOCKLEN_SZ 8

// Block methods
void sdo_block_reset(sdo_block_t *sdob);
bool sdo_block_alloc(sdo_block_t *sdob);
bool sdo_block_alloc_with_size(sdo_block_t *sdob, size_t block_sz);

// CBOR encoder methods

bool sdow_init(sdow_t *sdow);
int sdow_next_block(sdow_t *sdow, int type);
bool sdow_encoder_init(sdow_t *sdow_cbor);
bool sdow_start_array(sdow_t *sdow_cbor, size_t array_items);
bool sdow_start_map(sdow_t *sdow_cbor, size_t map_items);
bool sdow_byte_string(sdow_t *sdow_cbor, uint8_t *bytes , size_t byte_sz);
bool sdow_text_string(sdow_t *sdow_cbor, char *bytes , size_t byte_sz);
bool sdow_signed_int(sdow_t *sdow_cbor, int value);
bool sdow_unsigned_int(sdow_t *sdow_cbor, uint64_t value);
bool sdow_boolean(sdow_t *sdow_cbor, bool value);
bool sdow_null(sdow_t *sdow);
bool sdow_end_array(sdow_t *sdow_cbor);
bool sdow_end_map(sdow_t *sdow_cbor);
bool sdow_encoded_length(sdow_t *sdow_cbor, size_t *length);
void sdow_flush(sdow_t *sdow);

// CBOR decoder methods

bool sdor_init(sdor_t *sdor);
bool sdor_parser_init(sdor_t *sdor_cbor);
bool sdor_start_array(sdor_t *sdor);
bool sdor_start_map(sdor_t *sdor);
bool sdor_array_length(sdor_t *sdor, size_t *length);
bool sdor_string_length(sdor_t *sdor, size_t *length);
bool sdor_byte_string(sdor_t *sdor, uint8_t *buffer, size_t buffer_length);
bool sdor_text_string(sdor_t *sdor, char *buffer, size_t buffer_length);
bool sdor_is_value_null(sdor_t *sdor);
bool sdor_is_value_signed_int(sdor_t *sdor);
bool sdor_signed_int(sdor_t *sdor, int *result);
bool sdor_unsigned_int(sdor_t *sdor, uint64_t *result);
bool sdor_boolean(sdor_t *sdor, bool *result);
bool sdor_end_array(sdor_t *sdor);
bool sdor_end_map(sdor_t *sdor);
bool sdor_next(sdor_t *sdor);
void sdor_flush(sdor_t *sdor);

#endif /*__SDOBLOCKIO_H__ */
