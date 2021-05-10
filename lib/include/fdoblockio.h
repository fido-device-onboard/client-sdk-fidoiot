/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __FDOBLOCKIO_H__
#define __FDOBLOCKIO_H__

#include <stdbool.h>
#include <stdint.h>
#include "cbor.h"

#define INT2HEX(i) ((i) <= 9 ? '0' + (i) : 'A' - 10 + (i))

// a typical buffer and its associated size
typedef struct {
	size_t block_size;
	uint8_t *block;
} fdo_block_t;

// Helper struct that encodes values into CBOR using TinyCBOR's CborEncoder.
// the self-typed next pointer is used to go inside a container and encode.
// the self-typed previous pointer is used to come out of a container once encoding is done.
typedef struct _FDOW_CBOR_ENCODER {
	CborEncoder cbor_encoder;
	struct _FDOW_CBOR_ENCODER *next;
	struct _FDOW_CBOR_ENCODER *previous;
} fdow_cbor_encoder_t;

// Helper struct that decodes CBOR data using TinyCBOR's CborValue.
// the self-typed next pointer is used to go inside a container and decode.
// the self-typed previous pointer is used to come out of a container once decoding is done.
typedef struct _FDOR_CBOR_DECODER {
	CborValue cbor_value;
	struct _FDOR_CBOR_DECODER *next;
	struct _FDOR_CBOR_DECODER *previous;
} fdor_cbor_decoder_t;

// FDO Reader (FDOR) struct that handles the CBOR decode operation using the _FDOR_CBOR_DECODER struct
// and TinyCBOR's CborParser, finally placing the CBOR-decoded data and its size into
// fdo_block_t struct.
// have_block signifies if there's more data to be decoded while the msg_type signifies
// FDO type (Type 1x/3x/6x/255)
typedef struct _FDOR_s {
	fdo_block_t b;
	int msg_type;
	bool have_block;
	CborParser cbor_parser;
	fdor_cbor_decoder_t *current;
} fdor_t;

typedef int (*FDOReceive_fcn_ptr_t)(fdor_t *, int);

// FDO Writer (FDOW) struct that handles the CBOR encode operation using the _FDOR_CBOR_ENCODER struct,
// It CBOR-encodes the data present in fdo_block_t struct.
// msg_type signifies FDO type (Type 1x/3x/6x/255)
typedef struct _FDOW_s {
	fdo_block_t b;
	int msg_type;
	fdow_cbor_encoder_t *current;
} fdow_t;


#define CBOR_BUFFER_LENGTH 2048

#define FDO_FIX_UP_STR "\"0000\""
#define FDO_FIX_UP_TEMPL "\"%04x\""
#define FDO_FIX_UP_LEN 6
#define FDO_BLOCK_READ_SZ 7 // ["XXXX"
#define FDO_BLOCKINC 256
#define FDO_BLOCK_MASK ~255
#define FDO_OK 0
#define FDO_BLOCKLEN_SZ 8

// Block methods
void fdo_block_reset(fdo_block_t *fdob);
bool fdo_block_alloc(fdo_block_t *fdob);
bool fdo_block_alloc_with_size(fdo_block_t *fdob, size_t block_sz);

// CBOR encoder methods

bool fdow_init(fdow_t *fdow);
int fdow_next_block(fdow_t *fdow, int type);
bool fdow_encoder_init(fdow_t *fdow_cbor);
bool fdow_start_array(fdow_t *fdow_cbor, size_t array_items);
bool fdow_start_map(fdow_t *fdow_cbor, size_t map_items);
bool fdow_byte_string(fdow_t *fdow_cbor, uint8_t *bytes , size_t byte_sz);
bool fdow_text_string(fdow_t *fdow_cbor, char *bytes , size_t byte_sz);
bool fdow_signed_int(fdow_t *fdow_cbor, int value);
bool fdow_unsigned_int(fdow_t *fdow_cbor, uint64_t value);
bool fdow_boolean(fdow_t *fdow_cbor, bool value);
bool fdow_null(fdow_t *fdow);
bool fdow_end_array(fdow_t *fdow_cbor);
bool fdow_end_map(fdow_t *fdow_cbor);
bool fdow_encoded_length(fdow_t *fdow_cbor, size_t *length);
void fdow_flush(fdow_t *fdow);

// CBOR decoder methods

bool fdor_init(fdor_t *fdor);
bool fdor_parser_init(fdor_t *fdor_cbor);
bool fdor_start_array(fdor_t *fdor);
bool fdor_start_map(fdor_t *fdor);
bool fdor_array_length(fdor_t *fdor, size_t *length);
bool fdor_string_length(fdor_t *fdor, size_t *length);
bool fdor_byte_string(fdor_t *fdor, uint8_t *buffer, size_t buffer_length);
bool fdor_text_string(fdor_t *fdor, char *buffer, size_t buffer_length);
bool fdor_is_value_null(fdor_t *fdor);
bool fdor_is_value_signed_int(fdor_t *fdor);
bool fdor_signed_int(fdor_t *fdor, int *result);
bool fdor_unsigned_int(fdor_t *fdor, uint64_t *result);
bool fdor_boolean(fdor_t *fdor, bool *result);
bool fdor_end_array(fdor_t *fdor);
bool fdor_end_map(fdor_t *fdor);
bool fdor_next(fdor_t *fdor);
void fdor_flush(fdor_t *fdor);

#endif /*__FDOBLOCKIO_H__ */
