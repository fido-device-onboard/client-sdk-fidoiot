/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of low level CBOR parsing(reading/writing) APIs.
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

/**
 * Internal API
 */
void sdo_block_reset(sdo_block_t *sdob)
{
	if (!sdob)
		return;
	if (sdob->block) {
		if (sdob->block_size && memset_s(sdob->block, sdob->block_size, 0))
			LOG(LOG_ERROR, "Failed to clear memory\n");
		sdo_free(sdob->block);
	}
	sdob->block_size = 0;
}

bool sdo_block_alloc(sdo_block_t *sdob)
{

	sdob->block = sdo_alloc(CBOR_BUFFER_LENGTH * sizeof(uint8_t));
	sdob->block_size = CBOR_BUFFER_LENGTH;
	if (sdob->block == NULL) {
		LOG(LOG_ERROR, "SDOBlock alloc() failed!\n");
		return false;
	}

	if (memset_s(sdob->block, sdob->block_size, 0) != 0) {
		LOG(LOG_ERROR, "SDOW memset() failed!\n");
		return false;
	}
	return true;
}

/**
 * Internal API
 */
void sdo_resize_block(sdo_block_t *sdob, size_t need)
{
	if (need > sdob->block_size) {
		int new_size = (need + SDO_BLOCKINC - 1) & SDO_BLOCK_MASK;

		sdob->block = realloc(sdob->block, new_size);
		sdob->block_size = new_size;

		if (!sdob->block) {
			LOG(LOG_ERROR, "realloc failure at %s:%d\r\n", __FILE__,
			    __LINE__);
		}
	}
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

	sdo_block_reset(&sdow->b);
	return true;
}

int sdow_next_block(sdow_t *sdow, int type)
{
	sdow->msg_type = type;
	return true;
}

bool sdow_encoder_init(sdow_t *sdow_cbor)
{
	sdow_cbor->current = sdo_alloc(sizeof(sdow_cbor_encoder_t));
	sdow_cbor->current->next = NULL;
	sdow_cbor->current->previous = NULL;

	cbor_encoder_init(&sdow_cbor->current->cbor_encoder, sdow_cbor->b.block, sdow_cbor->b.block_size, 0);
	return true;
}

bool sdow_start_array(sdow_t *sdow_cbor, size_t array_items)
{
	// create next, create backlink and move forward.
	sdow_cbor->current->next = sdo_alloc(sizeof(sdow_cbor_encoder_t));
	sdow_cbor->current->next->previous = sdow_cbor->current;
	sdow_cbor->current = sdow_cbor->current->next;
	if (cbor_encoder_create_array(&sdow_cbor->current->previous->cbor_encoder, 
		&sdow_cbor->current->cbor_encoder, array_items) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to start Major Type 4 (array)\n");
		return false;
	}
	return true;
}

bool sdow_start_map(sdow_t *sdow_cbor, size_t map_items)
{
	// create next, create backlink and move forward.
	sdow_cbor->current->next = sdo_alloc(sizeof(sdow_cbor_encoder_t));
	sdow_cbor->current->next->previous = sdow_cbor->current;
	sdow_cbor->current = sdow_cbor->current->next;
	if (cbor_encoder_create_map(&sdow_cbor->current->previous->cbor_encoder, 
		&sdow_cbor->current->cbor_encoder, map_items) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to start Major Type 5 (map)\n");
		return false;
	}
	return true;
}

bool sdow_byte_string(sdow_t *sdow_cbor, uint8_t *bytes , size_t byte_sz)
{
	if (cbor_encode_byte_string(&sdow_cbor->current->cbor_encoder, bytes, byte_sz) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 2 (bstr)\n");
		return false;
	}
	return true;
}

bool sdow_text_string(sdow_t *sdow_cbor, char *bytes , size_t byte_sz)
{
	if (cbor_encode_text_string(&sdow_cbor->current->cbor_encoder, bytes, byte_sz) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 3 (tstr)\n");
		return false;
	}
	return true;
}

bool sdow_signed_int(sdow_t *sdow_cbor, int value)
{
	if (cbor_encode_int(&sdow_cbor->current->cbor_encoder, value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 1 (negative int)\n");
		return false;
	}
	return true;
}

bool sdow_unsigned_int(sdow_t *sdow_cbor, uint64_t value)
{
	if (cbor_encode_uint(&sdow_cbor->current->cbor_encoder, value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 0 (uint)\n");
		return false;
	}
	return true;
}

bool sdow_boolean(sdow_t *sdow_cbor, bool value)
{
	if (cbor_encode_boolean(&sdow_cbor->current->cbor_encoder, value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 7 (bool)\n");
		return false;
	}
	return true;
}

bool sdow_end_array(sdow_t *sdow_cbor)
{
	if (cbor_encoder_close_container_checked(
		&sdow_cbor->current->previous->cbor_encoder,
		&sdow_cbor->current->cbor_encoder) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to end Major Type 4 (array)\n");
		return false;
	}
	// move backwards and free previous
	sdow_cbor_encoder_t *current = sdow_cbor->current;
	sdow_cbor->current = sdow_cbor->current->previous;
	sdo_free(current);
	return true;
}

bool sdow_end_map(sdow_t *sdow_cbor)
{
	if (cbor_encoder_close_container_checked(
		&sdow_cbor->current->previous->cbor_encoder,
		&sdow_cbor->current->cbor_encoder) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to end Major Type 5 (map)\n");
		return false;
	}
	// move backwards and free previous
	sdow_cbor_encoder_t *current = sdow_cbor->current;
	sdow_cbor->current = sdow_cbor->current->previous;
	sdo_free(current);
	return true;
}

bool sdow_encoded_length(sdow_t *sdow, size_t *length) {
	*length = cbor_encoder_get_buffer_size(&sdow->current->cbor_encoder, sdow->b.block);
	return true;
}

void sdow_flush(sdow_t *sdow)
{
	sdo_block_t *sdob = &sdow->b;
	sdo_block_reset(sdob);
}

//==============================================================================
// Read values
//

/**
 * Initialize SDO CBOR packet reader engine
 *
 * @param sdor - Pointer of struct containing SDOR data structure,
 *
 * @return
 *        return true on success. false on failure.
 */
bool sdor_init(sdor_t *sdor)
{
	if (memset_s(sdor, sizeof(*sdor), 0) != 0) {
		LOG(LOG_ERROR, "SDOR memset() failed!\n");
		return false;
	}
	sdo_block_reset(&sdor->b);
	return true;
}

bool sdor_parser_init(sdor_t *sdor, sdo_block_t *received_block) {
	sdor->current = malloc(sizeof(sdor_cbor_decoder_t));
	sdor->current->next = NULL;
	sdor->current->previous = NULL;

	memcpy_s(sdor->b.block, CBOR_BUFFER_LENGTH, received_block->block, received_block->block_size);

    if (cbor_parser_init(sdor->b.block, sdor->b.block_size, 0, &sdor->cbor_parser,
	 	&sdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to initialize CBOR Parser\n");
		return false;
	}
	return true;
}

bool sdor_start_array(sdor_t *sdor) {
	// create next, create backlink and move forward.
	sdor->current->next = sdo_alloc(sizeof(sdor_cbor_decoder_t));
	sdor->current->next->previous = sdor->current;
	sdor->current = sdor->current->next;
	if (!cbor_value_is_array(&sdor->current->previous->cbor_value) ||
		cbor_value_enter_container(&sdor->current->previous->cbor_value, 
		&sdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to start Major Type 4 (array)\n");
		return false;
	}
	return true;
}

bool sdor_start_map(sdor_t *sdor) {
	// create next, create backlink and move forward.
	sdor->current->next = sdo_alloc(sizeof(sdor_cbor_decoder_t));
	sdor->current->next->previous = sdor->current;
	sdor->current = sdor->current->next;
	if (!cbor_value_is_map(&sdor->current->previous->cbor_value) ||
		cbor_value_enter_container(&sdor->current->previous->cbor_value, 
		&sdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to start Major Type 4 (array)\n");
		return false;
	}
	return true;
}

bool sdor_string_length(sdor_t *sdor, size_t *length) {
	if (cbor_value_calculate_string_length(&sdor->current->cbor_value,
		length) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read length of Major Type 2/3 (bstr/tstr)\n");
		return false;
	}
	return true;
}

bool sdor_byte_string(sdor_t *sdor, uint8_t *buffer, size_t buffer_length) {
	if (!cbor_value_is_byte_string(&sdor->current->cbor_value) ||
		cbor_value_copy_byte_string(&sdor->current->cbor_value, buffer, &buffer_length, NULL)
			!= CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read Major Type 2 (bstr)\n");
		return false;
	}
	if (!sdor_next(sdor)) {
		return false;
	}
	return true;
}

bool sdor_text_string(sdor_t *sdor, char *buffer, size_t buffer_length) {
	if (!cbor_value_is_text_string(&sdor->current->cbor_value) ||
		cbor_value_copy_text_string(&sdor->current->cbor_value, buffer, &buffer_length, NULL)
			!= CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read Major Type 3 (tstr)\n");
		return false;
	}
	if (!sdor_next(sdor))
		return false;
	return true;
}

bool sdor_signed_int(sdor_t *sdor, int *result) {
	if (!cbor_value_is_integer(&sdor->current->cbor_value) ||
		cbor_value_get_int(&sdor->current->cbor_value, result)
			!= CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read Major Type 1 (negative int)\n");
		return false;
	}
	if (!sdor_next(sdor))
		return false;
	return true;
}

bool sdor_unsigned_int(sdor_t *sdor, uint64_t *result) {
	if (!cbor_value_is_unsigned_integer(&sdor->current->cbor_value) ||
		cbor_value_get_uint64(&sdor->current->cbor_value, result)
			!= CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read Major Type 0 (uint)\n");
		return false;
	}
	if (!sdor_next(sdor))
		return false;
	return true;
}

bool sdor_boolean(sdor_t *sdor, bool *result) {
	if (!cbor_value_is_boolean(&sdor->current->cbor_value) ||
		cbor_value_get_boolean(&sdor->current->cbor_value, result)
			!= CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to start Major Type 7 (bool)\n");
		return false;
	}
	if (!sdor_next(sdor))
		return false;
	return true;
}

bool sdor_end_array(sdor_t *sdor) {
	if (!cbor_value_is_array(&sdor->current->previous->cbor_value) ||
		cbor_value_leave_container(&sdor->current->previous->cbor_value, 
		&sdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to end Major Type 4 (array)\n");
		return false;
	}
	// move backwards and free previous
	sdor_cbor_decoder_t *current = sdor->current;
	sdor->current = sdor->current->previous;
	sdo_free(current);
	return true;
}

bool sdor_end_map(sdor_t *sdor) {
	if (!cbor_value_is_map(&sdor->current->previous->cbor_value) ||
		cbor_value_leave_container(&sdor->current->previous->cbor_value, 
		&sdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to end Major Type 4 (array)\n");
		return false;
	}
	// move backwards and free previous
	sdor_cbor_decoder_t *current = sdor->current;
	sdor->current = sdor->current->previous;
	sdo_free(current);
	return true;
}

bool sdor_next(sdor_t *sdor) {
	if (cbor_value_advance(&sdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to advance element\n");
		return false;
	}
	return true;
}

void sdor_flush(sdor_t *sdor)
{
	sdo_block_t *sdob = &sdor->b;
	sdo_block_reset(sdob);
	free(sdor->current);
}