/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of low level CBOR parsing(reading/writing) APIs.
 * 
 */

#include "sdoblockio.h"
#include "base64.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "safe_lib.h"
#include "snprintf_s.h"

/**
 * Clear the internal buffer of the given sdo_block_t struct by setting the contents to 0,
 * upto the internal block size.
 * 
 * @param sdo_block_t - struct containg the buffer and its size
 */
void sdo_block_reset(sdo_block_t *sdob)
{
	if (!sdob)
		return;
	if (sdob->block) {
		if (sdob->block_size && memset_s(sdob->block, sdob->block_size, 0))
			LOG(LOG_ERROR, "Failed to clear memory\n");
	}
}

/**
 * Allocate memory for the underlying block with default size of 'CBOR_BUFFER_LENGTH'.
 *
 * @param sdo_block_t - struct containg the buffer and its size
 * @return true if the operation was a success, false otherwise
 * 
 * NOTE: The memory should be independently freed when not in use.
 */
bool sdo_block_alloc(sdo_block_t *sdob)
{
	return sdo_block_alloc_with_size(sdob, CBOR_BUFFER_LENGTH);
}

/**
 * Allocate memory for the underlying block with the given size.
 * 
 * @param sdo_block_t - struct containg the buffer and its size
 * @return true if the operation was a success, false otherwise
 *
 * NOTE: The memory should be independently freed when not in use.
 */
bool sdo_block_alloc_with_size(sdo_block_t *sdob, size_t block_sz)
{
	if (!sdob)
		return false;
	// if block exists, free it first, then alloc
	if (sdob->block != NULL)
		sdo_free(sdob->block);

	sdob->block = sdo_alloc(block_sz * sizeof(uint8_t));
	sdob->block_size = block_sz;
	if (sdob->block == NULL) {
		LOG(LOG_ERROR, "SDOBlock alloc() failed!\n");
		return false;
	}

	if (memset_s(sdob->block, sdob->block_size, 0) != 0) {
		LOG(LOG_ERROR, "SDOBlock memset() failed!\n");
		return false;
	}
	return true;
}

//==============================================================================
// Write values in CBOR
//

/**
 * Clear the contents of the given sdow_t struct alongwith its internal sdo_block_t buffer.
 * Memory must have been previously allocated for both sdow_t struct and its internal sdo_block_t.
 * 
 * @param sdow_t - struct sdow_t
 * @return true if the operation was a success, false otherwise
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

/**
 * Set the SDO Type for the given sdow_t struct to prepare for the next CBOR-encode operation.
 * 
 * @param sdow_t - struct sdow_t
 * @return 1 if the operation was a success, false otherwise
 */
int sdow_next_block(sdow_t *sdow, int type)
{
	sdow->msg_type = type;
	return true;
}

/**
 * Allocates for the internal sdow_cbor_encoder_t struct to initialize TinyCBOR's CborEncoder that
 * actually does the CBOR encoding. The newly initialized CborEncoder is provided with the
 * buffer that will be used to store the CBOR-encoded data, and its maximum size.
 * It is the root encoder onto which other CBOR encoders can be added.
 * The next and previous pointers to NULL. After this,
 * the given sdow_t struct is ready to do CBOR encoding.
 * 
 * @param sdow_t - struct sdow_t
 * @return true if the operation was a success, false otherwise
 */
bool sdow_encoder_init(sdow_t *sdow)
{
	// if there's a current block, free and then alloc
	if (sdow->current) {
		sdo_free(sdow->current);
	}
	sdow->current = sdo_alloc(sizeof(sdow_cbor_encoder_t));
	sdow->current->next = NULL;
	sdow->current->previous = NULL;

	cbor_encoder_init(&sdow->current->cbor_encoder, sdow->b.block, sdow->b.block_size, 0);
	return true;
}

/**
 * Mark the beginning of writing elements into a CBOR array (Major Type 4).
 * 
 * It does so by allocating for the internal next pointer and moving to it
 * (and keeping a refernce in previous) to create a new CborEncoder that
 * writes the tag into the pre-initialized buffer. At the end of this, every write operation
 * would be done using the newly created CborEncoder making them the items of this array,
 * until all the items are written.
 * The array needs to be closed using the method sdow_end_array().
 * 
 * @param sdow_t - struct sdow_t
 * @param array_items - total number of elements in the array
 * @return true if the operation was a success, false otherwise
 */
bool sdow_start_array(sdow_t *sdow, size_t array_items)
{
	// create next, create backlink and move forward.
	sdow->current->next = sdo_alloc(sizeof(sdow_cbor_encoder_t));
	sdow->current->next->previous = sdow->current;
	sdow->current = sdow->current->next;
	if (cbor_encoder_create_array(&sdow->current->previous->cbor_encoder, 
		&sdow->current->cbor_encoder, array_items) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to start Major Type 4 (array)\n");
		return false;
	}
	return true;
}

/**
 * Mark the beginning of writing elements into a CBOR map (Major Type 5).
 * 
 * It does so by allocating for the internal next pointer and moving to it
 * (and keeping a refernce in previous) to create a new CborEncoder that
 * writes the tag into the pre-initialized buffer. At the end of this, every write operation
 * would be done using the newly created CborEncoder making them the key-value pairs of this map,
 * until all the items are written.
 * The map needs to be closed using the method sdow_end_map().
 * 
 * @param sdow_t - struct sdow_t
 * @param array_items - total number of key-value pairs in the map
 * @return true if the operation was a success, false otherwise
 */
bool sdow_start_map(sdow_t *sdow, size_t map_items)
{
	// create next, create backlink and move forward.
	sdow->current->next = sdo_alloc(sizeof(sdow_cbor_encoder_t));
	sdow->current->next->previous = sdow->current;
	sdow->current = sdow->current->next;
	if (cbor_encoder_create_map(&sdow->current->previous->cbor_encoder, 
		&sdow->current->cbor_encoder, map_items) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to start Major Type 5 (map)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR bstr (Major Type 2) value.
 * 
 * @param sdow_t - struct sdow_t
 * @param bytes - buffer whose contents will be written as bstr
 * @param byte_sz - size of the buffer
 * @return true if the operation was a success, false otherwise
 */
bool sdow_byte_string(sdow_t *sdow, uint8_t *bytes , size_t byte_sz)
{
	if (cbor_encode_byte_string(&sdow->current->cbor_encoder, bytes, byte_sz) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 2 (bstr)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR tstr (Major Type 3) value.
 * 
 * @param sdow_t - struct sdow_t
 * @param bytes - buffer whose contents will be written as tstr
 * @param byte_sz - size of the buffer
 * @return true if the operation was a success, false otherwise
 */
bool sdow_text_string(sdow_t *sdow, char *bytes , size_t byte_sz)
{
	if (cbor_encode_text_string(&sdow->current->cbor_encoder, bytes, byte_sz) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 3 (tstr)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR signed/unsigned integer (Major Type 0/1) value.
 * 
 * @param sdow_t - struct sdow_t
 * @param value - integer value to be written, could be positive or negative
 * @return true if the operation was a success, false otherwise
 */
bool sdow_signed_int(sdow_t *sdow, int value)
{
	if (cbor_encode_int(&sdow->current->cbor_encoder, value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 1 (negative int)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR unsigned integer (Major Type 0) value.
 * 
 * @param sdow_t - struct sdow_t
 * @param value - unsigned integer value to be written, positive values only
 * @return true if the operation was a success, false otherwise
 */
bool sdow_unsigned_int(sdow_t *sdow, uint64_t value)
{
	if (cbor_encode_uint(&sdow->current->cbor_encoder, value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 0 (uint)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR primitive bool (Major Type 7, Additional Info 20/21) value.
 * 
 * @param sdow_t - struct sdow_t
 * @param value - bool value to be written
 * @return true if the operation was a success, false otherwise
 */
bool sdow_boolean(sdow_t *sdow, bool value)
{
	if (cbor_encode_boolean(&sdow->current->cbor_encoder, value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 7 (bool)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR primitive NULL (Major Type 7, Additional Info 22) value.
 * 
 * @param sdow_t - struct sdow_t
 * @return true if the operation was a success, false otherwise
 */
bool sdow_null(sdow_t *sdow)
{
	if (cbor_encode_null(&sdow->current->cbor_encoder) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 7 (NULL)\n");
		return false;
	}
	return true;
}

/**
 * Mark the completion of writing elements into a CBOR array (Major Type 4).
 * 
 * It moves back to previous CborEncoder and frees the node containing the current
 * CborEncoder (next), closing the array. At the end of this, every write operation
 * would be done using the previous CborEncoder (represented by current).
 * 
 * @param sdow_t - struct sdow_t
 * @return true if the operation was a success, false otherwise
 */
bool sdow_end_array(sdow_t *sdow)
{
	if (cbor_encoder_close_container_checked(
		&sdow->current->previous->cbor_encoder,
		&sdow->current->cbor_encoder) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to end Major Type 4 (array)\n");
		return false;
	}
	// move backwards and free next
	sdow->current = sdow->current->previous;
	sdo_free(sdow->current->next);
	return true;
}

/**
 * Mark the completion of writing elements into a CBOR map (Major Type 5).
 * 
 * It moves back to previous CborEncoder and frees the node containing the current
 * CborEncoder (next), closing the map. At the end of this, every write operation
 * would be done using the previous CborEncoder (represented by current).
 * 
 * @param sdow_t - struct sdow_t
 * @return true if the operation was a success, false otherwise
 */
bool sdow_end_map(sdow_t *sdow)
{
	if (cbor_encoder_close_container_checked(
		&sdow->current->previous->cbor_encoder,
		&sdow->current->cbor_encoder) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to end Major Type 5 (map)\n");
		return false;
	}
	// move backwards and free next
	sdow->current = sdow->current->previous;
	sdo_free(sdow->current->next);
	return true;
}

/**
 * Store the length of the CBOR data that has been written so far to the supplied buffer
 * (sdow_t.sdo_block_t.block) in the output size_t variable.
 * 
 * @param sdow_t - struct sdow_t
 * @param length out pointer where the length will stored
 * @return true if the operation was a success, false otherwise
 */
bool sdow_encoded_length(sdow_t *sdow, size_t *length) {
	*length = cbor_encoder_get_buffer_size(&sdow->current->cbor_encoder, sdow->b.block);
	return true;
}

/**
 * Clear and deallocate the internal buffer (sdow_t.sdo_block_t.block) alongwith the current node.
 * 
 * @param sdow_t - struct sdow_t
 */
void sdow_flush(sdow_t *sdow)
{
	sdo_block_t *sdob = &sdow->b;
	sdo_block_reset(sdob);
	sdo_free(sdob->block);
	sdo_free(sdow->current);
}

//==============================================================================
// Read values
//

/**
 * Clear the contents of the given sdor_t struct alongwith its internal sdo_block_t buffer.
 * Memory must have been previously allocated for both sdor_t struct and its internal sdo_block_t.
 * 
 * @param sdor_t - struct sdor_t
 * @return true if the operation was a success, false otherwise
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

/**
 * Allocates for the internal sdor_cbor_decoder_t struct to initialize TinyCBOR's CborParser that
 * actually does the CBOR decoding. The newly initialized CborDecoder is provided with the
 * buffer that contains the CBOR-encoded data (the data to be decoded), its maximum size,
 * and TinyCbor's CborValue.
 * It is the root decoder that takes as many CborValue's as the number of arrays/maps to be read.
 * The next and previous pointers to NULL. After this,
 * the given sdor_t struct is ready to do CBOR decoding.
 * 
 * @param sdor_t - struct sdor_t
 * @return true if the operation was a success, false otherwise
 */
bool sdor_parser_init(sdor_t *sdor) {
	// if there's a current block, free and then alloc
	if (sdor->current){
		sdo_free(sdor->current);
	}
	sdor->current = sdo_alloc(sizeof(sdor_cbor_decoder_t));
	sdor->current->next = NULL;
	sdor->current->previous = NULL;

    if (cbor_parser_init(sdor->b.block, sdor->b.block_size, 0, &sdor->cbor_parser,
	 	&sdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to initialize CBOR Parser\n");
		return false;
	}
	return true;
}

/**
 * Mark the beginning of reading elements from a CBOR array (Major Type 4).
 * 
 * It does so by allocating for the internal next pointer and moving to it
 * (and keeping a refernce in previous) to create a new CborValue that
 * reads the tag from the input buffer. At the end of this, every read operation
 * would be done using the newly created CborValue treating them as the items of this array.
 * The array needs to be closed using the method sdor_end_array().
 * 
 * @param sdor_t - struct sdow_t
 * @return true if the operation was a success, false otherwise
 */
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

/**
 * Mark the beginning of reading elements from a CBOR map (Major Type 5).
 * 
 * It does so by allocating for the internal next pointer and moving to it
 * (and keeping a refernce in previous) to create a new CborValue that
 * reads the tag from the input buffer. At the end of this, every read operation
 * would be done using the newly created CborValue treating them as the items of this map.
 * The map needs to be closed using the method sdor_end_map().
 * 
 * @param sdor_t - struct sdow_t
 * @return true if the operation was a success, false otherwise
 */
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

/**
 * Store the number of items in the CBOR array (Major Type 4) into the supplied size_t variable.
 * 
 * @param sdor_t - struct sdow_t
 * @param length - output variable where the array's number of items will be stored
 * @return true if the operation was a success, false otherwise
 */
bool sdor_array_length(sdor_t *sdor, size_t *length) {
	if (cbor_value_get_array_length(&sdor->current->cbor_value,
		length) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read length of Major Type 4 (array)\n");
		return false;			
	}
	return true;
}

/**
 * Store the CBOR bstr/tstr (Major Type 2/3) length into the supplied size_t variable.
 * 
 * @param sdor_t - struct sdow_t
 * @param length - output variable where the string length will be stored
 * @return true if the operation was a success, false otherwise
 */
bool sdor_string_length(sdor_t *sdor, size_t *length) {
	if (cbor_value_calculate_string_length(&sdor->current->cbor_value,
		length) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read length of Major Type 2/3 (bstr/tstr)\n");
		return false;
	}
	return true;
}

/**
 * Read a CBOR bstr (Major Type 2) value.
 * 
 * @param sdor_t - struct sdor_t
 * @param buffer - buffer whose contents will be read as bstr
 * @param buffer_length - size of the buffer
 * @return true if the operation was a success, false otherwise
 */
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

/**
 * Read a CBOR tstr (Major Type 3) value.
 * 
 * @param sdor_t - struct sdor_t
 * @param buffer - buffer whose contents will be read as tstr
 * @param buffer_length - size of the buffer
 * @return true if the operation was a success, false otherwise
 */
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

/**
 * Check if the current value is CBOR NULL (Major Type 7, Additional Info 22) value.
 * 
 * @param sdor_t - struct sdor_t
 * @return true if value is CBOR NULL, false otherwise
 */
bool sdor_is_value_null(sdor_t *sdor) {
	return cbor_value_is_null(&sdor->current->cbor_value);
}

/**
 * Check if the current value is CBOR integer (Major Type 0/1) value.
 * 
 * @param sdor_t - struct sdor_t
 * @return true if the current value is integer, false otherwise
 */
bool sdor_is_value_signed_int(sdor_t *sdor) {
	return cbor_value_is_integer(&sdor->current->cbor_value);
}

/**
 * Read a CBOR signed/unsigned integer (Major Type 0/1) value.
 * 
 * @param sdor_t - struct sdor_t
 * @param result - output variable where the read integer will be stored
 * @return true if the operation was a success, false otherwise
 */
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

/**
 * Read a CBOR unsigned integer (Major Type 0) value.
 * 
 * @param sdor_t - struct sdor_t
 * @param result - output variable where the read integer will be stored
 * @return true if the operation was a success, false otherwise
 */
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

/**
 * Read a CBOR primitive bool (Major Type 7, Additional Info 20/21) value.
 * 
 * @param sdor_t - struct sdor_t
 * @param result - output variable where the read bool will be stored
 * @return true if the operation was a success, false otherwise
 */
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

/**
 * Mark the completion of reading elements from a CBOR array (Major Type 4).
 * 
 * It moves back to previous CborValue and frees the node containing the current
 * CborValue (next), closing the array. At the end of this, every read operation
 * would be done using the previous CborValue (represented by current).
 * 
 * @param sdor_t - struct sdor_t
 * @return true if the operation was a success, false otherwise
 */
bool sdor_end_array(sdor_t *sdor) {
	if (!cbor_value_is_array(&sdor->current->previous->cbor_value) ||
		cbor_value_leave_container(&sdor->current->previous->cbor_value, 
		&sdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to end Major Type 4 (array)\n");
		return false;
	}
	// move backwards and free next
	sdor->current = sdor->current->previous;
	sdo_free(sdor->current->next);
	return true;
}

/**
 * Mark the completion of reading elements from a CBOR map (Major Type 5).
 * 
 * It moves back to previous CborValue and frees the node containing the current
 * CborValue (next), closing the map. At the end of this, every read operation
 * would be done using the previous CborValue (represented by current).
 * 
 * @param sdor_t - struct sdor_t
 * @return true if the operation was a success, false otherwise
 */
bool sdor_end_map(sdor_t *sdor) {
	if (!cbor_value_is_map(&sdor->current->previous->cbor_value) ||
		cbor_value_leave_container(&sdor->current->previous->cbor_value, 
		&sdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to end Major Type 4 (array)\n");
		return false;
	}
	// move backwards and free next
	sdor->current = sdor->current->previous;
	sdo_free(sdor->current->next);
	return true;
}

/**
 * Advance to the next value in the CBOR data stream.
 * 
 * @param sdor_t - struct sdor_t
 * @return true if the operation was a success, false otherwise
 */
bool sdor_next(sdor_t *sdor) {
	if (cbor_value_advance(&sdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to advance element\n");
		return false;
	}
	return true;
}

/**
 * Clear and deallocate the internal buffer (sdor_t.sdo_block_t.block) alongwith the current node.
 * 
 * @param sdor_t - struct sdor_t
 */
void sdor_flush(sdor_t *sdor)
{
	sdo_block_t *sdob = &sdor->b;
	sdo_block_reset(sdob);
	sdo_free(sdob->block);
	sdo_free(sdor->current);
}