/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of low level CBOR parsing(reading/writing) APIs.
 * 
 */

#include "fdoblockio.h"
#include "base64.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "safe_lib.h"
#include "snprintf_s.h"

/**
 * Clear the internal buffer of the given fdo_block_t struct by setting the contents to 0,
 * upto the internal block size.
 * 
 * @param fdo_block_t - struct containg the buffer and its size
 */
void fdo_block_reset(fdo_block_t *fdob)
{
	if (!fdob)
		return;
	if (fdob->block) {
		if (fdob->block_size && memset_s(fdob->block, fdob->block_size, 0))
			LOG(LOG_ERROR, "Failed to clear memory\n");
	}
}

/**
 * Allocate memory for the underlying block with default size of 'CBOR_BUFFER_LENGTH'.
 *
 * @param fdo_block_t - struct containg the buffer and its size
 * @return true if the operation was a success, false otherwise
 * 
 * NOTE: The memory should be independently freed when not in use.
 */
bool fdo_block_alloc(fdo_block_t *fdob)
{
	return fdo_block_alloc_with_size(fdob, CBOR_BUFFER_LENGTH);
}

/**
 * Allocate memory for the underlying block with the given size.
 * 
 * @param fdo_block_t - struct containg the buffer and its size
 * @return true if the operation was a success, false otherwise
 *
 * NOTE: The memory should be independently freed when not in use.
 */
bool fdo_block_alloc_with_size(fdo_block_t *fdob, size_t block_sz)
{
	if (!fdob)
		return false;
	// if block exists, free it first, then alloc
	if (fdob->block != NULL)
		fdo_free(fdob->block);

	fdob->block = fdo_alloc(block_sz * sizeof(uint8_t));
	fdob->block_size = block_sz;
	if (fdob->block == NULL) {
		LOG(LOG_ERROR, "FDOBlock alloc() failed!\n");
		return false;
	}

	if (memset_s(fdob->block, fdob->block_size, 0) != 0) {
		LOG(LOG_ERROR, "FDOBlock memset() failed!\n");
		return false;
	}
	return true;
}

//==============================================================================
// Write values in CBOR
//

/**
 * Clear the contents of the given fdow_t struct alongwith its internal fdo_block_t buffer.
 * Memory must have been previously allocated for both fdow_t struct and its internal fdo_block_t.
 * 
 * @param fdow_t - struct fdow_t
 * @return true if the operation was a success, false otherwise
 */
bool fdow_init(fdow_t *fdow)
{
	if (memset_s(fdow, sizeof(*fdow), 0) != 0) {
		LOG(LOG_ERROR, "FDOW memset() failed!\n");
		return false;
	}

	fdo_block_reset(&fdow->b);
	return true;
}

/**
 * Set the FDO Type for the given fdow_t struct to prepare for the next CBOR-encode operation.
 * 
 * @param fdow_t - struct fdow_t
 * @return 1 if the operation was a success, false otherwise
 */
int fdow_next_block(fdow_t *fdow, int type)
{
	fdow->msg_type = type;
	return true;
}

/**
 * Allocates for the internal fdow_cbor_encoder_t struct to initialize TinyCBOR's CborEncoder that
 * actually does the CBOR encoding. The newly initialized CborEncoder is provided with the
 * buffer that will be used to store the CBOR-encoded data, and its maximum size.
 * It is the root encoder onto which other CBOR encoders can be added.
 * The next and previous pointers to NULL. After this,
 * the given fdow_t struct is ready to do CBOR encoding.
 * 
 * @param fdow_t - struct fdow_t
 * @return true if the operation was a success, false otherwise
 */
bool fdow_encoder_init(fdow_t *fdow)
{
	// if there's a current block, free and then alloc
	if (fdow->current) {
		fdo_free(fdow->current);
	}
	fdow->current = fdo_alloc(sizeof(fdow_cbor_encoder_t));
	fdow->current->next = NULL;
	fdow->current->previous = NULL;

	cbor_encoder_init(&fdow->current->cbor_encoder, fdow->b.block, fdow->b.block_size, 0);
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
 * The array needs to be closed using the method fdow_end_array().
 * 
 * @param fdow_t - struct fdow_t
 * @param array_items - total number of elements in the array
 * @return true if the operation was a success, false otherwise
 */
bool fdow_start_array(fdow_t *fdow, size_t array_items)
{
	// create next, create backlink and move forward.
	fdow->current->next = fdo_alloc(sizeof(fdow_cbor_encoder_t));
	fdow->current->next->previous = fdow->current;
	fdow->current = fdow->current->next;
	if (cbor_encoder_create_array(&fdow->current->previous->cbor_encoder, 
		&fdow->current->cbor_encoder, array_items) != CborNoError) {
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
 * The map needs to be closed using the method fdow_end_map().
 * 
 * @param fdow_t - struct fdow_t
 * @param array_items - total number of key-value pairs in the map
 * @return true if the operation was a success, false otherwise
 */
bool fdow_start_map(fdow_t *fdow, size_t map_items)
{
	// create next, create backlink and move forward.
	fdow->current->next = fdo_alloc(sizeof(fdow_cbor_encoder_t));
	fdow->current->next->previous = fdow->current;
	fdow->current = fdow->current->next;
	if (cbor_encoder_create_map(&fdow->current->previous->cbor_encoder, 
		&fdow->current->cbor_encoder, map_items) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to start Major Type 5 (map)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR bstr (Major Type 2) value.
 * 
 * @param fdow_t - struct fdow_t
 * @param bytes - buffer whose contents will be written as bstr
 * @param byte_sz - size of the buffer
 * @return true if the operation was a success, false otherwise
 */
bool fdow_byte_string(fdow_t *fdow, uint8_t *bytes , size_t byte_sz)
{
	if (cbor_encode_byte_string(&fdow->current->cbor_encoder, bytes, byte_sz) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 2 (bstr)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR tstr (Major Type 3) value.
 * 
 * @param fdow_t - struct fdow_t
 * @param bytes - buffer whose contents will be written as tstr
 * @param byte_sz - size of the buffer
 * @return true if the operation was a success, false otherwise
 */
bool fdow_text_string(fdow_t *fdow, char *bytes , size_t byte_sz)
{
	if (cbor_encode_text_string(&fdow->current->cbor_encoder, bytes, byte_sz) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 3 (tstr)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR signed/unsigned integer (Major Type 0/1) value.
 * 
 * @param fdow_t - struct fdow_t
 * @param value - integer value to be written, could be positive or negative
 * @return true if the operation was a success, false otherwise
 */
bool fdow_signed_int(fdow_t *fdow, int value)
{
	if (cbor_encode_int(&fdow->current->cbor_encoder, value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 1 (negative int)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR unsigned integer (Major Type 0) value.
 * 
 * @param fdow_t - struct fdow_t
 * @param value - unsigned integer value to be written, positive values only
 * @return true if the operation was a success, false otherwise
 */
bool fdow_unsigned_int(fdow_t *fdow, uint64_t value)
{
	if (cbor_encode_uint(&fdow->current->cbor_encoder, value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 0 (uint)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR primitive bool (Major Type 7, Additional Info 20/21) value.
 * 
 * @param fdow_t - struct fdow_t
 * @param value - bool value to be written
 * @return true if the operation was a success, false otherwise
 */
bool fdow_boolean(fdow_t *fdow, bool value)
{
	if (cbor_encode_boolean(&fdow->current->cbor_encoder, value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to write Major Type 7 (bool)\n");
		return false;
	}
	return true;
}

/**
 * Write a CBOR primitive NULL (Major Type 7, Additional Info 22) value.
 * 
 * @param fdow_t - struct fdow_t
 * @return true if the operation was a success, false otherwise
 */
bool fdow_null(fdow_t *fdow)
{
	if (cbor_encode_null(&fdow->current->cbor_encoder) != CborNoError) {
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
 * @param fdow_t - struct fdow_t
 * @return true if the operation was a success, false otherwise
 */
bool fdow_end_array(fdow_t *fdow)
{
	if (cbor_encoder_close_container_checked(
		&fdow->current->previous->cbor_encoder,
		&fdow->current->cbor_encoder) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to end Major Type 4 (array)\n");
		return false;
	}
	// move backwards and free next
	fdow->current = fdow->current->previous;
	fdo_free(fdow->current->next);
	return true;
}

/**
 * Mark the completion of writing elements into a CBOR map (Major Type 5).
 * 
 * It moves back to previous CborEncoder and frees the node containing the current
 * CborEncoder (next), closing the map. At the end of this, every write operation
 * would be done using the previous CborEncoder (represented by current).
 * 
 * @param fdow_t - struct fdow_t
 * @return true if the operation was a success, false otherwise
 */
bool fdow_end_map(fdow_t *fdow)
{
	if (cbor_encoder_close_container_checked(
		&fdow->current->previous->cbor_encoder,
		&fdow->current->cbor_encoder) != CborNoError) {
		LOG(LOG_ERROR, "CBOR encoder: Failed to end Major Type 5 (map)\n");
		return false;
	}
	// move backwards and free next
	fdow->current = fdow->current->previous;
	fdo_free(fdow->current->next);
	return true;
}

/**
 * Store the length of the CBOR data that has been written so far to the supplied buffer
 * (fdow_t.fdo_block_t.block) in the output size_t variable.
 * 
 * @param fdow_t - struct fdow_t
 * @param length out pointer where the length will stored
 * @return true if the operation was a success, false otherwise
 */
bool fdow_encoded_length(fdow_t *fdow, size_t *length) {
	*length = cbor_encoder_get_buffer_size(&fdow->current->cbor_encoder, fdow->b.block);
	return true;
}

/**
 * Clear and deallocate the internal buffer (fdow_t.fdo_block_t.block) alongwith the current node.
 * 
 * @param fdow_t - struct fdow_t
 */
void fdow_flush(fdow_t *fdow)
{
	fdo_block_t *fdob = &fdow->b;
	fdo_block_reset(fdob);
	fdo_free(fdob->block);
	fdo_free(fdow->current);
}

//==============================================================================
// Read values
//

/**
 * Clear the contents of the given fdor_t struct alongwith its internal fdo_block_t buffer.
 * Memory must have been previously allocated for both fdor_t struct and its internal fdo_block_t.
 * 
 * @param fdor_t - struct fdor_t
 * @return true if the operation was a success, false otherwise
 */
bool fdor_init(fdor_t *fdor)
{
	if (memset_s(fdor, sizeof(*fdor), 0) != 0) {
		LOG(LOG_ERROR, "FDOR memset() failed!\n");
		return false;
	}
	fdo_block_reset(&fdor->b);
	return true;
}

/**
 * Allocates for the internal fdor_cbor_decoder_t struct to initialize TinyCBOR's CborParser that
 * actually does the CBOR decoding. The newly initialized CborDecoder is provided with the
 * buffer that contains the CBOR-encoded data (the data to be decoded), its maximum size,
 * and TinyCbor's CborValue.
 * It is the root decoder that takes as many CborValue's as the number of arrays/maps to be read.
 * The next and previous pointers to NULL. After this,
 * the given fdor_t struct is ready to do CBOR decoding.
 * 
 * @param fdor_t - struct fdor_t
 * @return true if the operation was a success, false otherwise
 */
bool fdor_parser_init(fdor_t *fdor) {
	// if there's a current block, free and then alloc
	if (fdor->current){
		fdo_free(fdor->current);
	}
	fdor->current = fdo_alloc(sizeof(fdor_cbor_decoder_t));
	fdor->current->next = NULL;
	fdor->current->previous = NULL;

    if (cbor_parser_init(fdor->b.block, fdor->b.block_size, 0, &fdor->cbor_parser,
	 	&fdor->current->cbor_value) != CborNoError) {
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
 * The array needs to be closed using the method fdor_end_array().
 * 
 * @param fdor_t - struct fdow_t
 * @return true if the operation was a success, false otherwise
 */
bool fdor_start_array(fdor_t *fdor) {
	// create next, create backlink and move forward.
	fdor->current->next = fdo_alloc(sizeof(fdor_cbor_decoder_t));
	fdor->current->next->previous = fdor->current;
	fdor->current = fdor->current->next;
	if (!cbor_value_is_array(&fdor->current->previous->cbor_value) ||
		cbor_value_enter_container(&fdor->current->previous->cbor_value, 
		&fdor->current->cbor_value) != CborNoError) {
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
 * The map needs to be closed using the method fdor_end_map().
 * 
 * @param fdor_t - struct fdow_t
 * @return true if the operation was a success, false otherwise
 */
bool fdor_start_map(fdor_t *fdor) {
	// create next, create backlink and move forward.
	fdor->current->next = fdo_alloc(sizeof(fdor_cbor_decoder_t));
	fdor->current->next->previous = fdor->current;
	fdor->current = fdor->current->next;
	if (!cbor_value_is_map(&fdor->current->previous->cbor_value) ||
		cbor_value_enter_container(&fdor->current->previous->cbor_value, 
		&fdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to start Major Type 4 (array)\n");
		return false;
	}
	return true;
}

/**
 * Store the number of items in the CBOR array (Major Type 4) into the supplied size_t variable.
 * 
 * @param fdor_t - struct fdow_t
 * @param length - output variable where the array's number of items will be stored
 * @return true if the operation was a success, false otherwise
 */
bool fdor_array_length(fdor_t *fdor, size_t *length) {
	if (!cbor_value_is_array(&fdor->current->cbor_value) ||
		cbor_value_get_array_length(&fdor->current->cbor_value,
		length) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read length of Major Type 4 (array)\n");
		return false;			
	}
	return true;
}

/**
 * Store the CBOR bstr/tstr (Major Type 2/3) length into the supplied size_t variable.
 * 
 * @param fdor_t - struct fdow_t
 * @param length - output variable where the string length will be stored
 * @return true if the operation was a success, false otherwise
 */
bool fdor_string_length(fdor_t *fdor, size_t *length) {
	if ((!cbor_value_is_byte_string(&fdor->current->cbor_value) &&
		!cbor_value_is_text_string(&fdor->current->cbor_value)) ||
		cbor_value_calculate_string_length(&fdor->current->cbor_value,
		length) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read length of Major Type 2/3 (bstr/tstr)\n");
		return false;
	}
	return true;
}

/**
 * Read a CBOR bstr (Major Type 2) value.
 * 
 * @param fdor_t - struct fdor_t
 * @param buffer - buffer whose contents will be read as bstr
 * @param buffer_length - size of the buffer
 * @return true if the operation was a success, false otherwise
 */
bool fdor_byte_string(fdor_t *fdor, uint8_t *buffer, size_t buffer_length) {
	if (!cbor_value_is_byte_string(&fdor->current->cbor_value) ||
		cbor_value_copy_byte_string(&fdor->current->cbor_value, buffer, &buffer_length, NULL)
			!= CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read Major Type 2 (bstr)\n");
		return false;
	}
	if (!fdor_next(fdor)) {
		return false;
	}
	return true;
}

/**
 * Read a CBOR tstr (Major Type 3) value.
 * 
 * @param fdor_t - struct fdor_t
 * @param buffer - buffer whose contents will be read as tstr
 * @param buffer_length - size of the buffer
 * @return true if the operation was a success, false otherwise
 */
bool fdor_text_string(fdor_t *fdor, char *buffer, size_t buffer_length) {
	if (!cbor_value_is_text_string(&fdor->current->cbor_value) ||
		cbor_value_copy_text_string(&fdor->current->cbor_value, buffer, &buffer_length, NULL)
			!= CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read Major Type 3 (tstr)\n");
		return false;
	}
	if (!fdor_next(fdor))
		return false;
	return true;
}

/**
 * Check if the current value is CBOR NULL (Major Type 7, Additional Info 22) value.
 * 
 * @param fdor_t - struct fdor_t
 * @return true if value is CBOR NULL, false otherwise
 */
bool fdor_is_value_null(fdor_t *fdor) {
	return cbor_value_is_null(&fdor->current->cbor_value);
}

/**
 * Check if the current value is CBOR integer (Major Type 0/1) value.
 * 
 * @param fdor_t - struct fdor_t
 * @return true if the current value is integer, false otherwise
 */
bool fdor_is_value_signed_int(fdor_t *fdor) {
	return cbor_value_is_integer(&fdor->current->cbor_value);
}

/**
 * Read a CBOR signed/unsigned integer (Major Type 0/1) value.
 * 
 * @param fdor_t - struct fdor_t
 * @param result - output variable where the read integer will be stored
 * @return true if the operation was a success, false otherwise
 */
bool fdor_signed_int(fdor_t *fdor, int *result) {
	if (!cbor_value_is_integer(&fdor->current->cbor_value) ||
		cbor_value_get_int(&fdor->current->cbor_value, result)
			!= CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read Major Type 1 (negative int)\n");
		return false;
	}
	if (!fdor_next(fdor))
		return false;
	return true;
}

/**
 * Read a CBOR unsigned integer (Major Type 0) value.
 * 
 * @param fdor_t - struct fdor_t
 * @param result - output variable where the read integer will be stored
 * @return true if the operation was a success, false otherwise
 */
bool fdor_unsigned_int(fdor_t *fdor, uint64_t *result) {
	if (!cbor_value_is_unsigned_integer(&fdor->current->cbor_value) ||
		cbor_value_get_uint64(&fdor->current->cbor_value, result)
			!= CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to read Major Type 0 (uint)\n");
		return false;
	}
	if (!fdor_next(fdor))
		return false;
	return true;
}

/**
 * Read a CBOR primitive bool (Major Type 7, Additional Info 20/21) value.
 * 
 * @param fdor_t - struct fdor_t
 * @param result - output variable where the read bool will be stored
 * @return true if the operation was a success, false otherwise
 */
bool fdor_boolean(fdor_t *fdor, bool *result) {
	if (!cbor_value_is_boolean(&fdor->current->cbor_value) ||
		cbor_value_get_boolean(&fdor->current->cbor_value, result)
			!= CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to start Major Type 7 (bool)\n");
		return false;
	}
	if (!fdor_next(fdor))
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
 * @param fdor_t - struct fdor_t
 * @return true if the operation was a success, false otherwise
 */
bool fdor_end_array(fdor_t *fdor) {
	if (!cbor_value_is_array(&fdor->current->previous->cbor_value) ||
		!cbor_value_at_end(&fdor->current->cbor_value) ||
		cbor_value_leave_container(&fdor->current->previous->cbor_value, 
		&fdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to end Major Type 4 (array)\n");
		return false;
	}
	// move backwards and free next
	fdor->current = fdor->current->previous;
	fdo_free(fdor->current->next);
	return true;
}

/**
 * Mark the completion of reading elements from a CBOR map (Major Type 5).
 * 
 * It moves back to previous CborValue and frees the node containing the current
 * CborValue (next), closing the map. At the end of this, every read operation
 * would be done using the previous CborValue (represented by current).
 * 
 * @param fdor_t - struct fdor_t
 * @return true if the operation was a success, false otherwise
 */
bool fdor_end_map(fdor_t *fdor) {
	if (!cbor_value_is_map(&fdor->current->previous->cbor_value) ||
		!cbor_value_at_end(&fdor->current->cbor_value) ||
		cbor_value_leave_container(&fdor->current->previous->cbor_value, 
		&fdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to end Major Type 4 (array)\n");
		return false;
	}
	// move backwards and free next
	fdor->current = fdor->current->previous;
	fdo_free(fdor->current->next);
	return true;
}

/**
 * Advance to the next value in the CBOR data stream.
 * 
 * @param fdor_t - struct fdor_t
 * @return true if the operation was a success, false otherwise
 */
bool fdor_next(fdor_t *fdor) {
	if (cbor_value_advance(&fdor->current->cbor_value) != CborNoError) {
		LOG(LOG_ERROR, "CBOR decoder: Failed to advance element\n");
		return false;
	}
	return true;
}

/**
 * Clear and deallocate the internal buffer (fdor_t.fdo_block_t.block) alongwith the current node.
 * 
 * @param fdor_t - struct fdor_t
 */
void fdor_flush(fdor_t *fdor)
{
	fdo_block_t *fdob = &fdor->b;
	fdo_block_reset(fdob);
	fdo_free(fdob->block);
	fdo_free(fdor->current);
}