/*
 * Copyright 2023 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "util.h"
#include "fdo_sim.h"
#include "safe_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "fdo_crypto_hal.h"
#include "fdo_crypto.h"

// CBOR-decoder. Interchangeable with any other CBOR implementation.
static fdor_t *fdor = NULL;
// // CBOR-encoder. Interchangeable with any other CBOR implementation.
static fdow_t *fdow = NULL;

// filename that will either be read from or written onto
static char filename[FILE_NAME_LEN];
// local hasMore flag that represents whether the module has data/response to
// send NOW 'true' if there is data to send, 'false' otherwise
static bool hasmore = false;
// local isMore flag that represents whether the module has data/response to
// send in the NEXT messege SHOULD be 'true' if there is data to send, 'false'
// otherwise For simplicity, it is 'false' always (also a valid value)
static bool ismore = false;
// the type of operation to perform, generally used to manage responses
static fdoSimModMsg write_type = FDO_SIM_MOD_MSG_NONE;

static fdo_hash_t *expectedCheckSum = NULL;
static size_t expected_len = -1;
static int return_code = -1;
static size_t bytes_received = 0;

int fdo_sim_download(fdo_sdk_si_type type, char *module_message,
		     uint8_t *module_val, size_t *module_val_sz,
		     uint16_t *num_module_messages, bool *has_more,
		     bool *is_more, size_t mtu)
{
	int strcmp_filedesc = 1;
	int strcmp_sha_384 = 1;
	int strcmp_length = 1;
	int strcmp_write = 1;
	int result = FDO_SI_INTERNAL_ERROR;
	uint8_t *bin_data = NULL;
	size_t bin_len = 0;
	size_t temp_module_val_sz = 0;

	switch (type) {
	case FDO_SI_START:
		result = fdo_sim_start(&fdor, &fdow);
		goto end;
	case FDO_SI_END:
	case FDO_SI_FAILURE:
		result = fdo_sim_failure(&fdor, &fdow);
		goto end;
	case FDO_SI_HAS_MORE_DSI:
		result = fdo_sim_has_more_dsi(has_more, hasmore);
		goto end;
	case FDO_SI_IS_MORE_DSI:
		result = fdo_sim_is_more_dsi(is_more, ismore);
		goto end;
	case FDO_SI_GET_DSI_COUNT:
		result = fdo_sim_get_dsi_count(num_module_messages);
		goto end;
	case FDO_SI_GET_DSI:
		result = fdo_sim_get_dsi(&fdow, mtu, module_message, module_val,
					 module_val_sz, return_code, bin_data,
					 temp_module_val_sz, &hasmore,
					 &write_type, filename);
		goto end;
	case FDO_SI_SET_OSI:
		result = fdo_sim_set_osi_download(
		    module_message, module_val, module_val_sz, &strcmp_filedesc,
		    &strcmp_length, &strcmp_sha_384, &strcmp_write);

		if (result != FDO_SI_SUCCESS) {
			goto end;
		}

		if (strcmp_filedesc == 0) {
			result = fdo_sim_set_osi_strcmp(bin_len, bin_data);
			goto end;
		} else if (strcmp_length == 0) {
			result = fdo_sim_set_osi_length(bin_len);
			goto end;
		} else if (strcmp_sha_384 == 0) {
			result = fdo_sim_set_osi_sha_384(bin_len, bin_data);
			goto end;
		} else if (strcmp_write == 0) {
			result = fdo_sim_set_osi_write(bin_len, bin_data);
			goto end;
		}
	default:
		result = FDO_SI_FAILURE;
	}

end:
	result = fdo_sim_end(&fdor, &fdow, result, bin_data, NULL, 0, &hasmore,
			     &write_type);
	return result;
}

int fdo_sim_set_osi_download(char *module_message, uint8_t *module_val,
			     size_t *module_val_sz, int *strcmp_filedesc,
			     int *strcmp_length, int *strcmp_sha_384,
			     int *strcmp_write)
{
	if (!module_message || !module_val || !module_val_sz ||
	    *module_val_sz > MOD_MAX_BUFF_SIZE) {
		return FDO_SI_CONTENT_ERROR;
	}

	int result = FDO_SI_INTERNAL_ERROR;

	// Process the received Owner ServiceInfo contained within
	// 'fdor', here.
	strcmp_s(module_message, FDO_MODULE_MSG_LEN, "name", strcmp_filedesc);
	strcmp_s(module_message, FDO_MODULE_MSG_LEN, "length", strcmp_length);
	strcmp_s(module_message, FDO_MODULE_MSG_LEN, "sha-384", strcmp_sha_384);
	strcmp_s(module_message, FDO_MODULE_MSG_LEN, "data", strcmp_write);

	if (*strcmp_filedesc && *strcmp_length && *strcmp_sha_384 &&
	    *strcmp_write) {
		LOG(LOG_ERROR, "Module fdo.download - Invalid moduleMessage\n");
		result = FDO_SI_CONTENT_ERROR;
		goto end;
	}
	// reset, copy CBOR data and initialize Parser.
	fdo_block_reset(&fdow->b);
	if (0 != memcpy_s(fdor->b.block, *module_val_sz, module_val,
			  *module_val_sz)) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to copy buffer "
			       "into temporary FDOR\n");
		goto end;
	}
	fdor->b.block_size = *module_val_sz;

	if (!fdor_parser_init(fdor)) {
		LOG(LOG_ERROR,
		    "Module fdo.download - Failed to init FDOR parser\n");
		goto end;
	}
	result = FDO_SI_SUCCESS;
end:
	return result;
}

int fdo_sim_set_osi_strcmp(size_t bin_len, uint8_t *bin_data)
{
	int result = FDO_SI_INTERNAL_ERROR;

	if (!fdor_string_length(fdor, &bin_len)) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to read "
			       "fdo.download:name length\n");
		goto end;
	}

	if (bin_len == 0) {
		LOG(LOG_ERROR, "Module fdo.download - Empty value received for "
			       "fdo.download:name\n");
		// received file name cannot be empty
		result = FDO_SI_CONTENT_ERROR;
		goto end;
	}

	bin_data = FSIMModuleAlloc(bin_len * sizeof(uint8_t));
	if (!bin_data) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to "
			       "alloc for fdo.download:name\n");
		goto end;
	}

	if (!fdor_text_string(fdor, (char *)bin_data, bin_len)) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to "
			       "read fdo.download:name\n");
		goto end;
	}

	if (memset_s(filename, sizeof(filename), 0) != 0) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to clear "
			       "fdo.download:name buffer\n");
		goto end;
	}

	if (0 !=
	    strncpy_s(filename, FILE_NAME_LEN, (char *)bin_data, bin_len)) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to "
			       "copy fdo.download:name\n");
		goto end;
	}

	if (true == fsim_delete_old_file((const char *)filename)) {
		result = FDO_SI_SUCCESS;
	}
	LOG(LOG_INFO, "Module fdo.download - File created on path: %s\n",
	    filename);
end:
	result = fdo_sim_end(&fdor, &fdow, result, bin_data, NULL, 0, &hasmore,
			     &write_type);
	return result;
}

int fdo_sim_set_osi_length(size_t bin_len)
{
	int result = FDO_SI_INTERNAL_ERROR;

	if (!fdor_unsigned_int(fdor, &bin_len)) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to process "
			       "fdo.download:length\n");
		goto end;
	}

	expected_len = bin_len;

	LOG(LOG_INFO, "Module fdo.download - expected file length %ld\n",
	    expected_len);
	result = FDO_SI_SUCCESS;
end:
	return result;
}

int fdo_sim_set_osi_sha_384(size_t bin_len, uint8_t *bin_data)
{
	int result = FDO_SI_INTERNAL_ERROR;

	if (!fdor_string_length(fdor, &bin_len)) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to "
			       "read fdo.download:sha384 length\n");
		goto end;
	}

	if (bin_len == 0) {
		LOG(LOG_DEBUG, "Module fdo.download - Empty value "
			       "received for fdo.download:sha384\n");
		// received file content can be empty for an
		// empty file do not allocate for the same and
		// skip reading the entry
		if (!fdor_next(fdor)) {
			LOG(LOG_ERROR, "Module fdo.download - Failed to read "
				       "fdo.download:sha384\n");
			result = FDO_SI_CONTENT_ERROR;
			goto end;
		}
		result = FDO_SI_SUCCESS;
		goto end;
	}

	bin_data = FSIMModuleAlloc(bin_len * sizeof(uint8_t));
	if (!bin_data) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to "
			       "alloc for fdo.download:sha384\n");
		goto end;
	}

	if (!fdor_byte_string(fdor, bin_data, bin_len)) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to read value for "
			       "fdo.download:sha384\n");
		goto end;
	}

	expectedCheckSum =
	    fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_384, SHA384_DIGEST_SIZE);
	if (!expectedCheckSum) {
		LOG(LOG_ERROR,
		    "Module fdo.download - Failed to alloc expectedCheckSum\n");
		goto end;
	}

	if (0 != memcpy_s(expectedCheckSum->hash->bytes, SHA384_DIGEST_SIZE,
			  (char *)bin_data, bin_len)) {
		LOG(LOG_ERROR,
		    "Module fdo.download - Failed to copy expectedCheckSum\n");
		fdo_hash_free(expectedCheckSum);
		goto end;
	}
	result = FDO_SI_SUCCESS;
end:
	result = fdo_sim_end(&fdor, &fdow, result, bin_data, NULL, 0, &hasmore,
			     &write_type);
	return result;
}

int fdo_sim_set_osi_write(size_t bin_len, uint8_t *bin_data)
{
	int result = FDO_SI_INTERNAL_ERROR;
	fdo_hash_t *hash = NULL;
	size_t file_len = 0;
	uint8_t *file_data = NULL;

	if (!fdor_string_length(fdor, &bin_len)) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to "
			       "read fdo.download:data length\n");
		goto end;
	}

	if (bytes_received == expected_len || !bin_len) {
		// Entire file has been sent
		result = FDO_SI_SUCCESS;
		goto end;
	}

	bytes_received += bin_len;

	bin_data = FSIMModuleAlloc(bin_len * sizeof(uint8_t));
	if (!bin_data) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to "
			       "alloc for fdo.download:data\n");
		goto end;
	}

	if (!fdor_byte_string(fdor, bin_data, bin_len)) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to read value for "
			       "fdo.download:data\n");
		goto end;
	}

	if (!fsim_process_data(FDO_SIM_MOD_MSG_WRITE, bin_data, bin_len,
			       filename, NULL)) {
		LOG(LOG_ERROR, "Module fdo.download - Failed to process value "
			       "for fdo.download:data\n");
		goto end;
	}

	if (bytes_received == expected_len) {
		// Entire file has been sent
		// Validate hash of received file
		file_len = fsim_get_file_sz(filename);

		if (file_len == expected_len) {
			file_data = FSIMModuleAlloc(file_len * sizeof(uint8_t));
			if (!file_data) {
				LOG(LOG_ERROR,
				    "Module fdo.download - Failed to "
				    "alloc for fdo.download:data\n");
				goto end;
			}

			if (!fsim_read_buffer_from_file_from_pos(
				filename, file_data, file_len, 0)) {
				LOG(LOG_ERROR,
				    "Module fdo.download - Failed to read "
				    "fdo.download:data content from %s\n",
				    filename);
				goto end;
			}

			hash = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_384,
					      SHA384_DIGEST_SIZE);
			if (!hash) {
				LOG(LOG_ERROR, "Module fdo.download - Failed "
					       "to alloc hash\n");
				goto end;
			}

			if ((0 != crypto_hal_hash(FDO_CRYPTO_HASH_TYPE_SHA_384,
						  file_data, file_len,
						  hash->hash->bytes,
						  hash->hash->byte_sz))) {
				LOG(LOG_ERROR, "Module fdo.download - Failed "
					       "to calculate hash\n");
				fdo_hash_free(hash);
				goto end;
			}

			if (fdo_compare_hashes(hash, expectedCheckSum)) {
				LOG(LOG_DEBUG,
				    "Module fdo.download - Hash matched \n");
				return_code = file_len;
			} else {
				LOG(LOG_ERROR,
				    "Module fdo.download: Failed to verify "
				    " hash\n");
				return_code = -1;
			}
		}
		hasmore = true;
		write_type = FDO_SIM_MOD_MSG_DONE;
	}

	result = FDO_SI_SUCCESS;
end:
	if (bytes_received == expected_len) {
		if (hash) {
			fdo_hash_free(hash);
			hash = NULL;
		}
		if (expectedCheckSum) {
			fdo_hash_free(expectedCheckSum);
			expectedCheckSum = NULL;
		}
		if (file_data) {
			FSIMModuleFree(file_data);
		}
	}

	result = fdo_sim_end(&fdor, &fdow, result, bin_data, NULL, 0, &hasmore,
			     &write_type);
	return result;
}
