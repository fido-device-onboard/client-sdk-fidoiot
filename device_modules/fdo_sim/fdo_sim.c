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
#include "fdo_sim_utils.h"

// position/offset on the file from which data will be read
static size_t file_seek_pos = 0;
// size of the file from which data will be read
static size_t file_sz = 0;
// EOT value whose value is 0 for 'fetch-data'success, and 1 for failure
static int fetch_data_status = 1;
// local isMore flag that represents whether the module has data/response to
// send in the NEXT messege SHOULD be 'true' if there is data to send, 'false'
// otherwise For simplicity, it is 'false' always (also a valid value)
static bool ismore = false;

/**
 * List of helper functions used in switch case
 *
 * fdo_sim_start
 * fdo_sim_failure
 * fdo_sim_has_more_dsi
 * fdo_sim_is_more_dsi
 * fdo_sim_get_dsi_count
 * fdo_sim_get_dsi
 * fdo_sim_end
 */

int fdo_sim_start(fdor_t **fdor, fdow_t **fdow)
{
	int result = FDO_SI_INTERNAL_ERROR;

	// Initialize module's CBOR Reader/Writer objects.
	*fdow = FSIMModuleAlloc(sizeof(fdow_t));
	if (!fdow_init(*fdow) ||
	    !fdo_block_alloc_with_size(&(*fdow)->b, 8192)) {
		LOG(LOG_ERROR, "Module fdo_sim - FDOW "
			       "Initialization/Allocation failed!\n");
		result = FDO_SI_CONTENT_ERROR;
		goto end;
	}

	*fdor = FSIMModuleAlloc(sizeof(fdor_t));
	if (!fdor_init(*fdor) ||
	    !fdo_block_alloc_with_size(&(*fdor)->b, 8192)) {
		LOG(LOG_ERROR, "Module fdo_sim - FDOR "
			       "Initialization/Allocation failed!\n");
		goto end;
	}
	result = FDO_SI_SUCCESS;
end:
	return result;
}

int fdo_sim_failure(fdor_t **fdor, fdow_t **fdow)
{
	// perform clean-ups as needed
	if (!fsim_process_data(FDO_SIM_MOD_MSG_EXIT, NULL, 0, NULL, NULL)) {
		LOG(LOG_ERROR, "Module fdo_sim - Failed to perform "
			       "clean-up operations\n");
		return FDO_SI_INTERNAL_ERROR;
	}

	if (*fdow) {
		fdow_flush(*fdow);
		FSIMModuleFree(*fdow);
	}
	if (*fdor) {
		fdor_flush(*fdor);
		FSIMModuleFree(*fdor);
	}
	return FDO_SI_SUCCESS;
}

int fdo_sim_has_more_dsi(bool *has_more, bool hasmore)
{
	// calculate whether there is ServiceInfo to send NOW and update
	// 'has_more'. For testing purposes, set this to true here, and
	// false once first write is done.
	if (!has_more) {
		return FDO_SI_CONTENT_ERROR;
	}

	*has_more = hasmore;
	if (*has_more) {
		LOG(LOG_INFO,
		    "Module fdo_sim - There is ServiceInfo to send\n");
	}
	return FDO_SI_SUCCESS;
}

int fdo_sim_is_more_dsi(bool *is_more)
{
	// calculate whether there is ServiceInfo to send in the NEXT
	// iteration and update 'is_more'.
	if (!is_more) {
		LOG(LOG_ERROR, "is_more is NULL\n");
		return FDO_SI_CONTENT_ERROR;
	}

	// sending either true or false is valid
	// for simplicity, setting this to 'false' always,
	// since managing 'ismore' by looking-ahead can be error-prone
	*is_more = ismore;
	return FDO_SI_SUCCESS;
}

int fdo_sim_get_dsi_count(uint16_t *num_module_messages)
{
	// calculate the number of ServiceInfo items to send NOW and update
	// 'num_module_messages'. For testing purposes, set this to 1 here, and
	// 0 once first write is done.
	if (!num_module_messages) {
		return FDO_SI_CONTENT_ERROR;
	}
	*num_module_messages = 1;
	return FDO_SI_SUCCESS;
}

int fdo_sim_get_dsi(fdow_t **fdow, size_t mtu, char *module_message,
		   uint8_t *module_val, size_t *module_val_sz, size_t bin_len,
		   uint8_t *bin_data, size_t temp_module_val_sz, bool *hasmore,
		   fdoSimModMsg *write_type, char *filename)
{
	// write Device ServiceInfo using 'fdow' by partitioning the
	// messages as per MTU, here.
	if (mtu == 0 || !module_message || !module_val || !module_val_sz) {
		return FDO_SI_CONTENT_ERROR;
	}

	int result = FDO_SI_INTERNAL_ERROR;

	(void)bin_len;
	(void)filename;

	// reset and initialize FDOW's encoder for usage
	fdo_block_reset(&(*fdow)->b);
	if (!fdow_encoder_init(*fdow)) {
		LOG(LOG_ERROR, "Module fdo_sim - Failed to initialize "
			       "FDOW encoder\n");
		goto end;
	}

	if (!*hasmore || *write_type == FDO_SIM_MOD_MSG_EXIT) {
		LOG(LOG_ERROR, "Module fdo_sim - Invalid state\n");
		goto end;
	}

	// TO-DO: Imlement functionality

	if (!fdow_encoded_length(*fdow, &temp_module_val_sz)) {
		LOG(LOG_ERROR,
		    "Module fdo_sim - Failed to get encoded length\n");
		goto end;
	}
	*module_val_sz = temp_module_val_sz;
	if (memcpy_s(module_val, *module_val_sz, (*fdow)->b.block,
		     *module_val_sz) != 0) {
		LOG(LOG_ERROR, "Module fdo_sim - Failed to copy "
			       "CBOR-encoded module value\n");
		goto end;
	}
	result = FDO_SI_SUCCESS;
end:
	result =
	    fdo_sim_end(NULL, fdow, result, bin_data, NULL, 0, hasmore, write_type);
	return result;
}

int fdo_sim_end(fdor_t **fdor, fdow_t **fdow, int result, uint8_t *bin_data,
	    uint8_t **exec_instr, size_t total_exec_array_length, bool *hasmore,
	    fdoSimModMsg *write_type)
{
	// End of function, clean-up state variables/objects
	if (bin_data) {
		FSIMModuleFree(bin_data);
	}
	if (exec_instr && total_exec_array_length > 0) {
		int exec_counter = total_exec_array_length - 1;
		while (exec_counter >= 0) {
			FSIMModuleFree(exec_instr[exec_counter]);
			--exec_counter;
		}
		FSIMModuleFree(exec_instr);
		total_exec_array_length = 0;
	}
	if (result != FDO_SI_SUCCESS) {
		// clean-up state variables/objects
		*hasmore = false;
		file_sz = 0;
		file_seek_pos = 0;
		fetch_data_status = 1;
		*write_type = FDO_SIM_MOD_MSG_EXIT;

		if (*fdow) {
			fdow_flush(*fdow);
			FSIMModuleFree(*fdow);
		}
		if (*fdor) {
			fdor_flush(*fdor);
			FSIMModuleFree(*fdor);
		}
	}
	return result;
}
