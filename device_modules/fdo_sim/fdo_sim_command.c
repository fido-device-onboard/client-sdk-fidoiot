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

// CBOR-decoder. Interchangeable with any other CBOR implementation.
static fdor_t *fdor = NULL;
// CBOR-encoder. Interchangeable with any other CBOR implementation.
static fdow_t *fdow = NULL;

// filename that will either be read from or written onto
static char filename[FILE_NAME_LEN];
// Number of items in the exec/exec_cb array
// used to perform clean-up on memory allocated for exec/exec_cb instructions
static size_t total_exec_array_length = 0;
// local hasMore flag that represents whether the module has data/response to
// send NOW 'true' if there is data to send, 'false' otherwise
static bool hasmore = false;
static fdoSimModMsg write_type = FDO_SIM_MOD_MSG_EXIT;
static uint8_t *fdo_cmd = NULL;
static size_t fdo_cmd_len = 0;
static uint8_t **fdo_exec_instr = NULL;

int fdo_sim_command(fdo_sdk_si_type type, char *module_message,
		    uint8_t *module_val, size_t *module_val_sz,
		    uint16_t *num_module_messages, bool *has_more,
		    bool *is_more, size_t mtu)
{
	int strcmp_cmd = 1;
	int strcmp_args = 1;
	int strcmp_may_fail = 1;
	int strcmp_return_stdout = 1;
	int strcmp_return_stderr = 1;
	int strcmp_sig = 1;
	int strcmp_exec = 1;
	int result = FDO_SI_INTERNAL_ERROR;
	uint8_t *bin_data = NULL;
	size_t bin_len = 0;
	size_t exec_array_index = 0;
	uint8_t **exec_instr = NULL;
	size_t exec_instructions_sz = 0;
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
		result = fdo_sim_is_more_dsi(is_more);
		goto end;
	case FDO_SI_GET_DSI_COUNT:
		result = fdo_sim_get_dsi_count(num_module_messages);
		goto end;
	case FDO_SI_GET_DSI:
		result = fdo_sim_get_dsi(&fdow, mtu, module_message, module_val,
					module_val_sz, bin_len, bin_data,
					temp_module_val_sz, &hasmore,
					&write_type, filename);
		goto end;
	case FDO_SI_SET_OSI:
		result = fdo_sim_set_osi_command(
		    module_message, module_val, module_val_sz, &strcmp_cmd,
		    &strcmp_args, &strcmp_may_fail, &strcmp_return_stdout,
		    &strcmp_return_stderr, &strcmp_sig, &strcmp_exec);

		if (result != FDO_SI_SUCCESS) {
			goto end;
		}

		if (strcmp_cmd == 0) {
			result = fdo_sim_set_osi_cmd(bin_len, bin_data);
			goto end;
		} else if (strcmp_args == 0) {
			result = fdo_sim_set_osi_args(exec_array_index,
						     &exec_instructions_sz);
			goto end;
		} else if (strcmp_may_fail == 0) {
			result = fdo_sim_set_osi_may_fail();
			goto end;
		} else if (strcmp_return_stdout == 0) {
			result = fdo_sim_set_osi_return_stdout();
			goto end;
		} else if (strcmp_return_stderr == 0) {
			result = fdo_sim_set_osi_return_stderr();
			goto end;
		} else if (strcmp_sig == 0) {
			result = fdo_sim_set_osi_sig(bin_len);
			goto end;
		} else if (strcmp_exec == 0) {
			result = fdo_sim_set_osi_exec(fdo_exec_instr);
			goto end;
		}
	default:
		result = FDO_SI_FAILURE;
	}

end:
	result = fdo_sim_end(&fdor, &fdow, result, bin_data, exec_instr,
			 total_exec_array_length, &hasmore, &write_type);
	return result;
}

int fdo_sim_set_osi_command(char *module_message, uint8_t *module_val,
			   size_t *module_val_sz, int *strcmp_cmd,
			   int *strcmp_args, int *strcmp_may_fail,
			   int *strcmp_return_stdout, int *strcmp_return_stderr,
			   int *strcmp_sig, int *strcmp_exec)
{
	if (!module_message || !module_val || !module_val_sz ||
	    *module_val_sz > MOD_MAX_BUFF_SIZE) {
		return FDO_SI_CONTENT_ERROR;
	}

	int result = FDO_SI_INTERNAL_ERROR;

	// Process the received Owner ServiceInfo contained within
	// 'fdor', here.
	strcmp_s(module_message, FDO_MODULE_MSG_LEN, "command", strcmp_cmd);
	strcmp_s(module_message, FDO_MODULE_MSG_LEN, "execute", strcmp_exec);
	strcmp_s(module_message, FDO_MODULE_MSG_LEN, "may_fail",
		 strcmp_may_fail);
	strcmp_s(module_message, FDO_MODULE_MSG_LEN, "return_stdout",
		 strcmp_return_stdout);
	strcmp_s(module_message, FDO_MODULE_MSG_LEN, "return_stderr",
		 strcmp_return_stderr);
	strcmp_s(module_message, FDO_MODULE_MSG_LEN, "args", strcmp_args);
	strcmp_s(module_message, FDO_MODULE_MSG_LEN, "sig", strcmp_sig);

	if (*strcmp_exec && *strcmp_may_fail && *strcmp_return_stdout &&
	    *strcmp_return_stderr && *strcmp_cmd && *strcmp_args &&
	    *strcmp_sig) {
		LOG(LOG_ERROR, "Module fdo.command - Invalid moduleMessage\n");
		result = FDO_SI_CONTENT_ERROR;
		goto end;
	}

	// reset, copy CBOR data and initialize Parser.
	fdo_block_reset(&fdor->b);
	if (0 != memcpy_s(fdor->b.block, *module_val_sz, module_val,
			  *module_val_sz)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to copy buffer "
			       "into temporary FDOR\n");
		goto end;
	}
	fdor->b.block_size = *module_val_sz;

	if (!fdor_parser_init(fdor)) {
		LOG(LOG_ERROR,
		    "Module fdo.command - Failed to init FDOR parser\n");
		goto end;
	}
	result = FDO_SI_SUCCESS;
end:
	return result;
}

int fdo_sim_set_osi_may_fail(void)
{
	bool may_fail;
	int result = FDO_SI_INTERNAL_ERROR;

	if (!fdor_boolean(fdor, &may_fail)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to read "
			       "fdo.command:may_fail\n");
		goto end;
	}

	// if (may_fail == false) {
	// TO-DO - implement functionality
	// }

	result = FDO_SI_SUCCESS;
end:
	return result;
}

int fdo_sim_set_osi_return_stdout(void)
{
	bool return_stdout;
	int result = FDO_SI_INTERNAL_ERROR;

	if (!fdor_boolean(fdor, &return_stdout)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to read "
			       "fdo.command:return_stdout\n");
		goto end;
	}

	if (return_stdout == true) {
		// TO-DO - implement functionality
	}
	result = FDO_SI_SUCCESS;
end:
	return result;
}

int fdo_sim_set_osi_return_stderr(void)
{
	bool return_stderr;
	int result = FDO_SI_INTERNAL_ERROR;

	if (!fdor_boolean(fdor, &return_stderr)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to read "
			       "fdo.command:return_stderr\n");
		goto end;
	}

	if (return_stderr == true) {
		// TO-DO - implement functionality
	}
	result = FDO_SI_SUCCESS;
end:
	return result;
}

int fdo_sim_set_osi_sig(size_t sigValue)
{
	int result = FDO_SI_INTERNAL_ERROR;

	if (!fdor_unsigned_int(fdor, &sigValue)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to process "
			       "fdo.command:sig\n");
		goto end;
	}

	if (sigValue == 0) {
		LOG(LOG_ERROR, "Module fdo.command - Empty value received for "
			       "fdo.command:sig\n");
		// received file name cannot be empty
		result = FDO_SI_CONTENT_ERROR;
		goto end;
	}
	LOG(LOG_INFO,
	    "Module fdo.command:sig - Process Signal received : %ld\n",
	    sigValue);

	if (sigValue == 9 || sigValue == 15) {
		result = fdo_sim_failure(&fdor, &fdow);
		goto end;
	}

	result = FDO_SI_SUCCESS;
end:
	return result;
}

int fdo_sim_set_osi_cmd(size_t bin_len, uint8_t *bin_data)
{
	int result = FDO_SI_INTERNAL_ERROR;

	if (!fdor_string_length(fdor, &bin_len)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to read "
			       "fdo.command:command length\n");
		goto end;
	}

	if (bin_len == 0) {
		LOG(LOG_ERROR, "Module fdo.command - Empty value received for "
			       "fdo.command:command\n");
		// received file name cannot be empty
		result = FDO_SI_CONTENT_ERROR;
		goto end;
	}

	bin_data = FSIMModuleAlloc(bin_len * sizeof(uint8_t));
	if (!bin_data) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to "
			       "alloc for fdo.command:command\n");
		goto end;
	}

	if (!fdor_text_string(fdor, (char *)bin_data, bin_len)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to "
			       "read fdo.command:command\n");
		goto end;
	}

	fdo_cmd_len = bin_len;
	fdo_cmd = FSIMModuleAlloc(fdo_cmd_len * sizeof(uint8_t));
	if (!fdo_cmd) {
		LOG(LOG_DEBUG, "Module fdo.command - Failed to "
			       "alloc for fdo.command:command\n");
		goto end;
	}

	if (0 != memcpy_s(fdo_cmd, fdo_cmd_len, (char *)bin_data, bin_len)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to copy command\n");
		goto end;
	}
	result = FDO_SI_SUCCESS;
end:
	result = fdo_sim_end(&fdor, &fdow, result, bin_data, NULL,
			 total_exec_array_length, &hasmore, &write_type);
	return result;
}

int fdo_sim_set_osi_args(int exec_array_index, size_t *exec_instructions_sz)
{
	int result = FDO_SI_INTERNAL_ERROR;
	int flag = 0;
	size_t exec_array_length = 0;

	if (!fdor_array_length(fdor, &exec_array_length)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to read "
			       "fdo.command:args array length\n");
		goto end;
	}

	if (exec_array_length == 0) {
		LOG(LOG_ERROR, "Module fdo.command - Empty array received for "
			       "fdo.command:args\n");
		// received exec array cannot be empty
		result = FDO_SI_CONTENT_ERROR;
		goto end;
	}

	if (!fdor_start_array(fdor)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to start "
			       "fdo.command:args array\n");
		goto end;
	}

	total_exec_array_length = exec_array_length + 1;
	// allocate memory for exec_instr
	fdo_exec_instr = (uint8_t **)FSIMModuleAlloc(
	    sizeof(uint8_t *) * (total_exec_array_length + 1));
	if (!fdo_exec_instr) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to alloc for "
			       "fdo.command:args instructions\n");
		goto end;
	}

	fdo_exec_instr[0] =
	    (uint8_t *)FSIMModuleAlloc(sizeof(uint8_t) * MOD_MAX_EXEC_ARG_LEN);
	if (!fdo_exec_instr[0]) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to alloc "
			       "for single fdo.command:args"
			       " instruction\n");
		goto end;
	}

	if (0 != memset_s(fdo_exec_instr[0],
			  sizeof(sizeof(uint8_t) * MOD_MAX_EXEC_ARG_LEN), 0)) {
		LOG(LOG_ERROR, "Module fdo.command -  Failed to clear "
			       "single fdo.command:args"
			       " instruction\n");
		goto end;
	}

	if (0 != memcpy_s(fdo_exec_instr[0], MOD_MAX_EXEC_ARG_LEN,
			  (char *)fdo_cmd, fdo_cmd_len)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to copy command\n");
		goto end;
	}

	for (exec_array_index = 1; exec_array_index <= (int)exec_array_length;
	     exec_array_index++) {
		fdo_exec_instr[exec_array_index] = (uint8_t *)FSIMModuleAlloc(
		    sizeof(uint8_t) * MOD_MAX_EXEC_ARG_LEN);
		if (!fdo_exec_instr[exec_array_index]) {
			LOG(LOG_ERROR, "Module fdo.command - Failed to alloc "
				       "for single fdo.command:args"
				       " instruction\n");
			goto end;
		}
		if (0 !=
		    memset_s(fdo_exec_instr[exec_array_index],
			     sizeof(sizeof(uint8_t) * MOD_MAX_EXEC_ARG_LEN),
			     0)) {
			LOG(LOG_ERROR, "Module fdo.command -  Failed to clear "
				       "single fdo.command:args"
				       " instruction\n");
			goto end;
		}
		if (!fdor_string_length(fdor, exec_instructions_sz) ||
		    *exec_instructions_sz > MOD_MAX_EXEC_ARG_LEN) {
			LOG(LOG_ERROR, "Module fdo.command - Failed to read "
				       "fdo.command:args text "
				       "length\n");
			goto end;
		}
		if (!fdor_text_string(fdor,
				      (char *)fdo_exec_instr[exec_array_index],
				      *exec_instructions_sz)) {
			LOG(LOG_ERROR, "Module fdo.command - Failed to read "
				       "fdo.command:args text\n");
			goto end;
		}

		// last argument is the filename
		if (exec_array_index == ((int)exec_array_length - 1)) {
			if (memset_s(filename, sizeof(filename), 0) != 0) {
				LOG(LOG_ERROR, "Module fdo.command - Failed "
					       "to clear filename for"
					       " fdo.command:args\n");
				goto end;
			}
			if (0 !=
			    strncpy_s(filename, FILE_NAME_LEN,
				      (char *)fdo_exec_instr[exec_array_index],
				      *exec_instructions_sz)) {
				LOG(LOG_ERROR, "Module fdo.command - Failed "
					       "to copy filename for"
					       " fdo.command:args\n");
				goto end;
			}
		}
	}
	fdo_exec_instr[exec_array_index] = NULL;

	if (!fdor_end_array(fdor)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to end "
			       "fdo.command:args array\n");
		goto end;
	}

	flag = 1;
	result = FDO_SI_SUCCESS;
end:
	if (!flag) {
		result =
		    fdo_sim_end(&fdor, &fdow, result, fdo_cmd, fdo_exec_instr,
			    total_exec_array_length, &hasmore, &write_type);
	} else {
		result =
		    fdo_sim_end(&fdor, &fdow, result, fdo_cmd, NULL,
			    total_exec_array_length, &hasmore, &write_type);
	}
	return result;
}

int fdo_sim_set_osi_exec(uint8_t **exec_instr)
{
	int result = FDO_SI_INTERNAL_ERROR;

	if (fdor_is_value_null(fdor)) {
		LOG(LOG_ERROR, "Module fdo.command - Failed to read "
			       "fdo.command:execute array length\n");
		goto end;
	}

	if (exec_instr) {
		if (!fsim_process_data(FDO_SIM_MOD_MSG_EXEC, NULL, 0, filename,
				       (char **)exec_instr)) {
			LOG(LOG_ERROR, "Module fdo.command - Failed to "
				       "process fdo.command:execute\n");
			goto end;
		}
	}
	result = FDO_SI_SUCCESS;
end:
	result = fdo_sim_end(&fdor, &fdow, result, NULL, exec_instr,
			 total_exec_array_length, &hasmore, &write_type);
	return result;
}
