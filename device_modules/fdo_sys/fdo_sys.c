/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */


#include "fdo_sys.h"
#include "base64.h"
#include "safe_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "fdo_sys_utils.h"

int fdo_sys(fdo_sdk_si_type type, fdor_t *fdor, char *module_message)
{
	static char filename[FILE_NAME_LEN];
	int strcmp_filedesc = 1;
	int strcmp_write = 1;
	int strcmp_exec = 1;
	int result = FDO_SI_INTERNAL_ERROR;
	uint8_t *bin_data = NULL;
	size_t bin_data_entry_len = 0;
	size_t bin_len = 0;
	size_t max_bin_len = MOD_MAX_EXEC_LEN;
	size_t exec_array_length = 0;
	size_t exec_array_index = 0;
	char exec_instructions[MOD_MAX_EXEC_ARG_LEN];
	size_t exec_instructions_sz = 0;
	char space_delimeter = ' ';
	char exec_terminator = '\0';

	switch (type) {
		case FDO_SI_START:
		case FDO_SI_END:
		case FDO_SI_FAILURE:
			result = FDO_SI_SUCCESS;
			goto end;
		case FDO_SI_GET_DSI:
			// this operation is not supported
			result = FDO_SI_FAILURE;
			goto end;
		case FDO_SI_SET_OSI:

		strcmp_s(module_message, FDO_MODULE_MSG_LEN, "filedesc",
					&strcmp_filedesc);
		strcmp_s(module_message, FDO_MODULE_MSG_LEN, "write", &strcmp_write);
		strcmp_s(module_message, FDO_MODULE_MSG_LEN, "exec", &strcmp_exec);

		if (strcmp_filedesc != 0 && strcmp_exec != 0 &&
					strcmp_write != 0) {
#ifdef DEBUG_LOGS
		printf("Invalid moduleMessage for fdo_sys "
			"Module\n");
#endif
			return FDO_SI_CONTENT_ERROR;
		}

		if (strcmp_filedesc == 0) {

			if (!fdor_string_length(fdor, &bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to read fdo_sys:filedesc length\n");
#endif
				goto end;			
			}

			if (bin_len == 0) {
#ifdef DEBUG_LOGS
				printf("Empty value received for fdo_sys:filedesc\n");
#endif
				// received file name cannot be empty
				return FDO_SI_CONTENT_ERROR;
			}

			bin_data = ModuleAlloc(bin_len * sizeof(uint8_t));
			if (!bin_data) {
#ifdef DEBUG_LOGS
					printf("Failed to alloc for fdo_sys:filedesc\n");
#endif
				goto end;
			}

			if (memset_s(bin_data, bin_len, 0) != 0) {
#ifdef DEBUG_LOGS
				printf("Failed to clear fdo_sys:filedesc buffer\n");
#endif
				goto end;
			}

			if (!fdor_text_string(fdor, (char *)bin_data, bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to read fdo_sys:filedesc\n");
#endif
				goto end;
			}
		
			if (0 != strncpy_s(filename, FILE_NAME_LEN,
				(char *)bin_data, bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to copy fdo:sys:filedesc\n");
#endif
				goto end;
			}

			if (true ==
				delete_old_file((const char *)filename)) {
				result = FDO_SI_SUCCESS;
			}

			goto end;
		} else if (strcmp_write == 0) {

			if (!fdor_string_length(fdor, &bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to read fdo_sys:write length\n");
#endif
				goto end;			
			}

			if (bin_len == 0) {
#ifdef DEBUG_LOGS
				printf("Empty value received for fdo_sys:write\n");
#endif
				// received file content can be empty for an empty file
				// do not allocate for the same and skip reading the entry
				if (!fdor_next(fdor)) {
#ifdef DEBUG_LOGS
					printf("Failed to read fdo_sys:write\n");
#endif
					goto end;
				}
				return FDO_SI_SUCCESS;
			}

			bin_data = ModuleAlloc(bin_len * sizeof(uint8_t));
			if (!bin_data) {
#ifdef DEBUG_LOGS
					printf("Failed to alloc for fdo_sys:write\n");
#endif
				goto end;
			}
			if (memset_s(bin_data, bin_len, 0) != 0) {
#ifdef DEBUG_LOGS
				printf("Failed to clear fdo_sys:write buffer\n");
#endif
				goto end;
			}

			if (!fdor_byte_string(fdor, bin_data, bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to read value for fdo_sys:write\n");
#endif
				goto end;
			}

			if (!process_data(FDO_SYS_MOD_MSG_WRITE, bin_data, bin_len, filename)) {
#ifdef DEBUG_LOGS
				printf("Failed to process value for fdo_sys:write");
#endif
				goto end;
			}
			result = FDO_SI_SUCCESS;
			goto end;
		} else if (strcmp_exec == 0) {

			bin_data = ModuleAlloc(max_bin_len * sizeof(uint8_t));
			if (!bin_data) {
#ifdef DEBUG_LOGS
					printf("Failed to alloc for fdo_sys:exec\n");
#endif
					goto end;
			}
			if (memset_s(bin_data, max_bin_len, 0) != 0) {
#ifdef DEBUG_LOGS
				printf("Failed to clear fdo_sys:filedesc buffer\n");
#endif
				goto end;
			}
			bin_data[0] = exec_terminator;

			if (!fdor_array_length(fdor, &exec_array_length)) {
#ifdef DEBUG_LOGS
				printf("Failed to read fdo_sys:exec array length\n");
#endif
				goto end;
			}

			if (!fdor_start_array(fdor)) {
#ifdef DEBUG_LOGS
				printf("Failed to start fdo_sys:exec array\n");
#endif
				goto end;
			}

			for (exec_array_index = 0; exec_array_index < exec_array_length; exec_array_index++) {
				if (0 != memset_s(&exec_instructions, sizeof(exec_instructions), 0)) {
#ifdef DEBUG_LOGS
					printf("fdo_sys exec : Failed to clear exec instructions\n");
#endif
				}
				if (!fdor_string_length(fdor, &exec_instructions_sz)) {
#ifdef DEBUG_LOGS
					printf("Failed to read fdo_sys:exec text length\n");
#endif
					goto end;
				}
				if (!fdor_text_string(fdor, &exec_instructions[0], exec_instructions_sz)) {
#ifdef DEBUG_LOGS
					printf("Failed to read fdo_sys:exec text\n");
#endif
					goto end;
				}
				// do +1 for extra space delimeter to be added and add the space
				exec_instructions_sz++;
				exec_instructions[exec_instructions_sz - 1] = space_delimeter;
				exec_instructions[exec_instructions_sz] = exec_terminator;

				// create the command by concatenating the received array content
				// add the additional intermediate space
				if (strncat_s((char *)bin_data, max_bin_len,
					exec_instructions, exec_instructions_sz) != 0) {
#ifdef DEBUG_LOGS
					printf("Failed to concatenate fdo_sys:exec text\n");
#endif
					goto end;
				}
				// length of the command so far
				bin_data_entry_len = strnlen_s((char *) bin_data, MOD_MAX_EXEC_ARG_LEN);
				if (!bin_data_entry_len || bin_data_entry_len == MOD_MAX_EXEC_ARG_LEN) {
#ifdef DEBUG_LOGS
					printf("Input for exec is not a string.\n");
#endif					
					goto end;
				}
				bin_len += bin_data_entry_len;
			}
			// remove the final space by pushing \0 at the position
			bin_data[bin_len - 1] = exec_terminator;
			if (!fdor_end_array(fdor)) {
#ifdef DEBUG_LOGS
				printf("Failed to start fdo_sys:exec array\n");
#endif
				goto end;
			}

			if (!process_data(FDO_SYS_MOD_MSG_EXEC, bin_data, bin_len, NULL)) {
#ifdef DEBUG_LOGS
				printf("Failed to process fdo_sys:exec\n");
#endif
				goto end;
			}
			result = FDO_SI_SUCCESS;
			goto end;
		}

		default:
		result = FDO_SI_FAILURE;
	}
end:
	if (bin_data) {
		ModuleFree(bin_data);
	}
	return result;
}
