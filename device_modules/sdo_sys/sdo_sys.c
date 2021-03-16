/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */


#include "sdo_sys.h"
#include "base64.h"
#include "safe_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "sdo_sys_utils.h"

int sdo_sys(sdo_sdk_si_type type, sdor_t *sdor, char *module_message)
{
	static char filename[FILE_NAME_LEN];
	int strcmp_filedesc = 1;
	int strcmp_write = 1;
	int strcmp_exec = 1;
	int result = SDO_SI_INTERNAL_ERROR;
	uint8_t *bin_data = NULL;
	size_t bin_len = 0;

	switch (type) {
		case SDO_SI_START:
		case SDO_SI_END:
		case SDO_SI_FAILURE:
			result = SDO_SI_SUCCESS;
			goto end;
		case SDO_SI_GET_DSI:
			// this operation is not supported
			result = SDO_SI_FAILURE;
			goto end;
		case SDO_SI_SET_OSI:

		strcmp_s(module_message, SDO_MODULE_MSG_LEN, "filedesc",
					&strcmp_filedesc);
		strcmp_s(module_message, SDO_MODULE_MSG_LEN, "write", &strcmp_write);
		strcmp_s(module_message, SDO_MODULE_MSG_LEN, "exec", &strcmp_exec);

		if (strcmp_filedesc != 0 && strcmp_exec != 0 &&
					strcmp_write != 0) {
#ifdef DEBUG_LOGS
		printf("Invalid moduleMessage for sdo_sys "
			"Module\n");
#endif
			return SDO_SI_CONTENT_ERROR;
		}

		if (strcmp_filedesc == 0) {

			if (!sdor_string_length(sdor, &bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to read sdo_sys:filedesc length\n");
#endif
				goto end;			
			}

			bin_data = ModuleAlloc(bin_len * sizeof(uint8_t));
			if (!bin_data) {
#ifdef DEBUG_LOGS
					printf("Failed to alloc for sdo_sys:filedesc\n");
#endif
				goto end;
			}

			if (memset_s(bin_data, bin_len, 0) != 0) {
#ifdef DEBUG_LOGS
				printf("Failed to clear sdo_sys:filedesc buffer\n");
#endif
				goto end;
			}

			if (!sdor_byte_string(sdor, bin_data, bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to read sdo_sys:filedesc\n");
#endif
				goto end;
			}
		
			if (0 != strncpy_s(filename, FILE_NAME_LEN,
				(char *)bin_data, bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to copy sdo:sys:filedesc\n");
#endif
				goto end;
			}

			if (true ==
				delete_old_file((const char *)filename)) {
				result = SDO_SI_SUCCESS;
			}

			goto end;
		}
		else if (strcmp_write == 0) {

			if (!sdor_string_length(sdor, &bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to read sdo_sys:write length\n");
#endif
				goto end;			
			}
			
			bin_data = ModuleAlloc(bin_len * sizeof(uint8_t));
			if (!bin_data) {
#ifdef DEBUG_LOGS
					printf("Failed to alloc for sdo_sys:write\n");
#endif
				goto end;
			}
			if (memset_s(bin_data, bin_len, 0) != 0) {
#ifdef DEBUG_LOGS
				printf("Failed to clear sdo_sys:write buffer\n");
#endif
				goto end;
			}

			if (!sdor_byte_string(sdor, bin_data, bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to read value for sdo_sys:write\n");
#endif
				goto end;
			}

			if (!process_data(SDO_SYS_MOD_MSG_WRITE, bin_data, bin_len, filename)) {
#ifdef DEBUG_LOGS
				printf("Failed to process value for sdo_sys:write");
#endif
				goto end;
			}
			result = SDO_SI_SUCCESS;
			goto end;
		}
		else if (strcmp_exec == 0) {

			if (!sdor_string_length(sdor, &bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to read sdo_sys:exec length\n");
#endif
				goto end;			
			}
			
			bin_data = ModuleAlloc(bin_len * sizeof(uint8_t));
			if (!bin_data) {
#ifdef DEBUG_LOGS
					printf("Failed to alloc for sdo_sys:exec\n");
#endif
				goto end;
			}
			if (memset_s(bin_data, bin_len, 0) != 0) {
#ifdef DEBUG_LOGS
				printf("Failed to clear sdo_sys:exec buffer\n");
#endif
				goto end;
			}

			if (!sdor_byte_string(sdor, bin_data, bin_len)) {
#ifdef DEBUG_LOGS
				printf("Failed to read value for sdo_sys:exec\n");
#endif
				goto end;
			}
			if (!process_data(SDO_SYS_MOD_MSG_EXEC, bin_data, bin_len, NULL)) {
#ifdef DEBUG_LOGS
				printf("Failed to process sdo_sys:exec\n");
#endif
				goto end;
			}
			result = SDO_SI_SUCCESS;
			goto end;
		}

		default:
		result = SDO_SI_FAILURE;
	}
end:
	if (bin_data)
		ModuleFree(bin_data);
	return result;
}
