/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */


#include "fdo_sys.h"
#include "safe_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "fdo_sys_utils.h"

// filename that will either be read from or written onto
static char filename[FILE_NAME_LEN];
// position/offset on the file from which data will be read
static size_t file_seek_pos = 0;
// size of the file from which data will be read
static size_t file_sz = 0;
// EOT value whose value is 0 for 'fetch-data'success, and 1 for failure
static int fetch_data_status = 1;
// Number of items in the exec/exec_cb array
// used to perform clean-up on memory allocated for exec/exec_cb instructions
static size_t exec_array_length = 0;
// status_cb isComplete value
static bool status_cb_iscomplete = false;
//  status_cb resultCode value
static int status_cb_resultcode = -1;
// status_cb waitSec value
static uint64_t status_cb_waitsec = -1;
// local hasMore flag that represents whether the module has data/response to send NOW
// 'true' if there is data to send, 'false' otherwise
static bool hasmore = false;
// local isMore flag that represents whether the module has data/response to send in
// the NEXT messege
// SHOULD be 'true' if there is data to send, 'false' otherwise
// For simplicity, it is 'false' always (also a valid value)
static bool ismore = false;
// the type of operation to perform, generally used to manage responses
static fdoSysModMsg write_type = FDO_SYS_MOD_MSG_NONE;

static bool write_status_cb(fdow_t *fdow);
static bool write_data(fdow_t *fdow, uint8_t *bin_data, size_t bin_len, size_t mtu);
static bool write_eot(fdow_t *fdow, int status);

int fdo_sys(fdo_sdk_si_type type, fdor_t *fdor, fdow_t *fdow,
	char *module_message, bool *has_more, bool *is_more, size_t mtu)
{
	int strcmp_filedesc = 1;
	int strcmp_write = 1;
	int strcmp_exec = 1;
	int strcmp_execcb = 1;
	int strcmp_statuscb = 1;
	int strcmp_fetch = 1;
	int result = FDO_SI_INTERNAL_ERROR;
	uint8_t *bin_data = NULL;
	size_t bin_len = 0;
	size_t exec_array_index = 0;
	size_t status_cb_array_length = 0;
	char **exec_instr = NULL;
	size_t exec_instructions_sz = 0;
	size_t file_remaining = 0;

	switch (type) {
		case FDO_SI_START:
		case FDO_SI_END:
		case FDO_SI_FAILURE:
			// perform clean-ups as needed
			if (!process_data(FDO_SYS_MOD_MSG_EXIT, NULL, 0, NULL,
				NULL, NULL, NULL, NULL)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to perform clean-up operations\n");
#endif
				goto end;
			}
			result = FDO_SI_SUCCESS;
			goto end;
		case FDO_SI_HAS_MORE_DSI:
			// calculate whether there is ServiceInfo to send NOW and update 'has_more'.
			// For testing purposes, set this to true here, and false once first write is done.
			if (!has_more) {
				result = FDO_SI_CONTENT_ERROR;
				goto end;
			}

			*has_more = hasmore;
			if (*has_more) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - There is ServiceInfo to send\n");
#endif
			}
			result = FDO_SI_SUCCESS;
			goto end;
		case FDO_SI_IS_MORE_DSI:
			// calculate whether there is ServiceInfo to send in the NEXT iteration
			// and update 'is_more'.
			if (!is_more) {
				result = FDO_SI_CONTENT_ERROR;
				goto end;
			}
			// sending either true or false is valid
			// for simplicity, setting this to 'false' always,
			// since managing 'ismore' by looking-ahead can be error-prone
			*is_more = ismore;
			result = FDO_SI_SUCCESS;
			goto end;
		case FDO_SI_GET_DSI:
			// write Device ServiceInfo using 'fdow' by partitioning the messages as per MTU, here.
			// however, it is not needed to be done currently and the variable is unused.
			(void)mtu;
			if (!fdow || mtu == 0) {
				result = FDO_SI_CONTENT_ERROR;
				goto end;
			}

			if (!hasmore || write_type == FDO_SYS_MOD_MSG_NONE) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Invalid state\n");
#endif
				goto end;
			}

			// Prepare Service structure as per Section 3.8 of FDO specification
			if (!fdow_start_array(fdow, 1)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to start ServiceInfo array\n");
#endif
				goto end;
			}

			if (!fdow_start_array(fdow, 1)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to start ServiceInfoKeyVal array\n");
#endif
				goto end;
			}

			if (write_type == FDO_SYS_MOD_MSG_STATUS_CB) {
				if (!write_status_cb(fdow)) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to respond with fdo_sys:status_cb\n");
#endif
					goto end;
				}
				// reset this because module has nothing else left to send
				hasmore = false;
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Responded with fdo_sys:status_cb"
					" [%d, %d, %"PRIu64"]\n",
					status_cb_iscomplete, status_cb_resultcode, status_cb_waitsec);
#endif

			} else if (write_type == FDO_SYS_MOD_MSG_DATA) {

				// if an error occcurs EOT is sent next with failure status code
				fetch_data_status = 1;

				// it's ok to not be able to send data here
				// if anything goes wrong, EOT will be sent now/next, regardless
				result = FDO_SI_SUCCESS;

				// if file size is 0 or has changed since first read or the seek/offset
				// point is more that file size (maybe file is corrupted), finish file transfer
				if (file_sz == 0 || file_sz != get_file_sz(filename) ||
					file_seek_pos > file_sz) {
				// file is empty or doesn't exist
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Empty/Invalid content for fdo_sys:data in %s\n",
						filename);
#endif
					if (!write_eot(fdow, fetch_data_status)) {
#ifdef DEBUG_LOGS
						printf("Module fdo_sys - Failed to respond with fdo_sys:eot\n");
#endif
						goto end;
					}
					result = FDO_SI_SUCCESS;
					goto end;
				}

				file_remaining = file_sz - file_seek_pos;
				bin_len = file_remaining > mtu ? mtu : file_remaining;
				bin_data = ModuleAlloc(bin_len * sizeof(uint8_t));
				if (!bin_data) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to alloc for fdo_sys:data buffer\n");
#endif
					goto end;
				}
				if (memset_s(bin_data, bin_len, 0) != 0) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to clear fdo_sys:data buffer\n");
#endif
					goto end;
				}

				if (!read_buffer_from_file_from_pos(filename, bin_data, bin_len, file_seek_pos)) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to read fdo_sys:data content from %s\n",
						filename);
#endif
					if (!write_eot(fdow, fetch_data_status)) {
#ifdef DEBUG_LOGS
						printf("Module fdo_sys - Failed to respond with fdo_sys:eot\n");
#endif
						goto end;
					}
					result = FDO_SI_SUCCESS;
					goto end;
				}

				file_seek_pos += bin_len;

				if (!write_data(fdow,bin_data, bin_len, mtu)) {
				// if this fails, then we're essentially sending an incomplete message to the Owner
				// This is non-recoverable as of now, since this requires us to rewrite msg/68
				// from start
				// it is HIGHLY UNLIKELY that this will error out though
				// TO-DO: Fix to recover from this
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to respond with fdo_sys:data\n");
#endif
					goto end;
				}
				hasmore = true;

				// if file is sent completely, then send EOT next
				fetch_data_status = 0;
				if (file_sz == file_seek_pos) {
					write_type = FDO_SYS_MOD_MSG_EOT;
				}

#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Responded with fdo_sys:data containing\n");
#endif
			} else if (write_type == FDO_SYS_MOD_MSG_EOT) {
				if (!write_eot(fdow, fetch_data_status)) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to respond with fdo_sys:eot\n");
#endif
					goto end;
				}
				hasmore = false;
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Responded with fdo_sys:eot\n");
#endif
			} else if (write_type == FDO_SYS_MOD_MSG_NONE) {
				// shouldn't reach here, if we do, it might a logical error
				// log and fail
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Invalid module write state\n");
#endif
				goto end;
			}

			if (!fdow_end_array(fdow)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to end ServiceInfoKeyVal array\n");
#endif
				goto end;
			}

			if (!fdow_end_array(fdow)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to end ServiceInfo array\n");
#endif
				goto end;
			}
			result = FDO_SI_SUCCESS;
			goto end;
		case FDO_SI_SET_OSI:
			// Process the received Owner ServiceInfo contained within 'fdor', here.
		strcmp_s(module_message, FDO_MODULE_MSG_LEN, "filedesc",
					&strcmp_filedesc);
		strcmp_s(module_message, FDO_MODULE_MSG_LEN, "write", &strcmp_write);
		strcmp_s(module_message, FDO_MODULE_MSG_LEN, "exec", &strcmp_exec);
		strcmp_s(module_message, FDO_MODULE_MSG_LEN, "exec_cb", &strcmp_execcb);
		strcmp_s(module_message, FDO_MODULE_MSG_LEN, "status_cb", &strcmp_statuscb);
		strcmp_s(module_message, FDO_MODULE_MSG_LEN, "fetch", &strcmp_fetch);

		if (strcmp_filedesc != 0 && strcmp_exec != 0 &&
					strcmp_write != 0 && strcmp_execcb != 0 &&
					strcmp_statuscb != 0 && strcmp_fetch != 0) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Invalid moduleMessage\n");
#endif
			return FDO_SI_CONTENT_ERROR;
		}

		if (strcmp_filedesc == 0) {

			if (!fdor_string_length(fdor, &bin_len)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to read fdo_sys:filedesc length\n");
#endif
				goto end;			
			}

			if (bin_len == 0) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Empty value received for fdo_sys:filedesc\n");
#endif
				// received file name cannot be empty
				return FDO_SI_CONTENT_ERROR;
			}

			bin_data = ModuleAlloc(bin_len * sizeof(uint8_t));
			if (!bin_data) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to alloc for fdo_sys:filedesc\n");
#endif
				goto end;
			}

			if (memset_s(bin_data, bin_len, 0) != 0) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to clear fdo_sys:filedesc buffer\n");
#endif
				goto end;
			}

			if (!fdor_text_string(fdor, (char *)bin_data, bin_len)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to read fdo_sys:filedesc\n");
#endif
				goto end;
			}

			if (memset_s(filename, sizeof(filename), 0) != 0) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to clear fdo_sys:filedesc buffer\n");
#endif
				goto end;
			}

			if (0 != strncpy_s(filename, FILE_NAME_LEN,
				(char *)bin_data, bin_len)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to copy fdo:sys:filedesc\n");
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
				printf("Module fdo_sys - Failed to read fdo_sys:write length\n");
#endif
				goto end;			
			}

			if (bin_len == 0) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Empty value received for fdo_sys:write\n");
#endif
				// received file content can be empty for an empty file
				// do not allocate for the same and skip reading the entry
				if (!fdor_next(fdor)) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to read fdo_sys:write\n");
#endif
					goto end;
				}
				return FDO_SI_SUCCESS;
			}

			bin_data = ModuleAlloc(bin_len * sizeof(uint8_t));
			if (!bin_data) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to alloc for fdo_sys:write\n");
#endif
				goto end;
			}
			if (memset_s(bin_data, bin_len, 0) != 0) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to clear fdo_sys:write buffer\n");
#endif
				goto end;
			}

			if (!fdor_byte_string(fdor, bin_data, bin_len)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to read value for fdo_sys:write\n");
#endif
				goto end;
			}

			if (!process_data(FDO_SYS_MOD_MSG_WRITE, bin_data, bin_len, filename,
				NULL, NULL, NULL, NULL)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to process value for fdo_sys:write\n");
#endif
				goto end;
			}
			result = FDO_SI_SUCCESS;
			goto end;
		} else if (strcmp_exec == 0 || strcmp_execcb == 0) {

			if (!fdor_array_length(fdor, &exec_array_length)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to read fdo_sys:exec/exec_cb array length\n");
#endif
				goto end;
			}

			if (exec_array_length == 0) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Empty array received for fdo_sys:exec/exec_cb\n");
#endif
				// received exec array cannot be empty
				result = FDO_SI_CONTENT_ERROR;
				goto end;
			}

			if (!fdor_start_array(fdor)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to start fdo_sys:exec/exec_cb array\n");
#endif
				goto end;
			}

			// allocate memory for exec_instr
			exec_instr = (char**)ModuleAlloc(sizeof(char*) * (exec_array_length + 1));
			if (!exec_instr) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to alloc for fdo_sys:exec/exec_cb instructions\n");
#endif
				goto end;
			}

			for (exec_array_index = 0; exec_array_index < exec_array_length; exec_array_index++) {
				exec_instr[exec_array_index] =
					(char *)ModuleAlloc(sizeof(char) * MOD_MAX_EXEC_ARG_LEN);
				if (!exec_instr[exec_array_index]) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to alloc for single fdo_sys:exec /exec_cb"
						" instruction\n");
#endif
					goto end;
				}
				if (0 != memset_s(exec_instr[exec_array_index],
					sizeof(sizeof(char) * MOD_MAX_EXEC_ARG_LEN), 0)) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys -  Failed to clear single fdo_sys:exec/exec_cb"
					" instruction\n");
#endif
					goto end;
				}
				if (!fdor_string_length(fdor, &exec_instructions_sz) ||
						exec_instructions_sz > MOD_MAX_EXEC_ARG_LEN) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to read fdo_sys:exec/exec_cb text length\n");
#endif
					goto end;
				}
				if (!fdor_text_string(fdor, exec_instr[exec_array_index], exec_instructions_sz)) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to read fdo_sys:exec/exec_cb text\n");
#endif
					goto end;
				}

				// 2nd argument is the filename
				if (exec_array_index == 1) {
					if (memset_s(filename, sizeof(filename), 0) != 0) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to clear filename for"
							" fdo_sys:exec/exec_cb\n");
#endif
					goto end;
				}
					if (0 != strncpy_s(filename, FILE_NAME_LEN,
						exec_instr[exec_array_index], exec_instructions_sz)) {
		#ifdef DEBUG_LOGS
						printf("Module fdo_sys - Failed to copy filename for"
							" fdo_sys:exec/exec_cb\n");
		#endif
						goto end;
					}
				}
			}
			exec_instr[exec_array_index] = NULL;

			if (!fdor_end_array(fdor)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to start fdo_sys:exec/exec_cb array\n");
#endif
				goto end;
			}

			if (strcmp_exec == 0) {
				if (!process_data(FDO_SYS_MOD_MSG_EXEC, NULL, 0, filename,
					exec_instr, NULL, NULL, NULL)) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to process fdo_sys:exec\n");
#endif
					goto end;
				}
			} else if (strcmp_execcb == 0) {
				if (!process_data(FDO_SYS_MOD_MSG_EXEC_CB, NULL, 0, filename,
					exec_instr, &status_cb_iscomplete, &status_cb_resultcode,
					&status_cb_waitsec)) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to process fdo_sys:exec_cb\n");
#endif
					goto end;
				}

				// respond with initial fdo_sys:status_cb message
				hasmore = true;
				write_type = FDO_SYS_MOD_MSG_STATUS_CB;
			}
			result = FDO_SI_SUCCESS;
			goto end;

		} else if (strcmp_statuscb == 0) {
			if (!fdor_array_length(fdor, &status_cb_array_length)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to process fdo_sys:status_cb array length\n");
#endif
				goto end;
			}
			if (status_cb_array_length != 3) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Invalid number of items in fdo_sys:status_cb\n");
#endif
				goto end;				
			}

			if (!fdor_start_array(fdor)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to start fdo_sys:status_cb array\n");
#endif
				goto end;
			}

			if (!fdor_boolean(fdor, &status_cb_iscomplete)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to process fdo_sys:status_cb isComplete\n");
#endif
				goto end;
			}
	
			if (!fdor_signed_int(fdor, &status_cb_resultcode)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to process fdo_sys:status_cb resultCode\n");
#endif
				goto end;
			}
	
			if (!fdor_unsigned_int(fdor, &status_cb_waitsec)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to process fdo_sys:status_cb waitSec\n");
#endif
				goto end;
			}

			if (!fdor_end_array(fdor)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to end fdo_sys:status_cb array\n");
#endif
				goto end;
			}

			// if isComplete is true from Owner, then there is going to be no response
			// from the device, Else respond with fdo_sys:status_cb
			if (status_cb_iscomplete) {
				hasmore = false;
				write_type = FDO_SYS_MOD_MSG_NONE;
			} else {
				hasmore = true;
				write_type = FDO_SYS_MOD_MSG_STATUS_CB;
			}

#ifdef DEBUG_LOGS
				printf("Module fdo_sys - fdo_sys:status_cb [%d, %d, %"PRIu64"]\n",
					status_cb_iscomplete, status_cb_resultcode, status_cb_waitsec);
#endif

			if (!process_data(FDO_SYS_MOD_MSG_STATUS_CB, bin_data, bin_len, NULL,
				NULL, &status_cb_iscomplete, &status_cb_resultcode, &status_cb_waitsec)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to process fdo_sys:status_cb\n");
#endif
				goto end;
			}

			result = FDO_SI_SUCCESS;
			goto end;

		} else if (strcmp_fetch == 0) {
			if (!fdor_string_length(fdor, &bin_len) ) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to read fdo_sys:fetch length\n");
#endif
				goto end;			
			}

			if (bin_len == 0) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Empty value received for fdo_sys:fetch\n");
#endif
				// received file name to be read cannot be empty
				// do not allocate for the same and skip reading the entry
				if (!fdor_next(fdor)) {
#ifdef DEBUG_LOGS
					printf("Module fdo_sys - Failed to read fdo_sys:fetch\n");
#endif
					goto end;
				}
				return FDO_SI_CONTENT_ERROR;
			}

			if (memset_s(filename, sizeof(filename), 0) != 0) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to clear fdo_sys:fetch filename buffer\n");
#endif
				goto end;
			}

			if (!fdor_text_string(fdor, &filename[0], bin_len)) {
#ifdef DEBUG_LOGS
				printf("Module fdo_sys - Failed to read value for fdo_sys:fetch\n");
#endif
				goto end;
			}

			// set the file size here so that we don't read any more than what we initially saw
			file_sz = get_file_sz(filename);
			hasmore = true;
			// reset the file offset to read a new file
			file_seek_pos = 0;
			write_type = FDO_SYS_MOD_MSG_DATA;
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
	if (exec_instr && exec_array_length > 0) {
		int exec_counter = exec_array_length - 1;
		while (exec_counter >= 0) {
			ModuleFree(exec_instr[exec_counter]);
			--exec_counter;
		}
		ModuleFree(exec_instr);
		exec_array_length = 0;
	}
	if (result != FDO_SI_SUCCESS) {
		// clean-up state variables/objects
		hasmore = false;
		file_sz = 0;
		file_seek_pos = 0;
		fetch_data_status = 1;
		write_type = FDO_SYS_MOD_MSG_NONE;
	}
	return result;
}

/**
 * Write CBOR-encoded fdo_sys:status_cb content into FDOW.
 */
static bool write_status_cb(fdow_t *fdow) {

	if (!fdow) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Invalid params for fdo_sys:status_cb array\n");
#endif
		return false;
	}

	char key[] = "fdo_sys:status_cb";

	if (!fdow_start_array(fdow, 2)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to start outer array in fdo_sys:status_cb\n");
#endif
		return false;
	}

	// -1 for ignoring \0 at end
	if (!fdow_text_string(fdow, key, sizeof(key) - 1)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to write fdo_sys:status_cb Key\n");
#endif
		return false;
	}

	if (!fdow_start_array(fdow, 3)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to start inner fdo_sys:status_cb array\n");
#endif
		return false;
	}

	if (!fdow_boolean(fdow, status_cb_iscomplete)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to write fdo_sys:status_cb isComplete\n");
#endif
		return false;
	}

	if (!fdow_signed_int(fdow, status_cb_resultcode)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to write fdo_sys:status_cb resultCode\n");
#endif
		return false;
	}

	if (!fdow_unsigned_int(fdow, status_cb_waitsec)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to write fdo_sys:status_cb waitSec\n");
#endif
		return false;
	}

	if (!fdow_end_array(fdow)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to end inner fdo_sys:status_cb array\n");
#endif
		return false;
	}

	if (!fdow_end_array(fdow)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to end outer array in fdo_sys:status_cb\n");
#endif
		return false;
	}
	return true;
}

/**
 * Write CBOR-encoded fdo_sys:data content into FDOW with given data.
 */
static bool write_data(fdow_t *fdow, uint8_t *bin_data, size_t bin_len, size_t mtu) {
	(void)mtu;
	char key[] = "fdo_sys:data";

	if (!fdow || !bin_data) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Invalid params for fdo_sys:data\n");
#endif
		return false;
	}

	if (!fdow_start_array(fdow, 2)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to start array in fdo_sys:data\n");
#endif
		return false;
	}

	// -1 for ignoring \0 at end
	if (!fdow_text_string(fdow, key, sizeof(key) - 1)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to write fdo_sys:data Key\n");
#endif
		return false;
	}

	if (!fdow_byte_string(fdow, bin_data, bin_len)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to write fdo_sys:data content\n");
#endif
		return false;
	}

	if (!fdow_end_array(fdow)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to end array in fdo_sys:data\n");
#endif
		return false;
	}

	return true;
}

/**
 * Write CBOR-encoded fdo_sys:eot content into FDOW with given status.
 */
static bool write_eot(fdow_t *fdow, int status) {
	char key[] = "fdo_sys:eot";

	if (!fdow) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Invalid params for fdo_sys:eot\n");
#endif
		return false;
	}

	if (!fdow_start_array(fdow, 2)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to start outer array in fdo_sys:eot\n");
#endif
		return false;
	}

	// -1 for ignoring \0 at end
	if (!fdow_text_string(fdow, key, sizeof(key) - 1)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to write fdo_sys:eot Key\n");
#endif
		return false;
	}

	if (!fdow_start_array(fdow, 1)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to start inner array in fdo_sys:eot\n");
#endif
		return false;
	}

	if (!fdow_signed_int(fdow, status)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to write fdo_sys:eot status\n");
#endif
		return false;
	}

	if (!fdow_end_array(fdow)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to end inner array in fdo_sys:eot\n");
#endif
		return false;
	}

	if (!fdow_end_array(fdow)) {
#ifdef DEBUG_LOGS
		printf("Module fdo_sys - Failed to end outer array in fdo_sys:eot\n");
#endif
		return false;
	}
	return true;
}