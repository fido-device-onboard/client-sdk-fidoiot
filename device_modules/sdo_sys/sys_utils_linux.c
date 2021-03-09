/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "safe_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sdo_sys_utils.h"
#include "sdo_sys.h"

/* Allow only alphanumeric file name either shell or python script*/
static bool is_valid_filename(const char *fname)
{
	bool ret = false;
	int strcmp_result = -1;
	uint8_t i = 0;
	static const char * const whitelisted[] = {"sh", "py"};
	char *substring = NULL, *t1 = NULL;
	char filenme_woextension[FILE_NAME_LEN] = {0};

	if (fname == NULL)
		goto end;

	if (strncpy_s(filenme_woextension, FILE_NAME_LEN, fname,
		      strnlen_s(fname, FILE_NAME_LEN))) {
		goto end;
	}

	if (strlastchar_s(filenme_woextension, 10, '.', &substring)) {
		goto end;
	}

	*substring = '\0'; // Nullify the pointer

	// Now the array is as follow
	//  "TEST FILENAME" "ext"

	// check the whitelisted extension type
	substring++;
	for (i = 0; i < (sizeof(whitelisted) / sizeof(whitelisted[0])); i++) {
		strcmp_s(substring, strnlen_s(substring, 3), whitelisted[i],
			 &strcmp_result);
		if (!strcmp_result) {
			// extension matched
			ret = true;
			break;
		}
	}
	if (ret != true) {
		goto end;
	}
	ret = false;
	t1 = filenme_woextension;

	// check for only alphanumeric no special char except _
	while (*t1 != '\0') {
		if ((*t1 >= 'a' && *t1 <= 'z') || (*t1 >= 'A' && *t1 <= 'Z') ||
		    (*t1 >= '0' && *t1 <= '9') || (*t1 == '_')) {
			t1++;
		} else {
			goto end;
		}
	}

	ret = true;
end:
	return ret;
}


void *ModuleAlloc(int size)
{
	void *buf = malloc(size);
	if (!buf) {
		printf("sdoAlloc failed to allocate\n");
		goto end;
	}

	if (memset_s(buf, size, 0) != 0) {
		printf("Memset Failed\n");
		free(buf);
		buf = NULL;
		goto end;
	}

end:
	return buf;
}

bool process_data(sdoSysModMsg type, uint8_t *data, uint32_t data_len,
		  char *file_name)
{
	int ret = false;
	FILE *fp = NULL;
	int error_code = 0;
	char *command = NULL;
	static char exec_instructions[MOD_MAX_DATA_LEN];
	static size_t exec_instructions_sz = 0;
	const char exec_terminator = '\0';
	const char *space_delimeter_str = " ";
	char *exec_token, *exec_token_next;
	int exec_token_index = 0;
	size_t data_index = 0;
	bool exec_received_complete = false;

	if (!data || !data_len) {
#ifdef DEBUG_LOGS
		printf("NULL params in Process_data");
#endif
		return false;
	}

	// For writing to a file
	if (type == SDO_SYS_MOD_MSG_WRITE) {

		fp = fopen(file_name, "a");
		if (!fp) {
#ifdef DEBUG_LOGS
			printf("sdo_sys write:Failed to open file(path): %s\n", file_name);
#endif
			return false;
		}

#ifdef DEBUG_LOGS
	printf("sdo_sys write : %"PRIu32 " bytes being written to the file %s\n",
		data_len, file_name);
#endif

		if (fwrite(data, sizeof(char), data_len, fp) !=
		    (size_t)data_len) {
#ifdef DEBUG_LOGS
			printf("sdo_sys write: Failed to write");
#endif
			goto end;
		}
		ret = true;
		goto end;
	}

	// For Exec call
	// TO-DO : Update based on fdo_sys spec when PRI implements it.
	if (type == SDO_SYS_MOD_MSG_EXEC) {

		// check if the received instruction is ending now with \0\0
		if (exec_terminator == data[data_len - 1] &&
			exec_terminator == data[data_len - 2]) {
			exec_received_complete = true;
		}
		// append the exec instructions (whether partial or full)
		// replace '\0' with ' '. this leaves two ' ' at the end
		while (data_index < data_len) {
			// -1 for final '\0'
			if (exec_instructions_sz >= MOD_MAX_DATA_LEN - 1) {
#ifdef DEBUG_LOGS
				printf("sdo_sys exec: Received command is too large. Cannot process\n");
#endif
				goto end;
			}
			if (exec_terminator == data[data_index]) {
				exec_instructions[exec_instructions_sz++] = space_delimeter_str[0];
				data_index++;
			} else {
				exec_instructions[exec_instructions_sz++] = data[data_index++];
			}
		}
		// set the 2nd last character to '\0'
		exec_instructions[exec_instructions_sz - 2] = exec_terminator;

		// if exec command is received completely, execute the instruction
		// if not, continue and look for it in the next iteration
		if (exec_received_complete) {

			// copy the 'exec_instructions' array upto 'exec_instructions_sz'
			// into 'command'. check if it is '\0' delimeted, and get the file name
			command = (char *) ModuleAlloc(exec_instructions_sz);
			if (command == NULL) {
#ifdef DEBUG_LOGS
				printf("sdo_sys exec : Failed to alloc for command\n");
#endif
				goto end;
			}

			if (0 != strncpy_s(command, exec_instructions_sz,
				&exec_instructions[0], exec_instructions_sz)) {
				goto end;
			}

			// exec_token empties itself in the tokenization process and
			// exec_token_next is provided for internal usage for strtok_s
			exec_token = strtok_s(exec_instructions, &exec_instructions_sz,
				space_delimeter_str, &exec_token_next);
			while (exec_token) {
				// 1st '\0' i.e 2nd token, gives the filename that will be executed.
				if (exec_token_index == 1) {
					// Proper error check for system call
					// Allow only filename (no absolute path for secure env)
					if (is_valid_filename((const char *) exec_token) == false) {
#ifdef DEBUG_LOGS
						printf("sdo_sys exec : Failed to get file name from command\n");
#endif
						goto end;
					}
					
					// Executable permission for current user for the file
					if (chmod(exec_token, 0700)) {
#ifdef DEBUG_LOGS
						printf("sdo_sys exec : Failed to set execute permission in %s\n",
							file_name);
#endif
						goto end;
					}
				}
				exec_token = strtok_s(NULL, &exec_instructions_sz,
					space_delimeter_str, &exec_token_next);
				exec_token_index++;
			}

#ifdef DEBUG_LOGS
			printf("sdo_sys exec: Received command completely. Executing...\n");
#endif
			error_code = system(command);
			if (error_code == -1) {
#ifdef DEBUG_LOGS
				printf("sdo_sys exec : Failed to execute command for file %s\n", file_name);
#endif
				goto end;
			}

		} else {
#ifdef DEBUG_LOGS
				printf("sdo_sys exec : Received command partially\n");
#endif
			// received partially. return now so that we don't clear exec_instructions
			return true;
		}
		ret = true;
	}

end:
	if (command)
		ModuleFree(command);
	// clear for next exec
	if (0 != memset_s(&exec_instructions, sizeof(exec_instructions), 0)) {
#ifdef DEBUG_LOGS
		printf("sdo_sys exec : Failed to clear exec instructions\n");
#endif
	}
	exec_instructions_sz = 0;

	if (fp) {
		if (fclose(fp) == EOF) {
#ifdef DEBUG_LOGS
			printf("Fclose failed\n");
#endif
		}
	}
	return ret;
}

bool delete_old_file(const char *filename)
{
	FILE *file = NULL;
	bool ret = false;

	file = fopen(filename, "w");
	if (file) {
		if (!fclose(file)) {
			ret = true;
		}
	} else {
		ret = true;
	}
	return ret;
}
