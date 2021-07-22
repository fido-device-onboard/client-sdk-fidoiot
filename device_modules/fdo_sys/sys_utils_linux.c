/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "safe_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "fdo_sys_utils.h"
#include "fdo_sys.h"

/* Allow only alphanumeric file name either shell or python script*/
static bool is_valid_filename(const char *fname)
{
	bool ret = false;
	int strcmp_result = -1;
	uint8_t i = 0;
	static const char * const whitelisted[] = {"sh", "py"};
	char *substring = NULL, *t1 = NULL;
	char filenme_woextension[FILE_NAME_LEN] = {0};
	size_t fname_len = 0;
	size_t ext_len = 0;
	const size_t EXT_MAX_LEN = 3;

	if (fname == NULL) {
		goto end;
	}

	fname_len = strnlen_s(fname, FILE_NAME_LEN);
	if (!fname_len || fname_len == FILE_NAME_LEN) {
		printf("ERROR: Didn't receive valid filename\n");
		goto end;
	}

	if (strncpy_s(filenme_woextension, FILE_NAME_LEN, fname, fname_len)) {
		goto end;
	}

	if (strlastchar_s(filenme_woextension, FILE_NAME_LEN, '.', &substring)) {
		goto end;
	}

	*substring = '\0'; // Nullify the pointer

	// Now the array is as follow
	//  "TEST FILENAME" "ext"

	// check the whitelisted extension type
	substring++;
	for (i = 0; i < (sizeof(whitelisted) / sizeof(whitelisted[0])); i++) {
		ext_len = strnlen_s(substring, EXT_MAX_LEN);
		if (!ext_len || ext_len == EXT_MAX_LEN) {
			printf("Couldn't find file extension");
			ret = false;
			break;
		}
		strcmp_s(substring, ext_len, whitelisted[i],
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
	if (size <= 0) {
		return NULL;
	}
	void *buf = malloc(size);
	if (!buf) {
		printf("fdoAlloc failed to allocate\n");
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

bool process_data(fdoSysModMsg type, uint8_t *data, uint32_t data_len,
		  char *file_name)
{
	int ret = false;
	FILE *fp = NULL;
	int error_code = 0;
	char *command = NULL;
	size_t command_len = data_len;
	const char exec_terminator = '\0';
	const char *space_delimeter_str = " ";
	char *exec_token, *exec_token_next;
	int exec_token_index = 0;

	if (!data || !data_len) {
#ifdef DEBUG_LOGS
		printf("NULL params in Process_data");
#endif
		return false;
	}

	// For writing to a file
	if (type == FDO_SYS_MOD_MSG_WRITE) {

		fp = fopen(file_name, "a");
		if (!fp) {
#ifdef DEBUG_LOGS
			printf("fdo_sys write:Failed to open file(path): %s\n", file_name);
#endif
			return false;
		}

#ifdef DEBUG_LOGS
	printf("fdo_sys write : %"PRIu32 " bytes being written to the file %s\n",
		data_len, file_name);
#endif

		if (fwrite(data, sizeof(char), data_len, fp) !=
		    (size_t)data_len) {
#ifdef DEBUG_LOGS
			printf("fdo_sys write: Failed to write");
#endif
			goto end;
		}
		ret = true;
		goto end;
	}

	// For Exec call
	if (type == FDO_SYS_MOD_MSG_EXEC) {

		if (exec_terminator != data[data_len]) {
#ifdef DEBUG_LOGS
			printf("fdo_sys exec : Command is not null-terminated\n");
#endif
			goto end;
		}
		// copy the 'exec_instructions' array upto 'exec_instructions_sz'
		// into 'command'. check if it is '\0' delimeted, and get the file name
		command = (char *) ModuleAlloc(data_len);
		if (command == NULL) {
#ifdef DEBUG_LOGS
			printf("fdo_sys exec : Failed to alloc for command\n");
#endif
			goto end;
		}

		if (0 != strncpy_s(command, command_len,
			(char *) data, command_len)) {
			goto end;
		}

		// exec_token empties itself in the tokenization process and
		// exec_token_next is provided for internal usage for strtok_s
		exec_token = strtok_s(command, &command_len,
			space_delimeter_str, &exec_token_next);
		while (exec_token) {
			// 1st ' ' i.e 2nd token, gives the filename that will be executed.
			if (exec_token_index == 1) {
				// Proper error check for system call
				// Allow only filename (no absolute path for secure env)
				if (is_valid_filename((const char *) exec_token) == false) {
#ifdef DEBUG_LOGS
					printf("fdo_sys exec : Failed to get file name from command\n");
#endif
					goto end;
				}
					
				// Executable permission for current user for the file
				if (chmod(exec_token, 0700)) {
#ifdef DEBUG_LOGS
					printf("fdo_sys exec : Failed to set execute permission in %s\n",
						file_name);
#endif
					goto end;
				}
			}
			exec_token = strtok_s(NULL, &command_len,
				space_delimeter_str, &exec_token_next);
			exec_token_index++;
		}

#ifdef DEBUG_LOGS
		printf("fdo_sys exec: Received command completely. Executing...\n");
#endif
		error_code = system((char *) data);
		if (error_code == -1) {
#ifdef DEBUG_LOGS
			printf("fdo_sys exec : Failed to execute command for file %s\n", file_name);
#endif
			goto end;
		}

		ret = true;
	}

end:
	if (command) {
		ModuleFree(command);
	}

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
