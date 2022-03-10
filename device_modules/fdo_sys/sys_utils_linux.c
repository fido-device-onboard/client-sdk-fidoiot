/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "safe_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "fdo_sys_utils.h"
#include "fdo_sys.h"

// Process ID of the process created by fdo_sys:exec_cb
static pid_t exec_pid = -1;

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
			printf("Couldn't find file extension\n");
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

	// check for only alphanumeric no special char except underscore '_' and hyphen '-'
	while (*t1 != '\0') {
		if ((*t1 >= 'a' && *t1 <= 'z') || (*t1 >= 'A' && *t1 <= 'Z') ||
		    (*t1 >= '0' && *t1 <= '9') || (*t1 == '_') || (*t1 == '-')) {
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
		  char *file_name, char **command, bool *status_iscomplete, int *status_resultcode,
		  uint64_t *status_waitsec)
{
	bool ret = false;
	FILE *fp = NULL;
	int status = -1;

	// For writing to a file
	if (type == FDO_SYS_MOD_MSG_WRITE) {

		if (!data || !data_len) {
#ifdef DEBUG_LOGS
			printf("fdo_sys write : Invalid params\n");
#endif
			return false;
		}
		if (!file_name) {
#ifdef DEBUG_LOGS
			printf("fdo_sys write : No filename present for fdo_sys:write\n");
#endif
			return false;
		}
		fp = fopen(file_name, "a");
		if (!fp) {
#ifdef DEBUG_LOGS
			printf("fdo_sys write : Failed to open file(path): %s\n", file_name);
#endif
			return false;
		}

		printf("fdo_sys write : %"PRIu32 " bytes being written to the file %s\n",
			data_len, file_name);

		if (fwrite(data, sizeof(char), data_len, fp) !=
		    (size_t)data_len) {
#ifdef DEBUG_LOGS
			printf("fdo_sys write : Failed to write\n");
#endif
			goto end;
		}
		ret = true;
		goto end;
	}

	// For exec/exec_cb call
	if (type == FDO_SYS_MOD_MSG_EXEC || type == FDO_SYS_MOD_MSG_EXEC_CB) {

		if (!file_name || !is_valid_filename((const char *) file_name)) {
#ifdef DEBUG_LOGS
			printf("fdo_sys exec/exec_cb : Invalid filename\n");
#endif
			return false;
		}

		if (!command) {
#ifdef DEBUG_LOGS
			printf("fdo_sys exec/exec_cb : Missing command\n");
#endif
			return false;
		}

		if (exec_pid != -1) {
#ifdef DEBUG_LOGS
			printf("fdo_sys exec/exec_cb : An exec instruction is currently in progress\n");
#endif
			return false;
		}

		printf("fdo_sys exec : Executing command...\n");
		exec_pid = fork();
		if (exec_pid < 0) {
			// error
#ifdef DEBUG_LOGS
			printf("fdo_sys exec : Failed to fork.\n");
#endif
			return false;
		} else if (exec_pid == 0) {
			// child process
			status = execv(command[0], command);
			if (status == -1) {
#ifdef DEBUG_LOGS
				printf("fdo_sys exec : Failed to execute command.\n");
#endif
				goto end;
			}
		} else {
			// parent process
			// if exec, block until process completes
			if (type == FDO_SYS_MOD_MSG_EXEC) {
				waitpid(exec_pid, &status, 0);
				if (WIFEXITED(status)) {
					if (WEXITSTATUS(status) != 0) {
#ifdef DEBUG_LOGS
						printf("fdo_sys exec : Proces execution failed.\n");
#endif
						goto end;

					} else {
#ifdef DEBUG_LOGS
						printf("fdo_sys exec : Process execution completed.\n");
#endif
						// reset the process ID since execution is done
						exec_pid = -1;
						ret = true;
						goto end;
					}
				}
			} else {
				if (!status_iscomplete || !status_resultcode || !status_waitsec) {
#ifdef DEBUG_LOGS
					printf("fdo_sys exec_cb : Invalid params\n");
#endif
					return ret;
				}
				*status_iscomplete = false;
				*status_resultcode = 0;
				*status_waitsec = 5;
				ret = true;
#ifdef DEBUG_LOGS
				printf("fdo_sys exec_cb : Process execution started\n");
#endif
			}
		}

		ret = true;
	}

	// For status_cb
	if (type == FDO_SYS_MOD_MSG_STATUS_CB) {

		if (!status_iscomplete || !status_resultcode || !status_waitsec) {
#ifdef DEBUG_LOGS
			printf("fdo_sys status_cb : Invalid params\n");
#endif
			return ret;
		}
		if (*status_iscomplete && exec_pid < 0) {
			// final Acknowledgement message from the Owner. NO-OP
			ret = true;
			return ret;
		}
		if (*status_iscomplete && exec_pid > 0) {
			// kill the process as requested by the Owner
			kill(exec_pid, SIGTERM);
			*status_iscomplete = true;
			*status_resultcode = 0;
			*status_waitsec = 0;
			ret = true;
			goto end;
		} else {
			// check for process status every second, until the given waitsec
			int wait_timer = *status_waitsec;
			while (wait_timer > 0) {
				if (waitpid(exec_pid, &status, WNOHANG) == -1) {
#ifdef DEBUG_LOGS
					printf("fdo_sys status_cb : Error occurred while checking process status\n");
#endif
					return ret;
				}
				if (WIFEXITED(status)) {
					*status_resultcode = WEXITSTATUS(status);
					*status_iscomplete = true;
					*status_waitsec = 0;
#ifdef DEBUG_LOGS
					printf("fdo_sys status_cb: Process execution completed\n");
#endif
					// reset the process ID since execution is done
					exec_pid = -1;
					ret = true;
					goto end;
				}
				sleep(1);
				wait_timer--;
			}
			*status_iscomplete = false;
			*status_resultcode = 0;
		}

		ret = true;
	}

	// For performing clean-up operations of module exit
	if (type == FDO_SYS_MOD_MSG_EXIT) {
		if (exec_pid > 0) {
			// kill the process as a part of clea-up operations
			kill(exec_pid, SIGTERM);
		}
		ret = true;
	}
end:

	if (fp) {
		if (fclose(fp) == EOF) {
#ifdef DEBUG_LOGS
			printf("Fclose failed\n");
#endif
		}
	}
	// upon error, kill the forked process
	if (!ret && exec_pid > 0) {
		kill(exec_pid, SIGTERM);
		exec_pid = -1;
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

/**
 * Return the length of the given file.
 */
size_t get_file_sz(char const *filename)
{
	if (!filename || !filename[0]) {
		return 0;
	}
	size_t file_length = 0;
	FILE *fp = fopen(filename, "rb");

	if (fp) {
		if (fseek(fp, 0, SEEK_END) != 0) {
			printf("fseek() failed in the file");
			if (fclose(fp) == EOF) {
				printf("Fclose Failed");
			}
			return 0;
		}
		file_length = ftell(fp);
		if (fclose(fp) == EOF) {
			printf("Fclose Failed");
		}
	}
	return file_length;
}

/**
 * Read the filename's content (size bytes) into the given buffer (pre-allocated memory)
 * starting at the specified offset (from).
 */
bool read_buffer_from_file_from_pos(const char *filename, uint8_t *buffer, size_t size, int from)
{
	FILE *file = NULL;
	size_t bytes_read = 0;

	file = fopen(filename, "rb");
	if (!file) {
		return false;
	}

	if (fseek(file, from, SEEK_SET) != 0) {
		printf("fseek() failed in the file");
		if (fclose(file) == EOF) {
			printf("Fclose Failed");
		}
		return false;
    }
	bytes_read = fread(buffer, 1, size, file);
	if (bytes_read != size) {
		if (fclose(file) == EOF) {
			printf("Fclose Failed");
		}
		return false;
	}

	if (fclose(file) == EOF) {
		printf("Fclose Failed");
	}
	return true;
}
