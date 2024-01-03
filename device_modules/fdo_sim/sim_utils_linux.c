/*
 * Copyright 2023 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "safe_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "fdo_sim_utils.h"
#include "fdo_sim.h"

// Process ID of the process created by Module:exec_cb
static pid_t exec_pid = -1;

void *FSIMModuleAlloc(int size)
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

bool fsim_process_data(fdoSimModMsg type, uint8_t *data, uint32_t data_len,
		       char *file_name, char **command, bool *status_iscomplete,
		       int *status_resultcode, uint64_t *status_waitsec)
{
	bool ret = false;
	FILE *fp = NULL;
	int status = -1;

	// For writing to a file
	if (type == FDO_SIM_MOD_MSG_WRITE) {

		if (!data || !data_len) {
#ifdef DEBUG_LOGS
			printf("Module fdo.download:data write : Invalid "
			       "params\n");
#endif
			return false;
		}
		if (!file_name) {
#ifdef DEBUG_LOGS
			printf("Module fdo.download:data write : No filename "
			       "present for "
			       "Module fdo.download:data\n");
#endif
			return false;
		}
		fp = fopen(file_name, "a");
		if (!fp) {
#ifdef DEBUG_LOGS
			printf("Module fdo.download:data write : Failed to "
			       "open file(path): %s\n",
			       file_name);
#endif
			return false;
		}

		printf("Module fdo.download:data write : %" PRIu32
		       " bytes being written to the file %s\n",
		       data_len, file_name);

		if (fwrite(data, sizeof(char), data_len, fp) !=
		    (size_t)data_len) {
#ifdef DEBUG_LOGS
			printf("Module fdo.download:data write : Failed to "
			       "write\n");
#endif
			goto end;
		}
		ret = true;
		goto end;
	}

	// For exec/exec_cb call
	if (type == FDO_SIM_MOD_MSG_EXEC || type == FDO_SIM_MOD_MSG_EXEC_CB) {

		if (!file_name) {
#ifdef DEBUG_LOGS
			printf(
			    "Module fdo.commmand:execute : Invalid filename\n");
#endif
			return false;
		}

		if (!command) {
#ifdef DEBUG_LOGS
			printf(
			    "Module fdo.commmand:execute : Missing command\n");
#endif
			return false;
		}

		if (exec_pid != -1) {
#ifdef DEBUG_LOGS
			printf("Module fdo.commmand:execute : An exec "
			       "instruction is "
			       "currently in progress\n");
#endif
			return false;
		}

		printf("Module fdo.commmand:execute : Executing command...\n");
		exec_pid = fork();
		if (exec_pid < 0) {
			// error
#ifdef DEBUG_LOGS
			printf(
			    "Module fdo.commmand:execute : Failed to fork.\n");
#endif
			return false;
		} else if (exec_pid == 0) {
			// child process
			status = execvp(command[0], command);
			if (status == -1) {
#ifdef DEBUG_LOGS
				printf("Module fdo.commmand:execute : Failed "
				       "to execute "
				       "command.\n");
#endif
				goto end;
			}
		} else {
			// parent process
			// if exec, block until process completes
			if (type == FDO_SIM_MOD_MSG_EXEC) {
				waitpid(exec_pid, &status, 0);
				if (WIFEXITED(status)) {
					if (WEXITSTATUS(status) != 0) {
#ifdef DEBUG_LOGS
						printf("Module "
						       "fdo.commmand:execute : "
						       "Proces "
						       "execution failed.\n");
#endif
						goto end;

					} else {
#ifdef DEBUG_LOGS
						printf(
						    "Module "
						    "fdo.commmand:execute : "
						    "Process "
						    "execution completed.\n");
#endif
						// reset the process ID since
						// execution is done
						exec_pid = -1;
						ret = true;
						goto end;
					}
				}
			} else {
				if (!status_iscomplete || !status_resultcode ||
				    !status_waitsec) {
#ifdef DEBUG_LOGS
					printf("Module fdo.commmand:execute : "
					       "Invalid "
					       "params\n");
#endif
					return ret;
				}
				*status_iscomplete = false;
				*status_resultcode = 0;
				*status_waitsec = 5;
				ret = true;
#ifdef DEBUG_LOGS
				printf("Module fdo.commmand:execute : Process "
				       "execution "
				       "started\n");
#endif
			}
		}

		ret = true;
	}

	// For status_cb
	if (type == FDO_SIM_MOD_MSG_STATUS_CB) {

		if (!status_iscomplete || !status_resultcode ||
		    !status_waitsec) {
#ifdef DEBUG_LOGS
			printf("Module status_cb : Invalid params\n");
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
			// check for process status every second, until the
			// given waitsec
			int wait_timer = *status_waitsec;
			while (wait_timer > 0) {
				if (waitpid(exec_pid, &status, WNOHANG) == -1) {
#ifdef DEBUG_LOGS
					printf("Module status_cb : Error "
					       "occurred while checking "
					       "process status\n");
#endif
					return ret;
				}
				if (WIFEXITED(status)) {
					*status_resultcode =
					    WEXITSTATUS(status);
					*status_iscomplete = true;
					*status_waitsec = 0;
#ifdef DEBUG_LOGS
					printf("Module status_cb: Process "
					       "execution completed\n");
#endif
					// reset the process ID since execution
					// is done
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
	if (type == FDO_SIM_MOD_MSG_EXIT) {
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

bool fsim_delete_old_file(const char *filename)
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
size_t fsim_get_file_sz(char const *filename)
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
 * Read the filename's content (size bytes) into the given buffer (pre-allocated
 * memory) starting at the specified offset (from).
 */
bool fsim_read_buffer_from_file_from_pos(const char *filename, uint8_t *buffer,
					 size_t size, int from)
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
