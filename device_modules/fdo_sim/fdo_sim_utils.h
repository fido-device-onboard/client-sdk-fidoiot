/*
 * Copyright 2023 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SYS_UTILS_H__
#define __SYS_UTILS_H__

#include <stdint.h>
#include <stddef.h>

#ifdef TARGET_OS_OPTEE
#include <tee_api.h>
#define ModuleFree(x)                                                          \
	{                                                                      \
		TEE_Free(x);                                                   \
		x = NULL;                                                      \
	}

#else
#define ModuleFree(x)                                                          \
	{                                                                      \
		free(x);                                                       \
		x = NULL;                                                      \
	}
#endif

typedef enum {
	FDO_SIM_MOD_MSG_WRITE,
	FDO_SIM_MOD_MSG_EXEC,
	FDO_SIM_MOD_MSG_EXEC_CB,
	FDO_SIM_MOD_MSG_STATUS_CB,
	FDO_SIM_MOD_MSG_DATA,
	FDO_SIM_MOD_MSG_EOT,
	FDO_SIM_MOD_MSG_EXIT,
	FDO_SIM_MOD_MSG_NONE
} fdoSimModMsg;

void *ModuleAlloc(int size);
bool process_data(fdoSimModMsg type, uint8_t *data, uint32_t dataLen,
		  char *file_name, char **command, bool *status_iscomplete,
		  int *status_resultcode, uint64_t *status_waitsec);

size_t get_file_sz(char const *filename);
bool read_buffer_from_file_from_pos(const char *filename, uint8_t *buffer,
				    size_t size, int from);
bool delete_old_file(const char *file_name);
#endif /* __SYS_UTILS_H__ */
