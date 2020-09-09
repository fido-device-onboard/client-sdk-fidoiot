/*
 * Copyright 2020 Intel Corporation
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
	{								       \
		free(x);                                                       \
		x = NULL;						       \
	}
#endif

typedef enum { SDO_SYS_MOD_MSG_WRITE, SDO_SYS_MOD_MSG_EXEC } sdoSysModMsg;

void *ModuleAlloc(int size);
bool process_data(sdoSysModMsg type, uint8_t *data, uint32_t dataLen,
		  char *File_name);

bool delete_old_file(const char *File_name);
#endif /* __SYS_UTILS_H__ */
