/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */


#ifndef __SDO_SYS_H__
#define __SDO_SYS_H__

#include <stdint.h>
#include <stddef.h>
#include "sdomodules.h"

// file path could also be supplied
#define FILE_NAME_LEN 150

#define MOD_MAX_MSG_LEN 10

#define MOD_ACTIVE_TAG "active"
#define MOD_ACTIVE_STATUS "1"

#define MOD_MAX_DATA_LEN 1024

int sdo_sys(sdoSdkSiType type, int *count, sdoSdkSiKeyValue *sv);

#endif /* __SDO_SYS_H__ */
