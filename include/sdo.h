/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDO_H__
#define __SDO_H__

#include "sdomodules.h"
#include <stdint.h>

/* Application ID */
#define APPID 0x01020304

typedef enum {
	SDO_RV_TIMEOUT = 1,
	SDO_CONN_TIMEOUT,
	SDO_DI_ERROR,
	SDO_TO1_ERROR,
	SDO_TO2_ERROR
} sdoSdkError;

// enum for sdk init return value
typedef enum {
	SDO_SUCCESS,
	SDO_INVALID_PATH,
	SDO_CONFIG_NOT_FOUND,
	SDO_INVALID_STATE,
	SDO_RESALE_NOT_SUPPORTED,
	SDO_RESALE_NOT_READY,
	SDO_WARNING,
	SDO_ERROR,
	SDO_ABORT
} sdoSdkStatus;

typedef enum {
	SDO_STATE_PRE_DI = 2,
	SDO_STATE_PRE_TO1,
	SDO_STATE_IDLE,
	SDO_STATE_RESALE,
	SDO_STATE_ERROR
} sdoSdkDeviceState;

sdoSdkStatus sdoSdkRun(void);

sdoSdkStatus sdoSdkResale(void);

sdoSdkDeviceState sdoSdkGetStatus(void);

// callback for error handling
typedef int (*sdoSdkErrorCB)(sdoSdkStatus type, sdoSdkError errorCode);

sdoSdkStatus sdoSdkInit(sdoSdkErrorCB errorHandlingCallback,
			uint32_t numModules,
			sdoSdkServiceInfoModule *moduleInformation);

int sdoDeInit(void);

#endif /* __MP_H__ */
