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
} sdo_sdk_error;

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
} sdo_sdk_status;

typedef enum {
	SDO_STATE_PRE_DI = 2,
	SDO_STATE_PRE_TO1,
	SDO_STATE_IDLE,
	SDO_STATE_RESALE,
	SDO_STATE_ERROR
} sdo_sdk_device_state;

sdo_sdk_status sdo_sdk_run(void);

sdo_sdk_status sdo_sdk_resale(void);

sdo_sdk_device_state sdo_sdk_get_status(void);

// callback for error handling
typedef int (*sdo_sdk_errorCB)(sdo_sdk_status type, sdo_sdk_error error_code);

sdo_sdk_status sdo_sdk_init(sdo_sdk_errorCB error_handling_callback,
			    uint32_t num_modules,
			    sdo_sdk_service_info_module *module_information);

void sdo_sdk_deinit(void);
int sdo_de_init(void);

#endif /* __MP_H__ */
