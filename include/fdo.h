/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __FDO_H__
#define __FDO_H__

#include "fdomodules.h"
#include <stdint.h>

typedef enum {
	FDO_RV_TIMEOUT = 1,
	FDO_CONN_TIMEOUT,
	FDO_DI_ERROR,
	FDO_TO1_ERROR,
	FDO_TO2_ERROR
} fdo_sdk_error;

// enum for sdk init return value
typedef enum {
	FDO_SUCCESS,
	FDO_INVALID_PATH,
	FDO_CONFIG_NOT_FOUND,
	FDO_INVALID_STATE,
	FDO_RESALE_NOT_SUPPORTED,
	FDO_RESALE_NOT_READY,
	FDO_WARNING,
	FDO_ERROR,
	FDO_ABORT
} fdo_sdk_status;

typedef enum {
	FDO_STATE_PRE_DI = 2,
	FDO_STATE_PRE_TO1,
	FDO_STATE_IDLE,
	FDO_STATE_RESALE,
	FDO_STATE_ERROR
} fdo_sdk_device_state;

#if defined(SELF_SIGNED_CERTS_SUPPORTED)
extern bool useSelfSignedCerts;
#endif

fdo_sdk_status fdo_sdk_run(void);

fdo_sdk_status fdo_sdk_resale(void);

fdo_sdk_device_state fdo_sdk_get_status(void);

// callback for error handling
typedef int (*fdo_sdk_errorCB)(fdo_sdk_status type, fdo_sdk_error error_code);

fdo_sdk_status fdo_sdk_init(fdo_sdk_errorCB error_handling_callback,
			    uint32_t num_modules,
			    fdo_sdk_service_info_module *module_information);

void fdo_sdk_deinit(void);
int fdo_de_init(void);

#endif /* __MP_H__ */
