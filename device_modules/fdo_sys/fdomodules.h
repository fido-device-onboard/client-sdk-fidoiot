/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __FDOMODULES_H__
#define __FDOMODULES_H__

#include "fdoblockio.h"

/*
 * FDO module specific #defs (SvInfo)
 */
#define FDO_MODULE_NAME_LEN 32
#define FDO_MODULE_MSG_LEN 32
#define FDO_MODULE_VALUE_LEN 1024
#define FDO_MAX_MODULES 2
#define FDO_MAX_STR_SIZE 512

#define FDO_MODULE_MESSAGE_ACTIVE "active"

/*==================================================================*/
/* Service Info module registration functionality */

// enum for ServiceInfo Types
typedef enum {
  FDO_SI_START,
  FDO_SI_GET_DSI,
  FDO_SI_SET_OSI,
  FDO_SI_END,
  FDO_SI_FAILURE
} fdo_sdk_si_type;

// enum for SvInfo module CB return value
enum { FDO_SI_CONTENT_ERROR, FDO_SI_INTERNAL_ERROR, FDO_SI_SUCCESS };

typedef struct fdoSdkSiKeyValue {
  char *key;
  char *value;
} fdoSdkSiKeyValue;


// callback to module
typedef int (*fdo_sdk_device_service_infoCB)(fdo_sdk_si_type type, fdow_t *fdow);
typedef int (*fdo_sdk_owner_service_infoCB)(fdo_sdk_si_type type,
	fdor_t *fdor, char *module_message);

/* module struct for modules */
typedef struct {
	bool active;
	char module_name[FDO_MODULE_NAME_LEN];
	fdo_sdk_owner_service_infoCB service_info_callback;
} fdo_sdk_service_info_module;

#endif /* __FDOTYPES_H__ */
