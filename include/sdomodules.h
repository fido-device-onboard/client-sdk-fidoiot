/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDOMODULES_H__
#define __SDOMODULES_H__

#include "sdoblockio.h"

/*
 * SDO module specific #defs (Sv_info)
 */
#define SDO_MODULE_NAME_LEN 32
#define SDO_MODULE_MSG_LEN 32
#define SDO_MODULE_VALUE_LEN 100

#ifdef EXTRA_MODULES
#define SDO_MAX_MODULES 4
#else
#define SDO_MAX_MODULES 1
#endif

#define FDO_MODULE_MESSAGE_ACTIVE "active"

/*==================================================================*/
/* Service Info module registration functionality */

// enum for Service_info Types
typedef enum {
	SDO_SI_START,
	SDO_SI_GET_DSI,
	SDO_SI_SET_OSI,
	SDO_SI_END,
	SDO_SI_FAILURE
} sdo_sdk_si_type;

// enum for Sv_info module CB return value
enum { SDO_SI_CONTENT_ERROR, SDO_SI_INTERNAL_ERROR, SDO_SI_SUCCESS };

typedef struct sdo_sdk_si_key_value {
	char *key;
	char *value;
} sdo_sdk_si_key_value;

// callback to module
typedef int (*sdo_sdk_device_service_infoCB)(sdo_sdk_si_type type, sdow_t *sdow);
typedef int (*sdo_sdk_owner_service_infoCB)(sdo_sdk_si_type type,
	sdor_t *sdor, char *module_message);

/* module struct for modules */
typedef struct {
	bool active;
	char module_name[SDO_MODULE_NAME_LEN];
	sdo_sdk_owner_service_infoCB service_info_callback;
} sdo_sdk_service_info_module;

extern int sdo_sys(sdo_sdk_si_type type, sdor_t *sdor, char *module_message);

// Modules CB
// TO-DO at a later time
extern int devconfig(sdo_sdk_si_type type, int *count,
		     sdo_sdk_si_key_value *si);
extern int keypair(sdo_sdk_si_type type, int *count, sdo_sdk_si_key_value *si);
extern int pelionconfig(sdo_sdk_si_type type, int *count,
			sdo_sdk_si_key_value *si);

#endif /* __SDOTYPES_H__ */
