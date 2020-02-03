/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDOMODULES_H__
#define __SDOMODULES_H__

/*
 * SDO module specific #defs (SvInfo)
 */
#define SDO_MODULE_NAME_LEN 32
#define SDO_MODULE_MSG_LEN 32
#define SDO_MODULE_VALUE_LEN 100
#ifdef TARGET_OS_OPTEE
#define SDO_MAX_MODULES 1
#else
#define SDO_MAX_MODULES 1
#endif

/*==================================================================*/
/* Service Info module registration functionality */

// enum for ServiceInfo Types
typedef enum {
	SDO_SI_START,
	SDO_SI_GET_DSI_COUNT,
	SDO_SI_SET_PSI,
	SDO_SI_GET_DSI,
	SDO_SI_SET_OSI,
	SDO_SI_END,
	SDO_SI_FAILURE
} sdoSdkSiType;

// enum for SvInfo module CB return value
enum { SDO_SI_CONTENT_ERROR, SDO_SI_INTERNAL_ERROR, SDO_SI_SUCCESS };

typedef struct sdoSdkSiKeyValue {
	char *key;
	char *value;
} sdoSdkSiKeyValue;

// callback to module
typedef int (*sdoSdkServiceInfoCB)(sdoSdkSiType type, int *count,
				   sdoSdkSiKeyValue *si);

/* module struct for modules */
typedef struct {
	char moduleName[SDO_MODULE_NAME_LEN];
	sdoSdkServiceInfoCB serviceInfoCallback;
} sdoSdkServiceInfoModule;

// Modules CB
extern int devconfig(sdoSdkSiType type, int *count, sdoSdkSiKeyValue *si);
extern int keypair(sdoSdkSiType type, int *count, sdoSdkSiKeyValue *si);
extern int sdo_sys(sdoSdkSiType type, int *count, sdoSdkSiKeyValue *si);
extern int pelionconfig(sdoSdkSiType type, int *count, sdoSdkSiKeyValue *si);

#endif /* __SDOTYPES_H__ */
