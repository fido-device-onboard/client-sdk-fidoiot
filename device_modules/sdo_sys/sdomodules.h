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
#define SDO_MODULE_VALUE_LEN 1024
#define SDO_MAX_MODULES 2
#define SDO_MAX_STR_SIZE 512

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

#endif /* __SDOTYPES_H__ */
