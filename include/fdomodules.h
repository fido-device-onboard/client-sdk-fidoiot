/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __FDOMODULES_H__
#define __FDOMODULES_H__

#include "fdoblockio.h"

/*
 * FDO module specific #defs (Sv_info)
 */
#define FDO_MODULE_NAME_LEN 32
#define FDO_MODULE_MSG_LEN 32

#ifdef EXTRA_MODULES
#define FDO_MAX_MODULES 4
#else
#define FDO_MAX_MODULES 1
#endif

#define FDO_MODULE_MESSAGE_ACTIVE "active"
#define FDO_MODULE_SEPARATOR ":"

/*==================================================================*/
/* Service Info module registration functionality */

// enum for Service_info Types
typedef enum {
	FDO_SI_START,
	FDO_SI_HAS_MORE_DSI,
	FDO_SI_IS_MORE_DSI,
	FDO_SI_GET_DSI,
	FDO_SI_SET_OSI,
	FDO_SI_END,
	FDO_SI_FAILURE
} fdo_sdk_si_type;

// enum for Sv_info module CB return value
enum { FDO_SI_CONTENT_ERROR, FDO_SI_INTERNAL_ERROR, FDO_SI_SUCCESS, FDO_SI_INVALID_MOD_ERROR };

typedef struct fdo_sdk_si_key_value {
	char *key;
	char *value;
} fdo_sdk_si_key_value;

// callback to module
typedef int (*fdo_sdk_service_infoCB)(fdo_sdk_si_type type,
	fdor_t *fdor, fdow_t *fdow, char *module_message, bool *has_more, bool *is_more, size_t mtu);

/* module struct for modules */
typedef struct {
	bool active;
	char module_name[FDO_MODULE_NAME_LEN];
	fdo_sdk_service_infoCB service_info_callback;
} fdo_sdk_service_info_module;

extern int fdo_sys(fdo_sdk_si_type type, fdor_t *fdor, fdow_t *fdow,
	char *module_message, bool *has_more, bool *is_more, size_t mtu);

extern int fido_alliance(fdo_sdk_si_type type, fdor_t *fdor, fdow_t *fdow,
	char *module_message, bool *has_more, bool *is_more, size_t mtu);

#endif /* __FDOTYPES_H__ */
