/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */


#ifndef __FDO_SYS_H__
#define __FDO_SYS_H__

#include <stdint.h>
#include <stddef.h>
#include "fdomodules.h"

// file path could also be supplied
#define FILE_NAME_LEN 150

#define MOD_MAX_MSG_LEN 10

#define MOD_ACTIVE_TAG "active"
#define MOD_ACTIVE_STATUS "1"

#define MOD_MAX_DATA_LEN 1024

/**
 * The registered callback method for 'fdo_sys' Owner ServiceInfo module.
 * 
 * The input FDOR object holds the CBOR-encoded binary stream for the entire
 * decrypted messsage of TO2.OwnerServiceInfo (Type 69), with the current position
 * set to the ServiceInfoVal.
 * The implementation 'MUST' directly parse and process ServiceInfoVal 'ONLY' 
 * that's currently being pointed at, depending on the given module message, and return.
 * 
 * The input fdo_sdk_si_type can be used to do specific tasks depending on the use-case.
 * However, it 'MUST' throw error on FDO_SI_GET_DSI.
 * (The types could be updated in the future)
 * 
 * @param type - enum value to describe the operation to be done.
 * @param fdor - FDOR object pointing to the ServiceInfoVal.
 * @param module_message - moduleMessage that decides how ServiceInfoVal is processed.
 * @return integer value FDO_SI_CONTENT_ERROR (0), FDO_SI_INTERNAL_ERROR (1), FDO_SI_SUCCESS (2).
 */
int fdo_sys(fdo_sdk_si_type type, fdor_t *fdor, char *module_message);

#endif /* __FDO_SYS_H__ */
