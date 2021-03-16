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

/**
 * The registered callback method for 'sdo_sys' Owner ServiceInfo module.
 * 
 * The input SDOR object holds the CBOR-encoded binary stream for the entire
 * decrypted messsage of TO2.OwnerServiceInfo (Type 69), with the current position
 * set to the ServiceInfoVal.
 * The implementation 'MUST' directly parse and process ServiceInfoVal 'ONLY' 
 * that's currently being pointed at, depending on the given module message, and return.
 * 
 * The input sdo_sdk_si_type can be used to do specific tasks depending on the use-case.
 * However, it 'MUST' throw error on SDO_SI_GET_DSI.
 * (The types could be updated in the future)
 * 
 * @param type - enum value to describe the operation to be done.
 * @param sdor - SDOR object pointing to the ServiceInfoVal.
 * @param module_message - moduleMessage that decides how ServiceInfoVal is processed.
 * @return integer value SDO_SI_CONTENT_ERROR (0), SDO_SI_INTERNAL_ERROR (1), SDO_SI_SUCCESS (2).
 */
int sdo_sys(sdo_sdk_si_type type, sdor_t *sdor, char *module_message);

#endif /* __SDO_SYS_H__ */
