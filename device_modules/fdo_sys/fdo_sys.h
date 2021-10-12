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

#define MOD_ACTIVE_TAG "active"
#define MOD_ACTIVE_STATUS "1"

// maximum length of exec command after combining all arguments of received exec array
#define MOD_MAX_EXEC_LEN 1024
// maximum length of the individual text arguments in the received exec array
#define MOD_MAX_EXEC_ARG_LEN 100

/**
 * The registered callback method for 'fdo_sys' ServiceInfo module.
 * The implementation is responsible for handling the received Owner ServiceInfo,
 * and for generating the Device ServiceInfo to send.
 * 
 * The input FDOR object holds the CBOR-encoded binary stream for the entire
 * decrypted messsage of TO2.OwnerServiceInfo (Type 69), with the current position
 * set to the ServiceInfoVal.
 * The implementation 'MUST' directly parse and process ServiceInfoVal 'ONLY' 
 * that's currently being pointed at, depending on the given module message, and return.
 *
 * The input FDOW object to be used to write the desired 'ServiceInfo' structure
 * as per the specification, that will be sent to the Owner. The FDOW can also be used
 * for other purposes such as ServiceInfo message partitioning (fit within MTU), or,
 * determining has_more/is_more etc. The module implemenation is responsible for maintaining
 * any internal state information, as needed.
 * 
 * The input fdo_sdk_si_type can be used to do specific tasks depending on the use-case.
 * However, it 'MUST' throw error on FDO_SI_GET_DSI.
 * (The types could be updated in the future)
 * 
 * @param type - enum value to describe the operation to be done.
 * @param fdor - FDOR object pointing to the ServiceInfoVal.
 * @param fdow - FDOW object to use to write Device ServiceInfoVal(s)
 * @param module_message - moduleMessage that decides how ServiceInfoVal is processed.
 * @param has_more - pointer to bool whose value must be set to
 * 'true' if there is Device ServiceInfo to send NOW/immediately, OR,
 * 'false' if there is no Device ServiceInfo to send NOW/immediately.
 * @param is_more - pointer to bool whose value must be set to
 * 'true' if there is Device ServiceInfo to send in the NEXT ietration, OR,
 * 'false' if there is no Device ServiceInfo to send in the NEXT iteration.
 * @param mtu - MTU value to be used as the upper bound for the ServiceInfo length.
 * @return integer value FDO_SI_CONTENT_ERROR (0), FDO_SI_INTERNAL_ERROR (1), FDO_SI_SUCCESS (2).
 */
int fdo_sys(fdo_sdk_si_type type, fdor_t *fdor, fdow_t *fdow,
    char *module_message, bool *has_more, bool *is_more, size_t mtu);

#endif /* __FDO_SYS_H__ */
