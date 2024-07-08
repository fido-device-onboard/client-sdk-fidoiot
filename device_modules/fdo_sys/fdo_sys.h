/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __FDO_SYS_H__
#define __FDO_SYS_H__

#include <stdint.h>
#include <stddef.h>
#include "fdomodules.h"

// Maximum buffer size to be used for reading/writing CBOR data
#define MOD_MAX_BUFF_SIZE 8192

// file path could also be supplied
#define FILE_NAME_LEN 150

#define MOD_ACTIVE_TAG "active"
#define MOD_ACTIVE_STATUS "1"

// maximum length of exec command after combining all arguments of received exec
// array
#define MOD_MAX_EXEC_LEN 1024
// maximum length of the individual text arguments in the received exec array
#define MOD_MAX_EXEC_ARG_LEN 100

/**
 * The registered callback method for 'fdo_sys' ServiceInfo module.
 * The implementation is responsible for handling the received Owner
 * ServiceInfo, and for generating the Device ServiceInfo to send.
 *
 * When module_message, module_val and module_val_sz are used as inputs in type
 * 'FDO_SI_SET_OSI', these represent the moduleMessage, CBOR-encoded
 * (bstr-unwrapped) module value i.e ServiceInfoVal cbor.bytes, as received in
 * TO2.OwnerServiceInfo (Type 69), and its length. The implementation must parse
 * and process the input module value depending on the given module message, and
 * return.
 *
 * However, the same set of variables are used as output parameters in type
 * 'FDO_SI_GET_DSI', wherein, module_message stores the current moduleMessage,
 * module_val stores the response CBOR-encoded module value (ServiceInfoVal),
 * and module_val_sz stores the corresponding length. The implementation is
 * responsible for generating the CBOR-encoded module value using any
 * mechanisms/third-party library. In the current implementation, the
 * CBOR-encoder/decoder from 'lib/fdoblockio.c' is used. These 3 parameters are
 * then, used to generate ServiceInfoKV at TO2.DeviceServiceInfo (Type 68), and
 * sent to the Owner.
 *
 * The input FDOW object to be used to write the desired 'ServiceInfo' structure
 * as per the specification, that will be sent to the Owner. The FDOW can also
 * be used for other purposes such as ServiceInfo message partitioning (fit
 * within MTU), or, determining has_more/is_more etc. The module implemenation
 * is responsible for maintaining any internal state information, as needed.
 *
 * The input fdo_sdk_si_type can be used to do specific tasks depending on the
 * use-case. (The types could be updated in the future)
 *
 * @param type - [IN] enum value to describe the operation to be done.
 * @param module_message - [IN/OUT] moduleMessage that decides how
 * ServiceInfoVal is processed.
 * @param module_val - [IN/OUT] bstr-unwrapped ServiceInfoVal corresponding to
 * the moduleMessage.
 * @param module_val_sz - [IN/OUT] ServiceInfoVal length corresponding to the
 * moduleMessage.
 * @param num_module_messages - [OUT] Number of ServiceInfoKVs to be sent.
 * Currently UNUSED.
 * @param has_more - [OUT] pointer to bool whose value must be set to
 * 'true' if there is Device ServiceInfo to send NOW/immediately, OR,
 * 'false' if there is no Device ServiceInfo to send NOW/immediately.
 * @param is_more - [OUT] pointer to bool whose value must be set to
 * 'true' if there is Device ServiceInfo to send in the NEXT ietration, OR,
 * 'false' if there is no Device ServiceInfo to send in the NEXT iteration.
 * @param mtu - [IN] MTU value to be used as the upper bound for the ServiceInfo
 * length.
 * @return integer value FDO_SI_CONTENT_ERROR (0), FDO_SI_INTERNAL_ERROR (1),
 * FDO_SI_SUCCESS (2).
 */
int fdo_sys(fdo_sdk_si_type type, char *module_message, uint8_t *module_val,
	    size_t *module_val_sz, uint16_t *num_module_messages,
	    bool *has_more, bool *is_more, size_t mtu);

// Prototype definitions for functions that are implemented in the module
int fdo_si_start(void);
int fdo_si_failure(void);
int fdo_si_has_more_dsi(bool *has_more);
int fdo_si_is_more_dsi(bool *is_more);
int fdo_si_get_dsi_count(uint16_t *num_module_messages);
int fdo_si_get_dsi(size_t mtu, char *module_message, uint8_t *module_val,
		   size_t *module_val_sz, size_t file_remaining, size_t bin_len,
		   uint8_t *bin_data, size_t temp_module_val_sz);

int fdo_si_set_osi(char *module_message, uint8_t *module_val,
		   size_t *module_val_sz, int *strcmp_filedesc,
		   int *strcmp_write, int *strcmp_exec, int *strcmp_execcb,
		   int *strcmp_statuscb, int *strcmp_fetch);

int fdo_si_set_osi_strcmp(size_t bin_len, uint8_t *bin_data);
int fdo_si_set_osi_write(size_t bin_len, uint8_t *bin_data);

int fdo_si_set_osi_exec(char **exec_instr,
			int exec_array_index, size_t *exec_instructions_sz,
			int *strcmp_exec, int *strcmp_execcb);

int fdo_si_set_osi_status_cb(size_t *status_cb_array_length);

int fdo_si_set_osi_fetch(size_t bin_len);

int fdo_end(int result, uint8_t *bin_data, char **exec_instr);
#endif /* __FDO_SYS_H__ */
