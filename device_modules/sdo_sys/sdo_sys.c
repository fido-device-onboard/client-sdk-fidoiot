/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */


#include "sdo_sys.h"
#include "base64.h"
#include "safe_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "sdo_sys_utils.h"

int sdo_sys(sdoSdkSiType type, int *count, sdoSdkSiKeyValue *sv)
{
	int ret = 0;
	static char *mod_data = NULL;
	static char *mod_msg = NULL;
	static char fileName[FILE_NAME_LEN];
	int strcmp_maxver = 1;
	int strcmp_minver = 1;
	size_t sv_key_len = 0;
	size_t sv_value_len = 0;
	int strcmp_filedesc = 1;
	int strcmp_write = 1;
	int strcmp_exec = 1;
	int result = SDO_SI_INTERNAL_ERROR;
	uint8_t *binData = NULL;
	int binLen = 0;
	int converted = 0;

	switch (type) {
	case SDO_SI_START:
		return SDO_SI_SUCCESS;
	case SDO_SI_GET_DSI_COUNT:
		if (count) {
			*count = 1;
			return SDO_SI_SUCCESS;
		}
		return SDO_SI_INTERNAL_ERROR;

	case SDO_SI_SET_PSI:
		if (!sv || !sv->key || !sv->value)
			return SDO_SI_INTERNAL_ERROR;

		sv_key_len = strnlen_s(sv->key, SDO_MAX_STR_SIZE);
		sv_value_len = strnlen_s(sv->value, SDO_MAX_STR_SIZE);

		if (sv_key_len == 0 || sv_value_len == 0 ||
		    sv_key_len == SDO_MAX_STR_SIZE ||
		    sv_value_len == SDO_MAX_STR_SIZE)
			return SDO_SI_CONTENT_ERROR;

		strcmp_s(sv->key, sv_key_len, "maxver", &strcmp_maxver);
		strcmp_s(sv->key, sv_key_len, "minver", &strcmp_minver);
		if (strcmp_maxver == 0 || strcmp_minver == 0) {
#ifdef DEBUG_LOGS
			printf("sdo_sys-%s:%s\n", sv->key, sv->value);
#endif
			return SDO_SI_SUCCESS;
		} else
			return SDO_SI_CONTENT_ERROR;

	case SDO_SI_GET_DSI:
		if (sv) {
			if (!count)
				return SDO_SI_INTERNAL_ERROR;
			if (*count == 0) {
				// send active status -> "active":"1"
				mod_msg = ModuleAlloc(MOD_MAX_MSG_LEN);
				if (!mod_msg) {
#ifdef DEBUG_LOGS
					printf("ModuleAlloc failed!\n");
#endif
					goto end_psi;
				}

				ret = strcpy_s(mod_msg, MOD_MAX_MSG_LEN,
					       MOD_ACTIVE_TAG);

				if (ret != 0) {
#ifdef DEBUG_LOGS
					printf("Strcpy failed!\n");
#endif
					goto end_psi;
				}

				sv->key = mod_msg;
#ifdef DEBUG_LOGS
				printf("sv->key:%s\n", sv->key);
#endif
				mod_data =
				    ModuleAlloc(strnlen_s(MOD_ACTIVE_STATUS,
							  SDO_MAX_STR_SIZE) +
						1); // +1 for NULL termination

				if (!mod_data) {
#ifdef DEBUG_LOGS
					printf("ModuleAlloc failed!\n");
#endif
					goto end_psi;
				}

				if (0 != strcpy_s(mod_data,
						  strnlen_s(MOD_ACTIVE_STATUS,
							    SDO_MAX_STR_SIZE) +
						      1,
						  MOD_ACTIVE_STATUS)) {
#ifdef DEBUG_LOGS
					printf("Strcpy failed!\n");
#endif
					goto end_psi;
				}

				sv->value = mod_data;
				result = SDO_SI_SUCCESS;
				return result;

			end_psi:
				if (mod_data)
					ModuleFree(mod_data);
				if (mod_msg)
					ModuleFree(mod_msg);
				return result;
			}
			return SDO_SI_INTERNAL_ERROR;
		}
		return SDO_SI_INTERNAL_ERROR;

	case SDO_SI_SET_OSI:
		if (sv != NULL && sv->value != NULL && sv->key != NULL) {
			sv_key_len = strnlen_s(sv->key, SDO_MAX_STR_SIZE);
			sv_value_len = strnlen_s(sv->value, MOD_MAX_DATA_LEN);

			if (sv_key_len == 0 || sv_value_len == 0 ||
			    sv_key_len == SDO_MAX_STR_SIZE ||
			    sv_value_len == MOD_MAX_DATA_LEN)
				return SDO_SI_CONTENT_ERROR;

			strcmp_s(sv->key, sv_key_len, "filedesc",
				 &strcmp_filedesc);
			strcmp_s(sv->key, sv_key_len, "write", &strcmp_write);
			strcmp_s(sv->key, sv_key_len, "exec", &strcmp_exec);

			if (strcmp_filedesc != 0 && strcmp_exec != 0 &&
			    strcmp_write != 0) {
#ifdef DEBUG_LOGS
				printf("Mod_Msg content is invalid for sdo_sys "
				       "Module\n");
#endif
				return SDO_SI_CONTENT_ERROR;
			}

			binLen = b64To_bin_length(sv_value_len);

			if (!binLen) {
				goto end;
			}

			binData = ModuleAlloc(binLen * sizeof(uint8_t));
			if (!binData) {
#ifdef DEBUG_LOGS
				printf("ModuleAlloc failed\n");
#endif
				goto end;
			}

			if (memset_s(binData, binLen, 0) != 0) {
#ifdef DEBUG_LOGS
				printf("Memset failed!\n");
#endif
				goto end;
			}

			converted =
			    b64To_bin(sv_value_len, (uint8_t *)sv->value, 0,
				       (size_t)binLen, binData, 0);
			if (converted <= 0) {
				goto end;
			}
			if (strcmp_filedesc == 0) {

				if (strncpy_s(fileName, FILE_NAME_LEN,
					      (char *)binData,
					      converted) != 0) {
#ifdef DEBUG_LOGS
					printf("Strcpy failed!\n");
#endif
					goto end;
				}

				if (true ==
				    delete_old_file((const char *)fileName)) {
					result = SDO_SI_SUCCESS;
				}

				goto end;
			} else if (strcmp_write == 0) {

				if (!process_data(SDO_SYS_MOD_MSG_WRITE,
						  binData, converted,
						  fileName)) {
#ifdef DEBUG_LOGS
					printf("Process_data for write fail");
#endif
					goto end;
				}
				result = SDO_SI_SUCCESS;
				goto end;
			} else {
				if (!process_data(SDO_SYS_MOD_MSG_EXEC, binData,
						  converted, fileName)) {
#ifdef DEBUG_LOGS
					printf("Process_data for exec fail");
#endif
					goto end;
				}
				result = SDO_SI_SUCCESS;
				goto end;
			}

		end:
			if (binData)
				ModuleFree(binData);
			return result;
		} else
			return SDO_SI_INTERNAL_ERROR;

	case SDO_SI_END:
	case SDO_SI_FAILURE:
		if (mod_msg)
			ModuleFree(mod_msg);
		if (mod_data)
			ModuleFree(mod_data);
		return SDO_SI_SUCCESS;

	default:
		return SDO_SI_INTERNAL_ERROR;
	}
}
