/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */


#include "fido_alliance.h"
#include "safe_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void *ModuleAlloc(int size);

int fido_alliance(fdo_sdk_si_type type, fdor_t *fdor, fdow_t *fdow,
	char *module_message, bool *has_more, bool *is_more, size_t mtu)
{
	int strcmp_dev_conformance = 1;

	int result = FDO_SI_INTERNAL_ERROR;
	uint8_t *bin_data = NULL;
	size_t bin_len = 0;
	char str_terminator = '\0';

	switch (type) {
		case FDO_SI_START:
		case FDO_SI_END:
		case FDO_SI_FAILURE:
			result = FDO_SI_SUCCESS;
			goto end;
		case FDO_SI_HAS_MORE_DSI:
			// calculate whether there is ServiceInfo to send NOW and update 'has_more'.
			// For testing purposes, set this to true here, and false once first write is done.
			if (!has_more) {
				result = FDO_SI_CONTENT_ERROR;
				goto end;
			}

			*has_more = false;
			result = FDO_SI_SUCCESS;
			goto end;
		case FDO_SI_IS_MORE_DSI:
			// calculate whether there is ServiceInfo to send in the NEXT iteration
			// and update 'is_more'.
			if (!is_more) {
				result = FDO_SI_CONTENT_ERROR;
				goto end;
			}
			*is_more = false;
			result = FDO_SI_SUCCESS;
			goto end;
		case FDO_SI_GET_DSI:
			// write Device ServiceInfo using 'fdow' by partitioning the messages as per MTU, here.
			// For now, simply write an empty message and reset the has_more flag
			// TO-DO : Update during keep-alive implementation
			(void)mtu;
			(void)fdow;
			result = FDO_SI_SUCCESS;
			goto end;
		case FDO_SI_SET_OSI:
			// Process the received Owner ServiceInfo contained within 'fdor', here.
		strcmp_s(module_message, FDO_MODULE_MSG_LEN, "dev_conformance",
					&strcmp_dev_conformance);

		if (strcmp_dev_conformance != 0) {
#ifdef DEBUG_LOGS
			printf("Invalid moduleMessage for fido_alliance "
				"Module\n");
#endif
			return FDO_SI_CONTENT_ERROR;
		}

		if (strcmp_dev_conformance == 0) {

			if (!fdor_string_length(fdor, &bin_len)) {
#ifdef DEBUG_LOGS
				printf("Module fido_alliance: Failed to read dev_conformance length\n");
#endif
				goto end;
			}

			if (bin_len == 0) {
#ifdef DEBUG_LOGS
				printf("Module fido_alliance: Empty value received for dev_conformance\n");
#endif
				// received content can be empty
			}

			// +1 for NULL terminator at the end
			bin_data = ModuleAlloc((bin_len + 1) * sizeof(uint8_t));
			if (!bin_data) {
#ifdef DEBUG_LOGS
					printf("Module fido_alliance: Failed to alloc dev_conformance\n");
#endif
				goto end;
			}

			if (!fdor_text_string(fdor, (char *)bin_data, bin_len)) {
#ifdef DEBUG_LOGS
				printf("Module fido_alliance: Failed to read dev_conformance as Text String\n");
#endif
				goto end;
			}
			bin_data[bin_len] = str_terminator;
			printf("fido_alliance:dev_conformance=%s\n", (char*)bin_data);
			result = FDO_SI_SUCCESS;
			goto end;
		}
		default:
			goto end;
	}
end:
	if (bin_data) {
		ModuleFree(bin_data);
	}
	return result;
}

void *ModuleAlloc(int size)
{
	if (size <= 0) {
		return NULL;
	}
	void *buf = malloc(size);
	if (!buf) {
		printf("fdoAlloc failed to allocate\n");
		goto end;
	}

	if (memset_s(buf, size, 0) != 0) {
		printf("Memset Failed\n");
		free(buf);
		buf = NULL;
		goto end;
	}

end:
	return buf;
}