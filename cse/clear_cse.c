/*
 * Copyright 2022 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */
#include "clear_cse.h"
#include <inttypes.h>
#include <linux/mei.h>
#include <metee.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MEI_FDO UUID_LE(0x125405E0, 0xFCA9, 0x4110, 0x8F, 0x88, 0xB4, 0xDB,\
		0xCD, 0xCB, 0x87, 0x6F)

/**
 * Initialize HECI
 * @param TEEHANDLE - Structure to store connection data
 * @return status for API function
 */

TEESTATUS heci_init(TEEHANDLE *cl)
{
	TEESTATUS status = -1;
	status = TeeInit(cl, &MEI_FDO, NULL);
	if (status != TEE_SUCCESS) {
		printf("TeeInit failed!\n");
		return status;
	}

	status = TeeConnect(cl);
	if (status != TEE_SUCCESS) {
		printf("TeeConnect failed!\n");
		return status;
	}

	return status;
}

/**
 * Deinitialize HECI
 * @param TEEHANDLE - Structure to store connection data
 */
void heci_deinit(TEEHANDLE *cl)
{
	TeeDisconnect(cl);
}

/**
 * Clears the data from the CSE storage
 * @param TEEHANDLE - Structure to store connection data
 * @param file_id - file id type Device status or OVH
 * @param fdo_status - status of the HECI call
 * @return status for API function
 */
TEESTATUS fdo_heci_clear_file(TEEHANDLE *cl, uint32_t file_id, FDO_STATUS
		*fdo_status)
{
	fdo_heci_clear_file_request FDORequest;
	fdo_heci_clear_file_response* FDOResponseMessage;
	TEESTATUS status = -1;

	FDORequest.header.command = FDO_HECI_CLEAR_FILE;
	FDORequest.header.app_id = FDO_APP_ID;
	FDORequest.header.length = sizeof(FDORequest) - sizeof(FDORequest.header);
	FDORequest.file_id = file_id;
	const size_t sz = sizeof(FDORequest);
	unsigned char *buf = NULL;
	size_t rsz, wsz = 0;

	rsz = cl->maxMsgLen; //sets maxMsgLen
	buf = (unsigned char *)calloc(rsz, sizeof(unsigned char));
	if (buf == NULL) {
		printf("calloc(%u) failed\n", (unsigned)rsz);
		goto out;
	}

	status = TeeWrite(cl, &FDORequest, sz, &wsz, 0);
	if (status != TEE_SUCCESS) {
		printf("TeeWrite failed (%u) [attempted %u cmd bytes]\n", status,
				(unsigned)sizeof(FDORequest));
		goto out;
	}

	if (wsz != sz) {
		status = TEE_UNABLE_TO_COMPLETE_OPERATION;
		goto out;
	}

	size_t NumOfBytesRead = 0;
	memset(buf, 0, rsz);

	FDOResponseMessage = (fdo_heci_clear_file_response*)(buf);

	status = TeeRead(cl, buf, rsz, &NumOfBytesRead, 0);
	if (status != TEE_SUCCESS) {
		printf("TeeRead failed (%u)\n", status);
		goto out;
	}
	*fdo_status = FDOResponseMessage->status;

out:
	if (buf) {
		free(buf);
	}
	return status;
}

int main(void) {
	TEEHANDLE cl;
	FDO_STATUS fdo_status;

	if (TEE_SUCCESS != heci_init(&cl)) {
		printf("HECI init failed!!\n");
		return 0;
	}

	if (TEE_SUCCESS != fdo_heci_clear_file(&cl, DS_FILE_ID, &fdo_status) ||
			FDO_STATUS_SUCCESS != fdo_status) {
		if (FDO_STATUS_API_INTERFACE_IS_CLOSED == fdo_status) {
			printf("CSE Interface is Closed!! Reboot required.\n");
			goto end;
		} else {
			printf("HECI CLEAR DEVICE STATUS failed!!\n");
		}
	}

	if (TEE_SUCCESS != fdo_heci_clear_file(&cl, OVH_FILE_ID, &fdo_status) ||
			FDO_STATUS_SUCCESS != fdo_status) {
		printf("HECI CLEAR OVH failed!!\n");
		goto end;
	}
	printf("Cleared Device Status and OVH from CSE!!\n");
end:
	heci_deinit(&cl);
	return 0;
}
