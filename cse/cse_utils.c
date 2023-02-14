/*
 * Copyright 2022 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "cse_utils.h"
#include "fdotypes.h"
#include "safe_lib.h"
#include "util.h"
#include "fdo_cse.h"
#include <linux/mei.h>
#include <metee.h>

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
        LOG(LOG_ERROR,"TeeInit failed!\n");
        return status;
    }

    status = TeeConnect(cl);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR,"TeeConnect failed!\n");
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
 * Read the version CSE firmware
 * @param TEEHANDLE - Structure to store connection data
 * @param major_v - a place top store the major version
 * @param minor_v - a place top store the minor version
 * @param fdo_status - status of the HECI call
 * @return status for API function
 */

TEESTATUS fdo_heci_get_version(TEEHANDLE *cl, uint16_t *major_v, uint16_t
        *minor_v, FDO_STATUS *fdo_status)
{
    fdo_heci_get_version_request FDORequest;
    fdo_heci_get_version_response* FDOResponseMessage;
    TEESTATUS status = -1;

    FDORequest.header.command = FDO_HECI_GET_VERSION;
    FDORequest.header.app_id = FDO_APP_ID;
    FDORequest.header.length = 0;
    const size_t sz = sizeof(FDORequest);
    unsigned char *buf = NULL;
    size_t rsz, wsz = 0;

    rsz = cl->maxMsgLen; //sets maxMsgLen
    buf = (unsigned char *)calloc(rsz, sizeof(unsigned char));
    if (buf == NULL) {
        LOG(LOG_ERROR, "calloc(%u) failed\n", (unsigned)rsz);
        goto out;
    }

    status = TeeWrite(cl, &FDORequest, sz, &wsz, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeWrite failed (%u) [attempted %u cmd bytes]\n",
                status, (unsigned)sizeof(FDORequest));
        goto out;
    }

    if (wsz != sz) {
        status = TEE_UNABLE_TO_COMPLETE_OPERATION;
        goto out;
    }

    size_t NumOfBytesRead = 0;
    FDOResponseMessage = (fdo_heci_get_version_response*)(buf);

    status = TeeRead(cl, buf, rsz, &NumOfBytesRead, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeRead failed (%u)\n", status);
        goto out;
    }

    *major_v = FDOResponseMessage->version.major_version;
    *minor_v = FDOResponseMessage->version.minor_version;
    *fdo_status = FDOResponseMessage->status;

out:
	if (buf) {
	    fdo_free(buf);
    }
	return status;
}

/**
 * Read the certificate chain from CSE
 * @param TEEHANDLE - Structure to store connection data
 * @param cert_chain a place top store the resulting cetificate
 * @param len_cert - length of the resulting cetificate
 * @param fdo_status - status of the HECI call
 * @return status for API function
 */
TEESTATUS fdo_heci_get_cert_chain(TEEHANDLE *cl, uint8_t *cert_chain, uint16_t
        *len_cert, FDO_STATUS *fdo_status)
{
    if (!cert_chain || !len_cert) {
        return -1;
    }

    fdo_heci_get_certificate_chain_request FDORequest;
    fdo_heci_get_certificate_chain_response* FDOResponseMessage;
    TEESTATUS status = -1;

    FDORequest.header.command = FDO_HECI_GET_CERTIFICATE_CHAIN;
    FDORequest.header.app_id = FDO_APP_ID;
    FDORequest.header.length = sizeof(FDORequest) - sizeof(FDORequest.header);
    const size_t sz = sizeof(FDORequest);
    unsigned char *buf = NULL;
    size_t rsz, wsz = 0;

    rsz = cl->maxMsgLen; //sets maxMsgLen
    buf = (unsigned char *)calloc(rsz, sizeof(unsigned char));
    if (buf == NULL) {
        LOG(LOG_ERROR,"calloc(%u) failed\n", (unsigned)rsz);
        goto out;
    }

    status = TeeWrite(cl, &FDORequest, sz, &wsz, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeWrite failed (%u) [attempted %u cmd bytes]\n",
                status, (unsigned)sizeof(FDORequest));
        goto out;
    }

    if (wsz != sz) {
        status = TEE_UNABLE_TO_COMPLETE_OPERATION;
        goto out;
    }

    size_t NumOfBytesRead = 0;
    FDOResponseMessage = (fdo_heci_get_certificate_chain_response*)(buf);

    status = TeeRead(cl, buf, rsz, &NumOfBytesRead, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeRead failed (%u)\n", status);
        goto out;
    }

    *fdo_status = FDOResponseMessage->status;

    if (memcpy_s(len_cert, sizeof(FDOResponseMessage->lengths_of_certificates),
            FDOResponseMessage->lengths_of_certificates,
            sizeof(FDOResponseMessage->lengths_of_certificates)) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto out;
	}

    if (memcpy_s(cert_chain, FDO_MAX_CERT_CHAIN_SIZE,
            FDOResponseMessage->certificate_chain,
            sizeof(FDOResponseMessage->certificate_chain)) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto out;
	}

out:
	if (buf) {
	    fdo_free(buf);
    }
	return status;
}

/**
 * Sign the data using ECDSA Signature from CSE
 * @param TEEHANDLE - Structure to store connection data
 * @param data - pointer of type uint8_t, holds the plaintext message.
 * @param data_len - size of message, type uint32_t.
 * @param sig_ptr - pointer of type uint8_t, which will be
 * by filled with signature.
 * @param sig_len - size of the signature
 * @param mp_ptr - pointer of type uint8_t, which will be
 * by filled with maroeprefix.
 * @param mp_len - size of maroeprefix, type unsigned int.
 * @param fdo_status - status of the HECI call
 * @return status for API function
 */
TEESTATUS fdo_heci_ecdsa_device_sign_challenge(TEEHANDLE *cl, uint8_t *data,
        uint32_t data_length, uint8_t *sig_ptr, size_t sig_len, uint8_t
        *mp_ptr, uint32_t *mp_len, FDO_STATUS *fdo_status)
{
    if (!data || !data_length || !sig_ptr || !sig_len ||
			!mp_ptr) {
		LOG(LOG_ERROR, "fdo_heci_ecdsa_device_sign_challenge params not valid\n");
		return -1;
	}

    if (data_length > FDO_MAX_FILE_SIZE || data_length < 0) {
        LOG(LOG_ERROR, "Invalid data length!\n");
		return -1;
    }

    fdo_heci_ecdsa_device_sign_challenge_request FDORequest;
    fdo_heci_ecdsa_device_sign_challenge_response* FDOResponseMessage;
    TEESTATUS status = -1;
    unsigned char *buf = NULL;
    size_t rsz, wsz = 0;

    FDORequest.header.command = FDO_HECI_ECDSA_DEVICE_SIGN_CHALLENGE;
    FDORequest.header.app_id = FDO_APP_ID;
    FDORequest.data_length = data_length;

    if (memcpy_s(FDORequest.data, FDORequest.data_length, data, data_length) !=
            0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto out;
	}

    FDORequest.header.length = sizeof(FDORequest.data_length) + data_length;
    const size_t sz = sizeof(FDORequest.header) + FDORequest.header.length;


    rsz = cl->maxMsgLen; //sets maxMsgLen
    buf = (unsigned char *)calloc(rsz, sizeof(unsigned char));
    if (buf == NULL) {
        LOG(LOG_ERROR,"calloc(%u) failed\n", (unsigned)rsz);
        goto out;
    }

    status = TeeWrite(cl, &FDORequest, sz, &wsz, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeWrite failed (%u) [attempted %u cmd bytes]\n",
                status, (unsigned)sizeof(FDORequest));
        goto out;
    }

    if (wsz != sz) {
        status = TEE_UNABLE_TO_COMPLETE_OPERATION;
        goto out;
    }

    size_t NumOfBytesRead = 0;
    FDOResponseMessage = (fdo_heci_ecdsa_device_sign_challenge_response*)(buf);

    status = TeeRead(cl, buf, rsz, &NumOfBytesRead, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeRead failed (%u)\n", status);
        goto out;
    }

    *fdo_status = FDOResponseMessage->status;
    *mp_len = FDOResponseMessage->maroeprefix_length;

    if (memcpy_s(mp_ptr, FDO_MAX_MAROE_PREFIX_SIZE,
            FDOResponseMessage->maroeprefix,
            FDOResponseMessage->maroeprefix_length) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto out;
	}

    if (memcpy_s(sig_ptr, sig_len, FDOResponseMessage->signature,
            FDO_SIGNATURE_LENGTH) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto out;
	}

out:
	if (buf) {
	    fdo_free(buf);
    }
	return status;
}

/**
 * Generate random number
 * @param TEEHANDLE - Structure to store connection data
 * @param random_bytes - pointer of type uint8_t, holds the random data.
 * @param length - size of random data, type uint32_t.
 * @param fdo_status - status of the HECI call
 * @return status for API function
 */
TEESTATUS fdo_heci_generate_random(TEEHANDLE *cl, uint8_t *random_bytes,
        uint32_t length, FDO_STATUS *fdo_status)
{
    if (!random_bytes || !length) {
        return -1;
    }

    if (length > FDO_MAX_RANDOM || length < 0) {
        return -1;
    }

    fdo_heci_generate_random_request FDORequest;
    fdo_heci_generate_random_response* FDOResponseMessage;
    TEESTATUS status = -1;

    FDORequest.header.command = FDO_HECI_GENERATE_RANDOM;
    FDORequest.header.app_id = FDO_APP_ID;
    FDORequest.header.length = sizeof(FDORequest) - sizeof(FDORequest.header);
    FDORequest.length = length;
    const size_t sz = sizeof(FDORequest);
    unsigned char *buf = NULL;
    size_t rsz, wsz = 0;

    rsz = cl->maxMsgLen; //sets maxMsgLen
    buf = (unsigned char *)calloc(rsz, sizeof(unsigned char));
    if (buf == NULL) {
        LOG(LOG_ERROR,"calloc(%u) failed\n", (unsigned)rsz);
        goto out;
    }

    status = TeeWrite(cl, &FDORequest, sz, &wsz, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeWrite failed (%u) [attempted %u cmd bytes]\n",
                status, (unsigned)sizeof(FDORequest));
        goto out;
    }

    if (wsz != sz) {
        status = TEE_UNABLE_TO_COMPLETE_OPERATION;
        goto out;
    }

    size_t NumOfBytesRead = 0;
    FDOResponseMessage = (fdo_heci_generate_random_response*)(buf);

    status = TeeRead(cl, buf, rsz, &NumOfBytesRead, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeRead failed (%u)\n", status);
        goto out;
    }

    *fdo_status = FDOResponseMessage->status;

    if (memcpy_s(random_bytes, length,
            FDOResponseMessage->random_bytes, FDOResponseMessage->length) !=
            0) {
            LOG(LOG_ERROR, "Memcpy Failed\n");
            goto out;
        }

out:
	if (buf) {
	    fdo_free(buf);
    }
	return status;
}

/**
 * Loads the data from CSE storage
 * @param TEEHANDLE - Structure to store connection data
 * @param file_id - file id type Device status or OVH
 * @param fdo_status - status of the HECI call
 * @return status for API function
 */
TEESTATUS fdo_heci_load_file(TEEHANDLE *cl, uint32_t file_id, FDO_STATUS
        *fdo_status)
{
    if (file_id != OVH_FILE_ID && file_id != DS_FILE_ID) {
        LOG(LOG_ERROR,"Invalid file id!\n");
        return -1;
    }

    fdo_heci_load_file_request FDORequest;
    fdo_heci_load_file_response* FDOResponseMessage;
    TEESTATUS status = -1;

    FDORequest.header.command = FDO_HECI_LOAD_FILE;
    FDORequest.header.app_id = FDO_APP_ID;
    FDORequest.header.length = sizeof(FDORequest) - sizeof(FDORequest.header);
    FDORequest.file_id = file_id;
    const size_t sz = sizeof(FDORequest);
    unsigned char *buf = NULL;
    size_t rsz, wsz = 0;

    rsz = cl->maxMsgLen; //sets maxMsgLen
    buf = (unsigned char *)calloc(rsz, sizeof(unsigned char));
    if (buf == NULL) {
        LOG(LOG_ERROR,"calloc(%u) failed\n", (unsigned)rsz);
        goto out;
    }

    status = TeeWrite(cl, &FDORequest, sz, &wsz, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeWrite failed (%u) [attempted %u cmd bytes]\n",
                status, (unsigned)sizeof(FDORequest));
        goto out;
    }

    if (wsz != sz)
    {
        status = TEE_UNABLE_TO_COMPLETE_OPERATION;
        goto out;
    }

    size_t NumOfBytesRead = 0;


    FDOResponseMessage = (fdo_heci_load_file_response*)(buf);

    status = TeeRead(cl, buf, rsz, &NumOfBytesRead, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeRead failed (%u)\n", status);
        goto out;
    }

    *fdo_status = FDOResponseMessage->status;

out:
	if (buf) {
	    fdo_free(buf);
    }
	return status;
}

/**
 * Update the data in the CSE storage
 * @param TEEHANDLE - Structure to store connection data
 * @param file_id - file id type Device status or OVH
 * @param data - pointer of type uint8_t, holds the plaintext message.
 * @param data_length - size of message, type uint32_t.
 * @param hmac_ptr - pointer of type uint8_t, which will be
 * by filled with HMAC.
 * @param hmac_length - size of HMAC, type unsigned int.
 * @param fdo_status - status of the HECI call
 * @return status for API function
 */
TEESTATUS fdo_heci_update_file(TEEHANDLE *cl, uint32_t file_id, uint8_t *data,
        uint32_t data_length, uint8_t *hmac_ptr, size_t hmac_length, FDO_STATUS
        *fdo_status)
{
    if (!data || !data_length) {
		return -1;
	}

    if (file_id != OVH_FILE_ID && file_id != DS_FILE_ID) {
        LOG(LOG_ERROR,"Invalid file id!\n");
        return -1;
    }

    fdo_heci_update_file_request FDORequest;
    fdo_heci_update_file_response* FDOResponseMessage;
    TEESTATUS status = -1;
    unsigned char *buf = NULL;
    size_t rsz, wsz = 0;

    FDORequest.header.command = FDO_HECI_UPDATE_FILE;
    FDORequest.header.app_id = FDO_APP_ID;
    FDORequest.file_id = file_id;
    FDORequest.data_length = data_length;
    FDORequest.header.length = sizeof(FDORequest.data_length) +
            sizeof(FDORequest.file_id) + FDORequest.data_length;

    if (file_id == OVH_FILE_ID) {
        if (memcpy_s(FDORequest.data, FDORequest.data_length, data,
                data_length) != 0) {
            LOG(LOG_ERROR, "Memcpy Failed\n");
            goto out;
        }
    } else {
        FDORequest.data[0] = *data;
    }

    const size_t sz = sizeof(FDORequest.header) + FDORequest.header.length;

    rsz = cl->maxMsgLen; //sets maxMsgLen
    buf = (unsigned char *)calloc(rsz, sizeof(unsigned char));
    if (buf == NULL) {
        LOG(LOG_ERROR,"calloc(%u) failed\n", (unsigned)rsz);
        goto out;
    }

    status = TeeWrite(cl, &FDORequest, sz, &wsz, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeWrite failed (%u) [attempted %u cmd bytes]\n",
                status, (unsigned)sizeof(FDORequest));
        goto out;
    }

    if (wsz != sz) {
        status = TEE_UNABLE_TO_COMPLETE_OPERATION;
        goto out;
    }

    size_t NumOfBytesRead = 0;


    FDOResponseMessage = (fdo_heci_update_file_response*)(buf);

    status = TeeRead(cl, buf, rsz, &NumOfBytesRead, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeRead failed (%u)\n", status);
        goto out;
    }

    *fdo_status = FDOResponseMessage->status;

    if (file_id == OVH_FILE_ID) {
        if (hmac_ptr) {
            if (memcpy_s(hmac_ptr, FDO_HMAC_384_SIZE, FDOResponseMessage->HMAC,
                    hmac_length) != 0) {
                LOG(LOG_ERROR, "Memcpy Failed\n");
                goto out;
            }
        }
    }

out:
	if (buf) {
	    fdo_free(buf);
    }
	return status;
}

/**
 * Commits the updated data in the CSE storage
 * @param TEEHANDLE - Structure to store connection data
 * @param file_id - file id type Device status or OVH
 * @param fdo_status - status of the HECI call
 * @return status for API function
 */
TEESTATUS fdo_heci_commit_file(TEEHANDLE *cl, uint32_t file_id, FDO_STATUS
        *fdo_status)
{
    if (file_id != OVH_FILE_ID && file_id != DS_FILE_ID) {
        LOG(LOG_ERROR,"Invalid file id!\n");
        return -1;
    }

    fdo_heci_commit_file_request FDORequest;
    fdo_heci_commit_file_response* FDOResponseMessage;
    TEESTATUS status = -1;

    FDORequest.header.command = FDO_HECI_COMMIT_FILE;
    FDORequest.header.app_id = FDO_APP_ID;
    FDORequest.header.length = sizeof(FDORequest) - sizeof(FDORequest.header);
    FDORequest.file_id = file_id;
    const size_t sz = sizeof(FDORequest);
    unsigned char *buf = NULL;
    size_t rsz, wsz = 0;

    rsz = cl->maxMsgLen; //sets maxMsgLen
    buf = (unsigned char *)calloc(rsz, sizeof(unsigned char));
    if (buf == NULL) {
        LOG(LOG_ERROR,"calloc(%u) failed\n", (unsigned)rsz);
        goto out;
    }

    status = TeeWrite(cl, &FDORequest, sz, &wsz, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeWrite failed (%u) [attempted %u cmd bytes]\n",
                status, (unsigned)sizeof(FDORequest));
        goto out;
    }

    if (wsz != sz)
    {
        status = TEE_UNABLE_TO_COMPLETE_OPERATION;
        goto out;
    }

    size_t NumOfBytesRead = 0;


    FDOResponseMessage = (fdo_heci_commit_file_response*)(buf);

    status = TeeRead(cl, buf, rsz, &NumOfBytesRead, 0);
    if (status != TEE_SUCCESS)
    {
        LOG(LOG_ERROR, "TeeRead failed (%u)\n", status);
        goto out;
    }

    *fdo_status = FDOResponseMessage->status;

out:
	if (buf) {
	    fdo_free(buf);
    }
	return status;
}

/**
 * Reads the data from the CSE storage
 * @param TEEHANDLE - Structure to store connection data
 * @param file_id - file id type Device status or OVH
 * @param data_ptr - pointer of type uint8_t, holds the plaintext message.
 * @param data_length - size of message, type uint32_t.
 * @param hmac_ptr - pointer of type uint8_t, which will be
 * by filled with HMAC.
 * @param hmac_size - size of the HMAC
 * @param fdo_status - status of the HECI call
 * @return status for API function
 */
TEESTATUS fdo_heci_read_file(TEEHANDLE *cl, uint32_t file_id, uint8_t
        *data_ptr, uint32_t *data_length, uint8_t *hmac_ptr, size_t hmac_sz,
        FDO_STATUS *fdo_status)
{
    if (!data_ptr || !data_length) {
		return -1;
	}

    if (file_id != OVH_FILE_ID && file_id != DS_FILE_ID) {
        LOG(LOG_ERROR,"Invalid file id!\n");
        return -1;
    }

    fdo_heci_read_file_request FDORequest;
    fdo_heci_read_file_response* FDOResponseMessage;
    TEESTATUS status = -1;

    FDORequest.header.command = FDO_HECI_READ_FILE;
    FDORequest.header.app_id = FDO_APP_ID;
    FDORequest.header.length = sizeof(FDORequest) - sizeof(FDORequest.header);
    FDORequest.file_id = file_id;
    const size_t sz = sizeof(FDORequest);
    unsigned char *buf = NULL;
    size_t rsz, wsz = 0;

    rsz = cl->maxMsgLen; //sets maxMsgLen
    buf = (unsigned char *)calloc(rsz, sizeof(unsigned char));
    if (buf == NULL) {
        LOG(LOG_ERROR,"calloc(%u) failed\n", (unsigned)rsz);
        goto out;
    }

    status = TeeWrite(cl, &FDORequest, sz, &wsz, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeWrite failed (%u) [attempted %u cmd bytes]\n",
                status, (unsigned)sizeof(FDORequest));
        goto out;
    }

    if (wsz != sz) {
        status = TEE_UNABLE_TO_COMPLETE_OPERATION;
        goto out;
    }

    size_t NumOfBytesRead = 0;


    FDOResponseMessage = (fdo_heci_read_file_response*)(buf);

    status = TeeRead(cl, buf, rsz, &NumOfBytesRead, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeRead failed (%u)\n", status);
        goto out;
    }

    *fdo_status = FDOResponseMessage->status;
    *data_length = FDOResponseMessage->data_length;

    if (file_id == OVH_FILE_ID && *data_length) {
        if (memcpy_s(data_ptr, *data_length,
                FDOResponseMessage->data, FDOResponseMessage->data_length) !=
                0) {
            LOG(LOG_ERROR, "Memcpy Failed\n");
            goto out;
        }

        if (memcpy_s(hmac_ptr, hmac_sz, FDOResponseMessage->HMAC,
                FDO_HMAC_384_SIZE) != 0) {
            LOG(LOG_ERROR, "Memcpy Failed\n");
            goto out;
        }
    } else if (*data_length) {
        if (memcpy_s(data_ptr, *data_length,
                FDOResponseMessage->data, FDOResponseMessage->data_length) !=
                0) {
            LOG(LOG_ERROR, "Memcpy Failed\n");
            goto out;
        }
    }

out:
	if (buf) {
	    fdo_free(buf);
    }
	return status;
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
    if (file_id != OVH_FILE_ID && file_id != DS_FILE_ID) {
        LOG(LOG_ERROR,"Invalid file id!\n");
        return -1;
    }

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
        LOG(LOG_ERROR,"calloc(%u) failed\n", (unsigned)rsz);
        goto out;
    }

    status = TeeWrite(cl, &FDORequest, sz, &wsz, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeWrite failed (%u) [attempted %u cmd bytes]\n",
                status, (unsigned)sizeof(FDORequest));
        goto out;
    }

    if (wsz != sz)
    {
        status = TEE_UNABLE_TO_COMPLETE_OPERATION;
        goto out;
    }

    size_t NumOfBytesRead = 0;


    FDOResponseMessage = (fdo_heci_clear_file_response*)(buf);

    status = TeeRead(cl, buf, rsz, &NumOfBytesRead, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeRead failed (%u)\n", status);
        goto out;
    }

    *fdo_status = FDOResponseMessage->status;

out:
	if (buf) {
	    fdo_free(buf);
    }
	return status;
}

/**
 * Closes the CSE Interface
 * @param TEEHANDLE - Structure to store connection data
 * @param fdo_status - status of the HECI call
 * @return status for API function
 */
TEESTATUS fdo_heci_close_interface(TEEHANDLE *cl, FDO_STATUS *fdo_status)
{
    fdo_heci_close_interface_request FDORequest;
    fdo_heci_close_interface_response* FDOResponseMessage;
    TEESTATUS status = -1;

    FDORequest.header.command = FDO_HECI_CLOSE_INTERFACE;
    FDORequest.header.app_id = FDO_APP_ID;
    FDORequest.header.length = 0;
    const size_t sz = sizeof(FDORequest);
    unsigned char *buf = NULL;
    size_t rsz, wsz = 0;

    rsz = cl->maxMsgLen; //sets maxMsgLen
    buf = (unsigned char *)calloc(rsz, sizeof(unsigned char));
    if (buf == NULL) {
        LOG(LOG_ERROR,"calloc(%u) failed\n", (unsigned)rsz);
        goto out;
    }

    status = TeeWrite(cl, &FDORequest, sz, &wsz, 0);
    if (status != TEE_SUCCESS) {
        LOG(LOG_ERROR, "TeeWrite failed (%u) [attempted %u cmd bytes]\n",
                status, (unsigned)sizeof(FDORequest));
        goto out;
    }

    if (wsz != sz)
    {
        status = TEE_UNABLE_TO_COMPLETE_OPERATION;
        goto out;
    }

    size_t NumOfBytesRead = 0;


    FDOResponseMessage = (fdo_heci_close_interface_response*)(buf);

    status = TeeRead(cl, buf, rsz, &NumOfBytesRead, 0);
    if (status != TEE_SUCCESS)
    {
        LOG(LOG_ERROR, "TeeRead failed (%u)\n", status);
        goto out;
    }

    *fdo_status = FDOResponseMessage->status;

out:
	if (buf) {
	    fdo_free(buf);
    }
	return status;
}
