/*++

INTEL CONFIDENTIAL
Copyright 2020-2021 Intel Corporation All Rights Reserved.

The source code contained or described herein and all documents
related to the source code ("Material") are owned by Intel Corporation
or its suppliers or licensors. Title to the Material remains with
Intel Corporation or its suppliers and licensors. The Material
contains trade secrets and proprietary and confidential information of
Intel or its suppliers and licensors. The Material is protected by
worldwide copyright and trade secret laws and treaty provisions. No
part of the Material may be used, copied, reproduced, modified,
published, uploaded, posted, transmitted, distributed, or disclosed in
any way without Intel's prior express written permission.

No license under any patent, copyright, trade secret or other
intellectual property right is granted to or conferred upon you by
disclosure or delivery of the Materials, either expressly, by
implication, inducement, estoppel or otherwise. Any license under such
intellectual property rights must be express and approved by Intel in
writing.

--*/


#ifndef _FDO_DEFS_H_
#define _FDO_DEFS_H_

#include <stdio.h>
#include <stdint.h>

#define FDO_MAX_CERT_CHAIN_SIZE   3200 //4*800
#define FDO_ODCA_CHAIN_LEN        4
#define FDO_MAX_SIGNATURE_LENGTH  1024
#define FDO_MAX_DATA_TO_SIGN      1024
#define FDO_HMAC_384_SIZE         48
#define FDO_MAX_FILE_SIZE         8*1024 //8k
#define FDO_SIGNATURE_LENGTH      96 // FDO uses 384 curve so signature length will be 384/4 = 96
#define FDO_MAX_MAROE_PREFIX_SIZE 100
#define FDO_MAX_RANDOM            256
#define FDO_DATA_LENGTH_SIZE      4
#define FDO_APP_NAME  "FDO"
#define FDO_APP_NAME_MAX_LENGTH   3  //temp gil???


typedef enum
{
   FDO_ID =1,
}
App_ID;


typedef enum
{
   FDO_HECI_GET_VERSION = 1,
   FDO_HECI_GET_CERTIFICATE_CHAIN = 4,
   FDO_HECI_ECDSA_DEVICE_SIGN_CHALLENGE,
   FDO_HECI_GENERATE_RANDOM,
   FDO_HECI_LOAD_FILE = 11,
   FDO_HECI_UPDATE_FILE,
   FDO_HECI_COMMIT_FILE,
   FDO_HECI_READ_FILE,
   FDO_HECI_CLEAR_FILE,
   FDO_HECI_CLOSE_INTERFACE = 20,
} FDO_HECI_COMMANDS;

typedef enum
{
   FDO_STATUS_SUCCESS,
   FDO_STATUS_FEATURE_NOT_SUPPORTED,
   FDO_STATUS_ACTION_NOT_ALLOWED,
   FDO_STATUS_INVALID_INPUT_PARAMETER,
   FDO_STATUS_INTERNAL_ERROR,
   FDO_STATUS_FAIL_TO_LOAD_FILE,
   FDO_STATUS_API_INTERFACE_IS_CLOSED,
} FDO_STATUS;



typedef enum
{
   FDO_SIGN_ECDSA384_WITH_SHA384 = 0,
} FDO_SIGNING_MECHANISM;

typedef enum
{
   FDO_FILE_ID_OVH  = 0,
   FDO_FILE_ID_DEVICE_STATE,
   FDO_FILE_ID_END,
} FDO_FILE_ID;

// HECI interface

#pragma pack(1)

typedef struct
{
   uint16_t major_version;
   uint16_t minor_version;
}fdo_heci_version;


typedef struct
{
   fdo_heci_version     version;
   uint8_t              command;
   uint8_t              app_id; // 1 for FDO.
   uint16_t             length; //length of the command
}fdo_heci_header;

typedef struct
{
    fdo_heci_header     header;
    FDO_STATUS          status;
}fdo_heci_default_response;

/***********************************************/
/***** FDO_HECI_GET_VERSION  = 1           *****/
/***********************************************/
typedef struct
{
   fdo_heci_header      header;
}fdo_heci_get_version_request;

typedef struct
{
   fdo_heci_header      header;
   FDO_STATUS           status;
   fdo_heci_version	   version;
}fdo_heci_get_version_response;



/***********************************************/
/***** FDO_HECI_GET_CERTIFICATE_CHAIN  = 4 *****/
/***********************************************/
typedef struct
{
   fdo_heci_header      header;
}fdo_heci_get_certificate_chain_request;

typedef struct
{
   fdo_heci_header      header;
   FDO_STATUS           status;
   uint16_t             lengths_of_certificates[FDO_ODCA_CHAIN_LEN];
   uint8_t              certificate_chain[FDO_MAX_CERT_CHAIN_SIZE];
}fdo_heci_get_certificate_chain_response;


/****************************************************/
/***** FDO_HECI_ECDSA_DEVICE_SIGN_CHALLENGE = 5 *****/
/****************************************************/
typedef struct
{
   fdo_heci_header      header;
   uint32_t		         data_length; //max length of 1024Byte ?
   uint8_t 		         data[FDO_MAX_DATA_TO_SIGN];
}fdo_heci_ecdsa_device_sign_challenge_request;

typedef struct
{
   fdo_heci_header           header;
   FDO_STATUS                status;
   FDO_SIGNING_MECHANISM     signature_mechanism;
   uint32_t 				     maroeprefix_length;
   uint8_t                   maroeprefix[FDO_MAX_MAROE_PREFIX_SIZE];
   uint8_t                   signature[FDO_MAX_SIGNATURE_LENGTH];
}fdo_heci_ecdsa_device_sign_challenge_response;


/************************************************/
/*****     FDO_HECI_GENERATE_RANDOM = 6     *****/
/************************************************/
typedef struct
{
   fdo_heci_header      header;
   uint32_t			      length; //MAX is 256
}fdo_heci_generate_random_request;

typedef struct
{
   fdo_heci_header      header;
   FDO_STATUS           status;
   uint32_t			      length; //MAX is 256, same value as input
   uint8_t		         random_bytes[FDO_MAX_RANDOM];
}fdo_heci_generate_random_response;

/********************************************/
/*****     FDO_HECI_LOAD_FILE = 11      *****/
/********************************************/

typedef struct
{
   fdo_heci_header      header;
   uint32_t			      file_id; //0 or 1
}fdo_heci_load_file_request;

typedef struct
{
   fdo_heci_header      header;
   FDO_STATUS           status;
}fdo_heci_load_file_response;

/********************************************/
/*****     FDO_HECI_UPDATE_FILE = 12    *****/
/********************************************/
typedef struct
{
   fdo_heci_header      header;
   uint32_t 			   file_id; //0 or 1
   uint32_t 			   data_length;
   uint8_t		         data[FDO_MAX_FILE_SIZE];
}  fdo_heci_update_file_request;

typedef struct
{
    fdo_heci_header     header;
    FDO_STATUS          status;
    uint8_t	            HMAC[FDO_HMAC_384_SIZE];
}  fdo_heci_update_file_response;

/********************************************/
/*****     FDO_HECI_COMMIT_FILE = 13    *****/
/********************************************/
typedef struct
{
    fdo_heci_header     header;
    uint32_t		      file_id; //0 or 1
}  fdo_heci_commit_file_request;

typedef struct
{
    fdo_heci_header     header;
    FDO_STATUS          status;
}  fdo_heci_commit_file_response;


/********************************************/
/*****     FDO_HECI_READ_FILE = 14    *****/
/********************************************/

typedef struct
{
    fdo_heci_header    header;
    uint32_t		     file_id; //0 or 1

}  fdo_heci_read_file_request;

typedef struct
{
    fdo_heci_header     header;
    FDO_STATUS          status;
    uint32_t		      data_length;
    uint8_t			      data[FDO_MAX_FILE_SIZE];
    uint8_t	            HMAC[FDO_HMAC_384_SIZE];
}  fdo_heci_read_file_response;

/********************************************/
/*****     FDO_HECI_CLEAR_FILE = 15    *****/
/********************************************/
typedef struct
{
    fdo_heci_header     header;
    uint32_t		      file_id; //0 or 1
}  fdo_heci_clear_file_request;

typedef struct
{
    fdo_heci_header     header;
    FDO_STATUS          status;
}  fdo_heci_clear_file_response;



/************************************************/
/*****    FDO_HECI_CLOSE_INTERFACE = 20     *****/
/************************************************/
typedef struct
{
    fdo_heci_header     header;
}  fdo_heci_close_interface_request;

typedef struct
{
    fdo_heci_header     header;
    FDO_STATUS          status;
} fdo_heci_close_interface_response;



#pragma pack()

#endif // _FDO_DEFS_H_
