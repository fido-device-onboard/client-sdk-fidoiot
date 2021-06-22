/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __FDOPROT_H__
#define __FDOPROT_H__

#include "fdocred.h"
#include "fdotypes.h"
#include <stdbool.h>
#include <stdint.h>

#define INITIAL_SECRET_BYTES (32)
#define GID_SIZE (16)

// FDO Device States
#define FDO_DEVICE_STATE_PD 0     // Permanently Disabled
#define FDO_DEVICE_STATE_PC 1     // Pre-Configured
#define FDO_DEVICE_STATE_D 2      // Disabled
#define FDO_DEVICE_STATE_READY1 3 // Initial Transfer Ready
#define FDO_DEVICE_STATE_D1 4     // Initial Transfer Disabled
#define FDO_DEVICE_STATE_IDLE 5   // FDO Idle
#define FDO_DEVICE_STATE_READYN 6 // Transfer Ready
#define FDO_DEVICE_STATE_DN 7     // Transfer Disabled

// Ports
#define FDO_PORT_MAX_LEN 5 // max value of port is 65535 i.e. length 5
#define FDO_PORT_MIN_VALUE 1
#define FDO_PORT_MAX_VALUE 65535

// States
#define FDO_STATE_ERROR 81
#define FDO_STATE_DONE 82

// Note states are sequential to make fdo_state_toURL work

// DI
#define FDO_DI_APP_START 10
#define FDO_DI_SET_CREDENTIALS 11
#define FDO_DI_SET_HMAC 12
#define FDO_DI_DONE 13

// TO1
#define FDO_TO1_TYPE_HELLO_FDO 30
#define FDO_TO1_TYPE_HELLO_FDOAck 31
#define FDO_TO1_TYPE_PROVE_TO_FDO 32
#define FDO_TO1_TYPE_FDO_REDIRECT 33

// TO2
#define FDO_TO2_HELLO_DEVICE 60
#define FDO_TO2_PROVE_OVHDR 61
#define FDO_TO2_GET_OP_NEXT_ENTRY 62
#define FDO_TO2_OP_NEXT_ENTRY 63
#define FDO_TO2_PROVE_DEVICE 64
#define FDO_TO2_GET_NEXT_DEVICE_SERVICE_INFO 65
#define FDO_TO2_NEXT_DEVICE_SERVICE_INFO 66
#define FDO_TO2_SETUP_DEVICE 67
#define FDO_TO2_GET_NEXT_OWNER_SERVICE_INFO 68
#define FDO_TO2_OWNER_SERVICE_INFO 69
#define FDO_TO2_DONE 70
#define FDO_TO2_DONE2 71

#define FDO_STATE_DI_INIT FDO_DI_APP_START
#define FDO_STATE_DI_APP_START FDO_DI_APP_START
#define FDO_STATE_DI_SET_CREDENTIALS FDO_DI_SET_CREDENTIALS
#define FDO_STATE_DI_SET_HMAC FDO_DI_SET_HMAC
#define FDO_STATE_DI_DONE FDO_DI_DONE

// Protocol TO1: Device => FDO Server
#define FDO_STATE_TO1_INIT FDO_TO1_TYPE_HELLO_FDO
#define FDO_STATE_T01_SND_HELLO_FDO FDO_TO1_TYPE_HELLO_FDO
#define FDO_STATE_TO1_RCV_HELLO_FDOACK FDO_TO1_TYPE_HELLO_FDOAck
#define FDO_STATE_TO1_SND_PROVE_TO_FDO FDO_TO1_TYPE_PROVE_TO_FDO
#define FDO_STATE_TO1_RCV_FDO_REDIRECT FDO_TO1_TYPE_FDO_REDIRECT

// Protocol TO2: Device => FDO Owner
#define FDO_STATE_T02_INIT FDO_TO2_HELLO_DEVICE
#define FDO_STATE_T02_SND_HELLO_DEVICE FDO_TO2_HELLO_DEVICE
#define FDO_STATE_TO2_RCV_PROVE_OVHDR FDO_TO2_PROVE_OVHDR
#define FDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY FDO_TO2_GET_OP_NEXT_ENTRY
#define FDO_STATE_T02_RCV_OP_NEXT_ENTRY FDO_TO2_OP_NEXT_ENTRY
#define FDO_STATE_TO2_SND_PROVE_DEVICE FDO_TO2_PROVE_DEVICE
#define FDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO                         \
	FDO_TO2_GET_NEXT_DEVICE_SERVICE_INFO
#define FDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO                             \
	FDO_TO2_NEXT_DEVICE_SERVICE_INFO
#define FDO_STATE_TO2_RCV_SETUP_DEVICE FDO_TO2_SETUP_DEVICE
#define FDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO                          \
	FDO_TO2_GET_NEXT_OWNER_SERVICE_INFO
#define FDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO FDO_TO2_OWNER_SERVICE_INFO
#define FDO_STATE_TO2_SND_DONE FDO_TO2_DONE
#define FDO_STATE_TO2_RCV_DONE_2 FDO_TO2_DONE2

// Protocol message types
#define FDO_TYPE_ERROR 255

// Persistent
// TODO: Needs review (Only FDO_TYPE_HMAC is used in code)
#define FDO_TYPE_CRED_OWNER 1
#define FDO_TYPE_CRED_MFG 2
#define FDO_TYPE_OWNERSHIP_VOUCHER 3
#define FDO_TYPE_PUBLIC_KEY 4
#define FDO_TYPE_SERVICE_INFO 5
#define FDO_TYPE_DEVICE_CRED 6
#define FDO_TYPE_HMAC 7

// For restful URL mapping
// TODO: Not used, needs to review
#define FDOMsg_typeMIN FDO_TO1_TYPE_HELLO_FDO
#define FDOMsg_typeMAX FDO_TO2_DONE2

// Error Message
// TODO: Not used, needs to review (Only INTERNAL_SERVER_ERROR is used)
#define INVALID_JWT_TOKEN 1
#define INVALID_OWNERSHIP_VOUCHER 2
#define INVALID_OWNER_SIGN_BODY 3
#define INVALID_IP_ADDRESS 4
#define INVALID_GUID 5
#define RESOURCE_NOT_FOUND 6
#define INVALID_PROVE_REQUEST_EXCEPTION 7
#define INVALID_EPID_SIGNATURE 8
#define MESSAGE_BODY_ERROR 100
#define INVALID_MESSAGE_ERROR 101
#define INTERNAL_SERVER_ERROR 500

#define MAX_TO2_ROUND_TRIPS 1000000

// Current protocol version
#define FDO_PROT_SPEC_VERSION 100

/*
 * Set size of buffer for generating debugging messages.
 * The messages will be truncated appropriately, so this can be
 * any size.  To see an entire public key, you need more than 512 bytes,
 * which may be too much for a constrained system to put on the stack.
 *
 * An alternative is to declare the buffer global
 */
// TODO: Needs review, macro not used.
#define DEBUGBUFSZ 1024

// minimum ServiceInfo size
#define MIN_SERVICEINFO_SZ 1300
// maximum ServiceInfo size
#define MAX_SERVICEINFO_SZ 8192
// margin that gets added to either max or min ServiceInfo size to create
// the final buffer to read/write protcol (DI/TO1/TO2)
#define MSG_METADATA_SIZE 700

#if defined(REUSE_SUPPORTED)
static const bool reuse_supported = true;
#else
static const bool reuse_supported = false;
#endif
#if defined(RESALE_SUPPORTED)
static const bool resale_supported = true;
#else
static const bool resale_supported = false;
#endif

// Utility to convert type to URL
fdourl_t fdo_state_toURL(int state);

typedef struct fdo_prot_s {
	int state;
	int ecode;
	bool success;
	fdor_t fdor;
	fdow_t fdow;
	uint8_t gid[GID_SIZE];
	fdo_byte_array_t *g2; /* Our initial GUID */
	fdo_ip_address_t i1;
	uint32_t port1;
	char *dns1;
	int key_encoding;
	fdo_rvto2addr_t *rvto2addr;
	fdo_public_key_t *new_pk;
	fdo_dev_cred_t *dev_cred;
	fdo_public_key_t *mfg_public_key; // TO2.bo.oh.pk & DI.oh.ok
	// Installed during manufacturing is a hash of this
	fdo_public_key_t *
	    owner_public_key; // TO2.ProveOVHdr bo.pk - The new Owner Public key
	fdo_service_info_t *service_info;
	fdo_public_key_t *tls_key;
	fdo_public_key_t *local_key_pair;
	int ov_entry_num;
	fdo_ownership_voucher_t *ovoucher;
	fdo_hash_t *new_ov_hdr_hmac;
	fdo_rendezvous_t *rv;
	fdo_cose_t *to1d_cose;
	uint16_t serv_req_info_num;
	int maxOwnerServiceInfoSz;
	int maxDeviceServiceInfoSz;
	bool device_serviceinfo_ismore;
	size_t prot_buff_sz;
	int owner_supplied_service_info_num;
	int owner_supplied_service_info_rcv;
	fdo_owner_supplied_credentials_t *osc;
	fdo_byte_array_t *nonce_to1proof;
	fdo_byte_array_t *nonce_to2proveov;
	fdo_byte_array_t *nonce_to2proveov_rcv;
	fdo_byte_array_t *nonce_to2provedv;
	fdo_byte_array_t *nonce_to2setupdv;
	fdo_byte_array_t *nonce_to2setupdv_rcv;
	fdo_redirect_t fdo_redirect;
	uint32_t round_trip_count;
	//	void *key_ex_data;
	fdo_sdk_service_info_module_list_t
	    *sv_info_mod_list_head; // Global Sv_infomodule list head
	fdo_sv_info_dsi_info_t *dsi_info;
	int total_dsi_rounds; // device service infos + module DSI counts
	uint8_t rv_index;     // keep track of current rv index
	bool reuse_enabled;   // REUSE protocol flag
} fdo_prot_t;

/* DI function declarations */
int32_t msg10(fdo_prot_t *ps);
int32_t msg11(fdo_prot_t *ps);
int32_t msg12(fdo_prot_t *ps);
int32_t msg13(fdo_prot_t *ps);

/* TO1 function declarations */
int32_t msg30(fdo_prot_t *ps);
int32_t msg31(fdo_prot_t *ps);
int32_t msg32(fdo_prot_t *ps);
int32_t msg33(fdo_prot_t *ps);

/* TO2 function declarations */
int32_t msg60(fdo_prot_t *ps);
int32_t msg61(fdo_prot_t *ps);
int32_t msg62(fdo_prot_t *ps);
int32_t msg63(fdo_prot_t *ps);
int32_t msg64(fdo_prot_t *ps);
int32_t msg65(fdo_prot_t *ps);
int32_t msg66(fdo_prot_t *ps);
int32_t msg67(fdo_prot_t *ps);
int32_t msg68(fdo_prot_t *ps);
int32_t msg69(fdo_prot_t *ps);
int32_t msg70(fdo_prot_t *ps);
int32_t msg71(fdo_prot_t *ps);

/* Init functions of particular protocol (DI, TO1, TO2) */
void fdo_prot_di_init(fdo_prot_t *ps, fdo_dev_cred_t *dev_cred);
int32_t fdo_prot_to1_init(fdo_prot_t *ps, fdo_dev_cred_t *dev_cred);
bool fdo_prot_to2_init(fdo_prot_t *ps, fdo_service_info_t *si,
		       fdo_dev_cred_t *dev_cred,
		       fdo_sdk_service_info_module_list_t *module_list);

/* State machine management of protocols */
bool fdo_process_states(fdo_prot_t *ps);

bool fdo_check_to2_round_trips(fdo_prot_t *ps);

void fdo_send_error_message(fdow_t *fdow, int ecode, int msgnum,
					char *emsg, size_t errmsg_sz);
void fdo_receive_error_message(fdor_t *fdor, int *ecode, int *msgnum,
			       char *emsg, int emsg_sz);
bool fdo_prot_rcv_msg(fdor_t *fdor, fdow_t *fdow, char *prot_name, int *statep);

int ps_get_m_string(fdo_prot_t *ps);
int ps_get_m_string_cbor(fdo_byte_array_t *mstring);
#endif /* __FDOPROT_H__ */
