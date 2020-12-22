/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDOPROT_H__
#define __SDOPROT_H__

#include "sdocred.h"
#include "sdotypes.h"
#include <stdbool.h>
#include <stdint.h>

#define INITIAL_SECRET_BYTES (32)
#define GID_SIZE (16)

// SDO Device States
#define SDO_DEVICE_STATE_PD 0     // Permanently Disabled
#define SDO_DEVICE_STATE_PC 1     // Pre-Configured
#define SDO_DEVICE_STATE_D 2      // Disabled
#define SDO_DEVICE_STATE_READY1 3 // Initial Transfer Ready
#define SDO_DEVICE_STATE_D1 4     // Initial Transfer Disabled
#define SDO_DEVICE_STATE_IDLE 5   // SDO Idle
#define SDO_DEVICE_STATE_READYN 6 // Transfer Ready
#define SDO_DEVICE_STATE_DN 7     // Transfer Disabled

// Ports
#define SDO_PORT_TO1 8041
#define SDO_PORT_TO2 8042
#define SDO_PORT_REST 8085
#define SDO_PORT_REPORTED 980
#define SDO_PORT_MAX_LEN 5 // max value of port is 65535 i.e. length 5
#define SDO_PORT_MIN_VALUE 1
#define SDO_PORT_MAX_VALUE 65535

// States
#define SDO_STATE_RCV_ERROR 60
#define SDO_STATE_ERROR 61
#define SDO_STATE_DONE 62

// Operational States for the device
#define SDO_OP_STATE_APPLICATION 2 // SDO Complete, running customer application

// Note states are sequential to make sdo_state_toURL work

// Protocol Report: Device => Reporter Server
#define SDO_STATE_MGR_AGENT_INIT 17
#define SDO_STATE_SND_REPORT 18
#define SDO_STATE_RCV_REPORT_ACK 19

// DI
#define SDO_DI_APP_START 10
#define SDO_DI_SET_CREDENTIALS 11
#define SDO_DI_SET_HMAC 12
#define SDO_DI_DONE 13

// TO1
#define SDO_TO1_TYPE_HELLO_SDO 30
#define SDO_TO1_TYPE_HELLO_SDOAck 31
#define SDO_TO1_TYPE_PROVE_TO_SDO 32
#define SDO_TO1_TYPE_SDO_REDIRECT 33

// TO2
#define SDO_TO2_HELLO_DEVICE 40
#define SDO_TO2_PROVE_OVHDR 41
#define SDO_TO2_GET_OP_NEXT_ENTRY 42
#define SDO_TO2_OP_NEXT_ENTRY 43
#define SDO_TO2_PROVE_DEVICE 44
#define SDO_TO2_GET_NEXT_DEVICE_SERVICE_INFO 45
#define SDO_TO2_NEXT_DEVICE_SERVICE_INFO 46
#define SDO_TO2_SETUP_DEVICE 47
#define SDO_TO2_GET_NEXT_OWNER_SERVICE_INFO 48
#define SDO_TO2_OWNER_SERVICE_INFO 49
#define SDO_TO2_DONE 50
#define SDO_TO2_DONE2 51

#define SDO_STATE_DI_INIT SDO_DI_APP_START
#define SDO_STATE_DI_APP_START SDO_DI_APP_START
#define SDO_STATE_DI_SET_CREDENTIALS SDO_DI_SET_CREDENTIALS
#define SDO_STATE_DI_SET_HMAC SDO_DI_SET_HMAC
#define SDO_STATE_DI_DONE SDO_DI_DONE

// Protocol TO1: Device => SDO Server
#define SDO_STATE_TO1_INIT SDO_TO1_TYPE_HELLO_SDO
#define SDO_STATE_T01_SND_HELLO_SDO SDO_TO1_TYPE_HELLO_SDO
#define SDO_STATE_TO1_RCV_HELLO_SDOACK SDO_TO1_TYPE_HELLO_SDOAck
#define SDO_STATE_TO1_SND_PROVE_TO_SDO SDO_TO1_TYPE_PROVE_TO_SDO
#define SDO_STATE_TO1_RCV_SDO_REDIRECT SDO_TO1_TYPE_SDO_REDIRECT

// Protocol TO2: Device => SDO Owner
#define SDO_STATE_T02_INIT SDO_TO2_HELLO_DEVICE
#define SDO_STATE_T02_SND_HELLO_DEVICE SDO_TO2_HELLO_DEVICE
#define SDO_STATE_TO2_RCV_PROVE_OVHDR SDO_TO2_PROVE_OVHDR
#define SDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY SDO_TO2_GET_OP_NEXT_ENTRY
#define SDO_STATE_T02_RCV_OP_NEXT_ENTRY SDO_TO2_OP_NEXT_ENTRY
#define SDO_STATE_TO2_SND_PROVE_DEVICE SDO_TO2_PROVE_DEVICE
#define SDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO                         \
	SDO_TO2_GET_NEXT_DEVICE_SERVICE_INFO
#define SDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO                             \
	SDO_TO2_NEXT_DEVICE_SERVICE_INFO
#define SDO_STATE_TO2_RCV_SETUP_DEVICE SDO_TO2_SETUP_DEVICE
#define SDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO                          \
	SDO_TO2_GET_NEXT_OWNER_SERVICE_INFO
#define SDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO SDO_TO2_OWNER_SERVICE_INFO
#define SDO_STATE_TO2_SND_DONE SDO_TO2_DONE
#define SDO_STATE_TO2_RCV_DONE_2 SDO_TO2_DONE2

// Protocol message types
#define SDO_TYPE_ERROR 255

// Persistent
#define SDO_TYPE_CRED_OWNER 1
#define SDO_TYPE_CRED_MFG 2
#define SDO_TYPE_OWNERSHIP_VOUCHER 3
#define SDO_TYPE_PUBLIC_KEY 4
#define SDO_TYPE_SERVICE_INFO 5
#define SDO_TYPE_DEVICE_CRED 6
#define SDO_TYPE_HMAC 7

// Report
#define SDO_MGR_AGENT_SND_REPORT 52
#define SDO_MGR_AGENT_RCV_REPORT_ACK 53

// For restful URL mapping
#define SDOMsg_typeMIN SDO_TO1_TYPE_HELLO_SDO
#define SDOMsg_typeMAX SDO_TO2_DONE2

// Protocol version
#define SDO_VER_MAJOR 1
#define SDO_VER_MINOR 10

// Error Message
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
#define SDO_PROT_SPEC_VERSION 113

/*
 * Set size of buffer for generating debugging messages.
 * The messages will be truncated appropriately, so this can be
 * any size.  To see an entire public key, you need more than 512 bytes,
 * which may be too much for a constrained system to put on the stack.
 *
 * An alternative is to declare the buffer global
 */
#define DEBUGBUFSZ 1024

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
sdourl_t sdo_state_toURL(int state);

typedef struct sdo_prot_s {
	int state;
	int ecode;
	bool success;
	sdor_t sdor;
	sdow_t sdow;
	uint8_t gid[GID_SIZE];
	sdo_byte_array_t *g2; /* Our initial GUID */
	sdo_ip_address_t i1;
	uint32_t port1;
	char *dns1;
	int key_encoding;
	sdo_public_key_t *new_pk;
	sdo_dev_cred_t *dev_cred;
	sdo_public_key_t *mfg_public_key; // TO2.bo.oh.pk & DI.oh.ok
	// Installed during manufacturing is a hash of this
	sdo_public_key_t *
	    owner_public_key; // TO2.ProveOVHdr bo.pk - The new Owner Public key
	sdo_iv_t *iv;	 // IV store
	sdo_service_info_t *service_info;
	sdo_public_key_t *tls_key;
	sdo_public_key_t *local_key_pair;
	uint16_t ov_entry_num;
	sdo_ownership_voucher_t *ovoucher;
	sdo_hash_t *new_ov_hdr_hmac;
	sdo_rendezvous_t *rv;
	uint16_t serv_req_info_num;
	int owner_supplied_service_info_count;
	int owner_supplied_service_info_num;
	int owner_supplied_service_info_rcv;
	sdo_owner_supplied_credentials_t *osc;
	sdo_byte_array_t *n4;
	sdo_byte_array_t *n5;
	sdo_byte_array_t *n7;
	sdo_byte_array_t *n5r;
	sdo_byte_array_t *n6;
	sdo_byte_array_t *n7r;
	sdo_redirect_t sdo_redirect;
	uint32_t round_trip_count;
	//	void *key_ex_data;
	sdo_sdk_service_info_module_list_t
	    *sv_info_mod_list_head; // Global Sv_infomodule list head
	sdo_sv_info_dsi_info_t *dsi_info;
	int total_dsi_rounds; // device service infos + module DSI counts
	uint8_t rv_index;     // keep track of current rv index
	bool reuse_enabled;   // REUSE protocol flag
} sdo_prot_t;

/* DI function declarations */
int32_t msg10(sdo_prot_t *ps);
int32_t msg11(sdo_prot_t *ps);
int32_t msg12(sdo_prot_t *ps);
int32_t msg13(sdo_prot_t *ps);

/* TO1 function declarations */
int32_t msg30(sdo_prot_t *ps);
int32_t msg31(sdo_prot_t *ps);
int32_t msg32(sdo_prot_t *ps);
int32_t msg33(sdo_prot_t *ps);

/* TO2 function declarations */
int32_t msg40(sdo_prot_t *ps);
int32_t msg41(sdo_prot_t *ps);
int32_t msg42(sdo_prot_t *ps);
int32_t msg43(sdo_prot_t *ps);
int32_t msg44(sdo_prot_t *ps);
int32_t msg45(sdo_prot_t *ps);
int32_t msg46(sdo_prot_t *ps);
int32_t msg47(sdo_prot_t *ps);
int32_t msg48(sdo_prot_t *ps);
int32_t msg49(sdo_prot_t *ps);
int32_t msg50(sdo_prot_t *ps);
int32_t msg51(sdo_prot_t *ps);

/* Init functions of particular protocol (DI, TO1, TO2) */
void sdo_prot_di_init(sdo_prot_t *ps, sdo_dev_cred_t *dev_cred);
int32_t sdo_prot_to1_init(sdo_prot_t *ps, sdo_dev_cred_t *dev_cred);
bool sdo_prot_to2_init(sdo_prot_t *ps, sdo_service_info_t *si,
		       sdo_dev_cred_t *dev_cred,
		       sdo_sdk_service_info_module_list_t *module_list);

/* State machine management of protocols */
bool sdo_process_states(sdo_prot_t *ps);

bool sdo_check_to2_round_trips(sdo_prot_t *ps);

void sdo_send_error_message(sdow_t *sdow, int ecode, int msgnum,
					char *emsg);
void sdo_receive_error_message(sdor_t *sdor, int *ecode, int *msgnum,
			       char *emsg, int emsg_sz);
bool sdo_prot_rcv_msg(sdor_t *sdor, sdow_t *sdow, char *prot_name, int *statep);

int ps_get_m_string(sdo_prot_t *ps);
int ps_get_m_string_cbor(sdo_byte_array_t *mstring);
#endif /* __SDOPROT_H__ */
