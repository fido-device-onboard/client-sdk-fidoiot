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

// Note states are sequential to make sdoStateToURL work

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
#define SDOMsgTypeMIN SDO_TO1_TYPE_HELLO_SDO
#define SDOMsgTypeMAX SDO_TO2_DONE2

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
sdourl_t sdoStateToURL(int state);

typedef struct SDOProt_s {
	int state;
	int ecode;
	bool success;
	SDOR_t sdor;
	SDOW_t sdow;
	uint8_t gid[GID_SIZE];
	SDOByteArray_t *g2; /* Our initial GUID */
	SDOIPAddress_t i1;
	uint32_t port1;
	char *dns1;
	int keyEncoding;
	SDOPublicKey_t *new_pk;
	SDODevCred_t *devCred;
	SDOPublicKey_t *mfgPublicKey; // TO2.bo.oh.pk & DI.oh.ok
	// Installed during manufacturing is a hash of this
	SDOPublicKey_t
	    *ownerPublicKey; // TO2.ProveOVHdr bo.pk - The new Owner Public key
	SDOIV_t *iv;	 // IV store
	SDOServiceInfo_t *serviceInfo;
	SDOPublicKey_t *tlsKey;
	SDOPublicKey_t *localKeyPair;
	uint16_t ovEntryNum;
	SDOOwnershipVoucher_t *ovoucher;
	SDOHash_t *newOVHdrHMAC;
	SDORendezvous_t *rv;
	uint16_t servReqInfoNum;
	int ownerSuppliedServiceInfoCount;
	int ownerSuppliedServiceInfoNum;
	int ownerSuppliedServiceInfoRcv;
	SDOOwnerSuppliedCredentials_t *osc;
	SDOByteArray_t *n4;
	SDOByteArray_t *n5;
	SDOByteArray_t *n7;
	SDOByteArray_t *n5r;
	SDOByteArray_t *n6;
	SDOByteArray_t *n7r;
	SDORedirect_t SDORedirect;
	uint32_t RoundTripCount;
	//	void *keyExData;
	sdoSdkServiceInfoModuleList_t
	    *SvInfoModListHead; // Global SvInfomodule list head
	sdoSvInfoDsiInfo_t *dsiInfo;
	int totalDsiRounds; // device service infos + module DSI counts
	uint8_t rvIndex;    // keep track of current rv index
	bool reuse_enabled; // REUSE protocol flag
} SDOProt_t;

/* DI function declarations */
int32_t msg10(SDOProt_t *ps);
int32_t msg11(SDOProt_t *ps);
int32_t msg12(SDOProt_t *ps);
int32_t msg13(SDOProt_t *ps);

/* TO1 function declarations */
int32_t msg30(SDOProt_t *ps);
int32_t msg31(SDOProt_t *ps);
int32_t msg32(SDOProt_t *ps);
int32_t msg33(SDOProt_t *ps);

/* TO2 function declarations */
int32_t msg40(SDOProt_t *ps);
int32_t msg41(SDOProt_t *ps);
int32_t msg42(SDOProt_t *ps);
int32_t msg43(SDOProt_t *ps);
int32_t msg44(SDOProt_t *ps);
int32_t msg45(SDOProt_t *ps);
int32_t msg46(SDOProt_t *ps);
int32_t msg47(SDOProt_t *ps);
int32_t msg48(SDOProt_t *ps);
int32_t msg49(SDOProt_t *ps);
int32_t msg50(SDOProt_t *ps);
int32_t msg51(SDOProt_t *ps);

/* Init functions of particular protocol (DI, TO1, TO2) */
void sdoProtDIInit(SDOProt_t *ps, SDODevCred_t *devCred);
int32_t sdoProtTO1Init(SDOProt_t *ps, SDODevCred_t *devCred);
bool sdoProtTO2Init(SDOProt_t *ps, SDOServiceInfo_t *si, SDODevCred_t *devCred,
		    sdoSdkServiceInfoModuleList_t *moduleList);

/* State machine management of protocols */
bool sdo_process_states(SDOProt_t *ps);

bool sdoCheckTO2RoundTrips(SDOProt_t *ps);

void sdoSendErrorMessage(SDOW_t *sdow, int ecode, int msgnum, const char *emsg);
void sdoReceiveErrorMessage(SDOR_t *sdor, int *ecode, int *msgnum, char *emsg,
			    int emsgSz);
bool sdoProtRcvMsg(SDOR_t *sdor, SDOW_t *sdow, char *protName, int *statep);

int ps_get_m_string(SDOProt_t *ps);
#endif /* __SDOPROT_H__ */
