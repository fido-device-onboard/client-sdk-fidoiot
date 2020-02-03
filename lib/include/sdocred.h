/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDOCRED_H__
#define __SDOCRED_H__

#include "sdotypes.h"

SDOHash_t *sdoPubKeyHash(SDOPublicKey_t *pubKey);

typedef struct _sdo_credowner_t {
	int pv; // The protocol version
	int pe; // The KeyEncoding in this credential and in ownership proxies
	SDOByteArray_t *guid;       // Our initial GUID
	SDORendezvousList_t *rvlst; // Rendezvous information
	SDOHash_t *pkh;		    // Hash of the group public key, SHA-256
	SDOPublicKey_t *pk;
} SDOCredOwner_t;

typedef struct _sdo_credMfgBlock_t {
	SDOString_t *d;  // Manufacturer's DeviceInfo field
	SDOString_t *cu; // URL of the Certificate for the manufacturer
	SDOHash_t *ch;   // Hash of the above "cu" URL
} SDOCredMfg_t;

typedef struct _sdo_deviceCredentials_t {
	uint8_t ST;
	SDOCredMfg_t *mfgBlk;
	SDOCredOwner_t *ownerBlk;
} SDODevCred_t;

SDODevCred_t *sdoDevCredAlloc(void);
void sdoDevCredInit(SDODevCred_t *devCred);
void sdoDevCredFree(SDODevCred_t *devCred);
bool sdoDeviceCredentialRead(SDOR_t *sdor, SDODevCred_t *ourDevCred);
bool sdoDeviceCredentialWrite(SDOW_t *sdow, SDODevCred_t *ourDevCred);
#if 0
void SDODevCredPrint(SDODevCred_t *devCred);
#endif

SDOCredOwner_t *SDOCredOwnerAlloc(void);
void sdoCredOwnerFree(SDOCredOwner_t *ocred);
void sdoCredOwnerPrint(SDOCredOwner_t *ocred);

SDOCredMfg_t *sdoCredMfgAlloc(void);
void sdoCredMfgFree(SDOCredMfg_t *ocredMfg);
void sdoCredMfgPrint(SDOCredMfg_t *ocredMfg);

typedef struct _sdo_oventry_t {
	struct _sdo_oventry_t *next;
	uint16_t enn;
	SDOHash_t *hpHash;
	SDOHash_t *hcHash;
	SDOPublicKey_t *pk;
} SDOOvEntry_t;

SDOOvEntry_t *sdoOvEntryAllocEmpty(void);
SDOOvEntry_t *sdoOvEntryFree(SDOOvEntry_t *e);
bool sdoOvEntryAdd(SDOOvEntry_t *rootEntry, SDOOvEntry_t *e);

#define SDO_DEV_INFO_SZ 512 // max size of dev info we handle

typedef struct _sdo_ownershipvoucher_t {
	int protVersion;
	int keyEncoding;
	SDOByteArray_t *g2;
	SDORendezvousList_t *rvlst2;
	SDOString_t *devInfo;
	SDOPublicKey_t *mfgPubKey;
	SDOHash_t *ovoucherHdrHash;
	int numOVEntries;
	SDOOvEntry_t *OVEntries;
	SDOHash_t *hdc;
} SDOOwnershipVoucher_t;

SDOOwnershipVoucher_t *sdoOvAlloc(void);
void sdoOvFree(SDOOwnershipVoucher_t *ov);
void sdoOvPrint(SDOOwnershipVoucher_t *ov);
SDOOwnershipVoucher_t *sdoOvHdrRead(SDOR_t *sdor, SDOHash_t **hmac,
				    bool calHpHc);
SDOHash_t *sdoNewOVHdrSign(SDODevCred_t *devCred, SDOPublicKey_t *newPubKey);

typedef struct SDOOwnerSuppliedCredentials_s {
	SDORendezvousList_t *rvlst;
	SDOByteArray_t *guid;
	SDOServiceInfo_t *si;
} SDOOwnerSuppliedCredentials_t;

SDOOwnerSuppliedCredentials_t *sdoOwnerSuppliedCredentialsAlloc(void);
void sdoOwnerSuppliedCredentialsFree(SDOOwnerSuppliedCredentials_t *ocs);
void sdoIVFree(SDOIV_t *iv);

#endif /* __SDOCRED_H__ */
