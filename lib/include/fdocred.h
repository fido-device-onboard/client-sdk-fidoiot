/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __FDOCRED_H__
#define __FDOCRED_H__

#include "fdotypes.h"

// FDO Device States
typedef enum {
	FDO_DEVICE_STATE_PD = 0,     // Permanently Disabled
	FDO_DEVICE_STATE_PC = 1,     // Pre-Configured
	FDO_DEVICE_STATE_D = 2,      // Disabled
	FDO_DEVICE_STATE_READY1 = 3, // Initial Transfer Ready
	FDO_DEVICE_STATE_D1 = 4,     // Initial Transfer Disabled
	FDO_DEVICE_STATE_IDLE = 5,   // FDO Idle
	FDO_DEVICE_STATE_READYN = 6, // Transfer Ready
	FDO_DEVICE_STATE_DN = 7      // Transfer Disabled
} fdo_sdk_device_status;

fdo_hash_t *fdo_pub_key_hash(fdo_public_key_t *pub_key);

// 3.4.1, Device Credential sub-values
typedef struct _fdo_credowner_t {
	int pv; // The protocol version (DCProtVer)
	fdo_byte_array_t *guid;       // Initial GUID (DCGuid)
	fdo_rendezvous_list_t *rvlst; // RendezvousInfo (DCRVInfo)
	fdo_hash_t *pkh;	      // Hash of the group public key (DCPubKeyHash)
	fdo_public_key_t *pk;
} fdo_cred_owner_t;

// 3.4.1, Device Credential sub-values
typedef struct _fdo_cred_mfg_block_t {
	fdo_string_t *d;  // Manufacturer's Device info (DCDeviceInfo)
} fdo_cred_mfg_t;

// 3.4.1, Device Credential
typedef struct _fdo_device_credentials_t {
	fdo_sdk_device_status ST;
	bool dc_active;
	fdo_cred_mfg_t *mfg_blk;
	fdo_cred_owner_t *owner_blk;
} fdo_dev_cred_t;

fdo_dev_cred_t *fdo_dev_cred_alloc(void);
void fdo_dev_cred_init(fdo_dev_cred_t *dev_cred);
void fdo_dev_cred_free(fdo_dev_cred_t *dev_cred);
bool fdo_device_credential_read(fdor_t *fdor, fdo_dev_cred_t *our_dev_cred);
bool fdo_device_credential_write(fdow_t *fdow, fdo_dev_cred_t *our_dev_cred);

fdo_cred_owner_t *fdo_cred_owner_alloc(void);
void fdo_cred_owner_free(fdo_cred_owner_t *ocred);

fdo_cred_mfg_t *fdo_cred_mfg_alloc(void);
void fdo_cred_mfg_free(fdo_cred_mfg_t *ocred_mfg);

// 3.4.2, OVEntryPayload
typedef struct _fdo_oventry_t {
	struct _fdo_oventry_t *next;
	uint16_t enn;
	fdo_hash_t *hp_hash;	// Hash of previous entry (OVEHashPrevEntry)
	fdo_hash_t *hc_hash;	// Hash of header info (OVEHashHdrInfo)
	fdo_byte_array_t *ove_extra; // (OVEExtra)
	fdo_public_key_t *pk;	// public key (OVEPubKey)
} fdo_ov_entry_t;

fdo_ov_entry_t *fdo_ov_entry_alloc_empty(void);
fdo_ov_entry_t *fdo_ov_entry_free(fdo_ov_entry_t *e);
bool fdo_ov_entry_add(fdo_ov_entry_t *root_entry, fdo_ov_entry_t *e);

// 5.5.7, Replacement info supplied by the Owner in TO2.SetupDevice, Type 65
typedef struct FDOOwner_supplied_credentials_s {
	fdo_rendezvous_list_t *rvlst;	// replacement RendezvousInfo
	fdo_byte_array_t *guid;	// replacement GUID
	fdo_public_key_t *pubkey;	// replacement PublicKey
} fdo_owner_supplied_credentials_t;

fdo_owner_supplied_credentials_t *fdo_owner_supplied_credentials_alloc(void);
void fdo_owner_supplied_credentials_free(fdo_owner_supplied_credentials_t *ocs);

// 3.4.2 OwnershipVoucher
typedef struct _fdo_ownershipvoucher_t {
	int prot_version;	// OVHeader.OVHProtVer
	fdo_byte_array_t *g2;	// OVHeader.OVGuid
	fdo_rendezvous_list_t *rvlst2;	// OVHeader.OVRVInfo
	fdo_string_t *dev_info;	// OVHeader.OVDeviceInfo
	fdo_public_key_t *mfg_pub_key;	// OVHeader.OVPubKey
	fdo_hash_t *ovoucher_hdr_hash;	// OVHeaderHMac
	int num_ov_entries;	// num of OVEntries
	fdo_ov_entry_t *ov_entries;	// OVEntries
	fdo_hash_t *hdc;	// used for both OVDevCertChain and OVDevCertChainHash
} fdo_ownership_voucher_t;

fdo_ownership_voucher_t *fdo_ov_alloc(void);
void fdo_ov_free(fdo_ownership_voucher_t *ov);
void fdo_ov_print(fdo_ownership_voucher_t *ov);
fdo_ownership_voucher_t *fdo_ov_hdr_read(fdo_byte_array_t *ovheader);
bool fdo_ov_hdr_cse_load_hmac(fdo_byte_array_t *ovheader, fdo_hash_t **hmac);
bool fdo_ov_hdr_hmac(fdo_byte_array_t *ovheader, fdo_hash_t **hmac);
fdo_hash_t *fdo_new_ov_hdr_sign(fdo_dev_cred_t *dev_cred,
			fdo_owner_supplied_credentials_t *osc, fdo_hash_t *hdc);
bool fdo_ove_hash_prev_entry_save(fdow_t *fdow, fdo_ownership_voucher_t *ov,
	fdo_hash_t *hmac);
bool fdo_ove_hash_hdr_info_save(fdo_ownership_voucher_t *ov);
bool fdo_ovheader_write(fdow_t *fdow, int protver, fdo_byte_array_t *guid,
	fdo_rendezvous_list_t *rvlst, fdo_string_t *dev_info,
	fdo_public_key_t *pubkey, fdo_hash_t *hdc);

#endif /* __FDOCRED_H__ */
