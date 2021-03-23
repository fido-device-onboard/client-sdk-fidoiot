/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDOCRED_H__
#define __SDOCRED_H__

#include "sdotypes.h"

sdo_hash_t *sdo_pub_key_hash(sdo_public_key_t *pub_key);

// 3.4.1, Device Credential sub-values
typedef struct _sdo_credowner_t {
	int pv; // The protocol version (DCProtVer)
	sdo_byte_array_t *guid;       // Initial GUID (DCGuid)
	sdo_rendezvous_list_t *rvlst; // RendezvousInfo (DCRVInfo)
	sdo_hash_t *pkh;	      // Hash of the group public key (DCPubKeyHash)
	sdo_public_key_t *pk;
} sdo_cred_owner_t;

// 3.4.1, Device Credential sub-values
typedef struct _sdo_cred_mfg_block_t {
	sdo_string_t *d;  // Manufacturer's Device info (DCDeviceInfo)
} sdo_cred_mfg_t;

// 3.4.1, Device Credential
typedef struct _sdo_device_credentials_t {
	int ST;
	bool dc_active;
	sdo_cred_mfg_t *mfg_blk;
	sdo_cred_owner_t *owner_blk;
} sdo_dev_cred_t;

sdo_dev_cred_t *sdo_dev_cred_alloc(void);
void sdo_dev_cred_init(sdo_dev_cred_t *dev_cred);
void sdo_dev_cred_free(sdo_dev_cred_t *dev_cred);
bool sdo_device_credential_read(sdor_t *sdor, sdo_dev_cred_t *our_dev_cred);
bool sdo_device_credential_write(sdow_t *sdow, sdo_dev_cred_t *our_dev_cred);

sdo_cred_owner_t *sdo_cred_owner_alloc(void);
void sdo_cred_owner_free(sdo_cred_owner_t *ocred);

sdo_cred_mfg_t *sdo_cred_mfg_alloc(void);
void sdo_cred_mfg_free(sdo_cred_mfg_t *ocred_mfg);

// 3.4.2, OVEntryPayload
typedef struct _sdo_oventry_t {
	struct _sdo_oventry_t *next;
	uint16_t enn;
	sdo_hash_t *hp_hash;	// Hash of previous entry (OVEHashPrevEntry)
	sdo_hash_t *hc_hash;	// Hash of header info (OVEHashHdrInfo)
	sdo_public_key_t *pk;	// public key (OVEPubKey)
} sdo_ov_entry_t;

sdo_ov_entry_t *sdo_ov_entry_alloc_empty(void);
sdo_ov_entry_t *sdo_ov_entry_free(sdo_ov_entry_t *e);
bool sdo_ov_entry_add(sdo_ov_entry_t *root_entry, sdo_ov_entry_t *e);

#define SDO_DEV_INFO_SZ 512 // max size of dev info we handle

// 5.5.7, Replacement info supplied by the Owner in TO2.SetupDevice, Type 65
typedef struct SDOOwner_supplied_credentials_s {
	sdo_rendezvous_list_t *rvlst;	// replacement RendezvousInfo
	sdo_byte_array_t *guid;	// replacement GUID
	sdo_public_key_t *pubkey;	// replacement PublicKey
	sdo_service_info_t *si;
} sdo_owner_supplied_credentials_t;

sdo_owner_supplied_credentials_t *sdo_owner_supplied_credentials_alloc(void);
void sdo_owner_supplied_credentials_free(sdo_owner_supplied_credentials_t *ocs);

// 3.4.2 OwnershipVoucher
typedef struct _sdo_ownershipvoucher_t {
	int prot_version;	// OVHeader.OVProtVer
	sdo_byte_array_t *g2;	// OVHeader.OVGuid
	sdo_rendezvous_list_t *rvlst2;	// OVHeader.OVRVInfo
	sdo_string_t *dev_info;	// OVHeader.OVDeviceInfo
	sdo_public_key_t *mfg_pub_key;	// OVHeader.OVPubKey
	sdo_hash_t *ovoucher_hdr_hash;	// OVHeaderHMac
	int num_ov_entries;	// num of OVEntries
	sdo_ov_entry_t *ov_entries;	// OVEntries
	sdo_hash_t *hdc;	// used for both OVDevCertChain and OVDevCertChainHash
} sdo_ownership_voucher_t;

sdo_ownership_voucher_t *sdo_ov_alloc(void);
void sdo_ov_free(sdo_ownership_voucher_t *ov);
void sdo_ov_print(sdo_ownership_voucher_t *ov);
sdo_ownership_voucher_t *sdo_ov_hdr_read(sdor_t *sdor, sdo_hash_t **hmac);
bool sdo_ov_hdr_hmac(sdo_ownership_voucher_t *ov, sdo_hash_t **hmac);
sdo_hash_t *sdo_new_ov_hdr_sign(sdo_dev_cred_t *dev_cred,
			sdo_owner_supplied_credentials_t *osc, sdo_hash_t *hdc);
bool fdo_ove_hash_prev_entry_save(sdow_t *sdow, sdo_ownership_voucher_t *ov,
	sdo_hash_t *hmac);
bool fdo_ove_hash_hdr_info_save(sdo_ownership_voucher_t *ov);
bool fdo_ovheader_write(sdow_t *sdow, int protver, sdo_byte_array_t *guid,
	sdo_rendezvous_list_t *rvlst, sdo_string_t *dev_info,
	sdo_public_key_t *pubkey, sdo_hash_t *hdc);

void sdo_iv_free(sdo_iv_t *iv);

#endif /* __SDOCRED_H__ */
