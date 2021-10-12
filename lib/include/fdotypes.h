/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __FDOTYPES_H__
#define __FDOTYPES_H__

#include "fdo.h"
#include "fdoblockio.h"
#include "fdomodules.h"
#include <stddef.h>

/*
 * Wrapper around a URL
 * Just a string for now.
 */
typedef char *fdourl_t;

// Generic bit holder
typedef struct {
	size_t byte_sz;
	uint8_t *bytes;
} fdo_bits_t;

fdo_bits_t *fdo_bits_init(fdo_bits_t *b, size_t byte_sz);
fdo_bits_t *fdo_bits_alloc(size_t byte_sz);
fdo_bits_t *fdo_bits_alloc_with(size_t byte_sz, uint8_t *data);
void fdo_bits_free(fdo_bits_t *b);
void fdo_bits_empty(fdo_bits_t *b);
fdo_bits_t *fdo_bits_clone(fdo_bits_t *b);
bool fdo_bits_resize(fdo_bits_t *b, int byte_sz);
bool fdo_bits_fill(fdo_bits_t **b);
bool fdo_bits_fill_with(fdo_bits_t *b, uint8_t *data, uint32_t data_len);
bool fdo_bits_resize_with(fdo_bits_t *b, int new_byte_sz, uint8_t *data);
bool fdo_bits_equal(fdo_bits_t *b1, fdo_bits_t *b2);
int fdo_bits_randomize(fdo_bits_t *b);

// Byte Array
typedef fdo_bits_t fdo_byte_array_t;

fdo_byte_array_t *fdo_byte_array_alloc(int byte_sz);
fdo_byte_array_t *fdo_byte_array_alloc_with_int(int val);
fdo_byte_array_t *fdo_byte_array_alloc_with_byte_array(uint8_t *ba, int ba_len);
void fdo_byte_array_free(fdo_byte_array_t *ba);
bool fdo_byte_array_resize(fdo_byte_array_t *b, int byte_sz);
fdo_byte_array_t *fdo_byte_array_append(fdo_byte_array_t *baA,
					fdo_byte_array_t *baB);
fdo_byte_array_t *fdo_byte_array_clone(fdo_byte_array_t *ba);

// Generic string holder
typedef struct {
	int byte_sz;
	char *bytes;
} fdo_string_t;

void fdo_string_init(fdo_string_t *b);
fdo_string_t *fdo_string_alloc(void);
fdo_string_t *fdo_string_alloc_size(size_t byte_sz);
fdo_string_t *fdo_string_alloc_with(const char *data, int byte_sz);
fdo_string_t *fdo_string_alloc_with_str(const char *data);
void fdo_string_free(fdo_string_t *b);
bool fdo_string_resize(fdo_string_t *b, int byte_sz);
bool fdo_string_resize_with(fdo_string_t *b, int new_byte_sz, const char *data);

#define FDO_GUID_BYTES (128 / 8)
#define FDO_NONCE_BYTES (128 / 8)
// EAT-UEID is of length 17 (EAT-RAND(1) + EAT-GUID(16))
#define FDO_UEID_BYTES (1 + FDO_GUID_BYTES)

/*
 * GUID - 128-bit Random number used for identification.
 */
typedef uint8_t fdo_guid_t[FDO_GUID_BYTES];

char *fdo_guid_to_string(fdo_byte_array_t *g, char *buf, int buf_sz);

/*
 * nonce - 128-bit Random number, intended to be used naught but once.
 */
typedef uint8_t fdo_nonce_t[FDO_NONCE_BYTES];
typedef uint8_t fdo_ueid_t[FDO_UEID_BYTES];

/* Nonce  */
void fdo_nonce_init_rand(fdo_byte_array_t *n);
char *fdo_nonce_to_string(uint8_t *n, char *buf, int buf_sz);
bool fdo_nonce_equal(fdo_byte_array_t *n1, fdo_byte_array_t *n2);

typedef struct _fdo_hash_t {
	int hash_type;
	fdo_byte_array_t *hash;
} fdo_hash_t;

/*GID*/
bool fdo_siginfo_write(fdow_t *fdow);

// 3.3.2, hashtype as defined in FDO spec
#define FDO_CRYPTO_HASH_TYPE_SHA_256 -16
#define FDO_CRYPTO_HASH_TYPE_SHA_384 -43
#define FDO_CRYPTO_HMAC_TYPE_SHA_256 5
#define FDO_CRYPTO_HMAC_TYPE_SHA_384 6

// Legacy value, Currently used to represent an empty hash type for now
#define FDO_CRYPTO_HASH_TYPE_NONE 0

#ifdef ECDSA256_DA
#define FDO_CRYPTO_HASH_TYPE_USED FDO_CRYPTO_HASH_TYPE_SHA_256
#define FDO_CRYPTO_HMAC_TYPE_USED FDO_CRYPTO_HMAC_TYPE_SHA_256
#else
#define FDO_CRYPTO_HASH_TYPE_USED FDO_CRYPTO_HASH_TYPE_SHA_384
#define FDO_CRYPTO_HMAC_TYPE_USED FDO_CRYPTO_HMAC_TYPE_SHA_384
#endif
fdo_hash_t *fdo_hash_alloc_empty(void);
fdo_hash_t *fdo_hash_alloc(int hash_type, int size);
void fdo_hash_free(fdo_hash_t *hp);
int fdo_hash_read(fdor_t *fdor, fdo_hash_t *hp);
bool fdo_hash_write(fdow_t *fdow, fdo_hash_t *hp);

typedef fdo_byte_array_t fdo_key_exchange_t;

typedef struct {
	uint8_t length;
	uint8_t addr[16];
} fdo_ip_address_t;

fdo_ip_address_t *fdo_ipaddress_alloc(void);
bool fdo_null_ipaddress(fdo_ip_address_t *fdoip);
void fdo_init_ipv4_address(fdo_ip_address_t *fdoip, uint8_t *ipv4);
bool fdo_read_ipaddress(fdor_t *fdor, fdo_ip_address_t *fdoip);
bool fdo_convert_to_ipaddress(fdo_byte_array_t * ip_bytes, fdo_ip_address_t *fdoip);
char *fdo_ipaddress_to_string(fdo_ip_address_t *fdoip, char *buf, int buf_sz);

typedef struct {
	uint16_t length;
	char *name;
} fdo_dns_name_t;

// 3.3.4, PublicKey types (pkType)
#define FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256 -7
#define FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384 -35

// 3.3.5 COSECompatibleSignatureTypes
#define FDO_CRYPTO_SIG_TYPE_ECSDAp256 -7
#define FDO_CRYPTO_SIG_TYPE_ECSDAp384 -35

#define FDO_COSE_ALG_KEY 1

#define FDO_COSE_ENCRYPT0_AESPLAINTYPE_KEY 1
#define FDO_COSE_ENCRYPT0_AESIV_KEY 5

// Appendix E
#define FDO_EATFDO -17760707
#define FDO_EAT_MAROE_PREFIX_KEY -17760708
#define FDO_EAT_EUPHNONCE_KEY -17760709
#define FDO_EATNONCE_KEY 10
#define FDO_EATUEID_KEY 11

#define FDO_COSE_SIGN1_CUPHNONCE_KEY -17760701
#define FDO_COSE_SIGN1_CUPHOWNERPUBKEY_KEY -17760702

// AES GCM/CCM algotithm values from COSE specification, RFC 8152
#define FDO_CRYPTO_A128GCM 1
#define FDO_CRYPTO_A256GCM 3
#define FDO_CRYPTO_A128CCM 32
#define FDO_CRYPTO_A256CCM 33

// 3.3.4 PublicKey encodings (pkEnc)
#define FDO_CRYPTO_PUB_KEY_ENCODING_X509 1
#define FDO_CRYPTO_PUB_KEY_ENCODING_COSEX509 2

typedef struct {
	int pkalg;
	int pkenc;
	fdo_byte_array_t *key1; // in RSA, the Modulus/ binary for DSA
	fdo_byte_array_t *key2; // In RSA, the Exponent
} fdo_public_key_t;

typedef struct {
	int sig_type; /* Used to differentiate between epid and ecdsa in
			 EBread*/
	fdo_public_key_t *pubkey;
} fdo_sig_info_t;

bool fdo_siginfo_read(fdor_t *fdor);

fdo_public_key_t *fdo_public_key_alloc_empty(void);
fdo_public_key_t *fdo_public_key_alloc(int pkalg, int pkenc, int pklen,
				       uint8_t *pkey);
void fdo_public_key_free(fdo_public_key_t *pk);
bool fdo_public_key_write(fdow_t *fdow, fdo_public_key_t *pk);
fdo_public_key_t *fdo_public_key_read(fdor_t *fdor);
fdo_public_key_t *fdo_public_key_clone(fdo_public_key_t *pk);

#if defined(AES_MODE_GCM_ENABLED)
#define AES_GCM_IV_LEN 12
#define AES_IV_LEN AES_GCM_IV_LEN
#define AES_GCM_TAG_LEN 16
#define AES_TAG_LEN AES_GCM_TAG_LEN
#else
// The IV/Nonce length 'N' for CCM mode is dependent on the maximum message length 'L' value
// and should be equal to 15-L (in octets).
// Refer to [RFC3610](https://datatracker.ietf.org/doc/html/rfc3610) for more information on
// trade-offs between 'L' and 'N' value.
// The current implementation uses L=8, and hence the IV/Nonce length N = 15-8 = 7 octets
// As per FDO and COSE [RFC8152](https://datatracker.ietf.org/doc/html/rfc8152) specifications,
// L=2 could also be used. N=13 MUST be used in this case.
#define AES_CCM_IV_LEN 7
#define AES_IV_LEN AES_CCM_IV_LEN
#define AES_CCM_TAG_LEN 16
#define AES_TAG_LEN AES_CCM_TAG_LEN
#endif

typedef struct {
	uint8_t nulls_added;
	fdo_byte_array_t *ct_string;
	fdo_byte_array_t *em_body; // Ciphertext of Encrypted Message Body
	uint8_t tag[AES_TAG_LEN];
	fdo_hash_t *hmac;	  // HMAC of ct body
	uint8_t iv[AES_IV_LEN];	// iv of gcm/ccm.
	uint32_t offset;
	int aes_plain_type;
} fdo_encrypted_packet_t;

fdo_encrypted_packet_t *fdo_encrypted_packet_alloc(void);
void fdo_encrypted_packet_free(fdo_encrypted_packet_t *pkt);
fdo_encrypted_packet_t *fdo_encrypted_packet_read(fdor_t *fdor);
bool fdo_aad_write(fdow_t *fdow, int alg_type);
bool fdo_emblock_write(fdow_t *fdow, fdo_encrypted_packet_t *pkt);
bool fdo_etminnerblock_write(fdow_t *fdow, fdo_encrypted_packet_t *pkt);
bool fdo_etmouterblock_write(fdow_t *fdow, fdo_encrypted_packet_t *pkt);
bool fdo_encrypted_packet_unwind(fdor_t *fdor, fdo_encrypted_packet_t *pkt);
bool fdo_encrypted_packet_windup(fdow_t *fdow, int type);
bool fdo_prep_simple_encrypted_message(fdo_encrypted_packet_t *pkt,
	fdow_t *fdow, size_t fdow_buff_default_sz);
bool fdo_prep_composed_encrypted_message(fdo_encrypted_packet_t *pkt,
	fdow_t *fdow, size_t fdow_buff_default_sz);

typedef struct {
	int aes_plain_type;
} fdo_cose_encrypt0_protected_header_t;

typedef struct {
	uint8_t aes_iv[AES_IV_LEN];
} fdo_cose_encrypt0_unprotected_header_t;

typedef struct {
	fdo_cose_encrypt0_protected_header_t *protected_header;
	fdo_cose_encrypt0_unprotected_header_t *unprotected_header;
	fdo_byte_array_t *payload;
} fdo_cose_encrypt0_t;

void fdo_cose_encrypt0_free(fdo_cose_encrypt0_t *cose_encrypt0);
fdo_cose_encrypt0_t* fdo_cose_encrypt0_alloc(void);
bool fdo_cose_encrypt0_read_protected_header(fdor_t *fdor,
	fdo_cose_encrypt0_protected_header_t *protected_header);
bool fdo_cose_encrypt0_read_unprotected_header(fdor_t *fdor,
	fdo_cose_encrypt0_unprotected_header_t *unprotected_header);
bool fdo_cose_encrypt0_read(fdor_t *fdor, fdo_cose_encrypt0_t *cose_encrypt0);
bool fdo_cose_encrypt0_write_protected_header(fdow_t *fdow,
	fdo_cose_encrypt0_protected_header_t *protected_header);
bool fdo_cose_encrypt0_write_unprotected_header(fdow_t *fdow,
	fdo_cose_encrypt0_unprotected_header_t *unprotected_header);
bool fdo_cose_encrypt0_write(fdow_t *fdow, fdo_cose_encrypt0_t *cose_encrypt0);

typedef struct {
	int ph_sig_alg;
} fdo_eat_protected_header_t;

typedef struct {
	fdo_byte_array_t *eatmaroeprefix;
	fdo_byte_array_t *euphnonce;
} fdo_eat_unprotected_header_t;

typedef struct {
	fdo_eat_protected_header_t *eat_ph;
	fdo_eat_unprotected_header_t *eat_uph;
	fdo_byte_array_t *eat_payload;
	fdo_byte_array_t *eat_signature;
} fdo_eat_t;

// methods to handle Entity Attestation Token (EAT).
fdo_eat_t* fdo_eat_alloc(void);
void fdo_eat_free(fdo_eat_t *eat);
bool fdo_eat_write_protected_header(fdow_t *fdow, fdo_eat_protected_header_t *eat_ph);
bool fdo_eat_write_unprotected_header(fdow_t *fdow, fdo_eat_unprotected_header_t *eat_uph);
bool fdo_eat_write(fdow_t *fdow, fdo_eat_t *eat);
bool fdo_eat_write_sigstructure(fdo_eat_protected_header_t *eat_ph,
	fdo_byte_array_t *eat_payload, fdo_byte_array_t *external_aad,
	fdo_byte_array_t **sig_structure);

typedef struct {
	fdo_byte_array_t *eatpayloads;
	fdo_nonce_t eatnonce;
	fdo_ueid_t eatueid;
	// EATOtherClaims: Unused in  implementation. Should be added depending on the requirement.
} fdo_eat_payload_base_map_t;

bool fdo_eat_write_payloadbasemap(fdow_t *fdow, fdo_eat_payload_base_map_t *eat_payload);

typedef struct {
	int ph_sig_alg;
} fdo_cose_protected_header_t;

typedef struct {
	fdo_nonce_t cuphnonce;
	fdo_public_key_t *cuphowner_public_key;
} fdo_cose_unprotected_header_t;

typedef struct {
	fdo_cose_protected_header_t *cose_ph;
	fdo_cose_unprotected_header_t *cose_uph;
	fdo_byte_array_t *cose_payload;
	fdo_byte_array_t *cose_signature;
} fdo_cose_t;

void fdo_cose_free(fdo_cose_t *cose);
bool fdo_cose_read_protected_header(fdor_t *fdor, fdo_cose_protected_header_t *cose_ph);
bool fdo_cose_read_unprotected_header(fdor_t *fdor, fdo_cose_unprotected_header_t *cose_uph);
bool fdo_cose_read(fdor_t *fdor, fdo_cose_t *cose, bool empty_uph);
bool fdo_cose_write_protected_header(fdow_t *fdow, fdo_cose_protected_header_t *cose_ph);
bool fdo_cose_write_unprotected_header(fdow_t *fdow);
bool fdo_cose_write(fdow_t *fdow, fdo_cose_t *cose);
bool fdo_cose_write_sigstructure(fdo_cose_protected_header_t *cose_ph,
	fdo_byte_array_t *cose_payload, fdo_byte_array_t *external_aad,
	fdo_byte_array_t **sig_structure);

/*
 * This is a lookup on all possible TransportProtocol values (Section 3.3.12)
 */
#define PROTTCP 1
#define PROTTLS 2
#define PROTHTTP 3
#define PROTCOAP 4
#define PROTHTTPS 5
#define PROTCOAPS 6

typedef struct fdo_rvto2addr_entry_s {
	fdo_byte_array_t *rvip;
	fdo_string_t *rvdns;
	int rvport;
	int rvprotocol;
	struct fdo_rvto2addr_entry_s *next;
} fdo_rvto2addr_entry_t;

typedef struct {
	int num_rvto2addr;
	fdo_rvto2addr_entry_t *rv_to2addr_entry;
} fdo_rvto2addr_t;

void fdo_rvto2addr_entry_free(fdo_rvto2addr_entry_t *rvto2addr_entry);
void fdo_rvto2addr_free(fdo_rvto2addr_t *rvto2addr);
bool fdo_rvto2addr_entry_read(fdor_t *fdor, fdo_rvto2addr_entry_t *rvto2addr_entry);
bool fdo_rvto2addr_read(fdor_t *fdor, fdo_rvto2addr_t *rvto2addr);

typedef struct fdo_key_value_s {
	struct fdo_key_value_s *next;
	fdo_string_t *key;
	fdo_string_t *str_val;
	fdo_byte_array_t *bin_val;
	int *int_val;
	bool *bool_val;
} fdo_key_value_t;

fdo_key_value_t *fdo_kv_alloc(void);
fdo_key_value_t *fdo_kv_alloc_with_array(const char *key,
					 fdo_byte_array_t *val);
fdo_key_value_t *fdo_kv_alloc_with_str(const char *key, const char *val);
fdo_key_value_t *fdo_kv_alloc_key_only(const char *key);
void fdo_kv_free(fdo_key_value_t *kv);

/*
 * This is a lookup on all possible RVVariable
 */
#define BADKEY -1
#define RVDEVONLY 0
#define RVOWNERONLY 1
#define RVIPADDRESS 2
#define RVDEVPORT 3
#define RVOWNERPORT 4
#define RVDNS 5
#define RVSVCERTHASH 6
#define RVCLCERTHASH 7
#define RVUSERINPUT 8
#define RVWIFISSID 9
#define RVWIFIPW 10
#define RVMEDIUM 11
#define RVPROTOCOL 12
#define RVDELAYSEC 13
#define RVBYPASS 14
#define RVEXTRV 15

/*
 * This is a lookup on all possible RVProtocolValue (RVVariable 12)
 */
#define RVPROTREST 0
#define RVPROTHTTP 1
#define RVPROTHTTPS 2
#define RVPROTTCP 3
#define RVPROTTLS 4
#define RVPROTCOAPTCP 5
#define RVPROTCOAPUDP 6

typedef struct fdo_rendezvous_s {
	int num_params;
	struct fdo_rendezvous_s *next;
	bool *dev_only;
	bool *owner_only;
	fdo_ip_address_t *ip;
	int *po;
	int *pow;
	fdo_string_t *dn;
	fdo_hash_t *sch;
	fdo_hash_t *cch;
	bool *ui;
	fdo_string_t *ss;
	fdo_string_t *pw;
	fdo_string_t *wsp;
	uint64_t *me;
	uint64_t *pr;
	uint64_t *delaysec;
	bool *bypass;
} fdo_rendezvous_t;

fdo_rendezvous_t *fdo_rendezvous_alloc(void);
void fdo_rendezvous_free(fdo_rendezvous_t *rv);
bool fdo_rendezvous_read(fdor_t *fdor, fdo_rendezvous_t *rv);
bool fdo_rendezvous_write(fdow_t *fdow, fdo_rendezvous_t *rv);

typedef struct fdo_rendezvous_directive_s {
	uint16_t num_entries;
	struct fdo_rendezvous_directive_s *next;
	fdo_rendezvous_t *rv_entries;
} fdo_rendezvous_directive_t;

typedef struct fdo_rendezvous_list_s {
	uint16_t num_rv_directives;
	fdo_rendezvous_directive_t *rv_directives;
} fdo_rendezvous_list_t;

int fdo_rendezvous_directive_add(fdo_rendezvous_list_t *list,
	fdo_rendezvous_directive_t *directive);
fdo_rendezvous_directive_t *fdo_rendezvous_directive_get(
	fdo_rendezvous_list_t *list, int num);
fdo_rendezvous_list_t *fdo_rendezvous_list_alloc(void);
void fdo_rendezvous_list_free(fdo_rendezvous_list_t *list);
int fdo_rendezvous_list_add(fdo_rendezvous_directive_t *list, fdo_rendezvous_t *rv);
fdo_rendezvous_t *fdo_rendezvous_list_get(fdo_rendezvous_directive_t *list, int num);
int fdo_rendezvous_list_read(fdor_t *fdor, fdo_rendezvous_list_t *list);
bool fdo_rendezvous_list_write(fdow_t *fdow, fdo_rendezvous_list_t *list);

// List containing string of fixed length (FDO_MODULE_NAME_LEN)
typedef struct fdo_sv_invalid_modnames_s {
	char bytes[FDO_MODULE_NAME_LEN];
	struct fdo_sv_invalid_modnames_s *next;
} fdo_sv_invalid_modnames_t;

typedef struct fdo_service_info_s {
	size_t numKV;
	fdo_key_value_t *kv;
	size_t sv_index_end;
	size_t sv_index_begin;
	size_t sv_val_index;
} fdo_service_info_t;

fdo_service_info_t *fdo_service_info_alloc(void);
void fdo_service_info_free(fdo_service_info_t *si);
fdo_key_value_t **fdo_service_info_fetch(fdo_service_info_t *si,
					 const char *key);
fdo_key_value_t **fdo_service_info_get(fdo_service_info_t *si, int key_num);
bool fdo_service_info_add_kv_str(fdo_service_info_t *si, const char *key,
				 const char *val);
bool fdo_service_info_add_kv_bin(fdo_service_info_t *si, const char *key,
				 const fdo_byte_array_t *val);
bool fdo_service_info_add_kv_bool(fdo_service_info_t *si, const char *key,
				 bool val);
bool fdo_service_info_add_kv_int(fdo_service_info_t *si, const char *key,
				 int val);
bool fdo_service_info_add_kv(fdo_service_info_t *si, fdo_key_value_t *kv);
bool fdo_signature_verification(fdo_byte_array_t *plain_text,
				fdo_byte_array_t *sg, fdo_public_key_t *pk);

bool fdo_compare_public_keys(fdo_public_key_t *pk1, fdo_public_key_t *pk2);

/*==================================================================*/
/* Service Info functionality */

/* Module list */
typedef struct fdo_sdk_service_info_module_list_s {
	fdo_sdk_service_info_module module;
	int module_psi_index;
	int module_dsi_count;
	int module_osi_index;
	struct fdo_sdk_service_info_module_list_s
	    *next; // ptr to next module node
} fdo_sdk_service_info_module_list_t;

typedef struct fdo_sv_info_dsi_info_s {
	fdo_sdk_service_info_module_list_t *list_dsi;
	int module_dsi_index;
} fdo_sv_info_dsi_info_t;

/* exposed API for modules to register */
void fdo_sdk_service_info_register_module(fdo_sdk_service_info_module *module);
void fdo_sdk_service_info_deregister_module(void);
void print_service_info_module_list(void);

bool fdo_serviceinfo_write(fdow_t *fdow, fdo_service_info_t *si);
bool fdo_serviceinfo_kv_write(fdow_t *fdow, fdo_service_info_t *si, size_t num);
bool fdo_serviceinfo_modules_list_write(fdow_t *fdow);
bool fdo_serviceinfo_external_mod_is_more(fdow_t *fdow,
	fdo_sdk_service_info_module_list_t *module_list, size_t mtu, bool *is_more);
fdo_sdk_service_info_module* fdo_serviceinfo_get_external_mod_to_write(fdow_t *fdow,
	fdo_sdk_service_info_module_list_t *module_list,
	size_t mtu);
bool fdo_serviceinfo_external_mod_write(fdow_t *fdow, fdo_sdk_service_info_module *module,
	size_t mtu);
bool fdo_serviceinfo_fit_mtu(fdow_t *fdow, fdo_service_info_t *si, size_t mtu);

bool fdo_mod_exec_sv_infotype(fdo_sdk_service_info_module_list_t *module_list,
			      fdo_sdk_si_type type);

void fdo_sv_info_clear_module_psi_osi_index(
    fdo_sdk_service_info_module_list_t *module_list);

bool fdo_serviceinfo_read(fdor_t *fdor, fdo_sdk_service_info_module_list_t *module_list,
	int *cb_return_val, fdo_sv_invalid_modnames_t **serviceinfo_invalid_modnames);
bool fdo_supply_serviceinfoval(fdor_t *fdor, char *module_name, char *module_message,
	fdo_sdk_service_info_module_list_t *module_list, int *cb_return_val);
bool fdo_serviceinfo_invalid_modname_add(char *module_name,
	fdo_sv_invalid_modnames_t **serviceinfo_invalid_modnames);
void fdo_serviceinfo_invalid_modname_free(
	fdo_sv_invalid_modnames_t *serviceinfo_invalid_modnames);
bool fdo_serviceinfo_deactivate_modules(fdo_sdk_service_info_module_list_t *module_list);

bool fdo_compare_hashes(fdo_hash_t *hash1, fdo_hash_t *hash2);
bool fdo_compare_byte_arrays(fdo_byte_array_t *ba1, fdo_byte_array_t *ba2);
bool fdo_compare_rv_lists(fdo_rendezvous_list_t *rv_list1,
			  fdo_rendezvous_list_t *rv_list2);
bool fdo_rendezvous_instr_compare(fdo_rendezvous_t *entry1,
	fdo_rendezvous_t *entry2);

void fdo_log_block(fdo_block_t *fdob);

#endif /* __FDOTYPES_H__ */
