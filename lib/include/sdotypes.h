/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDOTYPES_H__
#define __SDOTYPES_H__

#include "sdo.h"
#include "sdoblockio.h"
#include "sdomodules.h"
#include <stddef.h>

/*
 * Wrapper around a URL
 * Just a string for now.
 */
typedef char *sdourl_t;

// Generic bit holder
typedef struct {
	size_t byte_sz;
	uint8_t *bytes;
} sdo_bits_t;

sdo_bits_t *sdo_bits_init(sdo_bits_t *b, int byte_sz);
sdo_bits_t *sdo_bits_alloc(int byte_sz);
sdo_bits_t *sdo_bits_alloc_with(int byte_sz, uint8_t *data);
void sdo_bits_free(sdo_bits_t *b);
void sdo_bits_empty(sdo_bits_t *b);
sdo_bits_t *sdo_bits_clone(sdo_bits_t *b);
bool sdo_bits_resize(sdo_bits_t *b, int byte_sz);
bool sdo_bits_fill(sdo_bits_t **b);
bool sdo_bits_fill_with(sdo_bits_t *b, uint8_t *data, uint32_t data_len);
bool sdo_bits_resize_with(sdo_bits_t *b, int new_byte_sz, uint8_t *data);
bool sdo_bits_equal(sdo_bits_t *b1, sdo_bits_t *b2);
int sdo_bits_randomize(sdo_bits_t *b);
char *sdo_bits_to_string(sdo_bits_t *b, const char *typname, char *buf,
			 int buf_sz);
char *sdo_bits_to_string_hex(sdo_bits_t *b, char *buf, int buf_sz);

#if 0
void sdo_bits_write(sdow_t *sdow, sdo_bits_t *b);
bool sdo_bits_read(sdor_t *sdor, sdo_bits_t *b);
#endif

// Byte Array
typedef sdo_bits_t sdo_byte_array_t;

#if 0
sdo_byte_array_t *sdo_byte_array_init(sdo_byte_array_t *bn, int byte_sz);
#endif
sdo_byte_array_t *sdo_byte_array_alloc(int byte_sz);
sdo_byte_array_t *sdo_byte_array_alloc_with_int(int val);
sdo_byte_array_t *sdo_byte_array_alloc_with_byte_array(uint8_t *ba, int ba_len);
void sdo_byte_array_free(sdo_byte_array_t *ba);
#if 0
void sdo_byte_array_empty(sdo_byte_array_t *ba);
#endif
bool sdo_byte_array_resize(sdo_byte_array_t *b, int byte_sz);
#if 0
bool sdo_byte_array_resize_with(sdo_byte_array_t *b, int new_byte_sz, uint8_t *data);
#endif
sdo_byte_array_t *sdo_byte_array_append(sdo_byte_array_t *baA,
					sdo_byte_array_t *baB);
sdo_byte_array_t *sdo_byte_array_clone(sdo_byte_array_t *ba);
bool sdo_byte_array_equal(sdo_byte_array_t *ba1, sdo_byte_array_t *ba2);
char *sdo_byte_array_to_string(sdo_byte_array_t *g, char *buf, int buf_sz);
int sdo_byte_array_read(sdor_t *sdor, sdo_byte_array_t *ba);
int sdo_byte_array_read_chars(sdor_t *sdor, sdo_byte_array_t *ba);
int sdo_byte_array_read_with_type(sdor_t *sdor, sdo_byte_array_t *ba,
				  sdo_byte_array_t **ct_string,
				  uint8_t *iv_data);
void sdo_byte_array_write(sdow_t *sdow, sdo_byte_array_t *ba);
void sdo_byte_array_write_chars(sdow_t *sdow, sdo_byte_array_t *ba);

// Bignum

typedef struct {
	bool sign;
	sdo_bits_t *value;
} sdo_bignum_t;

#define BN_POSITIVE true
#define BN_NEGATIVE false

sdo_bignum_t *sdo_big_num_alloc(void);
void sdo_big_num_free(sdo_bignum_t *bn);
bool sdo_bignum_equal(sdo_bignum_t *bn1, sdo_bignum_t *bn2);
char *sdo_bignum_to_string(sdo_bignum_t *g, char *buf, int buf_sz);

// Generic string holder
typedef struct {
	int byte_sz;
	char *bytes;
} sdo_string_t;

void sdo_string_init(sdo_string_t *b);
sdo_string_t *sdo_string_alloc(void);
sdo_string_t *sdo_string_alloc_with(const char *data, int byte_sz);
sdo_string_t *sdo_string_alloc_with_str(const char *data);
void sdo_string_free(sdo_string_t *b);
bool sdo_string_resize(sdo_string_t *b, int byte_sz);
bool sdo_string_resize_with(sdo_string_t *b, int new_byte_sz, const char *data);
char *sdo_string_to_string(sdo_string_t *b, char *buf, int buf_sz);
bool sdo_string_read(sdor_t *sdor, sdo_string_t *b);

#define SDO_GUID_BYTES (128 / 8)
#define SDO_GID_BYTES (128 / 8)
#define SDO_NONCE_BYTES (128 / 8)
#define SDO_NONCE_FIELD_BYTES 32
#define SDO_MSG_PRIFIX_LEN 48
#define SDO_MSG_UUID_LEN 16
#define SDO_APP_ID_BYTES 16

/*
 * GUID - 128-bit Random number used for identification.
 */
typedef uint8_t sdo_guid_t[SDO_GUID_BYTES];
/*
 * nonce - 128-bit Random number, intended to be used naught but once.
 */
typedef uint8_t sdo_nonce_t[SDO_NONCE_BYTES];

/* GUID */
char *sdo_guid_to_string(sdo_byte_array_t *g, char *buf, int buf_sz);

/* Nonce  */
void sdo_nonce_init_rand(sdo_byte_array_t *n);
char *sdo_nonce_to_string(uint8_t *n, char *buf, int buf_sz);
bool sdo_nonce_equal(sdo_byte_array_t *n1, sdo_byte_array_t *n2);

typedef struct _sdo_hash_t {
	int hash_type;
	sdo_byte_array_t *hash;
} sdo_hash_t;

/*GID*/
void sdo_gid_write(sdow_t *sdow);

/* Hash type as defined by protocol */
#define SDO_CRYPTO_HASH_TYPE_NONE 0
#define SDO_CRYPTO_HASH_TYPE_SHA_1 3
#define SDO_CRYPTO_HASH_TYPE_SHA_256 8
#define SDO_CRYPTO_HASH_TYPE_SHA_384 14
#define SDO_CRYPTO_HASH_TYPE_SHA_512 10
#define SDO_CRYPTO_HMAC_TYPE_SHA_256 108
#define SDO_CRYPTO_HMAC_TYPE_SHA_384 114
#define SDO_CRYPTO_HMAC_TYPE_SHA_512 110

#if !defined(KEX_ECDH384_ENABLED) /* TODO: do more generic */
#define SDO_CRYPTO_HASH_TYPE_USED SDO_CRYPTO_HASH_TYPE_SHA_256
#define SDO_CRYPTO_HMAC_TYPE_USED SDO_CRYPTO_HMAC_TYPE_SHA_256
#else
#define SDO_CRYPTO_HASH_TYPE_USED SDO_CRYPTO_HASH_TYPE_SHA_384
#define SDO_CRYPTO_HMAC_TYPE_USED SDO_CRYPTO_HMAC_TYPE_SHA_384
#endif
sdo_hash_t *sdo_hash_alloc_empty(void);
sdo_hash_t *sdo_hash_alloc(int hash_type, int size);
void sdo_hash_free(sdo_hash_t *hp);
int sdo_hash_read(sdor_t *sdor, sdo_hash_t *hp);
void sdo_hash_write(sdow_t *sdow, sdo_hash_t *hp);
void sdo_hash_null_write(sdow_t *sdow);
char *sdo_hash_type_to_string(int hash_type);
char *sdo_hash_to_string(sdo_hash_t *hp, char *buf, int buf_sz);

bool sdo_begin_readHMAC(sdor_t *sdor, int *sig_block_start);
bool sdo_end_readHMAC(sdor_t *sdor, sdo_hash_t **hmac, int sig_block_start);

typedef sdo_byte_array_t sdo_key_exchange_t;

typedef struct {
	uint8_t length;
	uint8_t addr[16];
} sdo_ip_address_t;

sdo_ip_address_t *sdo_ipaddress_alloc(void);
bool sdo_null_ipaddress(sdo_ip_address_t *sdoip);
void sdo_init_ipv4_address(sdo_ip_address_t *sdoip, uint8_t *ipv4);
#if 0
void sdo_init_ipv6_address(sdo_ip_address_t *sdoip, uint8_t *ipv6);
#endif
bool sdo_read_ipaddress(sdor_t *sdor, sdo_ip_address_t *sdoip);
void sdo_write_ipaddress(sdow_t *sdow, sdo_ip_address_t *sdoip);
char *sdo_ipaddress_to_string(sdo_ip_address_t *sdoip, char *buf, int buf_sz);
#if 0
int sdo_ipaddress_to_mem(sdo_ip_address_t *sdoip, uint8_t *copyto);
#endif

typedef struct {
	uint16_t length;
	char *name;
} sdo_dns_name_t;

char *sdo_read_dns(sdor_t *sdor);

#define SDO_APP_ID_TYPE_BYTES 2

void sdo_app_id_write(sdow_t *sdow);

// 4.2.1 Hash and HMAC types
#define SDO_PK_HASH_NONE 0
#define SDO_PK_HASH_SHA1 3
#define SDO_PK_HASH_SHA256 8
#define SDO_PK_HASH_SHA512 10
#define SDO_PK_HASH_SHA384 14
#define SDO_PK_HASH_HMAC_SHA256 108
#define SDO_PK_HASH_HMAC_SHA512 110
#define SDO_PK_HASH_HMAC_SHA_384 114

// 4.2.2 Public key types
#define SDO_CRYPTO_PUB_KEY_ALGO_NONE 0
#define SDO_CRYPTO_PUB_KEY_ALGO_RSA 1
#define SDO_CRYPTO_PUB_KEY_ALGO_DH 2
#define SDO_CRYPTO_PUB_KEY_ALGO_DSA 3
#define SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256 13
#define SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384 14
#define SDO_CRYPTO_PUB_KEY_ALGO_EPID_1_1 91
#define SDO_CRYPTO_PUB_KEY_ALGO_EPID_2_0 92

//#define SDO_CRYPTO_PUB_KEY_ALGO_EPID_1_1 201
//#define SDO_CRYPTO_PUB_KEY_ALGO_EPID_2_0 202

// 4.2.3 Public key encodings
#define SDO_CRYPTO_PUB_KEY_ENCODING_NONE 0
#define SDO_CRYPTO_PUB_KEY_ENCODING_X509 1
#define SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP 3
#define SDO_CRYPTO_PUB_KEY_ENCODING_EPID 4
#define SDO_EPID20 92 // should be 3
#define SDOEPID_VERSION SDO_EPID20

#define SDOEPID20_GID_LEN (16)

//#define SDO_PK_ENC_DEFAULT SDO_CRYPTO_PUB_KEY_ENCODING_X509
#define SDO_PK_ENC_DEFAULT SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP
// Define the encryption values
//#define SDOEAlgAES_ECB_No_padding 1

typedef struct {
	uint16_t len;	// Total bytes in the certificate chain
	uint8_t type;	// Format of certificate entries (1 == x509)
	uint8_t num_entries; // number of entries
	sdo_byte_array_t
	    *cert; // certs, from Device to CA, each signed by next.
} sdo_cert_chain_t;
sdo_cert_chain_t *sdo_cert_chain_alloc_empty(void);
sdo_cert_chain_t *sdo_cert_chain_read(sdor_t *sdor);

typedef struct {
	int pkalg;
	int pkenc;
	sdo_byte_array_t *key1; // in RSA, the Modulus/ binary for DSA
	sdo_byte_array_t *key2; // In RSA, the Exponent
} sdo_public_key_t;

typedef struct {
	int sig_type; /* Used to differentiate between epid and ecdsa in
			 EBread*/
	sdo_public_key_t *pubkey;
} sdo_sig_info_t;

int32_t sdo_epid_info_eb_read(sdor_t *sdor);
int32_t sdo_eb_read(sdor_t *sdor);

sdo_public_key_t *sdo_public_key_alloc_empty(void);
sdo_public_key_t *sdo_public_key_alloc(int pkalg, int pkenc, int pklen,
				       uint8_t *pkey);
void sdo_public_key_free(sdo_public_key_t *pk);
void sdo_public_key_write(sdow_t *sdow, sdo_public_key_t *pk);
sdo_public_key_t *sdo_public_key_read(sdor_t *sdor);
sdo_public_key_t *sdo_public_key_clone(sdo_public_key_t *pk);
const char *sdo_pk_alg_to_string(int alg);
const char *sdo_pk_enc_to_string(int enc);
bool sdo_read_pk_null(sdor_t *sdor);
char *sdo_public_key_to_string(sdo_public_key_t *pk, char *buf, int bufsz);

#define AES_IV 16
#define AES_CTR_IV 12
#define AES_CTR_IV_COUNTER 4

typedef struct {
	uint8_t nulls_added;
	sdo_byte_array_t *ct_string;
	sdo_byte_array_t *em_body; // Ciphertext of Encrypted Message Body
	sdo_hash_t *hmac;	  // HMAC of ct body
	uint8_t iv[AES_IV];	// iv of ctr/cbc.
	uint32_t offset;

} sdo_encrypted_packet_t;

typedef struct {
	uint8_t ctr_iv[AES_CTR_IV];
	uint32_t ctr_enc;
	uint32_t ctr_dec;
	uint8_t cbc_iv_enc[AES_IV];
	uint8_t cbc_iv_dec[AES_IV];
	uint32_t pkt_count;
} sdo_iv_t; // IV store

sdo_encrypted_packet_t *sdo_encrypted_packet_alloc(void);
void sdo_encrypted_packet_free(sdo_encrypted_packet_t *pkt);
sdo_encrypted_packet_t *sdo_encrypted_packet_read(sdor_t *sdor);
void sdo_encrypted_packet_write(sdow_t *sdow, sdo_encrypted_packet_t *pkt);
#if 0
char *sdo_encrypted_packet_to_string(sdo_encrypted_packet_t *pkt, char *buf, int bufsz);
#endif
bool sdo_encrypted_packet_unwind(sdor_t *sdor, sdo_encrypted_packet_t *pkt,
				 sdo_iv_t *iv);
bool sdo_encrypted_packet_windup(sdow_t *sdow, int type, sdo_iv_t *iv);
bool sdo_get_iv(sdo_encrypted_packet_t *pkt, sdo_iv_t *ps_iv,
		sdo_encrypted_packet_t *last_pkt);
bool sdo_write_iv(sdo_encrypted_packet_t *pkt, sdo_iv_t *ps_iv, int len);

#define SDO_AES_128_BLOCK_SIZE 16

typedef struct {
	int sig_block_start;
	sdo_public_key_t *pk;
	sdo_byte_array_t *sg;
} sdo_sig_t;
#define SDO_EPDI_GROUPID_SZ 4

typedef struct {
	sdo_byte_array_t *plain_text;
	sdo_byte_array_t *obsig;
} sdo_redirect_t;

bool sdo_begin_read_signature(sdor_t *sdor, sdo_sig_t *sig);
bool sdo_end_read_signature(sdor_t *sdor, sdo_sig_t *sig);
bool sdo_end_read_signature_full(sdor_t *sdor, sdo_sig_t *sig,
				 sdo_public_key_t **getpk);
bool sdo_end_write_signature(sdow_t *sdow, sdo_sig_t *sig);
bool sdo_begin_write_signature(sdow_t *sdow, sdo_sig_t *sig,
			       sdo_public_key_t *pk);
bool sdoOVSignature_verification(sdor_t *sdor, sdo_sig_t *sig,
				 sdo_public_key_t *pk);

typedef struct sdo_key_value_s {
	struct sdo_key_value_s *next;
	sdo_string_t *key;
	sdo_string_t *val;
} sdo_key_value_t;

sdo_key_value_t *sdo_kv_alloc(void);
sdo_key_value_t *sdo_kv_alloc_with_array(const char *key,
					 sdo_byte_array_t *val);
sdo_key_value_t *sdo_kv_alloc_with_str(const char *key, const char *val);
void sdo_kv_free(sdo_key_value_t *kv);
void sdo_kv_write(sdow_t *sdow, sdo_key_value_t *kv);

typedef struct sdo_rendezvous_s {
	int num_params;
	struct sdo_rendezvous_s *next;
	sdo_string_t *only;
	sdo_ip_address_t *ip;
	uint32_t *po;
	uint32_t *pow;
	sdo_string_t *dn;
	sdo_hash_t *sch;
	sdo_hash_t *cch;
	uint32_t *ui;
	sdo_string_t *ss;
	sdo_string_t *pw;
	sdo_string_t *wsp;
	sdo_string_t *me;
	sdo_string_t *pr;
	uint32_t *delaysec;
} sdo_rendezvous_t;

sdo_rendezvous_t *sdo_rendezvous_alloc(void);
void sdo_rendezvous_free(sdo_rendezvous_t *rv);
bool sdo_rendezvous_read(sdor_t *sdor, sdo_rendezvous_t *rv);
bool sdo_rendezvous_write(sdow_t *sdow, sdo_rendezvous_t *rv);
char *sdo_rendezvous_to_string(sdo_rendezvous_t *rv, char *buf, int bufsz);
#define SDO_RENDEZVOUS_GET_IP_ADDRESS_P(rv) ((rv)->ip)
#define SDO_RENDEZVOUS_GET_PORT(rv) (*(rv)->po)
//#define SDORendezvous_set_port(rv,p) ((rv)->po = (p))

typedef struct sdo_rendezvous_list_s {
	uint16_t num_entries;
	sdo_rendezvous_t *rv_entries;
} sdo_rendezvous_list_t;

sdo_rendezvous_list_t *sdo_rendezvous_list_alloc(void);
void sdo_rendezvous_list_free(sdo_rendezvous_list_t *list);
int sdo_rendezvous_list_add(sdo_rendezvous_list_t *list, sdo_rendezvous_t *rv);
// int SDORendezvous_list_remove(sdo_rendezvous_list_t *list, int num);
sdo_rendezvous_t *sdo_rendezvous_list_get(sdo_rendezvous_list_t *list, int num);
int sdo_rendezvous_list_read(sdor_t *sdor, sdo_rendezvous_list_t *list);
bool sdo_rendezvous_list_write(sdow_t *sdow, sdo_rendezvous_list_t *list);

typedef struct sdo_service_info_s {
	int numKV;
	sdo_key_value_t *kv;
} sdo_service_info_t;

sdo_service_info_t *sdo_service_info_alloc(void);
sdo_service_info_t *sdo_service_info_alloc_with(char *key, char *val);
void sdo_service_info_free(sdo_service_info_t *si);
sdo_key_value_t **sdo_service_info_fetch(sdo_service_info_t *si,
					 const char *key);
sdo_key_value_t **sdo_service_info_get(sdo_service_info_t *si, int key_num);
bool sdo_service_info_add_kv_str(sdo_service_info_t *si, const char *key,
				 const char *val);
bool sdo_service_info_add_kv(sdo_service_info_t *si, sdo_key_value_t *kv);
bool sdo_signature_verification(sdo_byte_array_t *plain_text,
				sdo_byte_array_t *sg, sdo_public_key_t *pk);

bool sdo_compare_public_keys(sdo_public_key_t *pk1, sdo_public_key_t *pk2);
bool sdo_combine_platform_dsis(sdow_t *sdow, sdo_service_info_t *si);

/*==================================================================*/
/* Service Info functionality */

#define EMPTY_STRING_LEN 1

/* Module list */
typedef struct sdo_sdk_service_info_module_list_s {
	sdo_sdk_service_info_module module;
	int module_psi_index;
	int module_dsi_count;
	int module_osi_index;
	struct sdo_sdk_service_info_module_list_s
	    *next; // ptr to next module node
} sdo_sdk_service_info_module_list_t;

typedef struct sdo_sv_info_dsi_info_s {
	sdo_sdk_service_info_module_list_t *list_dsi;
	int module_dsi_index;
} sdo_sv_info_dsi_info_t;

/* exposed API for modules to registr */
void sdo_sdk_service_info_register_module(sdo_sdk_service_info_module *module);
void sdo_sdk_service_info_deregister_module(void);
void print_service_info_module_list(void);
bool sdo_get_module_name_msg_value(char *psi_tuple, int psi_len, char *mod_name,
				   char *mod_msg, char *mod_val,
				   int *cb_return_val);

bool sdo_psi_parsing(sdo_sdk_service_info_module_list_t *module_list, char *psi,
		     int psi_len, int *cb_return_val);
bool sdo_mod_exec_sv_infotype(sdo_sdk_service_info_module_list_t *module_list,
			      sdo_sdk_si_type type);
bool sdo_get_dsi_count(sdo_sdk_service_info_module_list_t *module_list,
		       int *modmescount, int *cb_return_val);
bool sdo_mod_data_kv(char *mod_name, sdo_sdk_si_key_value *sv_kv);
bool sdo_construct_module_dsi(sdo_sv_info_dsi_info_t *dsi_info,
			      sdo_sdk_si_key_value *sv_kv, int *cb_return_val);
bool sdo_mod_kv_write(sdow_t *sdow, sdo_sdk_si_key_value *kv);
void sdo_sv_key_value_free(sdo_sdk_si_key_value *sv_kv);

bool sdo_supply_modulePSI(sdo_sdk_service_info_module_list_t *module_list,
			  char *mod_name, sdo_sdk_si_key_value *sv_kv,
			  int *cb_return_val);
bool sdo_supply_moduleOSI(sdo_sdk_service_info_module_list_t *module_list,
			  char *mod_name, sdo_sdk_si_key_value *sv_kv,
			  int *cb_return_val);
bool sdo_osi_parsing(sdor_t *sdor,
		     sdo_sdk_service_info_module_list_t *module_list,
		     sdo_sdk_si_key_value *kv, int *cb_return_val);
bool sdo_osi_handling(sdo_sdk_service_info_module_list_t *module_list,
		      sdo_sdk_si_key_value *sv, int *cb_return_val);
void sdo_sv_info_clear_module_psi_osi_index(
    sdo_sdk_service_info_module_list_t *module_list);
bool sdo_construct_module_list(sdo_sdk_service_info_module_list_t *module_list,
			       char **mod_name);

bool sdo_compare_hashes(sdo_hash_t *hash1, sdo_hash_t *hash2);
bool sdo_compare_byte_arrays(sdo_byte_array_t *ba1, sdo_byte_array_t *ba2);
bool sdo_compare_rv_lists(sdo_rendezvous_list_t *rv_list1,
			  sdo_rendezvous_list_t *rv_list2);
bool sdo_ecdsa_dummyEBRead(sdor_t *sdor);
#define SDO_DSI_ACTIVE_LEN 6
/*==================================================================*/

#if 0
void sdo_service_info_print(sdo_service_info_t *si);
#endif

#endif /* __SDOTYPES_H__ */
