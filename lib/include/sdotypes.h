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
	size_t byteSz;
	uint8_t *bytes;
} SDOBits_t;

SDOBits_t *sdoBitsInit(SDOBits_t *b, int byteSz);
SDOBits_t *sdoBitsAlloc(int byteSz);
SDOBits_t *sdoBitsAllocWith(int byteSz, uint8_t *data);
void sdoBitsFree(SDOBits_t *b);
void sdoBitsEmpty(SDOBits_t *b);
SDOBits_t *sdoBitsClone(SDOBits_t *b);
bool sdoBitsResize(SDOBits_t *b, int byteSz);
bool sdoBitsFill(SDOBits_t **b);
bool sdoBitsFillWith(SDOBits_t *b, uint8_t *data, uint32_t dataLen);
bool sdoBitsResizeWith(SDOBits_t *b, int newByteSz, uint8_t *data);
bool sdoBitsEqual(SDOBits_t *b1, SDOBits_t *b2);
int sdoBitsRandomize(SDOBits_t *b);
char *sdoBitsToString(SDOBits_t *b, char *typname, char *buf, int bufSz);
char *sdoBitsToStringHex(SDOBits_t *b, char *buf, int bufSz);

#if 0
void SDOBitsWrite(SDOW_t *sdow, SDOBits_t *b);
bool SDOBitsRead(SDOR_t *sdor, SDOBits_t *b);
#endif

// Byte Array
typedef SDOBits_t SDOByteArray_t;

#if 0
SDOByteArray_t *SDOByteArrayInit(SDOByteArray_t *bn, int byteSz);
#endif
SDOByteArray_t *sdoByteArrayAlloc(int byteSz);
SDOByteArray_t *sdoByteArrayAllocWithInt(int val);
SDOByteArray_t *sdoByteArrayAllocWithByteArray(uint8_t *ba, int baLen);
void sdoByteArrayFree(SDOByteArray_t *ba);
#if 0
void SDOByteArrayEmpty(SDOByteArray_t *ba);
#endif
bool sdoByteArrayResize(SDOByteArray_t *b, int byteSz);
#if 0
bool SDOByteArrayResizeWith(SDOByteArray_t *b, int newByteSz, uint8_t *data);
#endif
SDOByteArray_t *sdoByteArrayAppend(SDOByteArray_t *baA, SDOByteArray_t *baB);
SDOByteArray_t *sdoByteArrayClone(SDOByteArray_t *ba);
bool SDOByteArrayEqual(SDOByteArray_t *ba1, SDOByteArray_t *ba2);
char *sdoByteArrayToString(SDOByteArray_t *g, char *buf, int bufSz);
int sdoByteArrayRead(SDOR_t *sdor, SDOByteArray_t *ba);
int sdoByteArrayReadChars(SDOR_t *sdor, SDOByteArray_t *ba);
int sdoByteArrayReadWithType(SDOR_t *sdor, SDOByteArray_t *ba,
			     SDOByteArray_t **ctString, uint8_t *ivData);
void SDOByteArrayWrite(SDOW_t *sdow, SDOByteArray_t *ba);
void sdoByteArrayWriteChars(SDOW_t *sdow, SDOByteArray_t *ba);

// Bignum

typedef struct {
	bool sign;
	SDOBits_t *value;
} SDOBignum_t;

#define BN_POSITIVE true
#define BN_NEGATIVE false

SDOBignum_t *sdoBigNumAlloc(void);
void sdoBigNumFree(SDOBignum_t *bn);
bool SDOBignumEqual(SDOBignum_t *bn1, SDOBignum_t *bn2);
char *SDOBignumToString(SDOBignum_t *g, char *buf, int bufSz);

// Generic string holder
typedef struct {
	int byteSz;
	char *bytes;
} SDOString_t;

void sdoStringInit(SDOString_t *b);
SDOString_t *sdoStringAlloc(void);
SDOString_t *sdoStringAllocWith(char *data, int byteSz);
SDOString_t *sdoStringAllocWithStr(char *data);
void sdoStringFree(SDOString_t *b);
bool sdoStringResize(SDOString_t *b, int byteSz);
bool sdoStringResizeWith(SDOString_t *b, int newByteSz, char *data);
char *sdoStringToString(SDOString_t *b, char *buf, int bufSz);
bool sdoStringRead(SDOR_t *sdor, SDOString_t *b);

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
char *sdoGuidToString(SDOByteArray_t *g, char *buf, int bufSz);

/* Nonce  */
void sdoNonceInitRand(SDOByteArray_t *n);
char *sdoNonceToString(uint8_t *n, char *buf, int bufSz);
bool sdoNonceEqual(SDOByteArray_t *n1, SDOByteArray_t *n2);

typedef struct _sdo_hash_t {
	int hashType;
	SDOByteArray_t *hash;
} SDOHash_t;

/*GID*/
void sdoGidWrite(SDOW_t *sdow);

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
SDOHash_t *sdoHashAllocEmpty(void);
SDOHash_t *sdoHashAlloc(int hashType, int size);
void sdoHashFree(SDOHash_t *hp);
int sdoHashRead(SDOR_t *sdor, SDOHash_t *hp);
void sdoHashWrite(SDOW_t *sdow, SDOHash_t *hp);
void sdoHashNullWrite(SDOW_t *sdow);
char *sdoHashTypeToString(int hashType);
char *sdoHashToString(SDOHash_t *hp, char *buf, int bufSz);

bool sdoBeginReadHMAC(SDOR_t *sdor, int *sigBlockStart);
bool sdoEndReadHMAC(SDOR_t *sdor, SDOHash_t **hmac, int sigBlockStart);

typedef SDOByteArray_t SDOKeyExchange_t;

typedef struct {
	uint8_t length;
	uint8_t addr[16];
} SDOIPAddress_t;

SDOIPAddress_t *sdoIPAddressAlloc(void);
bool sdoNullIPAddress(SDOIPAddress_t *sdoip);
void sdoInitIPv4Address(SDOIPAddress_t *sdoip, uint8_t *ipv4);
#if 0
void SDOInitIPv6Address(SDOIPAddress_t *sdoip, uint8_t *ipv6);
#endif
bool sdoReadIPAddress(SDOR_t *sdor, SDOIPAddress_t *sdoip);
void sdoWriteIPAddress(SDOW_t *sdow, SDOIPAddress_t *sdoip);
char *sdoIPAddressToString(SDOIPAddress_t *sdoip, char *buf, int bufSz);
#if 0
int SDOIPAddressToMem(SDOIPAddress_t *sdoip, uint8_t *copyto);
#endif

typedef struct {
	uint16_t length;
	char *name;
} SDODNSName_t;

char *sdoReadDNS(SDOR_t *sdor);

#define SDO_APP_ID_TYPE_BYTES 2

void sdoAppIDWrite(SDOW_t *sdow);

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
//#define SDOEAlgAES_ECB_NoPadding 1

typedef struct {
	uint16_t len;	 // Total bytes in the certificate chain
	uint8_t type;	 // Format of certificate entries (1 == x509)
	uint8_t numEntries;   // number of entries
	SDOByteArray_t *cert; // certs, from Device to CA, each signed by next.
} SDOCertChain_t;
SDOCertChain_t *sdoCertChainRead(SDOR_t *sdor);

typedef struct {
	int pkalg;
	int pkenc;
	SDOByteArray_t *key1; // in RSA, the Modulus/ binary for DSA
	SDOByteArray_t *key2; // In RSA, the Exponent
} SDOPublicKey_t;

typedef struct {
	int sigType; /* Used to differentiate between epid and ecdsa in EBread*/
	SDOPublicKey_t *pubkey;
} SDOSigInfo_t;

typedef struct {
	uint8_t EPIDType;
	SDOByteArray_t *sigRL;  // EPID sigRL
	SDOByteArray_t *pubkey; // EPID pubkey
} SDOEPIDInfoeB_t;
int32_t sdoEPIDInfoEBRead(SDOR_t *sdor);
void sdoEPIDInfoEBFree(SDOEPIDInfoeB_t *EPIDInfo);
int32_t sdoEBRead(SDOR_t *sdor);

SDOPublicKey_t *sdoPublicKeyAllocEmpty(void);
SDOPublicKey_t *sdoPublicKeyAlloc(int pkalg, int pkenc, int pklen,
				  uint8_t *pkey);
void sdoPublicKeyFree(SDOPublicKey_t *pk);
void sdoPublicKeyWrite(SDOW_t *sdow, SDOPublicKey_t *pk);
SDOPublicKey_t *sdoPublicKeyRead(SDOR_t *sdor);
SDOPublicKey_t *sdoPublicKeyClone(SDOPublicKey_t *pk);
char *sdoPKAlgToString(int alg);
char *sdoPKEncToString(int enc);
char *sdoPublicKeyToString(SDOPublicKey_t *pk, char *buf, int bufsz);

#define AES_IV 16
#define AES_CTR_IV 12
#define AES_CTR_IV_COUNTER 4

typedef struct {
	uint8_t nullsAdded;
	SDOByteArray_t *ctString;
	SDOByteArray_t *emBody; // Ciphertext of Encrypted Message Body
	SDOHash_t *hmac;	// HMAC of ct body
	uint8_t iv[AES_IV];     // iv of ctr/cbc.
	uint32_t offset;

} SDOEncryptedPacket_t;

typedef struct {
	uint8_t ctr_iv[AES_CTR_IV];
	uint32_t ctr_enc;
	uint32_t ctr_dec;
	uint8_t cbc_iv_enc[AES_IV];
	uint8_t cbc_iv_dec[AES_IV];
	uint32_t pktCount;
} SDOIV_t; // IV store

SDOEncryptedPacket_t *sdoEncryptedPacketAlloc(void);
void sdoEncryptedPacketFree(SDOEncryptedPacket_t *pkt);
SDOEncryptedPacket_t *sdoEncryptedPacketRead(SDOR_t *sdor);
void sdoEncryptedPacketWrite(SDOW_t *sdow, SDOEncryptedPacket_t *pkt);
#if 0
char *SDOEncryptedPacketToString(SDOEncryptedPacket_t *pkt, char *buf, int bufsz);
#endif
bool sdoEncryptedPacketUnwind(SDOR_t *sdor, SDOEncryptedPacket_t *pkt,
			      SDOIV_t *iv);
bool sdoEncryptedPacketWindup(SDOW_t *sdow, int type, SDOIV_t *iv);
bool sdoGetIV(SDOEncryptedPacket_t *pkt, SDOIV_t *ps_iv,
	      SDOEncryptedPacket_t *last_pkt);
bool sdoWriteIV(SDOEncryptedPacket_t *pkt, SDOIV_t *ps_iv, int len);

#define SDO_AES_128_BLOCK_SIZE 16

typedef struct {
	int sigBlockStart;
	SDOPublicKey_t *pk;
	SDOByteArray_t *sg;
} SDOSig_t;
#define SDO_EPDI_GROUPID_SZ 4

typedef struct {
	SDOByteArray_t *plainText;
	SDOByteArray_t *Obsig;
} SDORedirect_t;

bool sdoBeginReadSignature(SDOR_t *sdor, SDOSig_t *sig);
bool sdoEndReadSignature(SDOR_t *sdor, SDOSig_t *sig);
bool sdoEndReadSignatureFull(SDOR_t *sdor, SDOSig_t *sig,
			     SDOPublicKey_t **getpk);
bool sdoEndWriteSignature(SDOW_t *sdow, SDOSig_t *sig);
bool sdoBeginWriteSignature(SDOW_t *sdow, SDOSig_t *sig, SDOPublicKey_t *pk);
bool sdoOVSignatureVerification(SDOR_t *sdor, SDOSig_t *sig,
				SDOPublicKey_t *pk);

typedef struct SDOKeyValue_s {
	struct SDOKeyValue_s *next;
	SDOString_t *key;
	SDOString_t *val;
} SDOKeyValue_t;

SDOKeyValue_t *sdoKVAlloc(void);
SDOKeyValue_t *sdoKVAllocWithArray(char *key, SDOByteArray_t *val);
SDOKeyValue_t *sdoKVAllocWithStr(char *key, char *val);
void sdoKVFree(SDOKeyValue_t *kv);
void sdoKVWrite(SDOW_t *sdow, SDOKeyValue_t *kv);

typedef struct SDORendezvous_s {
	int numParams;
	struct SDORendezvous_s *next;
	SDOString_t *only;
	SDOIPAddress_t *ip;
	uint32_t *po;
	uint32_t *pow;
	SDOString_t *dn;
	SDOHash_t *sch;
	SDOHash_t *cch;
	uint32_t *ui;
	SDOString_t *ss;
	SDOString_t *pw;
	SDOString_t *wsp;
	SDOString_t *me;
	SDOString_t *pr;
	uint32_t *delaysec;
} SDORendezvous_t;

SDORendezvous_t *sdoRendezvousAlloc(void);
void sdoRendezvousFree(SDORendezvous_t *rv);
bool sdoRendezvousRead(SDOR_t *sdor, SDORendezvous_t *rv);
bool sdoRendezvousWrite(SDOW_t *sdow, SDORendezvous_t *rv);
char *sdoRendezvousToString(SDORendezvous_t *rv, char *buf, int bufsz);
#define SDO_RENDEZVOUS_GET_IP_ADDRESS_P(rv) ((rv)->ip)
#define SDO_RENDEZVOUS_GET_PORT(rv) (*(rv)->po)
//#define SDORendezvousSetPort(rv,p) ((rv)->po = (p))

typedef struct SDORendezvousList_s {
	uint16_t numEntries;
	SDORendezvous_t *rvEntries;
} SDORendezvousList_t;

SDORendezvousList_t *sdoRendezvousListAlloc(void);
void sdoRendezvousListFree(SDORendezvousList_t *list);
int sdoRendezvousListAdd(SDORendezvousList_t *list, SDORendezvous_t *rv);
// int SDORendezvousListRemove(SDORendezvousList_t *list, int num);
SDORendezvous_t *sdoRendezvousListGet(SDORendezvousList_t *list, int num);
int sdoRendezvousListRead(SDOR_t *sdor, SDORendezvousList_t *list);
bool sdoRendezvousListWrite(SDOW_t *sdow, SDORendezvousList_t *list);

typedef struct SDOServiceInfo_s {
	int numKV;
	SDOKeyValue_t *kv;
} SDOServiceInfo_t;

SDOServiceInfo_t *sdoServiceInfoAlloc(void);
SDOServiceInfo_t *sdoServiceInfoAllocWith(char *key, char *val);
void sdoServiceInfoFree(SDOServiceInfo_t *si);
SDOKeyValue_t **sdoServiceInfoFetch(SDOServiceInfo_t *si, char *key);
SDOKeyValue_t **sdoServiceInfoGet(SDOServiceInfo_t *si, int keyNum);
bool sdoServiceInfoAddKVStr(SDOServiceInfo_t *si, char *key, char *val);
bool sdoServiceInfoAddKV(SDOServiceInfo_t *si, SDOKeyValue_t *kv);
bool sdoSignatureVerification(SDOByteArray_t *plainText, SDOByteArray_t *sg,
			      SDOPublicKey_t *pk);

bool sdoComparePublicKeys(SDOPublicKey_t *pk1, SDOPublicKey_t *pk2);
bool sdoCombinePlatformDSIs(SDOW_t *sdow, SDOServiceInfo_t *si);

/*==================================================================*/
/* Service Info functionality */

#define EMPTY_STRING_LEN 1

/* Module list */
typedef struct sdoSdkServiceInfoModuleList_s {
	sdoSdkServiceInfoModule module;
	int modulePsiIndex;
	int moduleDsiCount;
	int moduleOsiIndex;
	struct sdoSdkServiceInfoModuleList_s *next; // ptr to next module node
} sdoSdkServiceInfoModuleList_t;

typedef struct sdoSvInfoDsiInfo_s {
	sdoSdkServiceInfoModuleList_t *list_dsi;
	int moduleDsiIndex;
} sdoSvInfoDsiInfo_t;

/* exposed API for modules to registr */
void sdoSdkServiceInfoRegisterModule(sdoSdkServiceInfoModule *module);
void printServiceInfoModuleList(void);
bool sdoGetModuleNameMsgValue(char *psi_tuple, int psi_len, char *mod_name,
			      char *mod_msg, char *mod_val, int *cbReturnVal);

bool sdoPsiParsing(sdoSdkServiceInfoModuleList_t *moduleList, char *psi,
		   int psiLen, int *cbReturnVal);
bool sdoModExecSvInfotype(sdoSdkServiceInfoModuleList_t *moduleList,
			  sdoSdkSiType type);
bool sdoGetDSICount(sdoSdkServiceInfoModuleList_t *moduleList, int *modmescount,
		    int *cbReturnVal);
bool sdoModDataKV(char *modName, sdoSdkSiKeyValue *sv_kv);
bool sdoConstructModuleDSI(sdoSvInfoDsiInfo_t *dsiInfo, sdoSdkSiKeyValue *sv_kv,
			   int *cbReturnVal);
bool sdoModKVWrite(SDOW_t *sdow, sdoSdkSiKeyValue *kv);
void sdoSVKeyValueFree(sdoSdkSiKeyValue *sv_kv);

bool sdoSupplyModulePSI(sdoSdkServiceInfoModuleList_t *moduleList,
			char *mod_name, sdoSdkSiKeyValue *sv_kv,
			int *cbReturnVal);
bool sdoSupplyModuleOSI(sdoSdkServiceInfoModuleList_t *moduleList,
			char *mod_name, sdoSdkSiKeyValue *sv_kv,
			int *cbReturnVal);
bool sdoOsiParsing(SDOR_t *sdor, sdoSdkServiceInfoModuleList_t *moduleList,
		   sdoSdkSiKeyValue *kv, int *cbReturnVal);
bool sdoOsiHandling(sdoSdkServiceInfoModuleList_t *moduleList,
		    sdoSdkSiKeyValue *sv, int *cbReturnVal);
void sdoSvInfoClearModulePsiOsiIndex(sdoSdkServiceInfoModuleList_t *moduleList);
bool sdoConstructModuleList(sdoSdkServiceInfoModuleList_t *moduleList,
			    char **mod_name);

bool sdoCompareHashes(SDOHash_t *hash1, SDOHash_t *hash2);
bool sdoCompareByteArrays(SDOByteArray_t *ba1, SDOByteArray_t *ba2);
bool sdoCompareRvLists(SDORendezvousList_t *rv_list1,
		       SDORendezvousList_t *rv_list2);
bool sdoEcdsaDummyEBRead(SDOR_t *sdor);
#define SDO_DSI_ACTIVE_LEN 6
/*==================================================================*/

#if 0
void SDOServiceInfoPrint(SDOServiceInfo_t *si);
#endif

#endif /* __SDOTYPES_H__ */
