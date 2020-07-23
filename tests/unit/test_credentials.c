/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for credential store/read routines of SDO library.
 */

#include <errno.h>
#include "util.h"
#include "unity.h"
#include "base64.h"
#include "load_credentials.h"
#include "safe_lib.h"
#include "sdoCryptoHal.h"
#include "platform_utils.h"

#ifdef TARGET_OS_FREERTOS
extern bool g_malloc_fail;
#endif

const char *NO_FILE = "0";
const char *BUFFER_FAIL = "4";
bool file_fail = false;

#ifdef TARGET_OS_LINUX
static bool g_malloc_fail = false;
#endif
/*** Unity Declarations ***/
void *__wrap_sdo_alloc(size_t size);
void test_read_normal_device_credentials(void);
void test_read_secure_device_credentials(void);
void test_read_mfg_device_credentials(void);
void test_load_credential(void);
void test_read_write_Device_credentials(void);
void test_store_credential(void);
void test_app_alloc_credentials(void);

/*** Wrapper Functions ***/
bool __real_sdor_next_block(sdor_t *sdor, uint32_t *typep);


#ifdef TARGET_OS_LINUX
void *__real_sdo_alloc(size_t size);
void *__wrap_sdo_alloc(size_t size)
{
	if (g_malloc_fail)
		return NULL;
	else
		return __real_sdo_alloc(size);
}
#endif

/**** Following function is repeated in tests/unit/test_sdoprot.c please do
 * related necessary changes there too
 ****/

/* preconfigure data and secret files for unit tests */
static int32_t configure_blobs(void)
{
	FILE *fp1 = NULL;
	size_t bytes_written = 0;

	unsigned char hmac_key[] = {
	    0xa3, 0x97, 0xa2, 0x55, 0x53, 0xbe, 0xf1, 0xfc, 0xf9, 0x79, 0x6b,
	    0x52, 0x14, 0x13, 0xe9, 0xe2, 0x2d, 0x51, 0x8e, 0x1f, 0x56, 0x08,
	    0x57, 0x27, 0xa7, 0x05, 0xd4, 0xd0, 0x52, 0x82, 0x77, 0x75};

	unsigned char data_platform_iv_bin[] = {
	    0xb6, 0x4c, 0x13, 0xd7, 0x70, 0x33, 0xe5, 0xb2,
	    0xcf, 0x9f, 0x0f, 0x9f, 0xb6, 0x4c, 0x13, 0xd7,
	    0x70, 0x33, 0xe5, 0xb2, 0xcf, 0x9f, 0x0f, 0xa0};
	unsigned int data_platform_iv_bin_len = 24;

	unsigned char data_platform_aes_key_bin[] = {
	    0xfb, 0xec, 0x33, 0xa8, 0xfe, 0xd3, 0x46, 0x81,
	    0x97, 0xe9, 0xed, 0xb6, 0xb6, 0x59, 0x4e, 0x38};
	unsigned int data_platform_aes_key_bin_len = 16;
	/*
	 * w4▒Dƞ▒G#~T▒▒▒3▒Q▒^s▒&▒▒ώ▒▒u▒{"ST":5,"O":{"pv":112,"pe":3,
	 * "g":"sYDPkGPiQ22w62u1PJIihA==","r":[1,[4,{"only":"dev",
	 * "ip":[4,"Ct9hFA=="],"po":8040,"pr":"http"}]],
	 * "pkh":[32,8,"4h6psd0hH+/vo+vNyvjvXslBqtosHpe94yGfUOe08wE="]}}
	 */
	unsigned char data_Normal_blob[] = {
	    0x77, 0x34, 0xd1, 0x44, 0xc6, 0x9e, 0xeb, 0x47, 0x23, 0x7e, 0x54,
	    0xa7, 0xf8, 0xf9, 0x33, 0x93, 0x0f, 0x51, 0xba, 0x5e, 0x73, 0xde,
	    0x26, 0x9e, 0xd6, 0xcf, 0x8e, 0xa2, 0x1f, 0xeb, 0xbb, 0x75, 0x00,
	    0x00, 0x00, 0xbe, 0x7b, 0x22, 0x53, 0x54, 0x22, 0x3a, 0x35, 0x2c,
	    0x22, 0x4f, 0x22, 0x3a, 0x7b, 0x22, 0x70, 0x76, 0x22, 0x3a, 0x31,
	    0x31, 0x32, 0x2c, 0x22, 0x70, 0x65, 0x22, 0x3a, 0x33, 0x2c, 0x22,
	    0x67, 0x22, 0x3a, 0x22, 0x73, 0x59, 0x44, 0x50, 0x6b, 0x47, 0x50,
	    0x69, 0x51, 0x32, 0x32, 0x77, 0x36, 0x32, 0x75, 0x31, 0x50, 0x4a,
	    0x49, 0x69, 0x68, 0x41, 0x3d, 0x3d, 0x22, 0x2c, 0x22, 0x72, 0x22,
	    0x3a, 0x5b, 0x31, 0x2c, 0x5b, 0x34, 0x2c, 0x7b, 0x22, 0x6f, 0x6e,
	    0x6c, 0x79, 0x22, 0x3a, 0x22, 0x64, 0x65, 0x76, 0x22, 0x2c, 0x22,
	    0x69, 0x70, 0x22, 0x3a, 0x5b, 0x34, 0x2c, 0x22, 0x43, 0x74, 0x39,
	    0x68, 0x46, 0x41, 0x3d, 0x3d, 0x22, 0x5d, 0x2c, 0x22, 0x70, 0x6f,
	    0x22, 0x3a, 0x38, 0x30, 0x34, 0x30, 0x2c, 0x22, 0x70, 0x72, 0x22,
	    0x3a, 0x22, 0x68, 0x74, 0x74, 0x70, 0x22, 0x7d, 0x5d, 0x5d, 0x2c,
	    0x22, 0x70, 0x6b, 0x68, 0x22, 0x3a, 0x5b, 0x33, 0x32, 0x2c, 0x38,
	    0x2c, 0x22, 0x34, 0x68, 0x36, 0x70, 0x73, 0x64, 0x30, 0x68, 0x48,
	    0x2b, 0x2f, 0x76, 0x6f, 0x2b, 0x76, 0x4e, 0x79, 0x76, 0x6a, 0x76,
	    0x58, 0x73, 0x6c, 0x42, 0x71, 0x74, 0x6f, 0x73, 0x48, 0x70, 0x65,
	    0x39, 0x34, 0x79, 0x47, 0x66, 0x55, 0x4f, 0x65, 0x30, 0x38, 0x77,
	    0x45, 0x3d, 0x22, 0x5d, 0x7d, 0x7d};
	unsigned int data_Normal_blob_len = 226;

	unsigned char data_Secure_blob[] = {
	    0xb6, 0x4c, 0x13, 0xd7, 0x70, 0x33, 0xe5, 0xb2, 0xcf, 0x9f, 0x0f,
	    0xa0, 0x3d, 0x07, 0xba, 0xd4, 0x2a, 0x08, 0x62, 0x32, 0xdb, 0xeb,
	    0xb0, 0x41, 0x99, 0xef, 0xc9, 0x8b, 0x00, 0x00, 0x00, 0x3b, 0x83,
	    0xce, 0x18, 0xdc, 0x61, 0x6f, 0x82, 0x25, 0xe4, 0x83, 0x82, 0x39,
	    0x52, 0x7d, 0xa3, 0xb4, 0xff, 0xef, 0xd7, 0x82, 0x7d, 0x3c, 0xd5,
	    0x19, 0xf4, 0x4a, 0x3e, 0x9f, 0xfb, 0xb3, 0x51, 0x33, 0xc6, 0x64,
	    0xfd, 0xda, 0x5b, 0x06, 0xc3, 0x2c, 0x61, 0x7d, 0x14, 0xc8, 0x4b,
	    0x9b, 0x1f, 0x30, 0x4d, 0xdd, 0xae, 0x58, 0xcc, 0x3e, 0xfb, 0xdd,
	    0x83, 0x27, 0xce};
	unsigned int data_Secure_blob_len = 91;

	unsigned char data_Mfg_blob[] = {
	    0x5c, 0x4f, 0x02, 0xda, 0xfa, 0xbb, 0xba, 0x73, 0xe8, 0x4d, 0x1d,
	    0x9c, 0xf0, 0xb6, 0xba, 0xd0, 0x58, 0xee, 0x93, 0xba, 0x07, 0x25,
	    0xc4, 0x30, 0xe5, 0xce, 0x6c, 0x01, 0xa0, 0xc9, 0x5e, 0x3b, 0x00,
	    0x00, 0x00, 0x5e, 0x7b, 0x22, 0x4d, 0x22, 0x3a, 0x7b, 0x22, 0x64,
	    0x22, 0x3a, 0x22, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x73,
	    0x65, 0x72, 0x69, 0x61, 0x6c, 0x22, 0x7d, 0x7d, 0x00, 0xaf, 0x55,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x70, 0xd3, 0x82, 0x07, 0x5a, 0x6e, 0x5f, 0xf0, 0x48, 0xd5, 0x12,
	    0xff, 0x7f, 0x00, 0x00, 0x5d, 0x5a, 0x8d, 0xa9, 0xaf, 0x55, 0x00,
	    0x00, 0xc0, 0xbc, 0x96, 0xa9, 0xaf, 0x55, 0x00, 0x00, 0x97, 0x8b,
	    0x6b, 0x22, 0xe8, 0x7f, 0x00, 0x00, 0xe8, 0x49, 0xd5, 0x12, 0xff,
	    0x7f, 0x00, 0x00, 0xd8, 0x49, 0xd5, 0x12, 0xff, 0x7f};
	unsigned int data_Mfg_blob_len = sizeof(data_Mfg_blob);

	/* Write Platform HMAC */
	if (!(fp1 = fopen((const char *)PLATFORM_HMAC_KEY, "w"))) {
		LOG(LOG_ERROR, "Could not open platform HMAC Key file!\n");
		goto err;
	}

	if (PLATFORM_HMAC_KEY_DEFAULT_LEN !=
	    fwrite(hmac_key, sizeof(char), PLATFORM_HMAC_KEY_DEFAULT_LEN,
		   fp1)) {
		LOG(LOG_ERROR,
		    "Plaform HMAC Key file is not written properly!\n");
		goto err;
	}
	if (fp1)
		fclose(fp1);

	/* Write iv bin */
	if (!(fp1 = fopen((const char *)PLATFORM_IV, "w"))) {
		LOG(LOG_ERROR, "Could not open platform HMAC Key file!\n");
		goto err;
	}
	if (fp1 != NULL) {
		bytes_written = fwrite(data_platform_iv_bin, sizeof(char),
				       data_platform_iv_bin_len, fp1);
		if (bytes_written != data_platform_iv_bin_len) {
			LOG(LOG_ERROR, "iv bin not written successfully!\n");
			goto err;
		}
	} else {
		LOG(LOG_ERROR, "Could not open bin!\n");
		goto err;
	}

	if (fp1)
		fclose(fp1);

	/* Write aes bin */
	if (!(fp1 = fopen((const char *)PLATFORM_AES_KEY, "w"))) {
		LOG(LOG_ERROR, "Could not open platform AES Key file!\n");
		goto err;
	}
	if (fp1 != NULL) {
		bytes_written = fwrite(data_platform_aes_key_bin, sizeof(char),
				       data_platform_aes_key_bin_len, fp1);
		if (bytes_written != data_platform_aes_key_bin_len) {
			LOG(LOG_ERROR, "Aes bin not written successfully!\n");
			goto err;
		}
	} else {
		LOG(LOG_ERROR, "Could not open Aes bin!\n");
		goto err;
	}

	if (fp1)
		fclose(fp1);

	/* Write Normal Blob */
	if (!(fp1 = fopen((const char *)SDO_CRED_NORMAL, "w"))) {
		LOG(LOG_ERROR, "Could not open platform HMAC Key file!\n");
		goto err;
	}
	if (fp1 != NULL) {
		bytes_written = fwrite(data_Normal_blob, sizeof(char),
				       data_Normal_blob_len, fp1);
		if (bytes_written != data_Normal_blob_len) {
			LOG(LOG_ERROR,
			    "Sealed Normal blob not written successfully!\n");
			goto err;
		}
	} else {
		LOG(LOG_ERROR, "Could not open Normal blob!\n");
		goto err;
	}

	if (fp1)
		fclose(fp1);

	/* Write secure dev blob */
	if (!(fp1 = fopen((const char *)SDO_CRED_SECURE, "w"))) {
		LOG(LOG_ERROR, "Could not open Sec dev blob!\n");
		goto err;
	}
	if (fp1 != NULL) {
		bytes_written = fwrite(data_Secure_blob, sizeof(char),
				       data_Secure_blob_len, fp1);
		if (bytes_written != data_Secure_blob_len) {
			LOG(LOG_ERROR,
			    "sec blobbin not written successfully!\n");
			goto err;
		}
	} else {
		LOG(LOG_ERROR, "Could not open Aes bin!\n");
		goto err;
	}

	if (fp1)
		fclose(fp1);

	/* Write mfg blob */
	if (!(fp1 = fopen((const char *)SDO_CRED_MFG, "w"))) {
		LOG(LOG_ERROR, "Could not open mfg cred file!\n");
		goto err;
	}
	if (fp1 != NULL) {
		bytes_written =
		    fwrite(data_Mfg_blob, sizeof(char), data_Mfg_blob_len, fp1);
		if (bytes_written != data_Mfg_blob_len) {
			LOG(LOG_ERROR, "Aes bin not written successfully!\n");
			goto err;
		}
	} else {
		LOG(LOG_ERROR, "Could not open Aes bin!\n");
		goto err;
	}

	if (fp1)
		fclose(fp1);

err:
	return -1;
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("read_normal_device_credentials", "[credentials][sdo]")
#else
void test_read_normal_device_credentials(void)
#endif
{
	int ret = -1;

	/*
	 * w4▒Dƞ▒G#~T▒▒▒3▒Q▒^s▒&▒▒ώ▒▒u▒{"ST":5,"O":{"pv":112,"pe":3,
	 * "g":"sYDPkGPiQ22w62u1PJIihA==","r":[1,[4,{"only":"dev",
	 * "ip":[4,"Ct9hFA=="],"po":8040,"pr":"http"}]],
	 * "pkh":[32,8,"4h6psd0hH+/vo+vNyvjvXslBqtosHpe94yGfUOe08wE="]}}
	 */
	unsigned char normal_buf[] = {
	    0x77, 0x34, 0xd1, 0x44, 0xc6, 0x9e, 0xeb, 0x47, 0x23, 0x7e, 0x54,
	    0xa7, 0xf8, 0xf9, 0x33, 0x93, 0x0f, 0x51, 0xba, 0x5e, 0x73, 0xde,
	    0x26, 0x9e, 0xd6, 0xcf, 0x8e, 0xa2, 0x1f, 0xeb, 0xbb, 0x75, 0x00,
	    0x00, 0x00, 0xbe, 0x7b, 0x22, 0x53, 0x54, 0x22, 0x3a, 0x35, 0x2c,
	    0x22, 0x4f, 0x22, 0x3a, 0x7b, 0x22, 0x70, 0x76, 0x22, 0x3a, 0x31,
	    0x31, 0x32, 0x2c, 0x22, 0x70, 0x65, 0x22, 0x3a, 0x33, 0x2c, 0x22,
	    0x67, 0x22, 0x3a, 0x22, 0x73, 0x59, 0x44, 0x50, 0x6b, 0x47, 0x50,
	    0x69, 0x51, 0x32, 0x32, 0x77, 0x36, 0x32, 0x75, 0x31, 0x50, 0x4a,
	    0x49, 0x69, 0x68, 0x41, 0x3d, 0x3d, 0x22, 0x2c, 0x22, 0x72, 0x22,
	    0x3a, 0x5b, 0x31, 0x2c, 0x5b, 0x34, 0x2c, 0x7b, 0x22, 0x6f, 0x6e,
	    0x6c, 0x79, 0x22, 0x3a, 0x22, 0x64, 0x65, 0x76, 0x22, 0x2c, 0x22,
	    0x69, 0x70, 0x22, 0x3a, 0x5b, 0x34, 0x2c, 0x22, 0x43, 0x74, 0x39,
	    0x68, 0x46, 0x41, 0x3d, 0x3d, 0x22, 0x5d, 0x2c, 0x22, 0x70, 0x6f,
	    0x22, 0x3a, 0x38, 0x30, 0x34, 0x30, 0x2c, 0x22, 0x70, 0x72, 0x22,
	    0x3a, 0x22, 0x68, 0x74, 0x74, 0x70, 0x22, 0x7d, 0x5d, 0x5d, 0x2c,
	    0x22, 0x70, 0x6b, 0x68, 0x22, 0x3a, 0x5b, 0x33, 0x32, 0x2c, 0x38,
	    0x2c, 0x22, 0x34, 0x68, 0x36, 0x70, 0x73, 0x64, 0x30, 0x68, 0x48,
	    0x2b, 0x2f, 0x76, 0x6f, 0x2b, 0x76, 0x4e, 0x79, 0x76, 0x6a, 0x76,
	    0x58, 0x73, 0x6c, 0x42, 0x71, 0x74, 0x6f, 0x73, 0x48, 0x70, 0x65,
	    0x39, 0x34, 0x79, 0x47, 0x66, 0x55, 0x4f, 0x65, 0x30, 0x38, 0x77,
	    0x45, 0x3d, 0x22, 0x5d, 0x7d, 0x7d};
	unsigned int data_Normal_blob_len = 226;

	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_SUCCESS, ret);

	ret = sdo_blob_write((char *)SDO_CRED_NORMAL, SDO_SDK_NORMAL_DATA,
			     normal_buf, data_Normal_blob_len);
	TEST_ASSERT_NOT_EQUAL(-1, ret);

	configure_blobs();
	ret = load_mfg_secret();
	TEST_ASSERT_NOT_EQUAL(-1, ret);

	sdo_dev_cred_t *Normal_cred = app_get_credentials();

	/* Negative case - no credentials file */
	ret = read_normal_device_credentials(NULL, SDO_SDK_NORMAL_DATA,
					     Normal_cred);
	TEST_ASSERT_FALSE(ret);

	ret = read_normal_device_credentials((char *)SDO_CRED_NORMAL, 0,
					     Normal_cred);
	TEST_ASSERT_FALSE(ret);

	/* Positive case */
	ret = read_normal_device_credentials((char *)SDO_CRED_NORMAL,
					     SDO_SDK_NORMAL_DATA, Normal_cred);
	TEST_ASSERT_TRUE(ret);
	sdo_sdk_deinit();

}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("read_secure_device_credentials", "[credentials][sdo]")
#else
void test_read_secure_device_credentials(void)
#endif
{
	int ret = -1;
	uint8_t secure_buf[100] = "{\"Secret\":[\"p++AC/nnKsfYOh1+WBU8cw==\"]}";
	// base64_init();
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_SUCCESS, ret);

	ret = sdo_blob_write((char *)SDO_CRED_SECURE, SDO_SDK_SECURE_DATA,
			     secure_buf, sizeof(secure_buf));
	TEST_ASSERT_NOT_EQUAL(-1, ret);

	sdo_dev_cred_t *Secure_cred = app_get_credentials();

	/* Positive case*/
	ret = read_secure_device_credentials((char *)SDO_CRED_SECURE,
					     SDO_SDK_SECURE_DATA, Secure_cred);
	TEST_ASSERT_TRUE(ret);

	/* Negative case - no credentials file */
	ret = read_secure_device_credentials(NULL, SDO_SDK_SECURE_DATA,
					     Secure_cred);
	TEST_ASSERT_FALSE(ret);

	/* Negative case */
	ret = read_secure_device_credentials((char *)SDO_CRED_SECURE, 0,
					     Secure_cred);
	TEST_ASSERT_FALSE(ret);

	sdo_sdk_deinit();
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("read_mfg_device_credentials", "[credentials][sdo]")
#else
void test_read_mfg_device_credentials(void)
#endif
{
	int ret = -1;
	uint8_t mfg_buf[] = "{\"M\":{\"d\":\"device-serial\"}}";
	// base64_init();
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_SUCCESS, ret);

	ret = sdo_blob_write((char *)SDO_CRED_MFG, SDO_SDK_NORMAL_DATA, mfg_buf,
			     sizeof(mfg_buf));
	TEST_ASSERT_NOT_EQUAL(-1, ret);

	sdo_dev_cred_t *Mfg_cred = app_get_credentials();

	/* Positive case */
	ret = read_mfg_device_credentials((char *)SDO_CRED_MFG,
					  SDO_SDK_NORMAL_DATA, Mfg_cred);
	TEST_ASSERT_TRUE(ret);

	/* Negative case - no credentials file */
	ret = read_mfg_device_credentials(NULL, SDO_SDK_SECURE_DATA, Mfg_cred);
	TEST_ASSERT_FALSE(ret);

	/* Negative case */
	ret = read_mfg_device_credentials((char *)SDO_CRED_MFG, 0, Mfg_cred);
	TEST_ASSERT_FALSE(ret);

	sdo_sdk_deinit();
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("load_credential", "[credentials][sdo]")
#else
void test_load_credential(void)
#endif
{
	int ret;
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_SUCCESS, ret);
	// base64_init();

	/* Negative case*/
	g_malloc_fail = true;
	ret = load_credential();
	TEST_ASSERT_EQUAL(-1, ret);
	g_malloc_fail = false;
	sdo_sdk_deinit();
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("read_write_Device_credentials", "[credentials][sdo]")
#else
void test_read_write_Device_credentials(void)
#endif
{

	int ret = -1;
	uint8_t normal_buf[400] =
	    "{\"ST\":5,\"O\":{\"pv\":112,\"pe\":3,\"g\":"
	    "\"qhYasJzvSNe63J4g0aNQew==\",\"r\":[3,[4,{"
	    "\"only\":\"dev\",\"po\":8041,\"dn\":\"localhost\","
	    "\"pr\":\"http\"}],[4,{\"only\":\"dev\",\"po\":"
	    "8041,\"dn\":\"localhost\",\"pr\":\"https\"}],[1,{"
	    "\"delaysec\":1}]],\"pkh\":[32,8,\"NsoZ7HFUH/"
	    "pt7+Fl0BTK1VdiXHbXKAeVWglf/Z7v7Gc=\"]}}";
	uint8_t mfg_buf[] = "{\"M\":{\"d\":\"device-serial\"}}";
	uint8_t secure_buf[100] = "{\"Secret\":[\"p++AC/nnKsfYOh1+WBU8cw==\"]}";

	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_SUCCESS, ret);

	ret = sdo_blob_write((char *)SDO_CRED_NORMAL, SDO_SDK_NORMAL_DATA,
			     normal_buf, sizeof(normal_buf));
	TEST_ASSERT_NOT_EQUAL(-1, ret);
	ret = sdo_blob_write((char *)SDO_CRED_MFG, SDO_SDK_NORMAL_DATA, mfg_buf,
			     sizeof(mfg_buf));
	TEST_ASSERT_NOT_EQUAL(-1, ret);
	ret = sdo_blob_write((char *)SDO_CRED_SECURE, SDO_SDK_SECURE_DATA,
			     secure_buf, sizeof(secure_buf));
	TEST_ASSERT_NOT_EQUAL(-1, ret);

	load_mfg_secret();

	sdo_dev_cred_t *ocred = app_get_credentials();
	ret = read_normal_device_credentials((char *)SDO_CRED_NORMAL,
					     SDO_SDK_NORMAL_DATA, ocred);
	TEST_ASSERT_TRUE(ret);

	ret = read_mfg_device_credentials((char *)SDO_CRED_MFG,
					  SDO_SDK_NORMAL_DATA, ocred);
	TEST_ASSERT_TRUE(ret);

	ret = read_secure_device_credentials((char *)SDO_CRED_SECURE,
					     SDO_SDK_SECURE_DATA, ocred);
	TEST_ASSERT_TRUE(ret);

	ret = write_normal_device_credentials((char *)SDO_CRED_NORMAL,
					      SDO_SDK_NORMAL_DATA, ocred);
	TEST_ASSERT_TRUE(ret);

	ret = write_mfg_device_credentials((char *)SDO_CRED_MFG,
					   SDO_SDK_NORMAL_DATA, ocred);
	TEST_ASSERT_TRUE(ret);

	ret = write_secure_device_credentials((char *)SDO_CRED_SECURE,
					      SDO_SDK_SECURE_DATA, ocred);
	TEST_ASSERT_TRUE(ret);
	sdo_sdk_deinit();
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("store_credential", "[credentials][sdo]")
#else
void test_store_credential(void)
#endif
{
	int ret = -1;
	uint8_t normal_buf[400] =
	    "{\"ST\":5,\"O\":{\"pv\":112,\"pe\":3,\"g\":"
	    "\"qhYasJzvSNe63J4g0aNQew==\",\"r\":[3,[4,{"
	    "\"only\":\"dev\",\"po\":8041,\"dn\":\"localhost\","
	    "\"pr\":\"http\"}],[4,{\"only\":\"dev\",\"po\":"
	    "8041,\"dn\":\"localhost\",\"pr\":\"https\"}],[1,{"
	    "\"delaysec\":1}]],\"pkh\":[32,8,\"NsoZ7HFUH/"
	    "pt7+Fl0BTK1VdiXHbXKAeVWglf/Z7v7Gc=\"]}}";
	uint8_t mfg_buf[] = "{\"M\":{\"d\":\"device-serial\"}}";
	uint8_t secure_buf[100] = "{\"Secret\":[\"p++AC/nnKsfYOh1+WBU8cw==\"]}";

	ret = sdo_blob_write((char *)SDO_CRED_NORMAL, SDO_SDK_NORMAL_DATA,
			     normal_buf, sizeof(normal_buf));
	TEST_ASSERT_NOT_EQUAL(-1, ret);

	ret = sdo_blob_write((char *)SDO_CRED_MFG, SDO_SDK_NORMAL_DATA, mfg_buf,
			     sizeof(mfg_buf));
	TEST_ASSERT_NOT_EQUAL(-1, ret);

	ret = sdo_blob_write((char *)SDO_CRED_SECURE, SDO_SDK_SECURE_DATA,
			     secure_buf, sizeof(secure_buf));
	TEST_ASSERT_NOT_EQUAL(-1, ret);

	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_SUCCESS, ret);
	load_mfg_secret();

	sdo_dev_cred_t *ocred = app_get_credentials();
	/* Positive Case */
	ret = store_credential(ocred);
	TEST_ASSERT_EQUAL(0, ret);
	sdo_sdk_deinit();
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("app_alloc_credentials", "[credentials][sdo]")
#else
void test_app_alloc_credentials(void)
#endif
{
	sdo_dev_cred_t *ret = NULL;

	g_malloc_fail = true;
	ret = app_alloc_credentials();
	TEST_ASSERT_EQUAL(NULL, ret);
	g_malloc_fail = false;
}
