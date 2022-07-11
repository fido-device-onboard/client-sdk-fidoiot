/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Unit tests for credential store/read routines of FDO library.
 */

#include <errno.h>
#include "util.h"
#include "unity.h"
#include "load_credentials.h"
#include "safe_lib.h"
#include "fdoCryptoHal.h"
#include "fdoCrypto.h"
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
void *__wrap_fdo_alloc(size_t size);
void test_read_normal_device_credentials(void);
void test_read_secure_device_credentials(void);
void test_load_credential(void);
void test_read_write_Device_credentials(void);
void test_store_credential(void);

/*** Wrapper Functions ***/
bool __real_fdor_next_block(fdor_t *fdor, uint32_t *typep);

#ifdef TARGET_OS_LINUX
void *__real_fdo_alloc(size_t size);
void *__wrap_fdo_alloc(size_t size)
{
	if (g_malloc_fail)
		return NULL;
	else
		return __real_fdo_alloc(size);
}
#endif

/**** Following function is repeated in tests/unit/test_fdoprot.c please do
 * related necessary changes there too
 ****/

/* preconfigure data and secret files for unit tests */
static int32_t configure_blobs(void)
{
	FILE *fp1 = NULL;
	size_t bytes_written = 0;

	// contents are hard-coded for AES-GCM-256 crypto

	unsigned char hmac_key[] = {
		0xa3, 0x97, 0xa2, 0x55, 0x53, 0xbe, 0xf1, 0xfc, 0xf9, 0x79, 0x6b,
		0x52, 0x14, 0x13, 0xe9, 0xe2, 0x2d, 0x51, 0x8e, 0x1f, 0x56, 0x08,
		0x57, 0x27, 0xa7, 0x05, 0xd4, 0xd0, 0x52, 0x82, 0x77, 0x75
	};

	unsigned char data_platform_iv_bin[] = {
		0x42, 0x42, 0x4e, 0x41, 0xaf, 0x32, 0x34, 0x49, 0xe8, 0xa6, 0xdb,
		0xcf, 0x42, 0x42, 0x4e, 0x41, 0xaf, 0x32, 0x34, 0x49, 0xe8, 0xa6,
		0xdb, 0xcf
	};
	unsigned int data_platform_iv_bin_len = 24;

	unsigned char data_platform_aes_key_bin[] = {
		0xc9, 0xbb, 0x49, 0xf6, 0x52, 0x1a, 0x6c, 0x7d, 0xcf, 0xfe, 0x1a,
		0x9c, 0x79, 0x32, 0x55, 0x29, 0x5b, 0xe0, 0x0b, 0xd3, 0xe2, 0xf9,
		0xd5, 0x31, 0xd9, 0xdf, 0xf2, 0x11, 0x73, 0x8a, 0x55, 0xb1
	};
	unsigned int data_platform_aes_key_bin_len = 32;

	/*
	[3, true, 100, "12345", h'C6F29F84DAD6456488CFEF0ED1AA889A',
	[[[5, "host.docker.internal"], [3, 8040], [12, 1], [2, h'7F000001'], [4, 8443]]],
	[-43, h'E2DE3109F7F73264C530C8694FD0F0FD9534F255C329ED1A9A23AF8C7B0884
	48E85C9B919C7A2C74F23804389006678F']]
	*/
	unsigned char data_Normal_blob[] = {
		0x30, 0x4c, 0x4e, 0x61, 0x5c, 0xa6, 0xb4, 0xd6, 0xba, 0x39, 0x40, 0x0f, 0xb0,
		0xba, 0x9f, 0x2e, 0x92, 0xa6, 0x89, 0xda, 0xb0, 0x93, 0xcb, 0xd5, 0xd5, 0xc8,
		0xe9, 0x97, 0xa5, 0x2b, 0x88, 0xdc, 0x00, 0x00, 0x00, 0x73, 0x87, 0x03, 0xf5,
		0x18, 0x64, 0x65, 0x31, 0x32, 0x33, 0x34, 0x35, 0x50, 0xc6, 0xf2, 0x9f, 0x84,
		0xda, 0xd6, 0x45, 0x64, 0x88, 0xcf, 0xef, 0x0e, 0xd1, 0xaa, 0x88, 0x9a, 0x81,
		0x85, 0x82, 0x05, 0x69, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
		0x82, 0x03, 0x19, 0x1f, 0x68, 0x82, 0x0c, 0x01, 0x82, 0x02, 0x44, 0x7f, 0x00,
		0x00, 0x01, 0x82, 0x04, 0x19, 0x20, 0xfb, 0x82, 0x38, 0x2a, 0x58, 0x30, 0xe2,
		0xde, 0x31, 0x09, 0xf7, 0xf7, 0x32, 0x64, 0xc5, 0x30, 0xc8, 0x69, 0x4f, 0xd0,
		0xf0, 0xfd, 0x95, 0x34, 0xf2, 0x55, 0xc3, 0x29, 0xed, 0x1a, 0x9a, 0x23, 0xaf,
		0x8c, 0x7b, 0x08, 0x84, 0x48, 0xe8, 0x5c, 0x9b, 0x91, 0x9c, 0x7a, 0x2c, 0x74,
		0xf2, 0x38, 0x04, 0x38, 0x90, 0x06, 0x67, 0x8f
	};
	unsigned int data_Normal_blob_len = sizeof(data_Normal_blob);

	unsigned char data_Secure_blob[] = {
		0x42, 0x42, 0x4e, 0x41, 0xaf, 0x32, 0x34, 0x49, 0xe8, 0xa6, 0xdb, 0xcf, 0xd7,
		0xa4, 0xe7, 0x43, 0x23, 0x4f, 0x63, 0xc8, 0x5c, 0xbe, 0x65, 0xff, 0xe1, 0x64,
		0x66, 0x36, 0x00, 0x00, 0x00, 0x22, 0x88, 0xe5, 0x86, 0x32, 0xc9, 0xc8, 0x4c,
		0x9e, 0x44, 0xc6, 0x9b, 0x01, 0x50, 0xe1, 0x02, 0x3d, 0x53, 0x87, 0x54, 0x1a,
		0x75, 0xbf, 0x2e, 0xb2, 0x66, 0x22, 0xfe, 0x8c, 0x09, 0x80, 0x53, 0x69, 0xb5,
		0x5c
	};
	unsigned int data_Secure_blob_len = sizeof(data_Secure_blob);

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
	if (!(fp1 = fopen((const char *)FDO_CRED_NORMAL, "w"))) {
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
	if (!(fp1 = fopen((const char *)FDO_CRED_SECURE, "w"))) {
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
	return 0;
err:
	if (fp1) {
		fclose(fp1);
		fp1 = NULL;
	}
	return -1;
}

static fdo_sdk_service_info_module *fdo_sv_info_modules_init(void)
{
	fdo_sdk_service_info_module *module_info = NULL;
	module_info = fdo_alloc(FDO_MAX_MODULES * (sizeof(fdo_sdk_service_info_module)));
	if (!module_info) {
		LOG(LOG_ERROR, "Malloc failed!\n");
		return NULL;
	}
	if (strncpy_s(module_info[0].module_name, FDO_MODULE_NAME_LEN,
		      "fdo_sys", FDO_MODULE_NAME_LEN) != 0) {
		LOG(LOG_ERROR, "Strcpy failed");
		free(module_info);
		return NULL;
	}
	module_info[0].service_info_callback = fdo_sys;
	return module_info;
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("read_normal_device_credentials", "[credentials][fdo]")
#else
void test_read_normal_device_credentials(void)
#endif
{
#if !defined (AES_MODE_GCM_ENABLED) || AES_BITS != 256
	TEST_IGNORE();
#endif
	int ret = -1;

	fdo_sdk_service_info_module *module_info = NULL;
	module_info = fdo_sv_info_modules_init();
	TEST_ASSERT_NOT_NULL(module_info);
	ret = fdo_sdk_init(NULL, FDO_MAX_MODULES, module_info);
	TEST_ASSERT_EQUAL(FDO_SUCCESS, ret);

	configure_blobs();
	ret = load_device_secret();
	TEST_ASSERT_NOT_EQUAL(-1, ret);

	fdo_dev_cred_t *normal_cred = app_get_credentials();

	// Negative case - no credentials file
	ret = read_normal_device_credentials(NULL, FDO_SDK_NORMAL_DATA,
					     normal_cred);
	TEST_ASSERT_FALSE(ret);

	// Invalid flags - leads to file not being read, i.e DI not done
	ret = read_normal_device_credentials((char *)FDO_CRED_NORMAL, 0,
					     normal_cred);
	TEST_ASSERT_TRUE(ret);

	// Normal use-case
	ret = read_normal_device_credentials((char *)FDO_CRED_NORMAL,
					     FDO_SDK_NORMAL_DATA, normal_cred);
	TEST_ASSERT_TRUE(ret);

	if (normal_cred) {
		fdo_dev_cred_free(normal_cred);
	}
	fdo_sdk_deinit();
	fdo_free(module_info);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("read_secure_device_credentials", "[credentials][fdo]")
#else
void test_read_secure_device_credentials(void)
#endif
{
#if !defined (AES_MODE_GCM_ENABLED) || AES_BITS != 256
	TEST_IGNORE();
#endif
	int ret = -1;

	fdo_sdk_service_info_module *module_info = NULL;
	module_info = fdo_sv_info_modules_init();
	TEST_ASSERT_NOT_NULL(module_info);
	ret = fdo_sdk_init(NULL, FDO_MAX_MODULES, module_info);
	TEST_ASSERT_EQUAL(FDO_SUCCESS, ret);

	configure_blobs();

	fdo_dev_cred_t *secure_cred = app_get_credentials();

	// Normal use-case
	ret = read_secure_device_credentials((char *)FDO_CRED_SECURE,
					     FDO_SDK_SECURE_DATA, secure_cred);
	TEST_ASSERT_TRUE(ret);

	// Negative case - no credentials file
	ret = read_secure_device_credentials(NULL, FDO_SDK_SECURE_DATA,
					     secure_cred);
	TEST_ASSERT_FALSE(ret);

	// Invalid flags - leads to file not being read, i.e DI not done
	ret = read_secure_device_credentials((char *)FDO_CRED_SECURE, 0,
					     secure_cred);
	TEST_ASSERT_TRUE(ret);

	if (secure_cred) {
		fdo_dev_cred_free(secure_cred);
	}
	fdo_sdk_deinit();
	fdo_free(module_info);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("load_credential", "[credentials][fdo]")
#else
void test_load_credential(void)
#endif
{
#if !defined(AES_MODE_GCM_ENABLED) || AES_BITS != 256
	TEST_IGNORE();
#endif
	int ret = -1;
	fdo_sdk_service_info_module *module_info = NULL;
	module_info = fdo_sv_info_modules_init();
	TEST_ASSERT_NOT_NULL(module_info);
	ret = fdo_sdk_init(NULL, FDO_MAX_MODULES, module_info);
	TEST_ASSERT_EQUAL(FDO_SUCCESS, ret);

	/* Negative case*/
	g_malloc_fail = true;
	ret = load_credential(NULL);
	TEST_ASSERT_EQUAL(-1, ret);

	g_malloc_fail = false;
	fdo_dev_cred_t *ocred = app_alloc_credentials();
	TEST_ASSERT_NOT_NULL(ocred);
	fdo_dev_cred_init(ocred);

	ret = load_credential(ocred);
	TEST_ASSERT_EQUAL(0, ret);

	configure_blobs();
	ret = load_credential(ocred);
	TEST_ASSERT_EQUAL(0, ret);

	fdo_sdk_deinit();
	fdo_free(module_info);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("read_write_Device_credentials", "[credentials][fdo]")
#else
void test_read_write_Device_credentials(void)
#endif
{
#if !defined (AES_MODE_GCM_ENABLED) || AES_BITS != 256
	TEST_IGNORE();
#endif
	int ret = -1;

	fdo_sdk_service_info_module *module_info = NULL;
	module_info = fdo_sv_info_modules_init();
	TEST_ASSERT_NOT_NULL(module_info);
	ret = fdo_sdk_init(NULL, FDO_MAX_MODULES, module_info);
	TEST_ASSERT_EQUAL(FDO_SUCCESS, ret);

	// write the pre-requisite blobs using file writers,
	// load/read them into internal structures
	// then, write the same back into blobs, using library.
	configure_blobs();

	ret = load_device_secret();
	TEST_ASSERT_EQUAL_INT(0, ret);

	fdo_dev_cred_t *ocred = app_get_credentials();
	ret = read_normal_device_credentials((char *)FDO_CRED_NORMAL,
					     FDO_SDK_NORMAL_DATA, ocred);
	TEST_ASSERT_TRUE(ret);

	ret = read_secure_device_credentials((char *)FDO_CRED_SECURE,
					     FDO_SDK_SECURE_DATA, ocred);
	TEST_ASSERT_TRUE(ret);

	ret = write_normal_device_credentials((char *)FDO_CRED_NORMAL,
					      FDO_SDK_NORMAL_DATA, ocred);
	TEST_ASSERT_TRUE(ret);

	ret = write_normal_device_credentials(NULL,
					      FDO_SDK_NORMAL_DATA, ocred);
	TEST_ASSERT_FALSE(ret);

	ret = write_secure_device_credentials((char *)FDO_CRED_SECURE,
					      FDO_SDK_SECURE_DATA, ocred);
	TEST_ASSERT_TRUE(ret);

	ret = write_secure_device_credentials(NULL,
					      FDO_SDK_SECURE_DATA, ocred);
	TEST_ASSERT_FALSE(ret);

	fdo_sdk_deinit();
	fdo_free(module_info);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("store_credential", "[credentials][fdo]")
#else
void test_store_credential(void)
#endif
{
#if !defined (AES_MODE_GCM_ENABLED) || AES_BITS != 256
	TEST_IGNORE();
#endif
	int ret = -1;

	fdo_sdk_service_info_module *module_info = NULL;
	module_info = fdo_sv_info_modules_init();
	TEST_ASSERT_NOT_NULL(module_info);
	ret = fdo_sdk_init(NULL, FDO_MAX_MODULES, module_info);
	TEST_ASSERT_EQUAL(FDO_SUCCESS, ret);

	// write the pre-requisite blobs using file writers,
	// load/read them into internal structures
	// then, write the same back into blobs, using library.
	configure_blobs();

	ret = load_device_secret();
	TEST_ASSERT_EQUAL_INT(0, ret);

	fdo_dev_cred_t *ocred = app_get_credentials();
	// Positive Case
	ret = store_credential(ocred);
	TEST_ASSERT_EQUAL(0, ret);

	if (ocred) {
		fdo_dev_cred_free(ocred);
	}
	fdo_sdk_deinit();
	fdo_free(module_info);
}

