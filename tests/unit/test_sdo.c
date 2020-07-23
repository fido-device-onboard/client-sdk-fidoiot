/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for SDO library entry/exit APIs.
 */

#include "unity.h"
#include "safe_lib.h"
#include "util.h"
#include "sdo.h"
#include "load_credentials.h"
#include "sdotypes.h"
#include "sdomodules.h"
#include "storage_al.h"

/*
#define HEXDEBUG 1
*/

// SDO Device States
#define SDO_DEVICE_STATE_PD 0     // Permanently Disabled
#define SDO_DEVICE_STATE_PC 1     // Pre-Configured
#define SDO_DEVICE_STATE_D 2      // Disabled
#define SDO_DEVICE_STATE_READY1 3 // Initial Transfer Ready
#define SDO_DEVICE_STATE_D1 4     // Initial Transfer Disabled
#define SDO_DEVICE_STATE_IDLE 5   // SDO Idle
#define SDO_DEVICE_STATE_READYN 6 // Transfer Ready
#define SDO_DEVICE_STATE_DN 7     // Transfer Disabled

bool sdoR_fail = false;
bool sdoW_fail = false;
bool kex_fail = false;
bool ip_fail = false;
bool pkalloc_fail = false;
bool store_pass = false;
bool alloc_fail_case = false;
bool g_memset_fail = false;
bool g_malloc_fail = false;

void *__real_sdo_alloc(size_t bytes);
bool __real_sdow_init(sdow_t *sdow);
bool __real_sdor_init(sdor_t *sdor);
errno_t __real_memset_s(void *dest, rsize_t len, uint8_t value);
sdo_dev_cred_t *__real_app_alloc_credentials(void);
void *__real_key_exchange_init(void);
bool __real_sdo_null_ipaddress(sdo_ip_address_t *sdoip);
int __real_store_credential(sdo_dev_cred_t *ocred);

#ifdef TARGET_OS_FREERTOS
extern bool g_simul_sdo_crypto_init_error;
#endif

#ifdef TARGET_OS_LINUX
/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
int __wrap_sdo_crypto_init(void);
void *__wrap_sdo_alloc(size_t bytes);
errno_t __wrap_memset_s(void *dest, rsize_t len, uint8_t value);
bool __wrap_sdor_init(sdor_t *sdor);
bool __wrap_sdow_init(sdow_t *sdow);
sdo_dev_cred_t *__wrap_app_alloc_credentials(void);
bool __wrap_sdo_null_ipaddress(sdo_ip_address_t *sdoip);
int __wrap_store_credential(sdo_dev_cred_t *ocred);
void test_sdo_sdk_run(void);
void test_sdo_resale(void);
void test_sdo_sdk_service_info_register_module(void);
int CB_1(sdo_sdk_si_type t1, int *l1, sdo_sdk_si_key_value *s1);
int CB_2(sdo_sdk_si_type t2, int *l2, sdo_sdk_si_key_value *s2);
int CB_3(sdo_sdk_si_type t3, int *l3, sdo_sdk_si_key_value *s3);

/*** Unity functions. ***/
/**
 * set_up function is called at the beginning of each test-case in unity
 * framework. Declare, Initialize all mandatory variables needed at the start
 * to execute the test-case.
 * @return none.
 */
void set_up(void)
{
}

void tear_down(void)
{
}

bool sdo_crypto_init_fail_case = false;
int __real_sdo_crypto_init(void);
int __wrap_sdo_crypto_init(void)
{
	if (sdo_crypto_init_fail_case) {
		return -1;
	} else {
		return __real_sdo_crypto_init();
	}
}

#endif
void *__wrap_sdo_alloc(size_t bytes)
{
	if (g_malloc_fail)
		return NULL;
	else
		return __real_sdo_alloc(bytes);
}

errno_t __wrap_memset_s(void *dest, rsize_t len, uint8_t value)
{
	if (g_memset_fail)
		return SDO_ERROR;
	else
		return __real_memset_s(dest, len, value);
}

bool __wrap_sdor_init(sdor_t *sdor)
{
	if (sdoR_fail)
		return false;
	else
		return __real_sdor_init(sdor);
}

bool __wrap_sdow_init(sdow_t *sdow)
{
	if (sdoW_fail)
		return false;
	else
		return __real_sdow_init(sdow);
}

sdo_dev_cred_t *__wrap_app_alloc_credentials(void)
{
	if (alloc_fail_case)
		return NULL;
	else
		return __real_app_alloc_credentials();
}
/*
void *__wrap_key_exchange_init(void)
{
	if (kex_fail)
		return NULL;
	return __real_key_exchange_init();
}
*/
bool __wrap_sdo_null_ipaddress(sdo_ip_address_t *sdoip)
{
	if (ip_fail)
		return false;
	return __real_sdo_null_ipaddress(sdoip);
}

int __wrap_store_credential(sdo_dev_cred_t *ocred)
{
	if (store_pass)
		return 0;
	else
		return __real_store_credential(ocred);
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_sdk_run(void)
#else
TEST_CASE("sdo_sdk_run", "[sdo_sdk_run][sdo]")
#endif
{
	int ret = 1;
#ifdef MODULES_ENABLED
/* Negative Test Case */
#ifdef TARGET_OS_FREERTOS
	g_simul_sdo_crypto_init_error = true;
#else
	sdo_crypto_init_fail_case = true;
#endif
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL_MESSAGE(SDO_ERROR, ret, "SDO Failed");
#ifdef TARGET_OS_FREERTOS
	g_simul_sdo_crypto_init_error = false;
#else
	sdo_crypto_init_fail_case = false;
#endif

	g_malloc_fail = true;
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL_MESSAGE(SDO_ERROR, ret, "sdosdk_Init Failed");
	g_malloc_fail = false;

	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	/* Negative Test Case */
	sdoW_fail = true;
	ret = sdo_sdk_run();
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	sdoW_fail = false;
	sdo_sdk_deinit();

	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	/* Negative Test Case */
	sdoR_fail = true;
	ret = sdo_sdk_run();
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	sdoR_fail = false;
	sdo_sdk_deinit();

	/* Negative Test Case */
	alloc_fail_case = true;
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	alloc_fail_case = false;
	sdo_sdk_deinit();

	uint8_t buf[BUFF_SIZE_8_BYTES] = "{\"ST\":2}";
	sdo_blob_write((char *)SDO_CRED_NORMAL, SDO_SDK_NORMAL_DATA, buf,
		       BUFF_SIZE_8_BYTES);
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);

	kex_fail = true;
	ret = sdo_sdk_run();
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	kex_fail = false;
	sdo_sdk_deinit();
#else
/* Negative Test Case */
#ifdef TARGET_OS_FREERTOS
	g_simul_sdo_crypto_init_error = true;
#else
	sdo_crypto_init_fail_case = true;
#endif
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
#ifdef TARGET_OS_FREERTOS
	g_simul_sdo_crypto_init_error = false;
#else
	sdo_crypto_init_fail_case = false;
#endif
	sdo_sdk_deinit();

	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL_MESSAGE(SDO_SUCCESS, ret, "sdosdk_Init Failed");

	g_memset_fail = true;
	ret = sdo_sdk_run();
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	g_memset_fail = false;
	sdo_sdk_deinit();

	g_malloc_fail = true;
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL_MESSAGE(SDO_ERROR, ret, "sdosdk_Init Failed");
	g_malloc_fail = false;

	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL_MESSAGE(SDO_SUCCESS, ret, "sdosdk_Init Failed");

	/* Negative Test Case */
	sdoW_fail = true;
	ret = sdo_sdk_run();
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	sdoW_fail = false;
	sdo_sdk_deinit();

	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL_MESSAGE(SDO_SUCCESS, ret, "sdosdk_Init Failed");

	/* Negative Test Case */
	sdoR_fail = true;
	ret = sdo_sdk_run();
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	sdoR_fail = false;
	sdo_sdk_deinit();

	uint8_t buf[BUFF_SIZE_8_BYTES] = "{\"ST\":2}";
	sdo_blob_write((char *)SDO_CRED_NORMAL, SDO_SDK_NORMAL_DATA, buf,
		       BUFF_SIZE_8_BYTES);

	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL_MESSAGE(SDO_SUCCESS, ret, "sdosdk_Init Failed");
	sdo_sdk_deinit();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_resale(void)
#else
TEST_CASE("sdo_sdk_resale", "[sdo_sdk_resale][sdo]")
#endif
{
	int ret;

#ifdef TARGET_OS_FREERTOS
	g_simul_sdo_crypto_init_error = false;
#else
	sdo_crypto_init_fail_case = false;
#endif
	ret = sdo_sdk_init(NULL, 0, NULL);
#ifdef MODULES_ENABLED
	TEST_ASSERT_EQUAL_MESSAGE(SDO_ERROR, ret, "sdosdk_Init Failed");
#else
	TEST_ASSERT_EQUAL_MESSAGE(SDO_SUCCESS, ret, "sdosdk_Init Failed");
#endif

	/* Negative Test Case => bad cred file for resale() */
	// now replace cred file contents to run TO1/TO2(ST=3)
	uint8_t buf[BUFF_SIZE_10_BYTES] = "{\"ST\":3}";
	sdo_blob_write((char *)SDO_CRED_NORMAL, SDO_SDK_NORMAL_DATA, buf,
		       BUFF_SIZE_10_BYTES);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(-1, ret, "sdo_blob_write Failed");

	/* Negative Test Case, resale() NOTREADY */
	ret = sdo_sdk_resale();
	TEST_ASSERT_EQUAL(SDO_RESALE_NOT_READY, ret);

	// now replace cred file contents to run DI(ST=1)
	uint8_t buf1[BUFF_SIZE_10_BYTES] = "{\"ST\":1}";
	ret = sdo_blob_write((char *)SDO_CRED_NORMAL, SDO_SDK_NORMAL_DATA, buf1,
			     BUFF_SIZE_10_BYTES);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(-1, ret, "sdo_blob_write Failed");

	/* Negative Test Case */
	sdoW_fail = true;
	ret = sdo_sdk_resale();
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	sdoW_fail = false;

	/* Negative Test Case */
	sdoR_fail = true;
	ret = sdo_sdk_resale();
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	sdoR_fail = false;

	/* Negative Test Case */
	alloc_fail_case = true;
	ret = sdo_sdk_resale();
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
	alloc_fail_case = false;

	/* Positive Test Case  */
	// now replace cred file contents to run resale(ST=5)
	uint8_t buf2[BUFF_SIZE_8_BYTES] = "{\"ST\":5}";
	sdo_blob_write((char *)SDO_CRED_NORMAL, SDO_SDK_NORMAL_DATA, buf2,
		       BUFF_SIZE_8_BYTES);
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL_MESSAGE(SDO_ERROR, ret, "sdosdk_Init Failed");
	sdo_sdk_deinit();

	// restore real cred file contents
	uint8_t buf3[BUFF_SIZE_8_BYTES] = "{\"ST\":1}";
	sdo_blob_write((char *)SDO_CRED_NORMAL, SDO_SDK_NORMAL_DATA, buf3,
		       BUFF_SIZE_8_BYTES);
	ret = sdo_sdk_init(NULL, 0, NULL);
#ifdef MODULES_ENABLED
	TEST_ASSERT_EQUAL_MESSAGE(SDO_ERROR, ret,
				  "sdosdk_Init Failed: Module Absence");
#else
	TEST_ASSERT_EQUAL_MESSAGE(SDO_SUCCESS, ret, "sdosdk_Init Passed");
#endif

	/*Negative testcase*/
	ret = sdo_sdk_resale();
	TEST_ASSERT_EQUAL(SDO_RESALE_NOT_READY, ret);
	sdo_sdk_deinit();
}

#ifdef MODULES_ENABLED
int CB_1(sdo_sdk_si_type t1, int *l1, sdo_sdk_si_key_value *s1)
{
	(void)t1;
	(void)l1;
	(void)s1;
	return 1;
}

int CB_2(sdo_sdk_si_type t2, int *l2, sdo_sdk_si_key_value *s2)
{
	(void)t2;
	(void)l2;
	(void)s2;
	return 2;
}
int CB_3(sdo_sdk_si_type t3, int *l3, sdo_sdk_si_key_value *s3)
{
	(void)t3;
	(void)l3;
	(void)s3;
	return 3;
}
#endif

void test_sdo_sdk_service_info_register_module(void)
{
#ifdef MODULES_ENABLED
	sdo_sdk_si_type test_par1 = 0;
	int ret = 1, temp = 0;
	int *test_par2 = &temp;
	sdo_sdk_si_key_value test_kv;
	test_kv.key = "test_key";
	test_kv.value = "test_value";

	sdo_sdk_service_info_module modules[3];

	if (strcpy_s(modules[0].module_name, sizeof(modules[0].module_name),
		     "module1") != 0) {
		LOG(LOG_ERROR, "strcpy failed!\n");
		return;
	}
	modules[0].service_info_callback = CB_1;

	if (strcpy_s(modules[1].module_name, sizeof(modules[1].module_name),
		     "module2") != 0) {
		LOG(LOG_ERROR, "strcpy failed!\n");
		return;
	}
	modules[1].service_info_callback = CB_2;

	if (strcpy_s(modules[2].module_name, sizeof(modules[2].module_name),
		     "module3") != 0) {
		LOG(LOG_ERROR, "strcpy failed!\n");
		return;
	}
	modules[2].service_info_callback = CB_3;

	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);

	for (int i = 0; i < 3; i++) {
		sdo_sdk_service_info_register_module(&modules[i]);
	}

	TEST_ASSERT_EQUAL_INT(1, modules[0].service_info_callback(
				     test_par1, test_par2, &test_kv));
	TEST_ASSERT_EQUAL_INT(2, modules[1].service_info_callback(
				     test_par1, test_par2, &test_kv));
	TEST_ASSERT_EQUAL_INT(3, modules[2].service_info_callback(
				     test_par1, test_par2, &test_kv));

	// Negative Test cases
	sdo_sdk_service_info_module module;
	if (memset_s(module.module_name, SDO_MODULE_NAME_LEN, 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return;
	}
	module.service_info_callback = NULL;
	ret = sdo_sdk_init(NULL, 1, &module);
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);

	ret = sdo_sdk_init(NULL, SDO_MAX_MODULES + 1, &module);
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);

	ret = sdo_sdk_init(NULL, 0, &module);
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);

	ret = sdo_sdk_init(NULL, 1, NULL);
	TEST_ASSERT_EQUAL(SDO_ERROR, ret);
#endif
}
