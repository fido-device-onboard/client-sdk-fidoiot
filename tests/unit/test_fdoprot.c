/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for fdo_prot of FDO library.
 */

#include "safe_lib.h"
#include "util.h"
#include "fdotypes.h"
#include "fdoprot.h"
#include "unity.h"
#include "load_credentials.h"
#include "platform_utils.h"

#ifdef TARGET_OS_LINUX
/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
fdo_key_value_t **__wrap_fdo_service_info_get(fdo_service_info_t *si,
					      int key_num);
fdo_dev_cred_t *__wrap_app_get_credentials(void);
bool __wrap_fdo_prot_rcv_msg(fdor_t *fdor, fdow_t *fdow, char *prot_name,
			     int *statep);
fdo_cred_mfg_t *__wrap_fdo_cred_mfg_alloc(void);
bool __wrap_fdo_begin_write_signature(fdow_t *fdow, fdo_sig_t *sig,
				      fdo_public_key_t *pk);
void __wrap_fdo_byte_array_write_chars(fdow_t *fdow, fdo_byte_array_t *ba);
void test_fdo_protDIRun(void);
void test_fdo_protTO2Run(void);
int dummy(fdor_t *a, int b);

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
#endif

static bool fdoserviceinfo = false;
extern fdo_key_value_t **__real_fdo_service_info_get(fdo_service_info_t *si,
						     int key_num);
fdo_key_value_t **__wrap_fdo_service_info_get(fdo_service_info_t *si,
					      int key_num)
{
	fdo_key_value_t **temp = fdo_alloc(sizeof(fdo_key_value_t));
	if (fdoserviceinfo)
		return temp;
	else
		return __real_fdo_service_info_get(si, key_num);
}

static bool get_credentials = false;
extern fdo_dev_cred_t *__real_app_get_credentials(void);
fdo_dev_cred_t *__wrap_app_get_credentials(void)
{
	if (get_credentials)
		return NULL;
	else
		return __real_app_get_credentials();
}

static bool fdoprotrcv = false;
extern bool __real_fdo_prot_rcv_msg(fdor_t *fdor, fdow_t *fdow, char *prot_name,
				    int *statep);
bool __wrap_fdo_prot_rcv_msg(fdor_t *fdor, fdow_t *fdow, char *prot_name,
			     int *statep)
{
	if (fdoprotrcv)
		return true;
	else
		return __real_fdo_prot_rcv_msg(fdor, fdow, prot_name, statep);
}

bool fdocredmfg = false;
extern fdo_cred_mfg_t *__real_fdo_cred_mfg_alloc(void);
fdo_cred_mfg_t *__wrap_fdo_cred_mfg_alloc(void)
{
	if (fdocredmfg)
		return NULL;
	else
		return __real_fdo_cred_mfg_alloc();
}
bool fdobeginwrite = false;
extern bool __real_fdo_begin_write_signature(fdow_t *fdow, fdo_sig_t *sig,
					     fdo_public_key_t *pk);
bool __wrap_fdo_begin_write_signature(fdow_t *fdow, fdo_sig_t *sig,
				      fdo_public_key_t *pk)
{
	if (fdobeginwrite)
		return true;
	else
		return __real_fdo_begin_write_signature(fdow, sig, pk);
}

bool fdobytearraywrite = false;
extern void __real_fdo_byte_array_write_chars(fdow_t *fdow,
					      fdo_byte_array_t *ba);
void __wrap_fdo_byte_array_write_chars(fdow_t *fdow, fdo_byte_array_t *ba)
{
	if (fdobytearraywrite)
		return;
	else
		__real_fdo_byte_array_write_chars(fdow, ba);
}

/* write Normal blob with hmac */
static int32_t configureWNormal_blob(void)
{
	FILE *fp1 = NULL;
	size_t bytes_written = 0;

	unsigned char hmac_key[] = {
	    0x71, 0xa8, 0xa9, 0x44, 0x5d, 0xea, 0xa9, 0x1c, 0x49, 0x33, 0x39,
	    0xcc, 0x6d, 0x50, 0xd7, 0x13, 0xc2, 0x6a, 0x7d, 0x2c, 0xcc, 0x1a,
	    0x5f, 0x39, 0x3f, 0xd0, 0x44, 0x54, 0x08, 0xe5, 0x06, 0xd9};

	unsigned char data_Normal_blob[] = {
	    0xb9, 0x62, 0x89, 0xdd, 0x78, 0xe3, 0xdd, 0x52, 0x0e, 0x97, 0xd6,
	    0x9d, 0x15, 0xa4, 0x38, 0xcb, 0x60, 0xcc, 0x99, 0xe1, 0x8e, 0x8d,
	    0x87, 0x6f, 0x0a, 0x0f, 0x8e, 0x8b, 0x5c, 0x69, 0xcd, 0xbe, 0x00,
	    0x00, 0x00, 0x08, 0x7b, 0x22, 0x53, 0x54, 0x22, 0x3a, 0x31, 0x7d};
	unsigned int data_Normal_blob_len = 44;

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

err:
	if (fp1) {
		fclose(fp1);
	}
	return -1;
}
#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_protDIRun", "[PROT][fdo]")
#else
void test_fdo_protDIRun(void)
#endif
{
	bool ret = true;
	fdo_prot_t ps = {0};

	// Negative test cases
	get_credentials = true;

	ret = fdo_process_states(&ps);
	TEST_ASSERT_FALSE(ret);
	get_credentials = false;

	configureWNormal_blob();
	ret = fdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(FDO_SUCCESS, ret);

	fdow_init(&ps.fdow);
	fdor_init(&ps.fdor, NULL, NULL);
	fdoprotrcv = true;
	ps.state = FDO_STATE_DI_APP_START;
	ps.dev_cred = app_get_credentials();
	fdo_process_states(&ps);
	ps.fdor.need_comma = 0;
	ps.fdor.b.cursor = 0;
	ps.fdor.b.block_max = 100;
	ps.fdor.b.block_size = 51;
	ps.fdor.need_comma = false;
	ps.fdor.have_block = true;
	load_mfg_secret();
	char in[100] =
	    "{\"devconfig:read\":\"abcde\",\"devname:maxver\":\"1.11\"}";
	ps.fdor.b.block = (uint8_t *)in;
	ps.dev_cred = app_get_credentials();
	fdocredmfg = true;
	ret = fdo_process_states(&ps);
	TEST_ASSERT_FALSE(ret);
	fdoprotrcv = false;
	fdocredmfg = false;
	if (ps.fdow.b.block)
		free(ps.fdow.b.block);
	fdo_sdk_deinit();
}

int dummy(fdor_t *a, int b)
{
	(void)a;
	(void)b;
	return 0;
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_protTO2Run", "[PROT][fdo]")
#else
void test_fdo_protTO2Run(void)
#endif
{
	fdo_prot_t ps = {0};
	int ret = true;
	ret = fdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(FDO_SUCCESS, ret);
	fdow_init(&ps.fdow);
	fdor_init(&ps.fdor, NULL, NULL);

	ps.fdor.have_block = false;
	ps.fdor.receive = dummy;
	int statep;
	ret = fdo_prot_rcv_msg(&ps.fdor, &ps.fdow, NULL, &statep);
	TEST_ASSERT_FALSE(ret);

	ps.state = FDO_STATE_TO2_RCV_DONE_2;
	ps.round_trip_count = 101;
	ret = fdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = FDO_STATE_T02_RCV_OP_NEXT_ENTRY;
	ret = fdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = FDO_STATE_TO2_RCV_PROVE_OVHDR;
	ret = fdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = FDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO;
	ret = fdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = FDO_STATE_TO2_RCV_SETUP_DEVICE;
	ret = fdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = FDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO;
	ret = fdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = FDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO;
	ps.service_info = fdo_alloc(sizeof(fdo_service_info_t));
	TEST_ASSERT_NOT_NULL(ps.service_info);
	ps.service_info->numKV = 3;
	ps.serv_req_info_num = 5;
	ps.dsi_info = NULL;
	ret = fdo_process_states(&ps);
	fdo_free(ps.service_info);
	TEST_ASSERT_FALSE(ret);

	ps.state = FDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO;
	fdoserviceinfo = true;
	ps.service_info = fdo_alloc(sizeof(fdo_service_info_t));
	TEST_ASSERT_NOT_NULL(ps.service_info);
	ps.service_info->numKV = 3;
	ps.serv_req_info_num = 2;
	ret = fdo_process_states(&ps);
	fdo_free(ps.service_info);
	TEST_ASSERT_FALSE(ret);
	fdoserviceinfo = false;
	if (ps.fdow.b.block)
		free(ps.fdow.b.block);
	fdo_sdk_deinit();
}
