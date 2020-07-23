/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for sdo_prot of SDO library.
 */

#include "safe_lib.h"
#include "util.h"
#include "sdotypes.h"
#include "sdoprot.h"
#include "unity.h"
#include "load_credentials.h"
#include "platform_utils.h"

#ifdef TARGET_OS_LINUX
/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
sdo_key_value_t **__wrap_sdo_service_info_get(sdo_service_info_t *si, int key_num);
sdo_dev_cred_t *__wrap_app_get_credentials(void);
bool __wrap_sdo_prot_rcv_msg(sdor_t *sdor, sdow_t *sdow, char *prot_name, int *statep);
sdo_cred_mfg_t *__wrap_sdo_cred_mfg_alloc(void);
bool __wrap_sdo_begin_write_signature(sdow_t *sdow, sdo_sig_t *sig, sdo_public_key_t *pk);
void __wrap_sdo_byte_array_write_chars(sdow_t *sdow, sdo_byte_array_t *ba);
void test_sdo_protDIRun(void);
void test_sdo_protTO2Run(void);
int dummy(sdor_t *a, int b);

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

static bool sdoserviceinfo = false;
extern sdo_key_value_t **__real_sdo_service_info_get(sdo_service_info_t *si,
						     int key_num);
sdo_key_value_t **__wrap_sdo_service_info_get(sdo_service_info_t *si,
					      int key_num)
{
	sdo_key_value_t **temp = sdo_alloc(sizeof(sdo_key_value_t));
	if (sdoserviceinfo)
		return temp;
	else
		return __real_sdo_service_info_get(si, key_num);
}

static bool get_credentials = false;
extern sdo_dev_cred_t *__real_app_get_credentials(void);
sdo_dev_cred_t *__wrap_app_get_credentials(void)
{
	if (get_credentials)
		return NULL;
	else
		return __real_app_get_credentials();
}

static bool sdoprotrcv = false;
extern bool __real_sdo_prot_rcv_msg(sdor_t *sdor, sdow_t *sdow, char *prot_name,
				    int *statep);
bool __wrap_sdo_prot_rcv_msg(sdor_t *sdor, sdow_t *sdow, char *prot_name,
			     int *statep)
{
	if (sdoprotrcv)
		return true;
	else
		return __real_sdo_prot_rcv_msg(sdor, sdow, prot_name, statep);
}

bool sdocredmfg = false;
extern sdo_cred_mfg_t *__real_sdo_cred_mfg_alloc(void);
sdo_cred_mfg_t *__wrap_sdo_cred_mfg_alloc(void)
{
	if (sdocredmfg)
		return NULL;
	else
		return __real_sdo_cred_mfg_alloc();
}
bool sdobeginwrite = false;
extern bool __real_sdo_begin_write_signature(sdow_t *sdow, sdo_sig_t *sig,
					     sdo_public_key_t *pk);
bool __wrap_sdo_begin_write_signature(sdow_t *sdow, sdo_sig_t *sig,
				      sdo_public_key_t *pk)
{
	if (sdobeginwrite)
		return true;
	else
		return __real_sdo_begin_write_signature(sdow, sig, pk);
}

bool sdobytearraywrite = false;
extern void __real_sdo_byte_array_write_chars(sdow_t *sdow,
					      sdo_byte_array_t *ba);
void __wrap_sdo_byte_array_write_chars(sdow_t *sdow, sdo_byte_array_t *ba)
{
	if (sdobytearraywrite)
		return;
	else
		__real_sdo_byte_array_write_chars(sdow, ba);
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
err:
	return -1;
}
#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_protDIRun", "[PROT][sdo]")
#else
void test_sdo_protDIRun(void)
#endif
{
	bool ret = true;
	sdo_prot_t ps = {0};

	// Negative test cases
	get_credentials = true;

	ret = sdo_process_states(&ps);
	TEST_ASSERT_FALSE(ret);
	get_credentials = false;

	configureWNormal_blob();
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_SUCCESS, ret);

	sdow_init(&ps.sdow);
	sdor_init(&ps.sdor, NULL, NULL);
	sdoprotrcv = true;
	ps.state = SDO_STATE_DI_APP_START;
	ps.dev_cred = app_get_credentials();
	sdo_process_states(&ps);
	ps.sdor.need_comma = 0;
	ps.sdor.b.cursor = 0;
	ps.sdor.b.block_max = 100;
	ps.sdor.b.block_size = 51;
	ps.sdor.need_comma = false;
	ps.sdor.have_block = true;
	load_mfg_secret();
	char in[100] =
	    "{\"devconfig:read\":\"abcde\",\"devname:maxver\":\"1.11\"}";
	ps.sdor.b.block = (uint8_t *)in;
	ps.dev_cred = app_get_credentials();
	sdocredmfg = true;
	ret = sdo_process_states(&ps);
	TEST_ASSERT_FALSE(ret);
	sdoprotrcv = false;
	sdocredmfg = false;
	if (ps.sdow.b.block)
		free(ps.sdow.b.block);
	sdo_sdk_deinit();
}

int dummy(sdor_t *a, int b)
{
	(void)a; (void)b;
	return 0;
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_protTO2Run", "[PROT][sdo]")
#else
void test_sdo_protTO2Run(void)
#endif
{
	sdo_prot_t ps = {0};
	int ret = true;
	ret = sdo_sdk_init(NULL, 0, NULL);
	TEST_ASSERT_EQUAL(SDO_SUCCESS, ret);
	sdow_init(&ps.sdow);
	sdor_init(&ps.sdor, NULL, NULL);

	ps.sdor.have_block = false;
	ps.sdor.receive = dummy;
	int statep;
	ret = sdo_prot_rcv_msg(&ps.sdor, &ps.sdow, NULL, &statep);
	TEST_ASSERT_FALSE(ret);

	ps.state = SDO_STATE_TO2_RCV_DONE_2;
	ps.round_trip_count = 101;
	ret = sdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = SDO_STATE_T02_RCV_OP_NEXT_ENTRY;
	ret = sdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = SDO_STATE_TO2_RCV_PROVE_OVHDR;
	ret = sdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = SDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO;
	ret = sdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = SDO_STATE_TO2_RCV_SETUP_DEVICE;
	ret = sdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = SDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO;
	ret = sdo_process_states(&ps);
	TEST_ASSERT_TRUE(ret);

	ps.state = SDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO;
	ps.service_info = sdo_alloc(sizeof(sdo_service_info_t));
	TEST_ASSERT_NOT_NULL(ps.service_info);
	ps.service_info->numKV = 3;
	ps.serv_req_info_num = 5;
	ps.dsi_info = NULL;
	ret = sdo_process_states(&ps);
	sdo_free(ps.service_info);
	TEST_ASSERT_FALSE(ret);

	ps.state = SDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO;
	sdoserviceinfo = true;
	ps.service_info = sdo_alloc(sizeof(sdo_service_info_t));
	TEST_ASSERT_NOT_NULL(ps.service_info);
	ps.service_info->numKV = 3;
	ps.serv_req_info_num = 2;
	ret = sdo_process_states(&ps);
	sdo_free(ps.service_info);
	TEST_ASSERT_FALSE(ret);
	sdoserviceinfo = false;
	if (ps.sdow.b.block)
		free(ps.sdow.b.block);
	sdo_sdk_deinit();
}
