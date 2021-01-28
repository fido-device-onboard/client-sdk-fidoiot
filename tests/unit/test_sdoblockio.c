/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Unit tests for credential store/read routines of SDO library.
 */

#include <errno.h>
#include <inttypes.h>
#include "util.h"
#include "unity.h"
#include "sdoblockio.h"
#include "sdotypes.h"
#include "safe_lib.h"

/*** Unity Declarations ***/
void test_encode_decode(void);

void test_encode_decode(void) {
    LOG(LOG_INFO, "Could not open platform HMAC Key file!\n");
	sdow_t *sdow = sdo_alloc(sizeof(sdow_t));
	sdor_t *sdor = sdo_alloc(sizeof(sdor_t));
    if (!sdow_init(sdow))
        LOG(LOG_ERROR, "Failed to initialize sdow\n");
	if (!sdor_init(sdor))
        LOG(LOG_ERROR, "Failed to initialize sdor\n");
	
	uint64_t key1 = 1, key2 = 2;
	int val1 = 50, val2 = 0, val3 = 100;
		
	TEST_ASSERT_TRUE(sdo_block_alloc(&sdow->b));
	TEST_ASSERT_TRUE(sdow_encoder_init(sdow));
	TEST_ASSERT_TRUE(sdo_block_alloc(&sdor->b));

    TEST_ASSERT_TRUE(sdow_start_array(sdow, 1));
	TEST_ASSERT_TRUE(sdow_start_array(sdow, 2));
	TEST_ASSERT_TRUE(sdow_start_map(sdow, 2));
	TEST_ASSERT_TRUE(sdow_unsigned_int(sdow, key1));
	TEST_ASSERT_TRUE(sdow_signed_int(sdow, val1));
	TEST_ASSERT_TRUE(sdow_unsigned_int(sdow, key2));
	sdo_byte_array_t *mstring = sdo_byte_array_alloc(sizeof(sdo_byte_array_t));
	sdow_byte_string(sdow, mstring->bytes, mstring->byte_sz);
	if (memset_s(mstring->bytes, mstring->byte_sz * sizeof(uint8_t), 0) != 0) {
		LOG(LOG_ERROR, "memset() failed!\n");
	}
	TEST_ASSERT_TRUE(sdow_end_map(sdow));
	TEST_ASSERT_TRUE(sdow_signed_int(sdow, val3));
	TEST_ASSERT_TRUE(sdow_end_array(sdow));
	TEST_ASSERT_TRUE(sdow_end_array(sdow));

    long unsigned i;
    size_t finalLength;
    TEST_ASSERT_TRUE(sdow_encoded_length(sdow, &finalLength));
	LOG(LOG_INFO, "\nEncoded Length : %zu\n", finalLength);
	for(i=0; i<finalLength; i++) {
		LOG(LOG_INFO, "%02x", sdow->b.block[i]);
	}
	LOG(LOG_INFO, "\nEncoding finished successfully\n");
	sdow->b.block_size = finalLength;

	sdor->b.block_size = finalLength;
	memcpy_s(sdor->b.block, CBOR_BUFFER_LENGTH, sdow->b.block, sdow->b.block_size);
	TEST_ASSERT_TRUE(sdor_parser_init(sdor));
	TEST_ASSERT_TRUE(sdor_start_array(sdor));
	TEST_ASSERT_TRUE(sdor_start_array(sdor));
	TEST_ASSERT_TRUE(sdor_start_map(sdor));
	uint64_t item1;
	TEST_ASSERT_TRUE(sdor_unsigned_int(sdor, &item1));
	TEST_ASSERT_EQUAL_UINT64(item1, key1);
    int item2;
	TEST_ASSERT_TRUE(sdor_signed_int(sdor, &item2));
	TEST_ASSERT_EQUAL_INT(item2, val1);
	uint64_t item3;
	TEST_ASSERT_TRUE(sdor_unsigned_int(sdor, &item3));
	TEST_ASSERT_EQUAL_UINT64(item3, key2);
	size_t length;
	TEST_ASSERT_TRUE(sdor_string_length(sdor, &length));
	uint8_t *item4 = sdo_alloc(length);
	TEST_ASSERT_TRUE(sdor_byte_string(sdor, item4, length));
	int cmp;
	memcmp_s(item4, length, mstring->bytes, mstring->byte_sz, &cmp);
	TEST_ASSERT_EQUAL_INT(cmp, val2);
	TEST_ASSERT_TRUE(sdor_end_map(sdor));
	int item5;
	TEST_ASSERT_TRUE(sdor_signed_int(sdor, &item5));
	TEST_ASSERT_EQUAL_INT(item5, val3);
	TEST_ASSERT_TRUE(sdor_end_array(sdor));
	TEST_ASSERT_TRUE(sdor_end_array(sdor));
	LOG(LOG_INFO, "\nDecoding finished successfully\n");
	sdow_flush(sdow);
	sdor_flush(sdor);
}