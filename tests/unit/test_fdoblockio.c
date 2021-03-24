/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Unit tests for credential store/read routines of FDO library.
 */

#include <errno.h>
#include <inttypes.h>
#include "util.h"
#include "unity.h"
#include "fdoblockio.h"
#include "fdotypes.h"
#include "safe_lib.h"

/*** Unity Declarations ***/
void test_encode_decode(void);

void test_encode_decode(void) {
    LOG(LOG_INFO, "Could not open platform HMAC Key file!\n");
	fdow_t *fdow = fdo_alloc(sizeof(fdow_t));
	fdor_t *fdor = fdo_alloc(sizeof(fdor_t));
    if (!fdow_init(fdow))
        LOG(LOG_ERROR, "Failed to initialize fdow\n");
	if (!fdor_init(fdor))
        LOG(LOG_ERROR, "Failed to initialize fdor\n");
	
	uint64_t key1 = 1, key2 = 2;
	int val1 = 50, val2 = 0, val3 = 100;
		
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdow->b));
	TEST_ASSERT_TRUE(fdow_encoder_init(fdow));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdor->b));

    TEST_ASSERT_TRUE(fdow_start_array(fdow, 1));
	TEST_ASSERT_TRUE(fdow_start_array(fdow, 2));
	TEST_ASSERT_TRUE(fdow_start_map(fdow, 2));
	TEST_ASSERT_TRUE(fdow_unsigned_int(fdow, key1));
	TEST_ASSERT_TRUE(fdow_signed_int(fdow, val1));
	TEST_ASSERT_TRUE(fdow_unsigned_int(fdow, key2));
	fdo_byte_array_t *mstring = fdo_byte_array_alloc(sizeof(fdo_byte_array_t));
	fdow_byte_string(fdow, mstring->bytes, mstring->byte_sz);
	if (memset_s(mstring->bytes, mstring->byte_sz * sizeof(uint8_t), 0) != 0) {
		LOG(LOG_ERROR, "memset() failed!\n");
	}
	TEST_ASSERT_TRUE(fdow_end_map(fdow));
	TEST_ASSERT_TRUE(fdow_signed_int(fdow, val3));
	TEST_ASSERT_TRUE(fdow_end_array(fdow));
	TEST_ASSERT_TRUE(fdow_end_array(fdow));

    long unsigned i;
    size_t finalLength;
    TEST_ASSERT_TRUE(fdow_encoded_length(fdow, &finalLength));
	LOG(LOG_INFO, "\nEncoded Length : %zu\n", finalLength);
	for(i=0; i<finalLength; i++) {
		LOG(LOG_INFO, "%02x", fdow->b.block[i]);
	}
	LOG(LOG_INFO, "\nEncoding finished successfully\n");
	fdow->b.block_size = finalLength;

	fdor->b.block_size = finalLength;
	memcpy_s(fdor->b.block, CBOR_BUFFER_LENGTH, fdow->b.block, fdow->b.block_size);
	TEST_ASSERT_TRUE(fdor_parser_init(fdor));
	TEST_ASSERT_TRUE(fdor_start_array(fdor));
	TEST_ASSERT_TRUE(fdor_start_array(fdor));
	TEST_ASSERT_TRUE(fdor_start_map(fdor));
	uint64_t item1;
	TEST_ASSERT_TRUE(fdor_unsigned_int(fdor, &item1));
	TEST_ASSERT_EQUAL_UINT64(item1, key1);
    int item2;
	TEST_ASSERT_TRUE(fdor_signed_int(fdor, &item2));
	TEST_ASSERT_EQUAL_INT(item2, val1);
	uint64_t item3;
	TEST_ASSERT_TRUE(fdor_unsigned_int(fdor, &item3));
	TEST_ASSERT_EQUAL_UINT64(item3, key2);
	size_t length;
	TEST_ASSERT_TRUE(fdor_string_length(fdor, &length));
	uint8_t *item4 = fdo_alloc(length);
	TEST_ASSERT_TRUE(fdor_byte_string(fdor, item4, length));
	int cmp;
	memcmp_s(item4, length, mstring->bytes, mstring->byte_sz, &cmp);
	TEST_ASSERT_EQUAL_INT(cmp, val2);
	TEST_ASSERT_TRUE(fdor_end_map(fdor));
	int item5;
	TEST_ASSERT_TRUE(fdor_signed_int(fdor, &item5));
	TEST_ASSERT_EQUAL_INT(item5, val3);
	TEST_ASSERT_TRUE(fdor_end_array(fdor));
	TEST_ASSERT_TRUE(fdor_end_array(fdor));
	LOG(LOG_INFO, "\nDecoding finished successfully\n");
	fdow_flush(fdow);
	fdor_flush(fdor);
}