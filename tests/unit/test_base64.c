/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for base64 encoding/decoding routines of SDO library.
 */

#include "base64.h"
#include "util.h"
#include "unity.h"

#define NO_OFFSET 0
#define TEST_OFFSET 1

extern uint8_t *g_b64To_bin;
extern uint8_t g_bin_toB64[];
extern int g_ch_equals;

#ifdef TARGET_OS_LINUX
uint8_t *_test_b64To_bin;
/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
void test_bin_toB64Length(void);
void test_b64To_bin_length(void);
void test_bin_toB64(void);
void test_b64To_bin(void);

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

#ifdef TARGET_OS_FREERTOS
TEST_CASE("bin_toB64Length", "[base64][sdo]")
#else
void test_bin_toB64Length(void)
#endif
{
	/* Test for a length of 0. */
	TEST_ASSERT_EQUAL_INT(0, bin_toB64Length(0));
	/* Test for n%3 == 1. */
	TEST_ASSERT_EQUAL_INT(8, bin_toB64Length(4));
	/* Test for n%3 == 2. */
	TEST_ASSERT_EQUAL_INT(8, bin_toB64Length(5));
	/* Test for n%3 == 0. */
	TEST_ASSERT_EQUAL_INT(8, bin_toB64Length(6));
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("b64To_bin_length", "[base64][sdo]")
#else
void test_b64To_bin_length(void)
#endif
{
	/* Check that 0 is returned when length is 0. */
	TEST_ASSERT_EQUAL_INT(0, b64To_bin_length(0));

	/*
	 * Check that length greater than or equal to a byte doesn't return 0.
	 */
	TEST_ASSERT_NOT_EQUAL(0, b64To_bin_length(4));
	TEST_ASSERT_NOT_EQUAL(0, b64To_bin_length(6));

	/*
	 * Test that the returned length is correct for one byte of padding,
	 * first without and then with an offset.
	 */
	// TEST_ASSERT_EQUAL_INT(4, b64To_bin_length(8));

	// TEST_ASSERT_EQUAL_INT(6, b64To_bin_length(8, b64val2, TEST_OFFSET));

	/*
	 * Test that the returned length is correct for two bytes of padding,
	 * first without and then with an offset.
	 */
	// uint8_t b64val3[9] = {1, 2, 3, 4, 5, 6, '=', '='};
	// TEST_ASSERT_EQUAL_INT(4, b64To_bin_length(8, b64val3, NO_OFFSET));
	// TEST_ASSERT_EQUAL_INT(6, b64To_bin_length(8, b64val3, TEST_OFFSET));

	/*
	 * Test that the returned length is correct with no padding,
	 * first without and then with an offset.
	 */
	// uint8_t b64val4[9] = {1, 2, 3, 4, 5, 6, 7, 8};
	// TEST_ASSERT_EQUAL_INT(6, b64To_bin_length(8, b64val4, NO_OFFSET));
	// TEST_ASSERT_EQUAL_INT(6, b64To_bin_length(8, b64val4, TEST_OFFSET));
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("bin_toB64", "[base64][sdo]")
#else
void test_bin_toB64(void)
#endif
{
	/* Check that 0 is returned if Base64 is not initialised. */
	uint8_t *bin_bytes = 0;
	uint8_t *b64Bytes = 0;

	TEST_ASSERT_EQUAL_INT(
	    -1, bin_toB64(0, bin_bytes, NO_OFFSET, 0, b64Bytes, NO_OFFSET));

	/* Check that an input of length 0 returns 0. */
	TEST_ASSERT_EQUAL_INT(
	    -1, bin_toB64(0, bin_bytes, NO_OFFSET, 0, b64Bytes, NO_OFFSET));

	/*
	 * Test that an input of 3 binary bytes correctly returns 4 base64 bytes
	 * with no padding, and then check that the converted bytes are correct.
	 */
	uint8_t bin_bytes2[] = {'_', '3', '?'};
	uint8_t b64Bytes2[5];
	uint8_t test_b64Bytes2[] = {'X', 'z', 'M', '/'};

	TEST_ASSERT_EQUAL_INT(
	    4, bin_toB64(3, bin_bytes2, NO_OFFSET, 5, b64Bytes2, NO_OFFSET));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(test_b64Bytes2, b64Bytes2, 4);

	/*
	 * Test that an input of 4 binary bytes correctly returns 8 base64 bytes
	 * with two bytes of padding added, and check that the returned bytes
	 * are
	 * correct.
	 */
	uint8_t bin_bytes3[] = {'_', '3', '?', '9'};
	uint8_t b64Bytes3[9];
	uint8_t test_b64Bytes3[] = {'X', 'z', 'M', '/', 'O', 'Q', '=', '='};

	TEST_ASSERT_EQUAL_INT(
	    8, bin_toB64(4, bin_bytes3, NO_OFFSET, 9, b64Bytes3, NO_OFFSET));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(test_b64Bytes3, b64Bytes3, 8);

	/*
	 * Test that an input of 5 binary bytes correctly returns 8 base64 bytes
	 * with one byte of padding added, and check that the returned bytes are
	 * correct.
	 */
	uint8_t bin_bytes4[] = {'_', '3', '?', '9', '!'};
	uint8_t b64Bytes4[9];
	uint8_t test_b64Bytes4[] = {'X', 'z', 'M', '/', 'O', 'S', 'E', '='};

	TEST_ASSERT_EQUAL_INT(
	    8, bin_toB64(5, bin_bytes4, NO_OFFSET, 9, b64Bytes4, NO_OFFSET));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(test_b64Bytes4, b64Bytes4, 8);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("b64To_bin", "[base64][sdo]")
#else
void test_b64To_bin(void)
#endif
{
	/* Check that 0 is returned if Base64 is not initialised. */
	uint8_t *bin_bytes = 0;
	uint8_t *b64Bytes = 0;

	TEST_ASSERT_EQUAL_INT(
	    -1, b64To_bin(0, b64Bytes, NO_OFFSET, 0, bin_bytes, NO_OFFSET));

	/* Check that an input length of 0 returns 0. */

	TEST_ASSERT_EQUAL_INT(
	    -1, b64To_bin(0, b64Bytes, NO_OFFSET, 0, bin_bytes, NO_OFFSET));

	/*
	 * Check that 0 is returned if the input is not a multiple of 4 base64
	 * bytes.
	 */
	uint8_t b64Bytes2[] = {'X', 'z', 'M'};
	uint8_t bin_bytes2[4];

	TEST_ASSERT_EQUAL_INT(
	    0, b64To_bin(3, b64Bytes2, NO_OFFSET, 4, bin_bytes2, NO_OFFSET));

	/*
	 * Test that an input of 4 base64 bytes correctly returns 3 binary bytes
	 * with no padding, and check that the returned bytes are correct.
	 */
	uint8_t b64Bytes3[] = {'X', 'z', 'M', '/'};
	uint8_t bin_bytes3[3];
	uint8_t test_bin_bytes3[] = {'_', '3', '?'};

	TEST_ASSERT_EQUAL_INT(
	    3, b64To_bin(4, b64Bytes3, NO_OFFSET, 4, bin_bytes3, NO_OFFSET));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(test_bin_bytes3, bin_bytes3, 3);

	/*
	 * Test that an input of 8 base64 bytes that includes one byte of
	 * padding correctly
	 * returns 5 binary bytes and check that the returned bytes are correct.
	 */
	uint8_t b64Bytes4[] = {'X', 'z', 'M', '/', 'O', 'S', 'E', '='};
	uint8_t bin_bytes4[5];
	uint8_t test_bin_bytes4[] = {'_', '3', '?', '9', '!'};

	TEST_ASSERT_EQUAL_INT(
	    5, b64To_bin(8, b64Bytes4, NO_OFFSET, 6, bin_bytes4, NO_OFFSET));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(test_bin_bytes4, bin_bytes4, 5);

	/*
	 * Test that an input of 8 base64 bytes that includes two bytes of
	 * padding correctly
	 * returns 4 binary bytes and check that the returned bytes are correct.
	 */
	uint8_t b64Bytes5[] = {'X', 'z', 'M', '/', 'O', 'S', '=', '='};
	uint8_t bin_bytes5[5];
	uint8_t test_bin_bytes5[] = {'_', '3', '?', '9'};

	TEST_ASSERT_EQUAL_INT(
	    4, b64To_bin(8, b64Bytes5, NO_OFFSET, 5, bin_bytes5, NO_OFFSET));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(test_bin_bytes5, bin_bytes5, 4);

	/*
	 * Test the input contains the character which is not base64 and
	 * which returns -1.
	 */
	uint8_t b64Bytes6[] = {'g', '^', 'u', 'y', 'u', 'S', 'y', 't'};
	uint8_t bin_bytes6[5];

	TEST_ASSERT_EQUAL_INT(
	    -1, b64To_bin(8, b64Bytes6, NO_OFFSET, 5, bin_bytes6, NO_OFFSET));

#if 0
	// Opnessl does not handle last char as '=' and process the input as it is
	// Test is disabled, but works fine for mbetls since it handles the sasme.
	/*
	 * Test the wrong base64 input, where last char is not equal to '='
	 * but last but one char is =, this shall through the error
	 */
	uint8_t b64Bytes7[] = {'g', 'y', 'u', 'y', 'u', 'S', '=', 't'};
	uint8_t bin_bytes7[5];

	TEST_ASSERT_EQUAL_INT(
	    -1, b64To_bin(7, b64Bytes7, NO_OFFSET, 4, bin_bytes7, NO_OFFSET));
#endif
}
