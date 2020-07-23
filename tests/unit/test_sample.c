/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief This is a stub file to demonstrate unity library integration into SDO
 * library.
 */

#include "sdoblockio.h"
#include "unity.h"
#include <stdlib.h>
#include "util.h"

#define WRAPPER_FN_TEST_VAR 5

#ifdef TARGET_OS_LINUX
/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
void test_sample_sdoblockinit(void);
int __wrap_sdo_read_string_sz(sdor_t *sdor);

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

/*** Wrapper functions (function stubbing). ***/

/* If a '-wrap=sdo_resize_block' flag is used at link time, all calls to
 * sdo_resize_block will be directed to this function. */
int __wrap_sdo_read_string_sz(sdor_t *sdor)
{
	(void)sdor;
	return WRAPPER_FN_TEST_VAR;
}
#endif

/*** Test functions. ***/

/* Dummy test function to illustrate that the Intel Secure Device Onboard
 * librarys are being linked correctly. */
void test_sample_sdoblockinit(void)
{
	sdor_t sdor;
	int return_val = 0;
	sdo_block_t *sdob = sdo_alloc(sizeof(sdo_block_t));
	TEST_ASSERT_NOT_NULL(sdob);
	sdo_block_init(sdob);
	sdo_free(sdob);

	sdor.need_comma = 0;
	sdor.b.cursor = 0;
	return_val = sdo_read_string_sz(&sdor);
	/* The return value should be the one from the wrapper function, not the
	 * real function. */
	TEST_ASSERT_EQUAL_INT(WRAPPER_FN_TEST_VAR, return_val);
}
