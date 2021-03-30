/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief This is a stub file to demonstrate unity library integration into FDO
 * library.
 */

#include "fdoblockio.h"
#include "unity.h"
#include <stdlib.h>
#include "util.h"

#define WRAPPER_FN_TEST_VAR 5

#ifdef TARGET_OS_LINUX
/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
void test_sample_fdoblockinit(void);
int __wrap_fdo_read_string_sz(fdor_t *fdor);

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

/* If a '-wrap=fdo_resize_block' flag is used at link time, all calls to
 * fdo_resize_block will be directed to this function. */
int __wrap_fdo_read_string_sz(fdor_t *fdor)
{
	(void)fdor;
	return WRAPPER_FN_TEST_VAR;
}
#endif

/*** Test functions. ***/

/* Dummy test function to illustrate that the Intel Secure Device Onboard
 * librarys are being linked correctly. */
void test_sample_fdoblockinit(void)
{
	fdor_t fdor;
	int return_val = 0;
	fdo_block_t *fdob = fdo_alloc(sizeof(fdo_block_t));
	TEST_ASSERT_NOT_NULL(fdob);
	fdo_block_init(fdob);
	fdo_free(fdob);

	fdor.need_comma = 0;
	fdor.b.cursor = 0;
	return_val = fdo_read_string_sz(&fdor);
	/* The return value should be the one from the wrapper function, not the
	 * real function. */
	TEST_ASSERT_EQUAL_INT(WRAPPER_FN_TEST_VAR, return_val);
}
