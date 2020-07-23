/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for printing and file handling utilities of SDO library.
 */

#include "sdoblockio.h"
#include "unity.h"
#include <stdlib.h>
#include "util.h"
#include "safe_lib.h"
/*** Function Declarations ***/
void set_up(void);
void tear_down(void);
FILE *__wrap_fopen(const char *filename, const char *mode);
int __wrap_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
int __wrap_fclose(FILE *stream);
long int __wrap_ftell(FILE *stream);
void *__wrap_sdo_alloc(size_t size);
void test_file_utils(void);

/*** Unity functions. ***/
/**
 * set_up function is called at the beginning of each test-case in unity
 * framework. Declare, Initialize all mandatory variables needed at the start
 * to execute the test-case.
 * @return none.
 */

#ifdef TARGET_OS_LINUX
void set_up(void)
{
}

void tear_down(void)
{
}
#endif

/*** Wrapper functions (function stubbing). ***/

int __real_fclose(FILE *stream);

#define WRAPPER_FN_TEST_VAR NULL
int fopen_normal = 1;
FILE *__real_fopen(const char *filename, const char *mode);
FILE *__wrap_fopen(const char *filename, const char *mode)
{
	if (fopen_normal)
		return __real_fopen(filename, mode);
	else
		return WRAPPER_FN_TEST_VAR;
}
#define WRAPPER_STR_SIZE 20
int fread_normal = 1;
int __real_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
int __wrap_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	if (fread_normal)
		return __real_fread(ptr, size, nmemb, stream);
	else
		return 0;
}

int __wrap_fclose(FILE *stream)
{
	return __real_fclose(stream);
}
int ftell_normal = 1;
long int __real_ftell(FILE *stream);
long int __wrap_ftell(FILE *stream)
{
	/*set wrong file size intentionally */
	if (!ftell_normal)
		return (__real_ftell(stream) + 100);
	else
		return __real_ftell(stream);
}
#ifdef TARGET_OS_LINUX
bool g_malloc_fail = false;
void *__real_sdo_alloc(size_t size);
void *__wrap_sdo_alloc(size_t size)
{
	if (g_malloc_fail)
		return __real_sdo_alloc(size);
	else
		return NULL;
}
#endif
/*** Test functions. ***/

/* Dummy test function to illustrate that the Intel Secure Device Onboard
 * librarys are being linked correctly. */
#ifndef TARGET_OS_FREERTOS
void test_file_utils(void)
{
	bool bret = true;
	// no filename
	bret = file_exists(NULL);
	TEST_ASSERT_FALSE(bret);

	// filename there but file doesn't exists
	bret = file_exists("hello.txt");
	TEST_ASSERT_FALSE(bret);
}
#endif
