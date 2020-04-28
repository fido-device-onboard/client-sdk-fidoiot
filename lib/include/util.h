/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Printing and file handling utilities interface.
 */
#ifndef __UTIL_H__
#define __UTIL_H__

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef TARGET_OS_OPTEE
#include <tee_api.h>
#define sdo_free(x)                                                            \
	{                                                                      \
		TEE_Free(x);                                                   \
		x = NULL;                                                      \
	}

int atoi(char *ptr);
int isalnum(int c);
#else
#define sdo_free(x)                                                            \
	{                                                                      \
		free(x);                                                       \
		x = NULL;                                                      \
	}
#endif

#define b64char_check(y)                                                       \
	if (!(isalnum(y) || '+' == y || '/' == y || '=' == y)) {               \
		return -1;                                                     \
	}

/* Printing priorities. */
typedef enum log_level {
	LOG_ERROR,
	LOG_INFO,
	LOG_DEBUG,
	LOG_DEBUGNTS, /*Debug No Time Stamp*/
} log_level_t;

#define LOG_MAX_LEVEL 3 /* LOG_MAX_LEVEL = LOG_DEBUGNTS */

#if defined(TARGET_OS_LINUX) || defined(TARGET_OS_FREERTOS) ||                 \
    defined(TARGET_OS_MBEDOS) || defined(TARGET_OS_OPTEE)
#include <stdio.h>
#include <time.h>
#include <string.h>
#define TIMESTAMP_LEN 9
#define LOG(level, ...)                                                        \
	{                                                                      \
		if (level <= LOG_LEVEL) {                                      \
			if (level == LOG_ERROR) {                              \
				printf("ERROR:[%s:%d] ", __FILE__, __LINE__);  \
			}                                                      \
			if (level == LOG_DEBUG) {                              \
				if (print_timestamp() != 0)                    \
					printf("Time_stamp ERROR\n");          \
			}                                                      \
			printf(__VA_ARGS__);                                   \
		}                                                              \
	}
#endif

#ifndef TARGET_OS_MBEDOS
#define ATTRIBUTE_FALLTHROUGH __attribute__((fallthrough))
#else
#define ATTRIBUTE_FALLTHROUGH
#endif /* TARGET_OS_MBEDOS */

#define BUFF_SIZE_0_BYTES 0
#define BUFF_SIZE_4_BYTES 4
#define BUFF_SIZE_8_BYTES 8
#define BUFF_SIZE_10_BYTES 10
#define BUFF_SIZE_12_BYTES 12
#define BUFF_SIZE_16_BYTES 16
#define BUFF_SIZE_32_BYTES 32
#define BUFF_SIZE_48_BYTES 48
#define BUFF_SIZE_64_BYTES 64
#define BUFF_SIZE_128_BYTES 128
#define BUFF_SIZE_256_BYTES 256
#define BUFF_SIZE_512_BYTES 512
#define BUFF_SIZE_1K_BYTES 1024
#define BUFF_SIZE_2K_BYTES 2048

#define BUFF_SIZE_64K_BYTES 64000
#define R_MAX_SIZE BUFF_SIZE_64K_BYTES // Maximum file size to read/write

/* Macro for MAX string length size
   - to be used in strnlen_s()/strcat_s()
   - as a replacement for strlen()/strcat()
*/
#define SDO_MAX_STR_SIZE BUFF_SIZE_512_BYTES
#define SDO_DEBUG_BUF_SIZE BUFF_SIZE_2K_BYTES
#define BIT7_MASK 0x80
/// Test if file exists
/*!
  \param[in] filename
  The file path.

  \returns bool
*/
bool file_exists(char const *filename);

/// Get file size
/*!
  \param[in] filename

  The file path.
  \returns size of the file in bytes
*/
size_t get_file_size(char const *filename);

#if 0
/// Allocate a buffer to hold the content of a file and load
/*!
  Logs an error message on failure.

  \param[in] filename
  The file path.
  \param[out] size
  The allocated size of the buffer in bytes (same as file size).

  \returns
  A pointer to the allocated buffer or NULL if the allocation failed.

*/
void *new_buffer_from_file(const char *filename, size_t *size);
#endif

/// print a buffer to standard out using default options
/*!
  \param[in] buf
  The buffer.
  \param[in] size
  The size of the buffer in bytes.
*/
void hexdump(const char *message, const void *buffer, size_t size);

/* Print a non null-terminated buffer. */
void print_buffer(int log_level, const uint8_t *buffer, size_t length);

/// Read a buffer from content of a file
/*!
  \param[in] filename
  The file path.
  \param[in] buffer
  The buffer to be filled.
  \param[out] size
  The allocated size of the buffer in bytes.

  \returns
  0 on successful read, -1 on error.

*/
int read_buffer_from_file(const char *filename, void *buffer, size_t size);

/*
 * Allocate a buffer and set its contents to 0 before using it.
 */
void *sdo_alloc(int size);

/* Print timestamp */
int print_timestamp(void);

#ifdef __cplusplus
}
#endif

#endif /* __UTIL_H__ */
