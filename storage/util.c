/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Printing and file handling utilities implementation.
 */

#include "util.h"
#include "network_al.h"
#include <stdlib.h>
#include <ctype.h>
#include "safe_lib.h"
#include "snprintf_s.h"

#ifdef TARGET_OS_FREERTOS
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#endif

bool file_exists(char const *filename)
{
	FILE *fp = NULL;

	if (!filename || !filename[0]) {
		return false;
	}
	fp = fopen(filename, "rb");
	if (fp) {
		if (fclose(fp) == EOF)
			LOG(LOG_INFO, "Fclose Failed");
		return true;
	}
	return false;
}

/**
 * Internal API
 */
size_t get_file_size(char const *filename)
{
	size_t file_length = 0;
	FILE *fp = fopen(filename, "rb");

	if (fp) {
		fseek(fp, 0, SEEK_END);
		file_length = ftell(fp);
		if (fclose(fp) == EOF)
			LOG(LOG_INFO, "Fclose Failed");
	}
	return file_length;
}

/**
 * Internal API
 */
int read_buffer_from_file(const char *filename, void *buffer, size_t size)
{
	FILE *file = NULL;
	size_t bytes_read = 0;

	file = fopen(filename, "rb");
	if (!file) {
		return -1;
	}

	bytes_read = fread(buffer, 1, size, file);
	if (bytes_read != size) {
		if (fclose(file) == EOF)
			LOG(LOG_INFO, "Fclose Failed");
		return -1;
	}

	if (fclose(file) == EOF)
		LOG(LOG_INFO, "Fclose Failed");
	return 0;
}

/**
 * Internal API
 */
/* For printing non null-terminated byte arrays. */
void print_buffer(int log_level, const uint8_t *buffer, size_t length)
{
#ifdef TARGET_OS_LINUX
	LOG(log_level, "%.*s\n", (int)length, buffer);
#else
	/* TODO: To see if we can remove the else part */
	size_t i;

	for (i = 0; i < length; i++) {
		LOG(log_level, "%c", buffer[i]);
	}

	LOG(log_level, "\n");

#endif /* TARGET_OS_LINUX */
}

/**
 * Internal API
 */
void hexdump(const char *message, const void *buffer, size_t size)
{
	size_t bytes_per_group = 1;
	size_t groups_per_line = 16;
	unsigned char *bytes = (unsigned char *)buffer;
	size_t bytes_per_line = bytes_per_group * groups_per_line;
	size_t line_offset = 0;
	size_t byte_offset = 0;
	size_t byte_col = 0;

	LOG(LOG_DEBUGNTS, "\n%s\n", message);
	LOG(LOG_DEBUGNTS,
	    "-------------------------------------------------------"
	    "---------------------\n");
	LOG(LOG_DEBUGNTS, "  offset");
	LOG(LOG_DEBUGNTS, ": ");

	while (byte_col < bytes_per_line) {
		LOG(LOG_DEBUGNTS, "%x%x", (int)byte_col, (int)byte_col);
		if (0 == (byte_col + 1) % bytes_per_group) {
			LOG(LOG_DEBUGNTS, " ");
		}
		byte_col += 1;
	}

	LOG(LOG_DEBUGNTS, "| ");

	byte_col = 0;
	while (byte_col < bytes_per_line) {
		LOG(LOG_DEBUGNTS, "%x", (int)byte_col);
		byte_col += 1;
	}

	LOG(LOG_DEBUGNTS, "\n");
	LOG(LOG_DEBUGNTS, "--------");
	LOG(LOG_DEBUGNTS, ": ");

	byte_col = 0;
	while (byte_col < bytes_per_line) {
		LOG(LOG_DEBUGNTS, "--");
		if (0 == (byte_col + 1) % bytes_per_group) {
			LOG(LOG_DEBUGNTS, "-");
		}
		byte_col += 1;
	}

	LOG(LOG_DEBUGNTS, "|-");

	byte_col = 0;
	while (byte_col < bytes_per_line) {
		LOG(LOG_DEBUGNTS, "-");
		byte_col += 1;
	}

	LOG(LOG_DEBUGNTS, "\n");

	while (line_offset < size) {
		LOG(LOG_DEBUGNTS, "%08x", (int)line_offset);
		LOG(LOG_DEBUGNTS, ": ");

		byte_col = 0;
		while (byte_col < bytes_per_line) {
			byte_offset = line_offset + byte_col;
			if (byte_offset < size) {
				LOG(LOG_DEBUGNTS, "%02x",
				    (int)bytes[byte_offset]);
			} else {
				LOG(LOG_DEBUGNTS, "  ");
			}
			if (0 == (byte_col + 1) % bytes_per_group) {
				LOG(LOG_DEBUGNTS, " ");
			}
			byte_col += 1;
		}

		LOG(LOG_DEBUGNTS, "| ");

		byte_col = 0;
		while (byte_col < bytes_per_line) {
			byte_offset = line_offset + byte_col;
			if (byte_offset < size) {
				unsigned char ch = bytes[byte_offset];

				if (isprint(ch)) {
					LOG(LOG_DEBUGNTS, "%c", ch);
				} else {
					LOG(LOG_DEBUGNTS, ".");
				}
			} else {
				LOG(LOG_DEBUGNTS, "  ");
			}
			byte_col += 1;
		}

		LOG(LOG_DEBUGNTS, "\n");
		line_offset += bytes_per_line;
	}
	LOG(LOG_DEBUGNTS, "\n");
}

/**
 * Internal API
 */
void *fdo_alloc(size_t size)
{
	void *buf = malloc(size);

	if (!buf) {
		LOG(LOG_ERROR, "%s failed to allocate\n",__func__);
		goto end;
	}

	if (memset_s(buf, size, 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		fdo_free(buf);
		goto end;
	}

end:
	return buf;
}
/**
 * Internal API
 */
int print_timestamp(void)
{
#if defined(TARGET_OS_FREERTOS)
	int tick, sec, ms, mins, hour;

	tick = x_task_get_tick_count();

	ms = (tick % CONFIG_FREERTOS_HZ) *
	     10; /*padding 0 by mul with 10  for 3 digit millisecond*/
	sec = (tick / CONFIG_FREERTOS_HZ) % 60;
	mins = (tick / CONFIG_FREERTOS_HZ) / 60;
	hour = (tick / CONFIG_FREERTOS_HZ) / 3600;

	printf("%.2d:%.2d:%.2d:%.3d ", hour, mins, sec, ms);

	return 0;
#endif

#if defined(TARGET_OS_LINUX)
	struct tm t;
	int ret;
	struct timespec ts;
	char buf[TIMESTAMP_LEN];

	clock_gettime(CLOCK_REALTIME, &ts);

	if (localtime_r(&(ts.tv_sec), &t) == NULL) {
		LOG(LOG_ERROR, "localtime_r Failed");
		return 1;
	}

	ret = strftime(buf, sizeof(buf), "%T", &t);

	if (ret == 0) {
		LOG(LOG_ERROR, "strftime Failed");
		return 1;
	}

	printf("%s:%3lu ", buf, ts.tv_nsec / 1000000);

	return 0;
#endif
	return 0;
}
