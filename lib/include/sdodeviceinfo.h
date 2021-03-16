/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDODEVICEINFO_H__
#define __SDODEVICEINFO_H__

#ifdef TARGET_OS_LINUX
#define OS_NAME "Linux"
#define ARCH "x86"
#define OS_VERSION "Ubuntu-14"
#define BIN_TYPE "x86"
#define PATH_SEPARATOR "/"
#define SEPARATOR ";"
#define NEWLINE "\n"
#define PROGENV "sh"

#elif defined TARGET_OS_FREERTOS
#define OS_NAME "FreeRTOS"
#define ARCH "Esp"
#define OS_VERSION "FreeRTOS-1.2"
#define BIN_TYPE "ihex"
#define PATH_SEPARATOR "/"
#define SEPARATOR ";"
#define NEWLINE "\n"
#define PROGENV "sh"

#elif defined TARGET_OS_MBEDOS
#define OS_NAME "MbedOS"
#define ARCH "CortexM"
#define OS_VERSION "MbedOS-5.8"
#define BIN_TYPE "arm"
#define PATH_SEPARATOR "/"
#define SEPARATOR ";"
#define NEWLINE "\n"
#define PROGENV "sh"

#elif defined TARGET_OS_OPTEE
#define OS_NAME "optee"
#define ARCH "armv8"
#define OS_VERSION "1.0" /* FIXME: */
#define BIN_TYPE "arm"
#define PATH_SEPARATOR "/"
#define SEPARATOR ";"
#define NEWLINE "\n"
#define PROGENV "sh"
#endif

#endif
