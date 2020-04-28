#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

BASE_DIR := .
include $(BASE_DIR)/base.mk

### LINUX
ifeq ($(TARGET_OS), linux)
    storage-srcs-y := storage_if_linux.c platform_utils_if_linux.c
endif

srcs-y += $(addprefix storage/$(TARGET_OS)/, $(storage-srcs-y))

srcs-y += $(addprefix storage/, util.c)
