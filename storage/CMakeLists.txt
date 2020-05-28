#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


client_sdk_include_directories(
  include
  )

client_sdk_sources(
  linux/storage_if_linux.c
  linux/platform_utils_if_linux.c
  util.c
  )
