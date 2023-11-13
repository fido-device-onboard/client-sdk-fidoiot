#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


client_sdk_include_directories(
  include
  )

add_library(storage "")

client_sdk_sources_with_lib( storage
  linux/storage_if_linux.c
  linux/platform_utils_if_linux.c
  util.c
  )

if (${DA} MATCHES tpm)
  client_sdk_sources_with_lib( storage
    linux/tpm2_nv_storage.c
  )
endif()

target_link_libraries(storage PUBLIC client_sdk_interface)
