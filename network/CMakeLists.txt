#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


client_sdk_include_directories(
  include
  )

add_library(network "")

client_sdk_sources_with_lib(
  network
  network_if_linux.c
  rest_interface.c
  )

target_link_libraries(network PUBLIC client_sdk_interface)
