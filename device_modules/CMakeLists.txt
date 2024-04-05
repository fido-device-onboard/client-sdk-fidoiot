#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


client_sdk_include_directories(
  fdo_sys
  fdo_sim
  )

client_sdk_sources(
  fdo_sys/fdo_sys.c
  fdo_sys/sys_utils_linux.c
  fdo_sim/fdo_sim.c
  fdo_sim/fdo_sim_download.c
  fdo_sim/fdo_sim_command.c
  fdo_sim/sim_utils_linux.c
  )




