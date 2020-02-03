#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

#include sdo/components.mk

PROJECT_NAME := SDO

.PHONY: all clean flash

all:
	make -C sdo
flash:
	make -C sdo flash
clean:
	make -C sdo clean
	rm -rf build

