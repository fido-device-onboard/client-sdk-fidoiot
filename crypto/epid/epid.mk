#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

BASE_DIR := ../..

include $(BASE_DIR)/base.mk

### SDK EPID
ifeq ($(EPID), epid_sdk)
SRC = epid_sdk_interface.c
EPID_SDK_MEMBER_INC_DIR = $(EPID_SDK_ROOT)/_install/epid-sdk/include/epid/member
CFLAGS += -I$(EPID_SDK_MEMBER_INC_DIR) -I$(EPID_SDK_ROOT)
endif

ifeq ($(EPID), epid_r6)
SRC = epid_sdk_interface.c
CFLAGS += -I$(EPID_SDK_R6_ROOT)
endif

### LINUX
ifeq ($(TARGET_OS), linux)
EPID_MAKEFILE = Makefile
EPID_TARGET = LINUX
PATH_PREFIX = $(BASE_DIR)
endif

CFLAGS += -I$(BASE_DIR)/crypto/include -I$(BASE_DIR)/crypto/epid/include
CFLAGS += $(CRYPTO_CFLAGS)
CFLAGS += -I$(BASE_DIR)/storage/include

OBJDIR = $(PATH_PREFIX)/$(OBJ_DIR_EPID)

OBJS = $(addprefix $(OBJDIR)/,$(notdir $(SRC:.c=.o)))

all: mkdir $(OBJS)

mkdir:
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c
	@echo "  CC    $<"
	$(CC) $(CFLAGS) -c $< -o $@
