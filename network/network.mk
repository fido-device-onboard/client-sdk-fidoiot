#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

BASE_DIR := ../
DATA_DIR := $(BASE_DIR)/data

include $(BASE_DIR)/base.mk

### LINUX
ifeq ($(TARGET_OS), linux)
PATH_PREFIX = $(BASE_DIR)
SRC = network_if_linux.c rest_interface.c
endif

CFLAGS += -I$(BASE_DIR)/crypto/include
CFLAGS += $(CRYPTO_CFLAGS)

OBJDIR = $(PATH_PREFIX)/$(OBJ_DIR_OS)

OBJS = $(addprefix $(OBJDIR)/,$(notdir $(SRC:.c=.o)))

all: mkdir $(OBJS)

mkdir:
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c
	@echo "  CC    $<"
ifeq ($(V), 1)
	$(CC) $(CFLAGS) -c $< -o $@
else
	@$(CC) $(CFLAGS) -c $< -o $@
endif
