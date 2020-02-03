#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#
BASE_DIR := ..
include $(BASE_DIR)/base.mk
include $(BASE_DIR)/crypto/conf.mk

### LINUX
ifeq ($(TARGET_OS), linux)
PATH_PREFIX = $(BASE_DIR)
CFLAGS += -I$(BASE_DIR)/app/include -I$(BASE_DIR)/crypto/include $(CRYPTO_CFLAGS)
endif

OBJDIR = $(PATH_PREFIX)/$(OBJ_DIR_APP)
SRC = main.c blob.c
ifeq ($(CRYPTO_HW), true)
SRC += se_provisioning.c
endif
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
