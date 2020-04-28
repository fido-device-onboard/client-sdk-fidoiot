#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

BASE_DIR := ..
include $(BASE_DIR)/base.mk

SRC = $(patsubst %,%,$(wildcard *.c))
DI_SRCS  := $(wildcard prot/di/*.c)
TO1_SRCS := $(wildcard prot/to1/*.c)
TO2_SRCS := $(wildcard prot/to2/*.c)

ifneq ($(CLI), true)
SRC := $(SRC)
else ifeq ($(TARGET_OS), linux)
SRC := $(SRC)
CFLAGS += -DCLI
endif

ifeq ($(HTTPPROXY), true)
CFLAGS += -DHTTPPROXY
ifeq ($(PROXY_DISCOVERY), true)
CFLAGS += -DPROXY_DISCOVERY
endif
endif

$(info RESALE = $(RESALE))
ifeq ($(RESALE), true)
CFLAGS += -DRESALE_SUPPORTED
endif

$(info REUSE = $(REUSE))
ifeq ($(REUSE), true)
CFLAGS += -DREUSE_SUPPORTED
endif

### LINUX
ifeq ($(TARGET_OS), linux)
PATH_PREFIX = $(BASE_DIR)
endif

# Manufacturer toolkit
ifeq ($(MANUFACTURER_TOOLKIT), true)
    CFLAGS += -DMANUFACTURER_TOOLKIT
endif

SDO_LIB_NAME = $(PATH_PREFIX)/$(LIB_DIR)/libsdo.a
OBJDIR = $(PATH_PREFIX)/$(LIB_DIR)
DI_OBJDIR := $(PATH_PREFIX)/$(LIB_DIR)/prot/di
TO1_OBJDIR := $(PATH_PREFIX)/$(LIB_DIR)/prot/to1
TO2_OBJDIR := $(PATH_PREFIX)/$(LIB_DIR)/prot/to2
OBJDIR_EPID = $(PATH_PREFIX)/$(OBJ_DIR_EPID)
OBJDIR_OS = $(PATH_PREFIX)/$(OBJ_DIR_OS)
OBJDIR_TLS = $(PATH_PREFIX)/$(OBJ_DIR_TLS)
OBJDIR_SE = $(PATH_PREFIX)/$(OBJ_DIR_SE)
OBJDIR_STORAGE = $(PATH_PREFIX)/$(OBJ_DIR_STORAGE)
OBJDIR_STORAGE_COMMON = $(PATH_PREFIX)/$(OBJ_DIR_STORAGE_COMMON)

### List of SDO library objects
OBJS = $(addprefix $(OBJDIR)/,$(notdir $(SRC:.c=.o)))
DI_OBJS  := $(addprefix $(DI_OBJDIR)/,$(notdir $(DI_SRCS:.c=.o)))
TO1_OBJS := $(addprefix $(TO1_OBJDIR)/,$(notdir $(TO1_SRCS:.c=.o)))
TO2_OBJS := $(addprefix $(TO2_OBJDIR)/,$(notdir $(TO2_SRCS:.c=.o)))
EPID_OBJS = $(wildcard $(OBJDIR_EPID)/*.o)
OS_OBJS   = $(wildcard $(OBJDIR_OS)/*.o)
OS_OBJS  += $(wildcard $(OBJDIR_STORAGE)/*.o)
OS_OBJS  += $(wildcard $(OBJDIR_STORAGE_COMMON)/*.o)
TLS_OBJS  = $(wildcard $(OBJDIR_TLS)/$(TLS)/*.o)
TLS_OBJS += $(wildcard $(OBJDIR_TLS)/ecdsa/*.o)
TLS_OBJS += $(wildcard $(OBJDIR_TLS)/common/*.o)
SE_OBJS   = $(wildcard $(OBJDIR_SE)/*.o)

CFLAGS += -I$(BASE_DIR)/crypto/include
CFLAGS += -I$(BASE_DIR)/storage/include
CFLAGS += -I$(BASE_DIR)/hal/epid/include
CFLAGS += $(CRYPTO_CFLAGS)

all: mkdir $(OBJS) $(DI_OBJS) $(TO1_OBJS) $(TO2_OBJS) $(SDO_LIB_NAME)

mkdir:
	mkdir -p $(OBJDIR)
	mkdir -p $(DI_OBJDIR)
	mkdir -p $(TO1_OBJDIR)
	mkdir -p $(TO2_OBJDIR)

$(SDO_LIB_NAME):
ifeq ($(V), 1)
	$(AR) rcs  $@ $(OBJS) $(DI_OBJS) $(TO1_OBJS) $(TO2_OBJS) \
		$(EPID_OBJS) $(OS_OBJS) $(TLS_OBJS) $(SE_OBJS)
else
	@$(AR) rcs  $@ $(OBJS) $(DI_OBJS) $(TO1_OBJS) $(TO2_OBJS) \
		$(EPID_OBJS) $(OS_OBJS) $(TLS_OBJS) $(SE_OBJS)
endif

$(OBJDIR)/%.o: %.c
	@echo "  CC    $<"
ifeq ($(V), 1)
	$(CC) $(CFLAGS) -c $< -o $@
else
	@$(CC) $(CFLAGS) -c $< -o $@
endif
