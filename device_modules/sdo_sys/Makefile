# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

CFLAGS = -fPIC -Wall -Wextra -O2 -g
LDFLAGS = -static
TARGET_LIB = libsdo_sys.a

#Flag(DEBUG_LOGS) to enable/disable module debug logs
#enable below flag to enable module traces

#CFLAGS +=-DDEBUG_LOGS

BASE_DIR := .
CFLAGS +=-I./
ifneq ($(OPENSSL_BIN_ROOT),)
CFLAGS += -I$(OPENSSL_BIN_ROOT)/include
endif

#Include Safe String library
CFLAGS +=-I$(SAFESTRING_ROOT)/
CFLAGS +=-I$(SAFESTRING_ROOT)/include
#Include utils header
CFLAGS +=-I$(BASE_DIR)/../utils
LDFLAGS +=-L$(SAFESTRING_ROOT)/
LDLIBS +=-l:libsafestring.a
LDFLAGS +=-L$(BASE_DIR)/../utils
LDLIBS +=-l:libutil.a

SRCS = sys_utils_linux.c sdo_sys.c
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	ar rcs $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	rm -f *.a *.o *.d

