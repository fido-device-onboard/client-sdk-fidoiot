# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

CFLAGS = -fPIC -Wall -Wextra -O2 -g
LDFLAGS = -static
TARGET_LIB = libutil.a

#Flag(DEBUG_LOGS) to enable/disable module debug logs
#uncomment below line to enable module traces
#CFLAGS +=-DDEBUG_LOGS

ifneq ($(OPENSSL_BIN_ROOT),)
CFLAGS += -I$(OPENSSL_BIN_ROOT)/include
endif

CFLAGS +=-I./
#Include Safe String library
CFLAGS +=-I$(SAFESTRING_ROOT)/
CFLAGS +=-I$(SAFESTRING_ROOT)/include
LDFLAGS +=-L$(SAFESTRING_ROOT)/
LDLIBS +=-l:libsafestring.a
LIBS = -lcrypto

SRCS = base64.c
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	ar rcs $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) $(LIBS) -MM $< >$@

#include $(SRCS:.c=.d)

.PHONY: clean
clean:
	rm -f *.a *.o *.d

