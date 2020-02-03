#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

$(shell ln -sfn ../base.mk  ./base.mk)

PROJECT_NAME := COMPONENT

.PHONY: all clean flash

all:
	make -C components
flash:
	make -C components flash
clean:
	make -C components clean
	unlink base.mk
