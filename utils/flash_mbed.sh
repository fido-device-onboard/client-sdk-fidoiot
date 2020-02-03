#!/bin/bash
FLASHFILE=$1
BOARD=$2
DISK=$(mbedls -u -s | awk '/dev/tty {print $3}')

pumount ${DISK}

if [ $BOARD = "NUCLEO_F429ZI" ]; then
	pmount /dev/disk/by-label/NODE_F429ZI NODE_F429ZI
else
	pmount /dev/disk/by-label/NODE_F767ZI NODE_F767ZI
fi

DISK=$(mbedls -u -s | awk '/dev/tty {print $3}')
mbedflsh -f $FLASHFILE -d $DISK > /dev/null
sleep 3
exit 0

