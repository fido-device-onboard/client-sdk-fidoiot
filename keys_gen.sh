#!/bin/bash
shopt -s extglob
set -e
bold=$(tput bold)
normal=$(tput sgr0)

CSDK_REPO=$1
CSDK_DATA=$CSDK_REPO/data

usage()
{
	echo -e "Usage:
        $0  <absolute_path_of_CSDK_repo>\n"
}

csdk_keys()
{
	# Generation of ECDSA 256 and 384 .pem files and .dat files
	openssl ecparam -name prime256v1 -genkey -noout -out $CSDK_DATA/ecdsa256privkey.pem
	echo `openssl asn1parse < $CSDK_DATA/ecdsa256privkey.pem | grep "HEX DUMP" |\
		cut -d ":" -f 4` | xxd -r -p > $CSDK_DATA/ecdsa256privkey.dat
	openssl ecparam -name secp384r1 -genkey -noout -out $CSDK_DATA/ecdsa384privkey.pem
	echo `openssl asn1parse < $CSDK_DATA/ecdsa384privkey.pem | grep "HEX DUMP" |\
		cut -d ":" -f 4` | xxd -r -p > $CSDK_DATA/ecdsa384privkey.dat
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	echo "################### CSDK PEM files Generated Successfully ####################"
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	git status $CSDK_REPO
}

if [[ $# == 1 ]]; then
	csdk_keys
else
	usage; exit 1;
fi
