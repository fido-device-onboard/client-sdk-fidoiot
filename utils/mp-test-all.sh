#!/bin/bash

retval=0
MPT_DIR=tests/functional

function run_test {
    echo -e "\n########################################################\n"
    echo EPID=$2
    if [ $# -eq 3 ]
    then echo TLS=$3
    fi
    echo ""

    if [ $# -eq 3 ]
    then
	mpt_epid_type=$2 mpt_tls_type=$3 ./$MPT_DIR/util/mpt_run_test.sh -t $MPT_DIR/tests/$1
    else
	mpt_epid_type=$2 ./$MPT_DIR/util/mpt_run_test.sh -t $MPT_DIR/tests/$1
    fi

    if [ "$?" == "1" ];
    then
	retval=1
	fail_list+="$1 EPID=$2"

	if [ $# -eq 2 ]
	then
	    fail_list+=" TLS=$3"
	fi
	fail_list+="\n"
    fi
}

### TESTS ###
test=positive-linux-CRI
run_test $test epid_sdk openssl

test=negative-linux-bad_GUID

test=negative-linux-bad_rendezvous_IP
run_test $test epid_sdk openssl

test=negative-linux-bad_rendezvous_port
run_test $test epid_sdk openssl

test=negative-linux-no_owner
run_test $test epid_sdk openssl

test=negative-linux-no_server
run_test $test epid_sdk openssl

test=positive-linux-production
run_test $test epid_sdk openssl

### RESULTS ###

echo -e "\n########################################################\n"

if [ "$retval" == "0" ]
then
    echo "                       SUCCESS"
else
    echo "FAILED:"
    echo -ne $fail_list
fi

echo -e "\n########################################################\n"
