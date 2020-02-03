#!/bin/bash

BASE_DIR=$1 # Base directory of SDO
DATA_DIR=$BASE_DIR/data

CACERT_FILE=$DATA_DIR/cacert.bin
PUB_KEY_FILE=$DATA_DIR/pubkey.dat
SIGRL_FILE=$DATA_DIR/sigrl.dat
RAW_BLOB=$DATA_DIR/raw.blob

gen_epid_blob ()
{
	#remove the '\n' from proxy file.

	declare -A RAW_BLOB_ARR;      declare -a orders;
	RAW_BLOB_ARR["cacert"]="$CACERT_FILE"; orders+=( "cacert" )
	RAW_BLOB_ARR["sigrl"]="$SIGRL_FILE"; orders+=( "sigrl" )
	RAW_BLOB_ARR["pubkey"]="$PUB_KEY_FILE"; orders+=( "pubkey" )


	echo -n "{" > $RAW_BLOB
	for i in "${!orders[@]}"
	do
		echo -n "\"${orders[$i]}\"" >> $RAW_BLOB
		echo -n ":[\"" >> $RAW_BLOB
		base64 ${RAW_BLOB_ARR[${orders[$i]}]} -w 0 >> $RAW_BLOB
		echo -n "\"]" >> $RAW_BLOB
		if [ ${orders[$i]} != "pubkey" ]
		then
			echo -n "," >> $RAW_BLOB
		fi
	done
	echo -n "}" >> $RAW_BLOB
}

gen_epid_blob

exit 0;
