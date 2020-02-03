#!/bin/bash

DATA_DIR=./data                          #SDO data directory
HMAC_KEY=$DATA_DIR/platform_hmac_key.bin #Platform HMAC (sealing) key
TMP_FILE=/tmp/tmpfile                    #Temporary file
RAW_DATA=/tmp/raw_data                   #Input Raw data (without hmac or length)
DATA_LEN=/tmp/data_len                   #File to contain datalen in binary
NEW_HMAC=/tmp/new_hmac                   #new HMAC on modified data

# Normal Blob (blob to modify)
if [ -z "$1" ] ; then
    NORMAL_BLOB=$DATA_DIR/Normal.blob
    echo "No argument supplied!"
else
    NORMAL_BLOB=$1
fi

echo "Input: $NORMAL_BLOB"

# Do not proceed if HMAC key not found
if [ ! -f $HMAC_KEY ] ; then
    echo "HMAC key not found!"
    echo "Please build SDO before using the script!"
    exit 0;
fi

# Do not proceed if onboarding not done
if [ $(grep -c "\"ST\":5" $NORMAL_BLOB) != 1 ] ; then
    echo "SDO Device not in IDLE (SDO_DEVICE_STATE_IDLE) state, exiting..."
    exit 0;
fi

# Work on fresh files everytime
rm -f $TMP_FILE $RAW_DATA $DATA_LEN $NEW_HMAC

# Trim Normal_blob to get length of raw-data
# blob contains 32 fixed bytes for 'HMAC' followed by 4 fixed bytes for 'datalen'
tail -c+33 $NORMAL_BLOB | head -c 4 > $DATA_LEN

# Convert 'datalen' from HEX to DEC
datalen=$(echo "ibase=16; `xxd -p -u $DATA_LEN`" | bc)

#echo "data_length:" $datalen

# Trim Normal_blob to get RAW data [offset = 36 (32(for HMAC) + 4(for datalen)]
echo -n `dd if=$NORMAL_BLOB ibs=1 skip=36 count=$datalen` > $RAW_DATA

# Modify Device State [SDO_DEVICE_STATE_IDLE("ST":5) to SDO_DEVICE_STATE_READY1("ST":3]
echo -n `<$RAW_DATA` | sed -e 's/{"ST":5/{"ST":3/g' > $TMP_FILE

cp $TMP_FILE $RAW_DATA

#echo "Modified RAW_DATA:"
#echo `<$RAW_DATA`

# Compute HMAC on new RAW data
cat $RAW_DATA | openssl dgst -sha256 -mac HMAC -macopt hexkey:$(xxd -p -c 64 $HMAC_KEY) -binary > $NEW_HMAC

# Construct modified blob along with HMAC and datalen
cat $NEW_HMAC $DATA_LEN $RAW_DATA > $TMP_FILE
cp -f $TMP_FILE $NORMAL_BLOB

#echo "Final Normal_blob:"
#echo  `<$NORMAL_BLOB`

echo "Ownership Credentials successfully modified, device is now ready for REUSE!!"

# Remove intermediate files
rm -f $TMP_FILE $RAW_DATA $DATA_LEN $NEW_HMAC

exit 0;
