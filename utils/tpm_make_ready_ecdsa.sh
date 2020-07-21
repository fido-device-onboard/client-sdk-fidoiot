export TPM2TOOLS_TCTI="tabrmd"
export OPENSSL_ENGINES=/usr/local/lib/engines-1.1/
TPM_KEY_FILE_INSIDE_DATA_DIR="tpm_ecdsa_priv_pub_blob.key"
DEVICE_MSTRING_FILE_INSIDE_DATA_DIR="device_mstring"
PARENT_DIR=""
MANUFACTURER_IP="10.66.244.137"

TPM_ENDORSEMENT_PRIMARY_KEY_CTX=tpm_primary_key.ctx
TPM_ENDORSEMENT_PRIMARY_KEY_PERSISTANT_HANDLE=0x81000001

DEVICE_MSTRING_KEYTYPE=13
DEVICE_MSTRING_DEVICE_SERIAL_NUM="intel-1234"
DEVICE_MSTRING_MODEL_NUM="model-123456"

found_path=0
verbose=0
curve="nist_p256"
primary_key_type="ecc256:aes128cfb"

usage() 
{
    echo "Usage: $0 -p <path of the parent to C-Device data directory> [-v verbose] [-c nist_p256/nist_p384, default:nist_p256] [-d device serial number for device mstring, default: intel-1234] [-m device model number for device mstring, default: model-123456] [-i use /dev/tpmrm0 as Resource Manager, if not provided TPM2-ABRMD will be used]"
    exit 2
}

check_curve() 
{
    if [ $curve != "nist_p256" ] && [ $curve != "nist_p384" ]; then
        echo "Invalid Curve option: $curve"
        exit 2
    fi
    if [ $curve == "nist_p384" ]; then
        echo "Device Keytype updated to 14 and curve updated to $curve".
        DEVICE_MSTRING_KEYTYPE=14
        primary_key_type="ecc384:aes128cfb"
    fi
}

parse_args() 
{
    OPTIND=1
    USE_TABRMD=2
    USE_TPMRM0=3

    while getopts "p:c:d:m:h:v:i" opt; do
        case ${opt} in
            p ) found_path=1;
                PARENT_DIR=$OPTARG
              ;;
            c ) curve=$OPTARG;
                check_curve                
              ;;
            d ) DEVICE_MSTRING_DEVICE_SERIAL_NUM=$OPTARG
                echo "Device Serial Number for Device mstring has been Updated to : $DEVICE_MSTRING_DEVICE_SERIAL_NUM"
              ;;
            m ) DEVICE_MSTRING_MODEL_NUM=$OPTARG
                echo "Device Model Number for Device mstring has been Updated to : $DEVICE_MSTRING_MODEL_NUM"
              ;;
            i ) export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
              ;;
            v ) verbose=1
              ;;
            h|* ) usage;;
        esac
    done
    
    if [ $found_path -eq 0 ]; then
        usage
    fi
}

execute_cmd_on_failure_exit() 
{
    eval exec_cmd="$1"
    eval success_msg="$2"
    eval failure_msg="$3"
    eval failure_code="$4"
    eval is_exit="$5"
    dash="---------------------"

    echo -e "\e[2;33mExecuting :\e[0m ${exec_cmd}"
    out=$(eval ${exec_cmd}" 2>&1")
    if [ `echo $?` != 0 ]; then
        echo -e "\e[2;31m${failure_msg}\e[0m"
        echo -e "$dash\nDetailed error output\n$dash\n$out\n$dash\n"
        if [ $is_exit != 0 ]; then
            exit "${failure_code}"
        fi
    else
        echo -e "\e[2;32m${success_msg}\e[0m"
        if [ $verbose -eq 1 ];then
            echo -e "$dash\nDetailed output\n$dash\n\e[2;34m$out\e[0m\n$dash\n"
        fi
    fi

    return 0
}

parse_args "$@"

echo "$TPM2TOOLS_TCTI in use as Resource Manager"

#Prepare all files path
tpm_endorsement_primary_key_ctx=$PARENT_DIR"/"$TPM_ENDORSEMENT_PRIMARY_KEY_CTX
tpm_device_key_file=$PARENT_DIR"/"$TPM_KEY_FILE_INSIDE_DATA_DIR
device_mstring_file=$PARENT_DIR"/"$DEVICE_MSTRING_FILE_INSIDE_DATA_DIR

echo "TPM Device Key file location : $tpm_device_key_file"
echo "Device MSTRING file location : $device_mstring_file"


rm -f $tpm_endorsement_primary_key_ctx

task="Delete keys if exists from persistance memory"
cmd="tpm2_evictcontrol -C o -c $TPM_ENDORSEMENT_PRIMARY_KEY_PERSISTANT_HANDLE -V"
success_string="$task completed successfully at $TPM_ENDORSEMENT_PRIMARY_KEY_PERSISTANT_HANDLE !!"
failure_string="$task failed [probably ignore it]"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 0

task="Primary key generation from endorsement seed"
cmd="tpm2_createprimary -C e -g sha256 -G $primary_key_type -c $tpm_endorsement_primary_key_ctx -V"
success_string="$task completed successfully at $tpm_endorsement_primary_key_ctx !!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 1

task="Load primary key inside persistance memory at $TPM_ENDORSEMENT_PRIMARY_KEY_PERSISTANT_HANDLE"
cmd="tpm2_evictcontrol -C o $TPM_ENDORSEMENT_PRIMARY_KEY_PERSISTANT_HANDLE -c $tpm_endorsement_primary_key_ctx -V"
success_string="$task completed successfully at $TPM_ENDORSEMENT_PRIMARY_KEY_PERSISTANT_HANDLE !!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 1

task="TPM ECDSA key generation using $curve"
cmd="tpm2tss-genkey -a ecdsa -c $curve $tpm_device_key_file -v -P $TPM_ENDORSEMENT_PRIMARY_KEY_PERSISTANT_HANDLE"
success_string="$task completed successfully at $tpm_device_key_file !!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\${cmd}" "\${success_string}" "\${failure_string}" 1 1

task="Device CSR generation from TPM"
cmd="openssl req -new -engine tpm2tss -keyform engine -out $device_mstring_file -key $tpm_device_key_file -subj \"/CN=sdo-tpm-device\" -verbose"
success_string="$task completed successfully at $device_mstring_file !!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 1

cp $device_mstring_file $device_mstring_file".org"

#Strip the generated CSR
truncate -s -1 $device_mstring_file

#Prepare device m-string
#Prepare device csr prefix in mstring
echo -n $DEVICE_MSTRING_KEYTYPE > /tmp/m_string.txt
truncate -s +1 /tmp/m_string.txt
echo -n $DEVICE_MSTRING_DEVICE_SERIAL_NUM >> /tmp/m_string.txt
truncate -s +1 /tmp/m_string.txt
if [ ! -z "$DEVICE_MSTRING_MODEL_NUM" ]; then
    echo "Appending device model number to device m-string"
    echo -n $DEVICE_MSTRING_MODEL_NUM >> /tmp/m_string.txt
fi
truncate -s +1 /tmp/m_string.txt
echo "Prefix of device CSR in m-string(hex): $(hexdump -e '16/1 "%02x " "\n"' /tmp/m_string.txt)"
cat $device_mstring_file >> /tmp/m_string.txt
base64 -w 0 /tmp/m_string.txt > $device_mstring_file
rm -f /tmp/m_string.txt

#Remove primary key context file
rm -f $tpm_endorsement_primary_key_ctx

#Set manufacturer IP
echo -n $MANUFACTURER_IP > $PARENT_DIR"/manufacturer_ip.bin"
