export TPM2TOOLS_TCTI="tabrmd"
export OPENSSL_ENGINES=/usr/local/lib/engines-1.1/
TPM_KEY_FILE_INSIDE_DATA_DIR="tpm_ecdsa_priv_pub_blob.key"
DEVICE_CSR_FILE_INSIDE_DATA_DIR="tpm_device_csr"
PARENT_DIR=""

TPM_ENDORSEMENT_PRIMARY_KEY_CTX=tpm_primary_key.ctx
TPM_ENDORSEMENT_PRIMARY_KEY_PERSISTANT_HANDLE=0x81000001

found_path=0
verbose=0
curve="nist_p256"
primary_key_type="ecc256:aes128cfb"

usage() 
{
    echo "Usage: $0 -p <path of the parent to C-Device data directory> [-v verbose] [-i use /dev/tpmrm0 as Resource Manager, if not provided TPM2-ABRMD will be used]"
    exit 2
}

parse_args() 
{
    OPTIND=1
    USE_TABRMD=2
    USE_TPMRM0=3

    while getopts "p:c:h:v:i" opt; do
        case ${opt} in
            p ) found_path=1;
                PARENT_DIR=$OPTARG
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
device_csr_file=$PARENT_DIR"/"$DEVICE_CSR_FILE_INSIDE_DATA_DIR

echo "TPM Device Key file location : $tpm_device_key_file"
echo "TPM Device CSR file location : $device_csr_file"

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
cmd="openssl req -new -engine tpm2tss -keyform engine -outform DER -out $device_csr_file -key $tpm_device_key_file -subj \"/CN=sdo-tpm-device\" -verbose"
success_string="$task completed successfully at $device_csr_file !!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 1

