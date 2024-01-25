export TPM2TOOLS_TCTI="tabrmd"
export OPENSSL3_BIN=/opt/openssl/bin

TPM_PUB_KEY_FILE_INSIDE_DATA_DIR="tpm_ecdsa_pub.key"
TPM_PRIV_KEY_FILE_INSIDE_DATA_DIR="tpm_ecdsa_priv.key"
DEVICE_CSR_FILE_INSIDE_DATA_DIR="tpm_device_csr"
PARENT_DIR=""

TPM_ENDORSEMENT_PRIMARY_KEY_CTX=tpm_primary_key.ctx
TPM_ECDSA_KEY_CTX=tpm_ecdsa_key.ctx
TPM_DEVICE_KEY_PERSISTANT_HANDLE=0x81020002

found_path=0
verbose=0

usage()
{
    echo "Usage: $0 -p <path of the parent to C-Device data directory> -e <ECDSA type 256 or 384> [-v verbose] [-i use /dev/tpmrm0 as Resource Manager, if not provided TPM2-ABRMD will be used]"
    exit 2
}

parse_args()
{
    OPTIND=1
    USE_TABRMD=2
    USE_TPMRM0=3

    while getopts "p:e:h:v:i" opt; do
        case ${opt} in
            p ) found_path=1;
                PARENT_DIR=$OPTARG
              ;;
            e ) ecc=$OPTARG
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

curve="nist_p$ecc"

if [ ${ecc} == "256" ]; then
      primary_key_type="ecc$ecc:aes128cfb"
else
      primary_key_type="ecc$ecc:aes256cfb"
fi

echo "$TPM2TOOLS_TCTI in use as Resource Manager"

#Prepare all files path
tpm_endorsement_primary_key_ctx=$PARENT_DIR"/"$TPM_ENDORSEMENT_PRIMARY_KEY_CTX
tpm_ecdsa_key_ctx=$PARENT_DIR"/"$TPM_ECDSA_KEY_CTX
tpm_device_pub_key_file=$PARENT_DIR"/"$TPM_PUB_KEY_FILE_INSIDE_DATA_DIR
tpm_device_priv_key_file=$PARENT_DIR"/"$TPM_PRIV_KEY_FILE_INSIDE_DATA_DIR
device_csr_file=$PARENT_DIR"/"$DEVICE_CSR_FILE_INSIDE_DATA_DIR

task="Primary key generation from endorsement seed"
cmd="tpm2_createprimary -C e -g sha$ecc -G $primary_key_type -c $tpm_endorsement_primary_key_ctx -V"
success_string="$task completed successfully at $tpm_endorsement_primary_key_ctx !!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 1

task="TPM ECDSA keys generation"
cmd="tpm2_create -g sha$ecc -G ecc$ecc -u $tpm_device_pub_key_file -r $tpm_device_priv_key_file -C $tpm_endorsement_primary_key_ctx -a \"fixedtpm|sensitivedataorigin|fixedparent|sign|userwithauth\" -V"
success_string="$task completed successfully at $tpm_endorsement_primary_key_ctx !!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 1

task="Load ECDSA keys"
cmd="tpm2_load -C $tpm_endorsement_primary_key_ctx -u $tpm_device_pub_key_file -r $tpm_device_priv_key_file -c $tpm_ecdsa_key_ctx -V"
success_string="$task completed successfully!!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 1

task="Copy ECDSA keys inside persistance memory at $TPM_DEVICE_KEY_PERSISTANT_HANDLE"
cmd="tpm2_evictcontrol -C o $TPM_DEVICE_KEY_PERSISTANT_HANDLE -c $tpm_ecdsa_key_ctx -V"
success_string="$task completed successfully!!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 1

task="Device CSR generation from TPM"
cmd="$OPENSSL3_BIN/openssl req -new -provider tpm2 -provider default -outform DER -out $device_csr_file -key handle:$TPM_DEVICE_KEY_PERSISTANT_HANDLE -subj \"/CN=fdo-tpm-device\" -verbose"
success_string="$task completed successfully!!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 1

# # write device csr inside tpm
task="Define a TPM Non-Volatile (NV) index for TPM Device CSR"
csr_size=$(wc -c < $device_csr_file)
cmd="tpm2_nvdefine -Q   0x01D10005 -C o -s $csr_size -a \"ownerwrite|authwrite|ownerread|authread|no_da|read_stclear|writedefine\""
success_string="$task completed successfully!!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 1

task="Write TPM Device CSR to a Non-Volatile (NV) index"
cmd="tpm2_nvwrite -Q   0x01D10005 -C o -i $device_csr_file"
success_string="$task completed successfully!!"
failure_string="$task failed"
execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string" 1 1

rm -f $tpm_device_pub_key_file
rm -f $tpm_device_priv_key_file
rm -f $device_csr_file
rm -f $tpm_endorsement_primary_key_ctx
rm -f $tpm_ecdsa_key_ctx

