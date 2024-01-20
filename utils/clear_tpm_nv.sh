#!/bin/bash

execute_cmd_on_failure_exit()
{
    eval exec_cmd="$1"
    eval success_msg="$2"
    eval failure_msg="$3"

    echo -e "\e[2;33mExecuting :\e[0m ${exec_cmd}"
    out=$(eval ${exec_cmd}" 2>&1")
    if [ `echo $?` != 0 ]; then
        echo -e "\e[2;31m${failure_msg}\e[0m"
    else
        echo -e "\e[2;32m${success_msg}\e[0m"
    fi

    return 0
}

for n in {1,5};
do
    task="Deleting a Non-Volatile (NV) index at 0x01D1000$n"
    cmd="tpm2_nvundefine 0x01D1000$n"
    success_string="$task completed successfully!!"
    failure_string="Non-Volatile (NV) index at 0x01D1000$n is not defined!!"
    execute_cmd_on_failure_exit "\$cmd" "\$success_string" "\$failure_string"
done
echo "TPM NV storage cleared!"
