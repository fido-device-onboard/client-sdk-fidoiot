#!/bin/bash

for n in {1..9};
do
    tpm2_nvundefine $n
done
echo "TPM NV storage cleared!"
