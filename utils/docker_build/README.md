# About

Docker Script for Building Client-SDK repository. Using this script you can build the local copy of the repository as well as the latest upstream of the repository.

## Prerequisites

- Operating system: **Ubuntu 20.04.**

- Docker engine : **18.06.0**

- Docker-compose : **1.23.2**



## Usage

When you want to build a local copy of the repository.

``` sudo docker-compose up --build ```

When you want to build the latest upstream of the repository.

``` sudo use_remote=1 docker-compose up --build ```

You also have the option to change the remote repository address as well as the remote repository branch in build.sh file.

    REMOTE_URL=link-to-your-fork
    REMOTE_BRANCH=branch-name

## Expected Outcome
As the docker script finishes its execution successfully, the executable files of the Client-SDK will be present in ```<Client-SDK>/ {<build>/<ecdsa256_c_device_bin>/<tpm_ecdsa_c_device_bin>/<ecdsa384_c_sct_device_bin>}``` folders.

## Updating Proxy Info (Optional )
If you are working behind a proxy network, ensure that both http and https proxy variables are set.

    export http_proxy=http-proxy-host:http-proxy-port
    export https_proxy=https-proxy-host:https-proxy-port
