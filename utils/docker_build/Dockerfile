# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

FROM ubuntu:20.04

ENV SAFESTRING_ROOT=/home/sdouser/safestringlib \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y git \
    build-essential \
    cmake \
    libssl-dev \
    ruby \
    wget \
    tar \
    unzip

# Create a user 'sdouser'. If the user name is updated, please update the same in docker-compose.yaml.
RUN useradd -ms /bin/bash sdouser
RUN mkdir -p /home/sdouser/client-sdk/ ; chown -R sdouser:sdouser /home/sdouser/client-sdk/

WORKDIR /home/sdouser/client-sdk/

RUN unset DEBIAN_FRONTEND
RUN echo "proxy $http_proxy"
RUN cd /tmp/ && wget https://raw.githubusercontent.com/secure-device-onboard/client-sdk/master/utils/install_tpm_libs.sh
RUN sed 's/sudo//g' /tmp/install_tpm_libs.sh > /tmp/tpm_libs.sh
RUN yes | bash /tmp/tpm_libs.sh -i

WORKDIR /home/sdouser/
RUN git clone http://github.com/intel/safestringlib.git
RUN cd safestringlib/ && make

WORKDIR /home/sdouser/client-sdk/
ENTRYPOINT ./utils/docker_build/build.sh
