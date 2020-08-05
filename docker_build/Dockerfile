# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

FROM ubuntu:bionic

RUN apt-get update && \
    apt-get install -y git

# Create a user 'sdouser'. If the user name is updated, please update the same in docker-compose.yaml.
RUN useradd -ms /bin/bash sdouser
RUN mkdir -p /home/sdouser/client-sdk/ ; chown -R sdouser:sdouser /home/sdouser/client-sdk/

WORKDIR /home/sdouser/client-sdk/
ENTRYPOINT ./docker_build/build.sh
