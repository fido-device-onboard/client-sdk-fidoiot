FROM ubuntu:22.04@sha256:f9d633ff6640178c2d0525017174a688e2c1aef28f0a0130b26bd5554491f0da

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y \
  git \
  build-essential \
  cmake \
  libxml2-dev \
  uuid-dev \
  libcurl4-openssl-dev \
  openssl \
  libssl-dev \
  wget \
  bsdmainutils \
  unzip \
  libglib2.0-dev \
  xxd \
  nghttp2 \
  libnghttp2-dev \
  ruby

RUN mkdir build_dir

# Build & Install Curl version 8.1.2
WORKDIR /build_dir/
RUN wget https://curl.se/download/curl-8.1.2.tar.gz -O - | tar -xz && cd curl-8.1.2 && \
./configure --with-openssl --enable-versioned-symbols --with-nghttp2 && make && make install

# Setup safestring
WORKDIR /build_dir
RUN git clone -b v1.2.0 --progress --verbose https://github.com/intel/safestringlib.git safestring
ENV SAFESTRING_ROOT /build_dir/safestring
WORKDIR ${SAFESTRING_ROOT}
RUN mkdir obj && make

# Setup tinycbor
WORKDIR /build_dir
RUN git clone -b v0.6.0 --progress --verbose https://github.com/intel/tinycbor.git tinycbor
ENV TINYCBOR_ROOT /build_dir/tinycbor
WORKDIR ${TINYCBOR_ROOT}
RUN make

# Setup metee
WORKDIR /build_dir
RUN git clone --progress --verbose https://github.com/intel/metee.git metee
ENV METEE_ROOT /build_dir/metee
WORKDIR ${METEE_ROOT}
RUN cmake . && make && make install

ENV OPENSSL3_ROOT /usr
ENV CURL_ROOT /usr

# Setup client-sdk-fidoiot.
# clone client-sdk-fidoiot to the current Dockerfile directory
WORKDIR /build_dir/
RUN mkdir /cse-fdoout
WORKDIR /build_dir/cse-fdoout/
RUN mkdir /client-sdk 
WORKDIR /build_dir/fdoout/client-sdk/
COPY . .

# Install tpm libraries
RUN grep -rl '/opt/openssl' ./ | xargs sed -i 's/\/opt\/openssl/\/usr/g'
RUN grep -rl '/opt/curl' ./ | xargs sed -i 's/\/opt\/curl/\/usr/g'
RUN sed -i 's/lib64/lib\/x86_64-linux-gnu/' utils/install_tpm_libs.sh
RUN sed -i 's/==/-eq/' utils/tpm_make_ready_ecdsa.sh
RUN sh utils/install_tpm_libs.sh -i


CMD ["bash", "build.sh"]