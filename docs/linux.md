


# Linux* OS
The development and execution OS used was `Ubuntu* OS version [20.04|22.04] / RHEL* OS version [8.4|8.6|8.8] / Debian 11.4` on x86. Follow these steps to compile and execute FIDO Device Onboard (FDO).

The FDO Client SDK execution depends on OpenSSL* toolkit 3.0.12 version. Users must install or upgrade the toolkit before compilation if the toolkit is not available by default in the environment.

## 1. Packages Requirements when Building Binaries:
* For Ubuntu* OS version [20.04|22.04] / Debian 11.4:
```shell
sudo apt-get install build-essential python-setuptools clang-format dos2unix ruby \
  libglib2.0-dev libpcap-dev autoconf libtool libproxy-dev doxygen cmake mercurial nghttp2 libnghttp2-dev
```

* For RHEL* OS version [8.4|8.6|8.8]:
```shell
sudo subscription-manager repos --enable codeready-builder-for-rhel-8-x86_64-rpms
sudo yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
```
```
sudo yum -y install gcc gcc-c++ python3-setuptools git-clang-format dos2unix ruby perl glibc-static \
  glib2-devel libpcap-devel autoconf libtool libproxy-devel mozjs52-devel doxygen cmake make mercurial perl nghttp2 libnghttp2-devel
```
## 2. Packages Requirements when Executing Binaries:

OpenSSL* toolkit version 3.0.12
GCC version > 7.5
Curl version 8.4.0

Following steps will replace the existing versions of OpenSSL and Curl from the system. If you want to keep the existing versions then use [Installation-Script](../utils/install_openssl_curl.sh) script to install Openssl and Curl at a different location.
> ***NOTE***: [Installation-Script](../utils/install_openssl_curl.sh) will install OpenSSL and Curl at /opt/ by default. To provide different path, modify these variables in the script
> OPENSSL_ROOT=/opt/openssl
> CURL_ROOT=/opt/curl
>
**Script usage command**

* Command to install OpenSSL and Curl
	```
	sudo ./install_openssl_curl.sh -i -v 3.0.12
	```

#### Steps to remove the older OpenSSL and curl packages

1. If libssl-dev, curl and libcurl are installed, uninstall it:

	```
	sudo apt-get remove --auto-remove libssl-dev
	sudo apt-get remove --auto-remove libssl-dev:i386
	sudo apt remove curl libcurl4-openssl-dev
	```
    In case of RHEL OS, use below commands to uninstall:

	```
	sudo yum remove libcurl-devel openssl-devel
	```

#### Steps to Upgrade the OpenSSL* Toolkit to Version 3.0.12

1. Pull the tarball:
	```
	wget https://www.openssl.org/source/openssl-3.0.12.tar.gz
	```
2. Unpack the tarball with:
	```
	tar -zxf openssl-3.0.12.tar.gz && cd openssl-3.0.12
	```
3. Issue the command:
	```
	./config --libdir=/usr/local/lib
	```

4. Issue the command:
	```
	make
	```

5. Check for possible errors:
	```
	make test
	```
6. Backup the current OpenSSL* binary:
	```
	sudo mv /usr/bin/openssl ~/tmp
	```
7. Issue the command:
	```
	sudo make install
	```
8. Create a symbolic link from the newly installed binary to the default location:
	```
	sudo ln -s /usr/local/bin/openssl /usr/bin/openssl
	```
9. Run the command to update symlinks and rebuild the library cache:
	```
	grep -qxF '/usr/local/lib/' /etc/ld.so.conf.d/libc.conf || echo /usr/local/lib/ | sudo tee -a /etc/ld.so.conf.d/libc.conf
	sudo ldconfig
	```
10. Assuming no errors in executing steps 4 through 10, you should have successfully installed the new version of the OpenSSL* toolkit.
Issue the following command from the terminal:
	```
	openssl version
	```
	  Your output should be as follows:
	```
	OpenSSL* 3.0.12  24 Oct 2023
	```

#### Steps to install curl version 8.4.0 configured with openssl

After installing openssl, proceed with the installation of curl.

1. Pull the tarball:
	```
	wget https://curl.se/download/curl-8.4.0.tar.gz
	```
2. Unpack the tarball with:
	```
	tar -zxf curl-8.4.0.tar.gz && cd curl-8.4.0
	```
3. Issue the command to configure the curl with openssl and nghttp2:
	```
	./configure --with-openssl="OpenSSL Path" --with-nghttp2 --enable-versioned-symbols
	```
4. Issue the command to build curl:
	```
	make -j$(nproc)
	```

5. Command to install curl:
	```
	sudo make install
	```

6. Assuming no errors in executing steps 1 through 5, you should have successfully installed curl configured with openssl
Issue the following command from the terminal:
	```
	curl --version
	```
	 Your output should point to the openssl version which you installed.
    ```
    curl 8.4.0 (x86_64-pc-linux-gnu) libcurl/8.4.0 OpenSSL/3.0.12 zlib/1.2.11
    ```
Note 1: If you are using no_proxy environment variable to exclude proxying for any FDO server IP addresses along with curl 8.4.0 in your setup, ensure to use CIDR notation (https://datatracker.ietf.org/doc/html/rfc1519) as given in below examples.

Single IP address example: no_proxy="10.60.132.45/32"
Two IP addresses example: no_proxy="10.60.132.45/32,10.60.132.46/32"
Range of IP addresses example: no_proxy="10.60.0.0/16"

Note 2: On RHEL, Curl could also be installed using yum package manager as shown below:
	```
	sudo yum -y install libcurl-devel
	```


## 3. Compiling Intel safestringlib
FDO Client SDK uses safestringlib for string and memory operations to prevent serious security vulnerabilities (For example, buffer overflows). Download safestringlib from <a href="https://github.com/intel/safestringlib">intel-safestringlib</a>, checkout to the tag `v1.2.0` and follow these instructions to build:
From the root of the safestringlib, do the following:
 ```shell
 mkdir obj
 make
 ```
After this step, `libsafestring.a` library will be created.

## 4. Compiling Intel TinyCBOR
FDO Client SDK uses TinyCBOR library for Concise Binary Object Representation (CBOR) encoding and decoding. Download TinyCBOR from <a href="https://github.com/intel/tinycbor">TinyCBOR</a>, checkout to the tag `v0.6.0` and follow these instructions to build:
From the root of the TinyCBOR (named `tinycbor`), do the following:
 ```shell
 make
 ```

## 5. Environment Variables
Add these environment variables to ~/.bashrc or similar (replace with actual paths).
Provide OpenSSL, Curl, safestringlib and tinycbor paths:
```shell
export OPENSSL3_ROOT=path/to/openssl (can be /usr or /usr/local or default provide /opt/openssl)
export CURL_ROOT=path/to/curl (can be /usr or /usr/local or default provide /opt/curl)
export SAFESTRING_ROOT=path/to/safestringlib
export TINYCBOR_ROOT=path/to/tinycbor
```

## 6. Compiling FDO Client SDK

The FDO Client SDK build system is based on <a href="https://www.gnu.org/software/make/">GNU make</a>. It assumes that all the requirements are set up according to [ FDO Compilation Setup ](setup.md). The application is built using the `cmake [options]` in the root of the repository for all supported platforms. The debug and release build modes are supported in building the FDO Client SDK.

For an advanced build configuration, refer to [ Advanced Build Configuration ](build_conf.md).

```shell
make pristine
cmake .
make
bash utils/keys_gen.sh .
```
> ***NOTE***:  [Keys_Gen](../utils/keys_gen.sh) script will use OpenSSL from `/opt/` by default. To provide a different path, use `which openssl` command to get the exact path of OpenSSL and modify this variable in the script
> OPENSSL3_BIN=/opt/openssl/bin (can be /usr/bin or /usr/local/bin)
>
> ***NOTE***:  To run with mTLS connection,
> 1. Compile the code with `-DMTLS=true` flag.
> 2. If signing with external CA, copy CA cert and CA key to `data` folder.
> 3. Execute `bash utils/user_csr_req.sh .`
> This will generate client CSR and private key.
>
Several other options to choose when building the device are, but not limited to, the following: device-attestation (DA) methods, Advanced Encryption Standard (AES) encryption modes (AES_MODE), and underlying cryptography library to use (TLS).
Refer to the section. [FDO Build configurations](build_conf.md)

<a name="run_linux_fdo"></a>

## 7. Running the Application <!-- Ensuring generic updates are captured where applicable -->
The FDO Client SDK Linux device is compatible with FDO PRI components namely: Manufacturer, Rendezvous, and Owner.

To test the FDO Client SDK Linux device, setup the [FDO PRI Manufacturer](https://github.com/fido-device-onboard/pri-fidoiot/blob/master/component-samples/demo/manufacturer/README.md),
[FDO PRI Rendezvous](https://github.com/fido-device-onboard/pri-fidoiot/blob/master/component-samples/demo/rv/README.md), and
[FDO PRI Owner](https://github.com/fido-device-onboard/pri-fidoiot/blob/master/component-samples/demo/owner/README.md).

After a successful compilation, the FDO Client SDK Linux device executable can be found at `<path-to-client-sdk-fidoiot>/build/linux-client`.
> ***NOTE***: Built binary can be either `debug` or `release` based on the compilation step.

- Before executing `linux-client`, prepare for Device Initialization (DI) by starting the FDO PRI Manufacturer.
  Refer to [ Device Initialization Setup ](DI_setup.md).
  Then, execute `linux-client`. The device is now initialized with the credentials and is ready for ownership transfer.

  ```shell
  ./build/linux-client
  ```

- To enable the device for Transfer Ownership protocol (TO1 and TO2), configure the FDO PRI Rendezvous and Owner.
  Refer to [ Ownership Transfer Setup ](ownership_transfer.md).
  After these are set up, execute `linux-client` again.

  ```shell
  ./build/linux-client
  ```

> ***NOTE***: Usage:
>
> ```
>./build/linux-client -ip <http|https>://<mfg addr>:<port>
>if -ip not specified, manufacturer_addr.bin will be used
>-ss: specify if backend servers are using self-signed certificates
>-r: enable resale
>```
