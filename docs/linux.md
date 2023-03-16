


# Linux* OS
The development and execution OS used was `Ubuntu* OS version 20.04 or 22.04 / RHEL* OS version 8.4 or 8.6 / Debian 11.4` on x86. Follow these steps to compile and execute FIDO Device Onboard (FDO).

The FDO Client SDK execution depends on OpenSSL* toolkit 1.1.1t version. Users must install or upgrade the toolkit before compilation if the toolkit is not available by default in the environment.

## 1. Packages Requirements when Building Binaries:
* For Ubuntu* OS version 20.04 or 22.04 / Debian 11.4:
```shell
sudo apt-get install build-essential python-setuptools clang-format dos2unix ruby build-essential \
  libglib2.0-dev libpcap-dev autoconf libtool libproxy-dev doxygen cmake libssl-dev mercurial
```

* For RHEL* OS version 8.4 or 8.6:
```shell
sudo subscription-manager repos --enable codeready-builder-for-rhel-8-x86_64-rpms
sudo yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
```
```
sudo yum -y install gcc gcc-c++ python3-setuptools git-clang-format dos2unix ruby gcc gcc-c++ make perl glibc-static \
  glib2-devel libpcap-devel autoconf libtool libproxy-devel mozjs52-devel doxygen cmake openssl-devel make mercurial perl
```
## 2. Packages Requirements when Executing Binaries:

OpenSSL* toolkit version 1.1.1t
GCC version > 7.5
Curl version 7.88

#### Steps to remove the older curl packages

1. If curl and libcurl are already installed, uninstall it:
	```
	sudo apt remove curl libcurl4-openssl-dev
	```
    In case of RHEL OS, use below commands to uninstall:
	```
	yum remove curl libcurl-devel
	```

#### Steps to Upgrade the OpenSSL* Toolkit to Version 1.1.1t

1. Pull the tarball:
	```
	wget https://www.openssl.org/source/openssl-1.1.1t.tar.gz
	```
2. Unpack the tarball with:
	```
	tar -zxf openssl-1.1.1t.tar.gz && cd openssl-1.1.1t
	```
3. Issue the command:
	```
	./config
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
	sudo ldconfig
	```
10. Assuming no errors in executing steps 4 through 10, you should have successfully installed the new version of the OpenSSL* toolkit.
Issue the following command from the terminal:
	```
	openssl version
	```
	  Your output should be as follows:
	```
	OpenSSL* 1.1.1t  7 Feb 2023
	```

#### Steps to install curl version 7.88 configured with openssl

After installing openssl, proceed with the installation of curl.

1. Pull the tarball:
	```
	wget https://github.com/curl/curl/releases/download/curl-7.88_0/curl-7.88.0.tar.gz
	```
2. Unpack the tarball with:
	```
	tar -zxf curl-7.88.0.tar.gz && cd curl-7.88.0
	```
3. Issue the command to configure the curl with openssl:
	```
	./configure --with-openssl --enable-versioned-symbols
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
    curl 7.88.0 (x86_64-pc-linux-gnu) libcurl/7.88.0 OpenSSL/1.1.1t zlib/1.2.11
    ```
Note 1: If above command is not successful, then link the path where curl is installed to the system path
	```
	sudo ln -s /usr/local/bin/curl /usr/bin/curl
	```

Note 2: If you are using no_proxy environment variable to exclude proxying for any FDO server IP addresses along with curl 7.88 in your setup, ensure to use CIDR notation (https://datatracker.ietf.org/doc/html/rfc1519) as given in below examples.

Single IP address example: no_proxy="10.60.132.45/32"
Two IP addresses example: no_proxy="10.60.132.45/32,10.60.132.46/32"
Range of IP addresses example: no_proxy="10.60.0.0/16"

Note 3: On RHEL, Curl could also be installed using yum package manager as shown below:
	```
	sudo yum -y install libcurl-devel
	```


## 3. Compiling Intel safestringlib
FDO Client SDK uses safestringlib for string and memory operations to prevent serious security vulnerabilities (For example, buffer overflows). Download safestringlib from <a href="https://github.com/intel/safestringlib">intel-safestringlib</a> and follow these instructions to build:
From the root of the safestringlib, do the following:
 ```shell
 mkdir obj
 make
 ```
After this step, `libsafestring.a` library will be created.

## 4. Compiling Intel TinyCBOR
FDO Client SDK uses TinyCBOR library for Concise Binary Object Representation (CBOR) encoding and decoding. Download TinyCBOR from <a href="https://github.com/intel/tinycbor">TinyCBOR</a>, checkout to the tag `v0.5.3` and follow these instructions to build:
From the root of the TinyCBOR (named `tinycbor`), do the following:
 ```shell
 make
 ```

## 5. Environment Variables
Add these environment variables to ~/.bashrc or similar (replace with actual paths).
Provide safestringlib and tinycbor paths:
```shell
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

Several other options to choose when building the device are, but not limited to, the following: device-attestation (DA) methods, Advanced Encryption Standard (AES) encryption modes (AES_MODE), and underlying cryptography library to use (TLS).
Refer to the section. [FDO Build configurations](build_conf.md)

<a name="run_linux_fdo"></a>

## 7. Running the Application <!-- Ensuring generic updates are captured where applicable -->
The FDO Client SDK Linux device is compatible with FDO PRI components namely: Manufacturer, Rendezvous, and Owner.

To test the FDO Client SDK Linux device, setup the [FDO PRI Manufacturer](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/manufacturer/README.md),
[FDO PRI Rendezvous](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/rv/README.md), and
[FDO PRI Owner](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/owner/README.md).

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
- If the client-sdk binary is built on openssl 1.1.1t environment and then executed with openssl 3 environment, it may fail with "libssl.so.1.1 not found" error. In order to successfully execute it,  build the specific 1.1.1 version dependent libraries and make it available as well:
```
    wget https://www.openssl.org/source/openssl-1.1.1t.tar.gz
    tar -zxf openssl-1.1.1t.tar.gz && cd openssl-1.1.1t
    ./config
    make
    cp libssl.so.1.1 /usr/lib/x86_64-linux-gnu/
    cp libcrypto.so.1.1 /usr/lib/x86_64-linux-gnu/
```
