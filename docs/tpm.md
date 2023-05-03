







# Linux* TPM* Implementation

`Ubuntu* OS version 20.04 or 22.04 / RHEL* OS version 8.4 or 8.6 / Debian 11.4` on x86 was used as a development and execution OS. Follow these steps to compile and execute FIDO Device Onboard (FDO).

The FDO Client SDK execution depends on OpenSSL* toolkit 3.0.8 version. Users must install or upgrade the toolkit before compilation if the toolkit is not available by default in the environment.

## 1. Packages Requirements when Building Binaries with TPM* 2.0:

* For Ubuntu* OS version 20.04 or 22.04 / Debian 11.4:
```shell
sudo apt-get install build-essential python-setuptools clang-format dos2unix ruby build-essential \
  libglib2.0-dev libpcap-dev autoconf libtool libproxy-dev doxygen cmake mercurial
```

* For RHEL* OS version 8.4 or 8.6:
```shell
sudo subscription-manager repos --enable codeready-builder-for-rhel-8-x86_64-rpms
sudo yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
```
```
sudo yum -y install gcc gcc-c++ python3-setuptools git-clang-format dos2unix ruby perl glibc-static \
  glib2-devel libpcap-devel autoconf libtool libproxy-devel mozjs52-devel doxygen cmake make mercurial
```

OpenSSL* toolkit version 3.0.8.
Curl version 8.0.1

#### Steps to Upgrade the OpenSSL* Toolkit to Version 3.0.8

Following steps will replace the existing versions of OpenSSL and Curl from the system. If you want to keep the existing versions then use [Installation-Script](../utils/install_openssl_curl.sh) script to install Openssl and Curl at a different location.
> ***NOTE***: [Installation-Script](../utils/install_openssl_curl.sh) will install OpenSSL and Curl at /opt/ by default. To provide different path, modify these variables in the script 
> OPENSSL_ROOT=/opt/openssl 
> CURL_ROOT=/opt/curl
> 
**Script usage command**

* Command to install OpenSSL and Curl
	```
	sudo ./install_openssl_curl.sh -i -v 3.0.8
	```

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
2. Pull the tarball:
	```
	wget https://www.openssl.org/source/openssl-3.0.8.tar.gz
	```
3. Unpack the tarball with:
	```
	tar -zxf openssl-3.0.8.tar.gz && cd openssl-3.0.8
	```
4. Issue the command:
	```
	./config --libdir=/usr/local/lib
	```
5. Issue the command:
	```
	make
	```

6. Check for possible errors:
	```
	make test
	```
7. Backup the current OpenSSL* binary:
	```
	sudo mv /usr/bin/openssl ~/tmp
	```
8. Issue the command:
	```
	sudo make install
	```
9. Create a symbolic link from the newly installed binary to the default location:
	```
	sudo ln -s /usr/local/bin/openssl /usr/bin/openssl
	```
10. Run the command to update symlinks and rebuild the library cache:
	```
	grep -qxF '/usr/local/lib/' /etc/ld.so.conf.d/libc.conf || echo /usr/local/lib/ | sudo tee -a /etc/ld.so.conf.d/libc.conf
	sudo ldconfig
	```
11. Assuming no errors in executing steps 4 through 10, you should have successfully installed the new version of the OpenSSL* toolkit.
Issue the following command from the terminal:
	```
	openssl version
	```
	  Your output should be as follows:
	```
	OpenSSL* 3.0.8  7 Feb 2023
	```

#### Steps to install curl version 8.0.1 configured with openssl

After installing openssl, proceed with the installation of curl.

1. Pull the tarball:
	```
	wget https://curl.se/download/curl-8.0.1.tar.gz
	```
2. Unpack the tarball with:
	```
	tar -zxf curl-8.0.1.tar.gz && cd curl-8.0.1
	```
3. Issue the command to configure the curl with openssl:
	```
	./configure --with-openssl="OpenSSL Path" --enable-versioned-symbols
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
    curl 8.0.1 (x86_64-pc-linux-gnu) libcurl/8.0.1 OpenSSL/3.0.8 zlib/1.2.11
    ```

Note 1: If you are using no_proxy environment variable to exclude proxying for any FDO server IP addresses, it may not work with curl 8.0.1. Workaround for this is to ensure the no_proxy IP is specified in CIDR notation (https://datatracker.ietf.org/doc/html/rfc1519)

Single IP address example: no_proxy="10.60.132.45/32"
Two IP addresses example: no_proxy="10.60.132.45/32,10.60.132.46/32"
Range of IP addresses example: no_proxy="10.60.0.0/16"

Note 2: On RHEL, Curl could also be installed using yum package manager as shown below:
	```
	sudo yum -y install libcurl-devel
	```


## 2. TPM* Library Installation

TPM* enabled FDO Client SDK uses TPM-TSS 4.0.1, TPM2-ABRMD 3.0.0, and TPM2-TOOLS 5.5 libraries for key and cryptography related operations. The TPM-TSS library is required for compiling the code while all 3 libraries are required for running the code. Create an empty directory, download and execute FDO TPM* [TPM-Library-Installation-Script](../utils/install_tpm_libs.sh) which can be used for both installation and uninstallation of TPM* libraries. Alternatively, perform steps listed in section 2.1 to setup TPM* library without using the TPM* [TPM-Library-Installation-Script](../utils/install_tpm_libs.sh).

To compile and execute TPM* enabled FDO Client SDK use one of the appropriate commands:

**Script usage command**
* **On Ubuntu OS version 20.04 or 22.04 / Debian 11.4:**
	```shell
	sudo ./install_tpm_libs.sh -h
	```

* TPM-TSS library setup to enable TPM* enabled FDO Client SDK code compilation

	* Command to install tpm-tss library
	```
	sudo ./install_tpm_libs.sh -t
	```
	* Command to uninstall tpm-tss library
	```
	sudo ./install_tpm_libs.sh -d
	```

* TPM* setup to enable TPM* enabled FDO Client SDK code compilation and execution

	* Command to install TPM* libraries
	```
	sudo ./install_tpm_libs.sh -i
	```

	* Command to uninstall TPM* libraries
	```
	sudo ./install_tpm_libs.sh -u
	```
	> ***NOTE***: [TPM-Library-Installation-Script](../utils/install_tpm_libs.sh) will use 	 	OpenSSL and Curl from /opt/ by default. If you have installed OpenSSL and Curl other than `/opt` path, use `openssl version -a` and `which curl` commands to get the exact path of OpenSSL and Curl and modify these variables in the script OPENSSL3_INCLUDE=/opt/openssl/include (can be /usr/include or /usr/local/include)
CURL_INCLUDE=/opt/curl/include (can be /usr/include or /usr/local/include)
OPENSSL3_LIB=/opt/openssl/lib64 (can be /usr/lib or /usr/local/lib or /usr/lib/x86_64-linux-gnu)
CURL_LIB=/opt/curl/lib (can be /usr/lib or /usr/local/lib or /usr/lib/x86_64-linux-gnu)
* **On RHEL\* OS version 8.4 or 8.6:**
> ***NOTE***: Use [TPM-Library-Installation-Script-RHEL](../utils/install_tpm_libs_rhel.sh) for RHEL 8.4 or 8.6. 
> Before executing [TPM-Library-Installation-Script-RHEL](../utils/install_tpm_libs_rhel.sh), make sure OpenSSL v3 and Curl is installed on the system (at /usr/local/ path). Use steps in section 1 to install OpenSSL and Curl on the system. 
```shell
sudo ./install_tpm_libs_rhel.sh -h
```

* TPM-TSS library setup to enable TPM* enabled FDO Client SDK code compilation

	* Command to install tpm-tss library
	```
	sudo ./install_tpm_libs_rhel.sh -t
	```
	* Command to uninstall tpm-tss library
	```
	sudo ./install_tpm_libs_rhel.sh -d
	```

* TPM* setup to enable TPM* enabled FDO Client SDK code compilation and execution

	* Command to install TPM* libraries
	```
	sudo ./install_tpm_libs_rhel.sh -i
	```

	* Command to uninstall TPM* libraries
	```
	sudo ./install_tpm_libs_rhel.sh -u
	```


### 2.1 Building and Installing Libraries for Trusted Platform Module (TPM*)

Following steps should be performed if FDO TPM* [TPM-Library-Installation-Script](../utils/install_tpm_libs.sh) script is not used to setup FDO TPM* libraries. Install only tpm2-tss library to enable TPM* enabled FDO Client SDK code compilation. To enable compilation and execution of TPM* enabled FDO Client SDK code, install all libraries namely: tpm2-tss, tpm2-abrmd, tpm2-tools, and tpm2-tss-engine.

- tpm2-tss-4.0.1

  This is the main library that creates commands per Trusted Computing Group (TCG) specification to use the TPM*. It uses release version 4.0.1 of the library.

  - Source Code

    The library can be downloaded from [tpm2-tss-4.0.1-download](https://github.com/tpm2-software/tpm2-tss/releases/download/4.0.1/tpm2-tss-4.0.1.tar.gz)

  - Build and Installation Process

    The build and installation process can be found at [tpm2-tss-4.0.1-install](https://github.com/tpm2-software/tpm2-tss/blob/4.0.1/INSTALL.md)

- tpm2-abrmd-3.0.0

  This is an optional but recommended library (daemon) to use TPM* in the device. This daemon will act as a resource manager for the TPM*, for all I/O calls that happen with the device. It uses release version 3.0.0 of the library.

  - Source Code

    The library can be downloaded from [tpm2-abrmd-3.0.0-download](https://github.com/tpm2-software/tpm2-abrmd/releases/download/3.0.0/tpm2-abrmd-3.0.0.tar.gz)

    Alternatively, the in-kernel RM /dev/tpmrm0 can be used. Please see section on Compiling FDO.

  - Build and Installation Process

    The build and installation process found at [tpm2-abrmd-3.0.0-install](https://github.com/tpm2-software/tpm2-abrmd/blob/master/INSTALL.md)

- tpm2-tools-5.5

  This library provides the necessary tools to interact and perform operations using the TPM*, to the users. It uses release version 5.5 of the library.

  - Source Code

    The library can be downloaded from [tpm2-tools-5.5-download](https://github.com/tpm2-software/tpm2-tools/releases/download/5.5/tpm2-tools-5.5.tar.gz)

  - Build and Installation Process

    The build and installation process can be found at [tpm2-tools-5.5-install](https://github.com/tpm2-software/tpm2-tools/blob/4.0.X/INSTALL.md)

- tpm2-openssl-1.1.1

  This library implements a provider that integrates the TPM 2.0 operations to the OpenSSL 3.0 to perform the OpenSSL* cryptography operation using the keys inside the TPM*. It uses release version 1.1.1 of the library.

  - Source Code

    The library can be downloaded from [tpm2-openssl-download](https://github.com/tpm2-software/tpm2-openssl/releases/download/1.1.1/tpm2-openssl-1.1.1.tar.gz)

  - Build and Installation Process

    The build and installation process can be found at [tpm2-openssl](https://github.com/tpm2-software/tpm2-openssl/blob/master/docs/INSTALL.md)

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

The FDO Client SDK build system is based on <a href="https://www.gnu.org/software/make/">GNU make</a>.  It assumes that all the requirements are set up according to [ FDO Compilation Setup ](setup.md). The application is built using the `make [options]` in the root of the repository for all supported platforms. The debug and release build modes are supported in building the FDO Client SDK.

Refer the TPM* Library Setup steps given in section 2 to compile TPM* enabled FDO Client SDK.

For an advanced build configuration, refer to [ Advanced Build Configuration ](build_conf.md).

Example command to build TPM* enabled FDO Client SDK with the Resource Manager as TPM2-ABRMD (tabrmd)

```shell
make pristine
cmake -DDA=tpm20_ecdsa256 .
make -j$(nproc)
```

To use the in-kernel Resource Manager '/dev/tpmrm0', use the following command
```shell
make pristine
cmake -DDA=tpm20_ecdsa256 -DTPM2_TCTI_TYPE=tpmrm0 .
make -j$(nproc)
```

Several other options to choose when building the device are, but not limited to, the following: device-attestation (DA) methods, Advanced Encryption Standard (AES) encryption modes (AES_MODE), and underlying cryptography library to use (TLS).
Refer to the section [FDO Build configurations](build_conf.md)


<a name="run_linux_fdo"></a>

## 7. Running the Application <!-- Ensuring generic updates are captured where applicable -->
The TPM* enabled FDO Client SDK Linux device is compatible with  FDO PRI components - Manufacturer, Reseller, Rendezvous, and Owner.

To test the FDO Client SDK Linux device, setup the [FDO PRI Manufacturer](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/manufacturer/README.md), [FDO PRI Rendezvous](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/rv/README.md) and [FDO PRI Owner](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/owner/README.md).

Refer the TPM* Library Setup steps given in section 2 to compile and execute TPM* enabled FDO Client SDK.

After a successful compilation, the FDO Client SDK Linux device executable can be found at `<path-to-client-sdk-fidoiot>/build/linux-client`.

- Before executing `linux-client`, prepare for Device Initialization (DI) by starting the FDO PRI Manufacturer.
  Refer to [ Device Initialization Setup ](DI_setup.md).
  Then, execute the TPM* make ready script. Refer to [TPM Make Ready](../utils/tpm_make_ready_ecdsa.sh).
  Alternatively, perform the steps listed in section 7.1 to initialise the device without using [TPM Make Ready](../utils/tpm_make_ready_ecdsa.sh) script.

  Script execution command:

  ```shell
  sudo ./tpm_make_ready_ecdsa.sh -e <ECDSA type 256 or 384> -p <FDO Client SDK data folder location>
  ```
> ***NOTE 1***:  [TPM Make Ready](../utils/tpm_make_ready_ecdsa.sh) script will use OpenSSL from `/opt/` by default. To provide a different path, use `which openssl` command to get the exact path of OpenSSL and modify this variable in the script
> OPENSSL3_BIN=/opt/openssl/bin (can be /usr/bin or /usr/local/bin)
> 
> ***NOTE 2***: Some platforms do not have the support for ECDSA 384 in TPM. [TPM Make Ready](../utils/tpm_make_ready_ecdsa.sh) script with option "-e 384" will fail in those platforms. Please use ECDSA 256 in that case.
>
- Once the TPM* make ready script is executed successfully, the device is now initialized with the credentials and is ready for ownership transfer. To run the device against the FDO PRI Manufacturer for the DI protocol, do the following:
  ```shell
  ./build/linux-client
  ```

- To enable the device for Transfer Ownership protocol (TO1 and TO2), configure the FDO PRI Rendezvous and Owner.
  Refer to [ Ownership Transfer Setup ](ownership_transfer.md).
  After these are set up, execute `linux-client` again.

  ```shell
  ./build/linux-client
  ```
> ***NOTE***:  linux-client may require elevated privileges. Please use 'sudo' to execute.



### 7.1 Prepare FDO Client SDK Data Folder

- Persistent Storage Index in TPM*

  Find a persistent storage index that is unused in the TPM* and note it down. It usually starts from 0x81000000. To see the indexes that are already being used, use the following command. FDO uses the 0x81000001 index for the following command examples.

  ```shell
  sudo tpm2_getcap handles-persistent
  ```


- Primary Key Generation from Endorsement Hierarchy

  ```shell
  sudo tpm2_createprimary -C e -g sha256 -G ecc256:aes128cfb -c data/tpm_primary_key.ctx -V
  ```

- Load the Primary Key into TPM* Persistent Memory

  ```shell
  sudo tpm2_evictcontrol -C o 0x81000001 -c data/tpm_primary_key.ctx -V
  ```

- Device ECDSA Key-Pair Generation

  ```shell
  sudo tpm2tss-genkey -a ecdsa -c nist_p256 data/tpm_ecdsa_priv_pub_blob.key -v -P 0x81000001
  ```

- Generate Device MString

  ```shell
  sudo openssl req -new -provider tpm2 -provider default -out data/device_mstring -key data/tpm_ecdsa_priv_pub_blob.key -subj "/CN=www.fdoDevice1.intel.com" -verbose; truncate -s -1 data/device_mstring; echo -n "13" > /tmp/m_string.txt; truncate -s +1 /tmp/m_string.txt; echo -n "intel-1234" >> /tmp/m_string.txt; truncate -s +1 /tmp/m_string.txt; echo -n "model-123456" >> /tmp/m_string.txt; truncate -s +1 /tmp/m_string.txt; cat data/device_mstring >> /tmp/m_string.txt; base64 -w 0 /tmp/m_string.txt > data/device_mstring; rm -f /tmp/m_string.txt
  ```

## 8. Troubleshooting Details

- TPM* Authorization Failure while Running tpm2-tools Command. <br />
Clear TPM* from the BIOS. To run the TPM* enabled FDO Client SDK implementation, the TPM* on the device should not be owned. To reset the TPM*, go to your device BIOS and clear the TPM*. To find the location of the option in the BIOS of your device, refer to your device manual.

- Clear the Used Persistent Index in TPM*.<br />
Use the tpm2_evictcontrol command to delete the content or clear TPM* from the BIOS. To run the TPM* based FDO implementation, the TPM* on the device should not be owned. To reset the TPM*, go to your device BIOS and clear the TPM*. To find the location of the option in the BIOS of your device, refer to your device manual.

  Assuming that the index is 0x81000001, run the following command to delete the keys.

  ```shell
  sudo tpm2_evictcontrol -C o -c 0x81000001 -V
  ```

- OpenSSL* Toolkit Library Linking Related Error While Building FDO Client SDK.<br />
  There is a dependency on the OpenSSL* toolkit version 3.0.8 for building and running the FDO Client SDK.
  Check the version of the OpenSSL* toolkit installed in your machine with the command

  ```shell
  openssl version
  ```
  If the OpenSSL* toolkit version in your machine is earlier than version 3.0.8, follow the steps given in section 1 to update the OpenSSL* version to 3.0.8.


