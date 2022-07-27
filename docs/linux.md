


# Linux* OS
The development and execution OS used was `Ubuntu* OS version 20.04 or 22.04 / RHEL* OS version 8.4 or 8.6 / Debian 11.4` on x86. Follow these steps to compile and execute FIDO Device Onboard (FDO).

The FDO Client SDK execution depend on OpenSSL* toolkit version. Currently we support 1.1.1q (and 3.0) version. In this release, to support openssl 3, the deprecated 1.1.1 APIs usage warnings are suppressed and actual porting will be done in a future release. Users must install or upgrade the toolkit before compilation if the toolkit is not available by default in the environment.

## 1. Packages Requirements when Building Binaries:
* For Ubuntu* OS version 20.04 or 22.04 / Debian 11.4:
```shell
sudo apt-get install python-setuptools clang-format dos2unix ruby libcurl4-openssl-dev \
  libglib2.0-dev libpcap-dev autoconf libtool libproxy-dev libmozjs-52-0 doxygen cmake libssl-dev mercurial
```

* For RHEL* OS version 8.4 or 8.6:
```shell
sudo subscription-manager repos --enable codeready-builder-for-rhel-8-x86_64-rpms
sudo yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
sudo yum -y install perl-Module-Load-Conditional perl-core
```
```
sudo yum -y install gcc gcc-c++ python3-setuptools git-clang-format dos2unix ruby libcurl-devel \
  glib2-devel libpcap-devel autoconf libtool libproxy-devel mozjs52-devel doxygen cmake openssl-devel make mercurial
```
## 2. Packages Requirements when Executing Binaries:

OpenSSL* toolkit version 1.1.1q
GCC version > 7.5
#### Steps to Upgrade the OpenSSL* Toolkit to Version 1.1.1q

1. Pull the tarball:
	```
	wget https://www.openssl.org/source/openssl-1.1.1q.tar.gz
	```
2. Unpack the tarball with:
	```
	tar -zxf openssl-1.1.1q.tar.gz && cd openssl-1.1.1q
	```
3. Issue the command:
	```
	./config
	```
4. Issue the command:
	```
	make
	```
	  (You may need to run `sudo apt install make gcc` before running this command successfully).

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
	OpenSSL* 1.1.1q  05 Jul 2022
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
- If the client-sdk binary is built on openssl 1.1.1q environment and then executed with openssl 3 environment, it may fail with "libssl.so.1.1 not found" error. In order to successfully execute it,  build the specific 1.1.1 version dependent libraries and make it available as well:
    wget https://www.openssl.org/source/openssl-1.1.1q.tar.gz
    tar -zxf openssl-1.1.1q.tar.gz && cd openssl-1.1.1q
    ./config
    make
    cp libssl.so.1.1 /usr/lib/x86_64-linux-gnu/
    cp libcrypto.so.1.1 /usr/lib/x86_64-linux-gnu/


