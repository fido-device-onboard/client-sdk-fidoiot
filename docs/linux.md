# Linux* OS
`Ubuntu* OS version 16.04/18.04` on x86 was used as a development and execution OS. Follow these steps to compile and execute Secure Device Onboard (SDO).

The SDO build and execution depend on OpenSSL* toolkit version 1.1.1c. Users must install or upgrade the toolkit before compilation if the toolkit is not available by default in the environment.

## 1. Packages requirements when building binaries (for Ubuntu OS version 16.04/18.04):

```shell
$ sudo apt-get install python-setuptools clang-format dos2unix ruby \
  libglib2.0-dev libpcap-dev autoconf libtool libproxy-dev doxygen
$ sudo easy_install pip
$ sudo pip install docutils
```
## 2. Packages requirements when executing binaries (on Ubuntu OS version 16.04/18.04):

OpenSSL toolkit version 1.1.1c

## 3. Compiling Intel safestringlib
 SDO client-sdk uses safestringlib for string and memory operations to prevent serious security vulnerabilities (e.g. buffer overflows). Download safestringlib from <a href="https://github.com/intel/safestringlib">intel-safestringlib</a>, checkout to the tag `v1.0.0` and follow these instructions to build:
From the root of the safestringlib, do the following:
 ```shell
 $ mkdir obj
 $ make
 ```
After this step, `libsafestring.a` library will be created.

## 4. Compiling Intel® Enhanced Privacy ID (Intel® EPID) SDK – version 6.0.1

To use Intel EPID for device attestation (DA), Intel EPID SDK must be installed. If any other DA method is used (e.g. ECDSA), this step can be skipped.

Intel EPID SDK can be downloaded from <a href="https://intel-epid-sdk.github.io/">intel-epid-sdk</a>. Follow these instructions to build the Intel EPID SDK:

From the root of the folder, do the following:

```shell
$ ./configure
$ make
$ make install
```
> **Note:** If `make` fails due to a misleading indentation error, add `-Wno-misleading-indentation` to compiler flags in the top-level Makefile.


## 5. Environment Variables
Add these environment variables to ~/.bashrc or similar (replace with actual paths).
Provide safestringlib and epid-sdk paths:
```shell
$ export SAFESTRING_ROOT=path/to/safestringlib
$ export EPID_SDK_R6_ROOT=path/to/intel-epid-sdk-v6.0.1
```
> **Note:** `EPID_SDK_R6_ROOT` is optional if the DA method is not Intel EPID.

## 6. Compiling Service Info Modules (optional)
Provide the service-info device module path to use the  SDO service-info functionality:
```shell
$ export SERVICE_INFO_DEVICE_MODULE_ROOT=path/to/service_info_module_dir
```
Service-info device module `*.a` must be present in the `SERVICE_INFO_DEVICE_MODULE_ROOT`, i.e. required service-info device modules must be built prior to this step, otherwise the  SDO client-sdk build will fail.

## 7. Compiling  SDO

The  SDO client-sdk build system is based on <a href="https://www.gnu.org/software/make/">GNU make</a>. SDO assumes that all the requirements are set up according to [ SDO Compilation Setup ](setup.md). The application is built using the `make [options]` in the root of the repository for all supported platforms. The debug and release build modes are supported in building the  SDO client-sdk.

For an advanced build configuration, refer to [ Advanced Build Configuration ](build_conf.md).

```shell
$ make TARGET_OS=linux BUILD=debug pristine
$ make TARGET_OS=linux BUILD=debug
```

Several other options to choose when building the device are, but not limited to, the following: device-attestation (DA) methods, Advanced Encryption Standard (AES) encryption modes (AES_MODE), key-exchange methods (KEX), Public-key encoding (PK_ENC) type, and SSL support (TLS).
Refer to the section [SDO Build configurations] (build_conf.md)

<a name="run_linux_sdo"></a>

## 8. Running the application <!-- Ensuring generic updates are captured where applicable -->
The  SDO Linux device is compatible with  SDO Java* Customer Reference Implementation (CRI) of manufacturer, rendezvous, and owner servers. 

To test the  SDO Linux device against the  SDO Java CRI implementation, obtain the  SDO Java CRI manufacturer, rendezvous, and owner server binaries from the `<release-package-dir>/cri/` directory.

After a successful compilation, the  SDO Linux device executable can be found at `<path-to-sdo-client-sdk>/build/linux/${BUILD}/linux-client`.
> **Note:** ${BUILD} can be either `debug` or `release` based on the compilation step.

- Before executing `linux-client`, prepare for Device Initialization (DI) using
  manufacturer CRI. Refer to [ DI CRI Setup](DI_setup.md). After the manufacturer CRI is set up,
  execute `linux-client`. The device is now initialized with the credentials and is ready for ownership transfer.
To run the device against the manufacturer CRI for the DI protocol, do the following:
  ```shell
  $ ./build/linux/${BUILD}/linux-client
  ```

- To enable the device for owner transfer, configure the rendezvous and owner CRIs.
  Refer to [ Ownership Transfer Setup ](ownership_transfer.md). After these
  CRIs are set up, execute `linux-client` again.
  
  ```shell
  $ ./build/linux/${BUILD}/linux-client
  ```

**Steps to upgrade the OpenSSL toolkit to version 1.1.1c**

1. If libssl-dev is installed, remove it:
```shell
sudo apt-get remove --auto-remove libssl-dev
sudo apt-get remove --auto-remove libssl-dev:i386
```
2. Pull the tarball: wget https://www.openssl.org/source/openssl-1.1.1c.tar.gz

3. Unpack the tarball with `tar -zxf openssl-1.1.1c.tar.gz && cd openssl-1.1.1c`

4. Issue the command `./config`.

5. Issue the command `make ` (You may need to run “sudo apt install make gcc” before running this command successfully).

6. Run `make test` to check for possible errors.

7. Backup the current OpenSSL binary: `sudo mv /usr/bin/openssl ~/tmp`

8. Issue the command `sudo make install`.

9. Create a symbolic link from the newly installed binary to the default location:

   `sudo ln -s /usr/local/bin/openssl /usr/bin/openssl`

10. Run the command `sudo ldconfig` to update symlinks and rebuild the library cache.
    Assuming no errors in executing steps 4 through 10, you should have successfully installed the new version of the OpenSSL toolkit.

11. Issue the following command from the terminal:

    ```
    openssl version
    ```

    Your output should be as follows:

    ```
    OpenSSL 1.1.1c  28 May 2019
    ```
