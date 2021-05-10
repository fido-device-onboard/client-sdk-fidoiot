# Linux* OS
The development and execution OS used was `Ubuntu* OS version 20.04` on x86. Follow these steps to compile and execute FIDO Device Onboard (FDO).

The FDO Client SDK execution depend on OpenSSL* toolkit version 1.1.1k. Users must install or upgrade the toolkit before compilation if the toolkit is not available by default in the environment.

## 1. Packages Requirements when Building Binaries (for Ubuntu OS version 20.04):

```shell
$ sudo apt-get install python-setuptools clang-format dos2unix ruby \
  libglib2.0-dev libpcap-dev autoconf libtool libproxy-dev libmozjs-52-0 doxygen cmake libssl-dev mercurial
```
## 2. Packages Requirements when Executing Binaries (on Ubuntu OS version 20.04):

OpenSSL* toolkit version 1.1.1k
GCC version > 7.5

## 3. Compiling Intel safestringlib
FDO Client SDK uses safestringlib for string and memory operations to prevent serious security vulnerabilities (For example, buffer overflows). Download safestringlib from <a href="https://github.com/intel/safestringlib">intel-safestringlib</a>, checkout to the tag `v1.0.0` and follow these instructions to build:
From the root of the safestringlib, do the following:
 ```shell
 $ mkdir obj
 $ make
 ```
After this step, `libsafestring.a` library will be created.

## 4. Compiling Intel TinyCBOR
FDO Client SDK uses TinyCBOR library for Concise Binary Object Representation (CBOR) encoding and decoding. Download TinyCBOR from <a href="https://github.com/intel/tinycbor">TinyCBOR</a>, checkout to the tag `v0.5.3` and follow these instructions to build:
From the root of the TinyCBOR (named `tinycbor`), do the following:
 ```shell
 $ make
 ```

## 5. Environment Variables
Add these environment variables to ~/.bashrc or similar (replace with actual paths).
Provide safestringlib and tinycbor paths:
```shell
$ export SAFESTRING_ROOT=path/to/safestringlib
$ export TINYCBOR_ROOT=path/to/tinycbor
```

## 6. Compiling FDO Client SDK

The FDO Client SDK build system is based on <a href="https://www.gnu.org/software/make/">GNU make</a>. It assumes that all the requirements are set up according to [ FDO Compilation Setup ](setup.md). The application is built using the `cmake [options]` in the root of the repository for all supported platforms. The debug and release build modes are supported in building the FDO Client SDK.

For an advanced build configuration, refer to [ Advanced Build Configuration ](build_conf.md).

```shell
$ make pristine
$ cmake -DTARGET_OS=linux -DBUILD=debug .
$ make
```

Several other options to choose when building the device are, but not limited to, the following: device-attestation (DA) methods, Advanced Encryption Standard (AES) encryption modes (AES_MODE), key-exchange methods (KEX), public-key encoding (PK_ENC) type, and SSL support (TLS).
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
  $ ./build/linux-client
  ```

- To enable the device for Transfer Ownership protocol (TO1 and TO2), configure the FDO PRI Rendezvous and Owner.
  Refer to [ Ownership Transfer Setup ](ownership_transfer.md).
  After these are set up, execute `linux-client` again.
  
  ```shell
  $ ./build/linux-client
  ```


**Steps to Upgrade the OpenSSL Toolkit to Version 1.1.1k**

1. Pull the tarball: wget https://www.openssl.org/source/openssl-1.1.1k.tar.gz

2. Unpack the tarball with `tar -zxf openssl-1.1.1k.tar.gz && cd openssl-1.1.1k`

3. Issue the command `./config`.

4. Issue the command `make ` (You may need to run ‘sudo apt install make gcc’ before running this command successfully).

5. Run `make test` to check for possible errors.

6. Backup the current OpenSSL binary: `sudo mv /usr/bin/openssl ~/tmp`

7. Issue the command `sudo make install`.

8. Create a symbolic link from the newly installed binary to the default location:

   `sudo ln -s /usr/local/bin/openssl /usr/bin/openssl`

9. Run the command `sudo ldconfig` to update symlinks and rebuild the library cache.
    Assuming no errors in executing steps 4 through 10, you should have successfully installed the new version of the OpenSSL toolkit.

10. Issue the following command from the terminal:

    ```
    openssl version
    ```

    Your output should be as follows:

    ```
	OpenSSL 1.1.1k  25 Mar 2021
    ```
