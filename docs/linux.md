# Linux* OS
The development and execution OS used was `Ubuntu* OS version 18.04` on x86.. Follow these steps to compile and execute Secure Device Onboard (SDO).

The SDO build and execution depend on OpenSSL* toolkit version 1.1.1g. Users must install or upgrade the toolkit before compilation if the toolkit is not available by default in the environment.

## 1. Packages requirements when building binaries (for Ubuntu OS version 18.04):

```shell
$ sudo apt-get install python-setuptools clang-format dos2unix ruby \
  libglib2.0-dev libpcap-dev autoconf libtool libproxy-dev libmozjs-38-0 python-pip3 doxygen
$ sudo pip install docutils
```
## 2. Packages requirements when executing binaries (on Ubuntu OS version 18.04):

OpenSSL toolkit version 1.1.1g
GCC version > 7.5

## 3. Compiling Intel safestringlib
 SDO client-sdk uses safestringlib for string and memory operations to prevent serious security vulnerabilities (e.g. buffer overflows). Download safestringlib from <a href="https://github.com/intel/safestringlib">intel-safestringlib</a>, checkout to the tag `v1.0.0` and follow these instructions to build:
From the root of the safestringlib, do the following:
 ```shell
 $ mkdir obj
 $ make
 ```
After this step, `libsafestring.a` library will be created.

## 4. Environment Variables
Add these environment variables to ~/.bashrc or similar (replace with actual paths).
Provide safestringlib paths:
```shell
$ export SAFESTRING_ROOT=path/to/safestringlib
```

## 5. Compiling  SDO

The  SDO client-sdk build system is based on <a href="https://www.gnu.org/software/make/">GNU make</a>. SDO assumes that all the requirements are set up according to [ SDO Compilation Setup ](setup.md). The application is built using the `cmake [options]` in the root of the repository for all supported platforms. The debug and release build modes are supported in building the  SDO client-sdk.

For an advanced build configuration, refer to [ Advanced Build Configuration ](build_conf.md).

```shell
$ make pristine
$ cmake -DTARGET_OS=linux -DBUILD=debug .
$ make
```

Several other options to choose when building the device are, but not limited to, the following: device-attestation (DA) methods, Advanced Encryption Standard (AES) encryption modes (AES_MODE), key-exchange methods (KEX), public-key encoding (PK_ENC) type, and SSL support (TLS).
Refer to the section. [SDO Build configurations](build_conf.md)

<a name="run_linux_sdo"></a>

## 6. Running the application <!-- Ensuring generic updates are captured where applicable -->
The  SDO Linux device is compatible with  SDO Supply Chain Toolkit (SCT), PRI rendezvous, and owner servers(OC).

To test the  SDO Linux device against the  SDO Java PRI implementation, obtain the  SCT binaries along with PRI rendezvous and PRI owner binaries from their respective directories.

After a successful compilation, the  SDO Linux device executable can be found at `<path-to-sdo-client-sdk>/build/linux-client`.
> **Note:** Built binary can be either `debug` or `release` based on the compilation step.

- Before executing `linux-client`, prepare for Device Initialization (DI) using the
  SCT. Refer to [ DI SCT Setup](DI_setup.md). After SCT is set up,
  execute `linux-client`. The device is now initialized with the credentials and is ready for ownership transfer.
To run the device against the SCT for the DI protocol, do the following:
  ```shell
  $ ./build/linux-client
  ```

- To enable the device for ownership transfer, configure the rendezvous and owner containers.
  Refer to [ Ownership Transfer Setup ](ownership_transfer.md). After these
  are set up, execute `linux-client` again.
  
  ```shell
  $ ./build/linux-client
  ```

## 7. Compiling and runing of unit tests for SDO
  Unit-test framework is located inside tests folder.

  Use following command to compile and running.

  ```shell
  $ make pristine || true; cmake -Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DKEX=ecdh -DAES_MODE=ctr -DDA=ecdsa256 -DPK_ENC=ecdsa .; make
  ```


**Steps to upgrade the OpenSSL toolkit to version 1.1.1g**

1. If libssl-dev is installed, remove it:
```shell
sudo apt-get remove --auto-remove libssl-dev
sudo apt-get remove --auto-remove libssl-dev:i386
```
2. Pull the tarball: wget https://www.openssl.org/source/openssl-1.1.1g.tar.gz

3. Unpack the tarball with `tar -zxf openssl-1.1.1g.tar.gz && cd openssl-1.1.1g`

4. Issue the command `./config`.

5. Issue the command `make ` (You may need to run ‘sudo apt install make gcc’ before running this command successfully).

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
	OpenSSL 1.1.1g  21 Apr 2020
    ```
