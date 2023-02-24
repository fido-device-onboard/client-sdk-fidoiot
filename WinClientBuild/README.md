
# Windows* OS
The development and execution OS used was `Windows 10` on x86. Follow these steps to compile and execute FIDO Device Onboard (FDO).

The FDO Client SDK execution depends on OpenSSL* toolkit 1.1.1s version. Users must install or upgrade the toolkit before compilation if the toolkit is not available by default in the environment.

## 1. Packages Requirements when Building and Executing Binaries:

-	Visual Studio 2019
-	Strawberry Perl: A perl environment for Microsoft Windows (Required to build OpenSSL)
-	Netwide Assembler (NASM): An assembler for the x86 CPU architecture (Required to build OpenSSL)
-	OpenSSL* toolkit version v1.1.1s
-	Curl version v7.87
-	Windows 10 SDK version 2104 (10.0.20348.0)
-	Safestring v1.2.0  for string and memory operations to prevent serious security vulnerabilities (For example, buffer overflows).
-	TinyCBOR v0.6.0 for Concise Binary Object Representation (CBOR) encoding and decoding. 


#### To build the Third party libraries:

To build the third party libraries on Windows, first, ensure that Perl, NASM, nmake, msbuild (Visual Studio 2019) are installed on your system and update the correct path of `vcvarsall.bat` inside [3rdParty_build.bat](3rdParty_build.bat) file. Make sure both Perl and NASM are on your %PATH%.

To build the third party libraries, simply run the [3rdParty_build.bat](3rdParty_build.bat)  file located in the WinClientBuild directory.

## 2. Compiling FDO Client SDK on Windows


To build the FDO Client SDK on Windows, first, ensure that nmake, msbuild (Visual Studio 2019) are installed on your system and update the correct path of `vcvarsall.bat` inside [csdk_build.bat](csdk_build.bat) file.

To build the FDO Client SDK, simply run the
1. [setup.bat](setup.bat)
2. [csdk_build.bat](csdk_build.bat)

files located in the WinClientBuild directory.
> ***NOTE***: Currenty we only support debug mode of compilation.

Several other options to choose when building the device are, but not limited to, the following: device-attestation (DA) methods, Advanced Encryption Standard (AES) encryption modes (AES_MODE), underlying cryptography library to use (TLS), Reuse and Resale.

> ***NOTE***: Running [setup.bat](setup.bat) file will call [keys_gen.bat](keys_gen.bat) file to generate keys. Then it copies the contents of [data](data) folder to `C:\ProgramData\Intel\FDO\data`. Make sure `C:\ProgramData\Intel\FDO\data` exits on your system.


## 3. Running the Application <!-- Ensuring generic updates are captured where applicable -->
The FDO Client SDK Linux device is compatible with FDO PRI components namely: Manufacturer, Rendezvous, and Owner.

To test the FDO Client SDK Linux device, setup the [FDO PRI Manufacturer](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/manufacturer/README.md),
[FDO PRI Rendezvous](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/rv/README.md), and
[FDO PRI Owner](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/owner/README.md).

After a successful compilation, the FDO Client SDK Linux device executable can be found at `<path-to-client-sdk-fidoiot>/WinClientBuild/build/win-client.exe`.

- Before executing `win-client.exe`, prepare for Device Initialization (DI) by starting the FDO PRI Manufacturer and update the manufacturer address in `C:\ProgramData\Intel\FDO\data\manufacturer_addr.bin`
> ***NOTE***: To do DI again, clear the blob files from `C:\ProgramData\Intel\FDO\data\` location.
-   Refer to [ Device Initialization Setup ](https://github.com/secure-device-onboard/client-sdk-fidoiot/blob/master/docs/DI_setup.md).
  Then, execute `win-client.exe`. The device is now initialized with the credentials and is ready for ownership transfer.

  ```shell
  win-client.exe
  ```

- To enable the device for Transfer Ownership protocol (TO1 and TO2), configure the FDO PRI Rendezvous and Owner.
  Refer to [ Ownership Transfer Setup ](https://github.com/secure-device-onboard/client-sdk-fidoiot/blob/master/docs/ownership_transfer.md).
  After these are set up, execute `win-client.exe` again.

  ```shell
  win-client.exe
  ```
> ***NOTE***: For accepting self-signed certs, additional runtime argument '-ss' is required.
 ```shell
  win-client.exe -ss
  ```
