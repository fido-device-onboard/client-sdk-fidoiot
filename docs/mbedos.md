# For Arm* Mbed* (Arm Cortex*-M4 and Cortex-M7) OS-based implementation

## 1. Hardware requirements:
- STM32 Nucleo*-144 development board with [STM32F767ZI](https://os.mbed.com/platforms/ST-Nucleo-F767ZI/) or [STM32F429ZI](https://os.mbed.com/platforms/ST-Nucleo-F429ZI/) MCU.
- Serial Peripheral Interface (SPI)-based MICROSD* card breakout board.
- SanDisk* 8 or 16GB MICROSD memory card.
- Ethernet cable.
- Jumper wires.
- MICROUSB cable.

## 2. Software requirements:
- Linux* OS (Ubuntu* OS version 16.04 LTS) as host machine.
- mbed-cli ([version 1.7.5](https://github.com/ARMmbed/mbed-cli/blob/1.7.5/README.md)) can also be installed using [this](https://pypi.org/project/mbed-cli/) link.
- Arm Cross compiler toolchain `gcc-arm-none-eabi-6-2017-q2-update`, can be downloaded from [this](https://launchpad.net/gcc-arm-embedded/+series) link.
- Configure the Arm cross compiler toolchain globally by setting `GCC_ARM_PATH` through mbed-cli:
  ```shell
$ mbed config -G GCC_ARM_PATH <Path to gcc-arm-none-eabi-6-2017-q2-update>/bin
  ```
  Use  [this](https://os.mbed.com/docs/mbed-os/v5.7/tools/configuring-mbed-cli.html) link for detailed steps.

## 3. Compiling Safestring

Building `safestringlib` library for the Mbed OS-based implementation can be skipped, the  SDO build system for Mbed OS will build the library by itself.

## 4. Compiling Intel® Enhanced Privacy ID (Intel® EPID)-SDK
Building `epid-sdk` library for Mbed OS-based implementation can be skipped, the  SDO build system for Mbed OS will build the library by itself.

## 5. Compiling Service Info Modules (optional)
This step is not required, the  SDO build system for Mbed OS will build the device modules present in the `SERVICE_INFO_DEVICE_MODULE_ROOT` directory by itself.

## 6. Environment Variables

Provide the safestringlib and epid-sdk path:
```shell
$ export SAFESTRING_ROOT=path/to/safestringlib
$ export EPID_SDK_R6_ROOT=path/to/intel-epid-sdk-v6.0.1
$ export SERVICE_INFO_DEVICE_MODULE_ROOT=path/to/service_info_module_dir
```
> **Note:**
> `EPID_SDK_R6_ROOT` is optional if the device attestation (DA) method is not Intel EPID.
`SERVICE_INFO_DEVICE_MODULE_ROOT` is optional if the device module is not used.

## 7. Compiling  SDO
The  SDO client-sdk build system is based on <a href="https://www.gnu.org/software/make/">GNU make</a>. SDO assumes that all requirements are set up from [  SDO Compilation Setup ](setup.md). The application is built using `make [options]` in the root of the repository for all supported platforms. The debug and release build modes are supported.

- To build STM32F767ZI:
   ```shell
   $ make TARGET_OS=mbedos BUILD=debug BOARD=NUCLEO_F767ZI pristine
   $ make TARGET_OS=mbedos BUILD=debug BOARD=NUCLEO_F767ZI
   ```

- To build STM32F429ZI:
   ```shell
   $ make TARGET_OS=mbedos BUILD=debug BOARD=NUCLEO_F429ZI pristine
   $ make TARGET_OS=mbedos BUILD=debug BOARD=NUCLEO_F429ZI
   ```

> **Note:** To build the Mbed OS (STM32F767ZI or STM32F429ZI) platforms, only the SD card is used as a data-store to store  SDO device credentials (device internal flash is not supported).

For an advanced build configuration, refer to [ Advanced Build Configuration ](build_conf.md)

## 8. Executing  SDO
The  SDO for the Linux device is compatible with the  SDO Java* CRI (Customer Reference Implementation) implementation of the manufacturer, rendezvous,
and owner servers. These CRI implementations can be downloaded from the `<release-package-dir>/cri/`
directory.

After a successful compilation, the  SDO M4/M7 device executable can be found at
`<path-to-sdo-client-sdk>/mbedos/components/build/mbedos/${BUILD}/${BOARD}/app/sdo.bin`.

> **Note:** ${BUILD} can be either `debug` or `release` based on the compilation step.
>           ${BOARD} can be either `NUCLEO_F767ZI` or `NUCLEO_F429ZI` based on the compilation step.

To flash the M4/M7-based device executable `sdo.bin`, mount the `/media/${user}/NODE_FXXXZI1/` and then copy the compiled  SDO executable file to the respective device:

```shell
$ cp mbedos/components/build/mbedos/debug/NUCLEO_FXXXZI/app/sdo.bin  /media/${user}/NODE_FXXXZI1/
$ umount /media/${user}/NODE_FXXXZI1/
```


> **Note:** Copy all  SDO device credentials (located under the `<path-to-sdo-client-sdk>/data` directory) 
> to the MICROSD* card attached to the M4/M7 device before onboarding is started.
> The MICROSD card needs to be FAT formatted. When the device is ready to run the onboarding process,
> the application will read the  SDO device credentials from the MICROSD card and proceeds further for onboarding.
> Ensure that the MICROSD card with the MMC board is properly connected to the M4/M7-based device before running
> the  SDO application. Hardware connection and pin details can be found in the following diagram:
>
>                            ------------------                  --------------------
>                           |   M4/M7 Board    |                | MMC Breakout Board |
>                            ------------------                  --------------------
>                           | CS/SSEL  |  PE_4 |<-------------->| CS                 |
>                            ------------------                  --------------------
>                           | SCK/SCLK |  PE_2 |<-------------->| SCK                |
>                            ------------------                  --------------------
>                           | MOSI     |  PE_6 |<-------------->| MOSI               |
>                            ------------------                  --------------------
>                           | MISO     |  PE_5 |<-------------->| MISO               |
>                            ------------------                  --------------------
>                           | VCC      |  5V   |<-------------->| VCC                |
>                            ------------------                  --------------------
>                           | GND      |  GND  |<-------------->| GND                |
>                            ------------------                  --------------------

* Once `sdo.bin` is flashed to the device, the device will run the DI protocol by itself.
- Before booting the board, you need to prepare for Device Initialization using the manufacturer CRI.
  Refer to [ DI CRI Setup](DI_setup.md). After the manufacturer CRI is setup,
  
  open four terminals:
1. **Terminal#1:** Starts the  SDO manufacturer CRI server.
2. **Terminal#2:** Starts the  SDO rendezvous CRI server.
3. **Terminal#3:** Starts the  SDO owner CRI server.
4. **Terminal#4:** Starts the  SDO client-sdk device application (for the  SDO M4/M70-based device, use the terminal to open the serial port, to view the stdout).

  
  Boot up the board. The device will be flashed with the credentials and becomes ready for
  ownership transfer.
On successful execution of the DI protocol, the device will be configured with the required  SDO credentials and the ownership proxy (.op) file will be generated.

- To enable the device for owner transfer, you need to configure the rendezvous and owner CRI.
  Refer to [Ownership Transfer Setup](ownership_transfer.md). Once these
  CRIs are set up, the CRIs are ready for device onboarding.

**To onboard the device:**
Reset the device to start onboarding. 
Since `sdo.bin` is already flashed to the device, the device will run the TO1/TO2 protocol based on the  SDO device credentials.

Using the following command, the serial port can be opened using the Mbed tool to view the device logs in standard output:
```shell
$ mbed sterm --port /dev/ttyACMX -b 115200
```

> **Note:** `/dev/ttyACMX` can be `/dev/ttyACM0`, `/dev/ttyACM1`, or `/dev/ttyACM2` based on the OS assignment.
