# For Arm* Mbed* (Arm Cortex*-M4 and Arm Cortex-M7) OS-Based Implementation

## 1. Hardware Requirements:
- STM32 Nucleo*-144 development board with [STM32F767ZI](https://os.mbed.com/platforms/ST-Nucleo-F767ZI/) or [STM32F429ZI](https://os.mbed.com/platforms/ST-Nucleo-F429ZI/) MCU.
- Serial Peripheral Interface (SPI)-based microSD* card breakout board.
- SanDisk* 8 or 16GB microSD memory card.
- Ethernet cable.
- Jumper wires.
- MICROUSB cable.

## 2. Software Requirements:
- Linux* OS (Ubuntu* OS version 20.04 LTS) as host machine.
- Arm* Mbed* CLI (mbed-cli) ([version 1.7.5](https://github.com/ARMmbed/mbed-cli/blob/1.7.5/README.md)) can also be installed using [this](https://pypi.org/project/mbed-cli/) link.
- Arm cross-compiler toolchain (`gcc 7-2018-q2-update`) can be downloaded from [this](https://launchpad.net/gcc-arm-embedded/+series) link.
- Configure the Arm cross-compiler toolchain globally by setting `GCC_ARM_PATH` through mbed-cli:
  ```shell
  $ mbed config -G GCC_ARM_PATH <Path to gcc cross compiler>/bin
  ```
  . Use  [this](https://os.mbed.com/docs/mbed-os/v5.7/tools/configuring-mbed-cli.html) link for detailed steps.

## 3. Compiling safestring

You do not have to build the `safestringlib` library for the Arm Mbed OS-based implementation because this will be done by SDO.

## 4. Environment Variables

Provide the safestringlib path:
```shell
$ export SAFESTRING_ROOT=path/to/safestringlib
```

## 5. Compiling SDO
The  SDO client-sdk build system is based on <a href="https://www.gnu.org/software/make/">GNU Make tool</a>. SDO assumes that all requirements are set up from [  SDO Compilation Setup ](setup.md). The application is built using `make [options]` in the root of the repository for all supported platforms. The debug and release build modes are supported.

- To build STM32F767ZI:
   ```shell
   $ make pristine
   $ cmake -DTARGET_OS=mbedos -DBUILD=debug -DBOARD=NUCLEO_F767ZI .
   $ make
   ```

- To build STM32F429ZI:
   ```shell
   $ make pristine
   $ cmake -DTARGET_OS=mbedos -DBUILD=debug -DBOARD=NUCLEO_F429ZI .
   $ make
   ```

> ***Note:*** To build the Arm Mbed OS (STM32F767ZI or STM32F429ZI) platforms, only the microSD* card is used as a data-store to store SDO device credentials (device internal flash is not supported).

For an advanced build configuration, refer to [Advanced Build Configuration.](build_conf.md)

## 6. Executing SDO
The  SDO for the Linux* device is compatible with the SDO implementation of the manufacturer, rendezvous,
and owner servers. These server implementations can be downloaded from their appropriate 
directories.

After a successful compilation, the SDO M4/M7 device executable can be found at
`<path-to-sdo-client-sdk>/build/sdo.bin`.

> ***Note:*** Build can be either `debug` or `release`, depending on the compilation step.
>           Board can be either `NUCLEO_F767ZI` or `NUCLEO_F429ZI`, depending on the compilation step.

To flash the M4/M7-based device executable `sdo.bin`, mount the `/media/${user}/NODE_FXXXZI1/` and then copy the compiled  SDO executable file to the respective device:

```shell
$ cp build/sdo.bin  /media/${user}/NODE_FXXXZI1/
$ umount /media/${user}/NODE_FXXXZI1/
```


> ***Note:*** Copy all  SDO device credentials (located under the `<path-to-sdo-client-sdk>/data` directory) 
> to the microSD* card attached to the M4/M7 device before onboarding is started.
> The microSD card needs to be FAT formatted. When the device is ready to run the onboarding process,
> the application will read the SDO device credentials from the microSD card and proceeds further for onboarding.
> Ensure that the microSD card with the microSD card module breakout board is properly connected to the M4/M7-based device before running
> the SDO application. Hardware connection and pin details can be found in the following diagram:
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

* After `sdo.bin` is flashed to the device, the device will run the device initialization (DI) protocol.
- Before booting the board, you need to prepare for DI using the Supply Chain Toolkit(sct).
  Refer to [ DI Setup](DI_setup.md). After the SCT is set up,
  
  open four terminals:
1. **Terminal#1:** Starts the  SDO SCT server.
2. **Terminal#2:** Starts the  SDO rendezvous server.
3. **Terminal#3:** Starts the  SDO owner server.
4. **Terminal#4:** Starts the  SDO client-sdk device application (for the  SDO M4/M7-based device, use the terminal to open the serial port, to view the stdout).

  
  Boot up the board. The device will be flashed with the credentials and becomes ready for
  ownership transfer.
On successful execution of the DI protocol, the device will be configured with the required  SDO credentials and the ownership proxy (.op) file will be generated.

- To enable the device for ownership transfer, you need to configure the Rendezvous and Owner.
  Refer to [Ownership Transfer Setup](ownership_transfer.md). After these
  servers are set up and are ready for device onboarding.

**To Onboard the Device:**
Reset the device to start onboarding. 
Because `sdo.bin` is already flashed to the device, the device will run the TO1 or TO2 protocol, depending on the SDO device credentials.

Using the following command, the serial port can be opened using a tool for Arm Mbed OS to view the device logs in standard output:
```shell
$ mbed sterm --port /dev/ttyACMX -b 115200
```

> ***Note:*** `/dev/ttyACMX` can be `/dev/ttyACM0`, `/dev/ttyACM1`, or `/dev/ttyACM2`, depending on the OS assignment.
