# Introduction
sdo-client-sdk is a portable implementation of the Secure Device Onboarding (SDO) protocol. This component is portable across multiple environments, including to various microprocessors (MPUs) and microcontrollers (MCUs).

At present, sdo-client-sdk is ported to following platforms showcasing SDO capabilities:

1. Linux* x86 machine (with Ubuntu* OS version 16.04/18.04): Reference implementation
2. [NUCLEO-F429ZI](https://www.st.com/en/evaluation-tools/nucleo-f429zi.html) STM32 Nucleo* development board running [STM32F429ZI](https://os.mbed.com/platforms/ST-Nucleo-F429ZI/) Arm* Cortex*-M4 MCU over Arm* Mbed* OS.
3. [NUCLEO-F767ZI](https://www.st.com/en/evaluation-tools/nucleo-f767zi.html) STM32 Nucleo-144 development board running [STM32F767ZI](https://os.mbed.com/platforms/ST-Nucleo-F767ZI/) Arm Cortex-M7 MCU over ARM Mbed OS.
4. [WaRP7]( https://www.nxp.com/files-static/nxp/brochure/WARP7-FLYER-V2.pdf) WaRP7 development board running [i.MX 7Solo](https://www.nxp.com/products/processors-and-microcontrollers/arm-based-processors-and-mcus/i.mx-applications-processors/i.mx-7-processors/i.mx-7solo-processors-heterogeneous-processing-with-arm-cortex-a7-and-cortex-m4-cores:i.MX7S) Arm Cortex-A7 MPU over ARM Mbed Linux OS.
5. [Raspberry Pi3](https://optee.readthedocs.io/building/gits/build.html#platforms-supported-by-build-git)

The SDK is to be linked with a customer application that initiates and drives the onboarding functionality. The SDK comes with a sample application that demonstrates how to onboard. The SDK also contains required documentations and an API guide.

The sdo-client-sdk is organized according to the following directory structure:

	├── app               : SDO application
	├── crypto            : Underlying cryptography and SSL/TLS shims
	├── data              : Data files, e.g. device credentials
	├── docs              : Documentation
	├── Network           : Hardware Abstraction Layer implementations
	├── host              : Client Application (CA) for SDO TA
	├── include           : Top level public headers
	├── lib               : SDO Device Library
	├── mak               : Device attestation key file selection
	├── mbedos            : Arm Mbed OS-specific build configurations
	├── storage           : OS-specific storage abstraction
	├── ta                : User Trusted Application (UTA) - SDO lib
	└── utils             : Utilities

