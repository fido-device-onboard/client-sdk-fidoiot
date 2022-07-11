
# Introduction
FIDO Device Onboard (FDO) Client SDK is a portable implementation of the FIDO Device Onboarding (FDO) protocol. This component is portable across multiple environments, including to various microprocessors (MPUs) and microcontrollers (MCUs).

At present, FDO Client SDK is tested to run on following platform showcasing FDO capabilities:

1. Linux* x86 machine (with Ubuntu* OS version 20.04): Reference implementation.

FDO Client SDK has not been updated to run on the following platforms yet. Support for the same will be added in future releases:
1. [NUCLEO-F429ZI](https://www.st.com/en/evaluation-tools/nucleo-f429zi.html) STM32 Nucleo* development board running [STM32F429ZI](https://os.mbed.com/platforms/ST-Nucleo-F429ZI/) Arm* Cortex*-M4 MCU over Arm* Mbed* OS.
2. [NUCLEO-F767ZI](https://www.st.com/en/evaluation-tools/nucleo-f767zi.html) STM32 Nucleo-144* development board running [STM32F767ZI](https://os.mbed.com/platforms/ST-Nucleo-F767ZI/) Arm* Cortex*-M7 MCU over ARM* Mbed* OS.
3. [WaRP7]( https://www.nxp.com/files-static/nxp/brochure/WARP7-FLYER-V2.pdf) WaRP7 development board running [i.MX 7Solo](https://www.nxp.com/products/processors-and-microcontrollers/arm-based-processors-and-mcus/i.mx-applications-processors/i.mx-7-processors/i.mx-7solo-processors-heterogeneous-processing-with-arm-cortex-a7-and-cortex-m4-cores:i.MX7S) Arm* Cortex*-A7 MPU over ARM* Mbed* Linux OS.
4. Other linux platfoms Raspberrian, yocto based build for different platforms(A7).

The SDK is to be linked with a customer application that initiates and drives the onboarding functionality. The SDK comes with a sample application that demonstrates how to onboard. The SDK also contains required documentations and an API guide.

FDO Client SDK is organized according to the following directory structure:

	├── app               : FDO application
	├── cmake*            : Cmake files
	├── crypto            : Underlying cryptography and SSL/TLS 
	├── data              : Data files, For example, device credentials
	├── device_modules    : ServiceInfo module implementation
	├── docs              : Documentation
	├── include           : Top level public headers
	├── lib               : FDO Device Library
	├── mbedos*           : Arm Mbed OS-specific build
	├── network           : OS-specific network abstraction
	├── storage           : OS-specific storage abstraction
	├── tests             : Unit tests
	└── utils             : Utilities
