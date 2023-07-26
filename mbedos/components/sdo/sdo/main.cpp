/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Main application. This file has implementation for entry point into
 * the platform and necessary things to initialize FDO, run it and exit
 * gracefully.
 */

#include "mbed.h"
#if DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

#include "mbedtls/platform.h"

#if defined(MBEDOS_SD_DATA) || defined(CLOUD_CLIENT)
#include "SDBlockDevice.h"
#include "FATFileSystem.h"
#endif
#include "EthernetInterface.h"

extern "C" int TO2_done;
extern "C" void app_main(bool is_resale);

// TO-DO : Look at the usage of this flag and remove later
// since this flag has been removed from the source.
#ifdef MODULES_ENABLED
extern void cloud_main(SDBlockDevice *bd, FATFileSystem *fs);
#endif

#if defined(MBEDOS_SD_DATA) || defined(CLOUD_CLIENT)
#define SD_MOUNT_POINT "sd"
SDBlockDevice bd(PE_6, PE_5, PE_2, PE_4);
FATFileSystem fs(SD_MOUNT_POINT, &bd);
#endif // defined(MBEDOS_SD_DATA)

InterruptIn button(USER_BUTTON);
DigitalOut led(LED1);
double delay = 1000; // 1000 ms

#if !defined(MBEDOS_SD_DATA)
extern int initiate_files_firsttime(void);
#endif

int init_eth(void); // initializes Ethernet
void end_eth(void); // closes Ethernet socket

// Network interface
EthernetInterface net;
nsapi_error_t status;

EthernetInterface *getNetinterface(void)
{
	return &net;
}

int init_eth(void)
{
	// net = NetworkInterface::get_default_instance();
	nsapi_error_t status = net.connect();

	if (status != 0) {
		printf("Error! net->connect() returned: %d\n", status);
		return status;
	}

	// Show the network address
	const char *ip = net.get_ip_address();
	const char *netmask = net.get_netmask();
	const char *gateway = net.get_gateway();
	printf("IP address: %s\n", ip ? ip : "None");
	printf("Netmask: %s\n", netmask ? netmask : "None");
	printf("Gateway: %s\n", gateway ? gateway : "None");
	if (!ip && !netmask && !gateway) {
		return 1;
	} else {
		return 0;
	}

} // end init_eth()

void end_eth(void)
{
	// Bring down the ethernet interface
	net.disconnect();
	// delete &net;
} // end end_eth

int do_onboarding(bool is_resale)
{
	int exit_code = MBEDTLS_EXIT_FAILURE;
#ifdef MBED_MAJOR_VERSION
	printf("Mbed OS version: %d.%d.%d\n\n", MBED_MAJOR_VERSION,
	       MBED_MINOR_VERSION, MBED_PATCH_VERSION);
#endif

	init_eth();
#if !defined(MBEDOS_SD_DATA)
	initiate_files_firsttime();
#endif
	if ((exit_code = mbedtls_platform_setup(NULL)) != 0) {
		printf("Platform initialization failed with error %d\n",
		       exit_code);
		return MBEDTLS_EXIT_FAILURE;
	}
	app_main(is_resale);
	if (TO2_done == 1) {
#ifdef CLOUD_CLIENT
		cloud_main(&bd, &fs);
#endif
	}
	end_eth();
	if (exit_code != 0) {
		mbedtls_printf("Example failed with error %d\n", exit_code);
		exit_code = MBEDTLS_EXIT_FAILURE;
	}

	mbedtls_platform_teardown(NULL);
	printf("Done\n");
	return 0;

}

void butn_released()
{
	do_onboarding(true);
	delay = 200;
	printf("Ready for resale -----\n");
}

int main()
{

	do_onboarding(false); //standard onboarding

	button.rise(&butn_released);

    while (1) {
       led = !led;
       thread_sleep_for(delay);
    }
}
