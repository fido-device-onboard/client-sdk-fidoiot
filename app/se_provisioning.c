/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include <stdio.h>
#include "safe_lib.h"
#include "util.h"
#include <safe_lib.h>
#include <atca_basic.h>
#include <atcacert/atcacert_client.h>
#include <atcacert/atcacert_def.h>

#define LOCKING_ENABLED 1

#define ECDSA_KEY_SLOT 0x0
#define AES_KEY_SLOT 0x1
#define WRITE_KEY_SLOT 0x4

/* Start offset for slot config */
#define WRITE_SLOT_CONFIG 20

/* size of the write i.e 2Bytes per slot 2*16=32Bytes */
#define WRITE_SLOT_CONFIG_SIZE 32

/* Start offset for key config */
#define WRITE_KEY_CONFIG 96

/* size of the write i.e 2Bytes per slot 2*16=32Bytes */
#define WRITE_KEY_CONFIG_SIZE 32

/* AES enabled or not info in config zone */
#define AES_ENABLED_OFFSET 13

/* Prototype needed  */
int se_provisioning(void);

/***********************************/
uint8_t slot_config[] = {
    0xAF, 0xCF, /* EC key, writes disabled but genkey allowed */
    0x8F, 0xCF, /* AES key same as above */
    0xC4, 0x64, /* HMAC key can be encrypted and stored here */
    0xC4, 0xF4, /* slot 3 */
    0x8F, 0x0F, /* Write key needed for HMAC operation */
    0x8F, 0xCF, /* Slot 5 */
    0xAF, 0xCF, /* Slot 6 */
    0x83, 0x64, /* Slot 7 */
    0x84, 0x44, /* Slot 8 */
    0x84, 0x64, /* Slot 9 */
    0x0F, 0x0F, /* Slot 10 */
    0x0F, 0x0F, /* Slot 11 */
    0x0F, 0x0F, /* Slot 12 */
    0x0F, 0x0F, /* Slot 13 */
    0x0F, 0x0F, /* Slot 14 */
    0x0F, 0x0F  /* Slot 15 */
};

uint8_t key_config[] = {
    0x33, 0x01, /* Slot 0 */
    0x18, 0x00, /* Slot 1 */
    0x1C, 0x00, /* Slot 2 */
    0x1C, 0x00, /* Slot 3 */
    0x3C, 0x00, /* Slot 4 */
    0x33, 0x00, /* Slot 5 */
    0x33, 0x00, /* Slot 6 */
    0x33, 0x00, /* Slot 7 */
    0x1C, 0x00, /* Slot 8 */
    0x1C, 0x00, /* Slot 9 */
    0x38, 0x10, /* Slot 10 */
    0x30, 0x00, /* Slot 11 */
    0x3C, 0x00, /* Slot 12 */
    0x3C, 0x00, /* Slot 13 */
    0x32, 0x00, /* Slot 14 */
    0x30, 0x00  /* Slot 15 */
};

static void print_arr(uint8_t *arr, uint32_t len)
{

	for (uint32_t i = 0; i < len; i++) {
		if (0 == (i % 16) && (0 != i)) {
			printf("\n");
		}
		printf("0x%x ", arr[i]);
	}
	printf("\n");
}

int se_provisioning(void)
{
	bool data_locked, config_locked;
	int32_t ret = 0;
	uint8_t ecdsa_public_key[64];
	uint8_t aes_enable;
	int32_t cmp_result;

	if (ATCA_SUCCESS != atcab_init(&cfg_ateccx08a_i2c_default)) {
		LOG(LOG_ERROR, "Unable to setup the Secure element\n");
		return -1;
	}

	ret = atcab_is_locked(LOCK_ZONE_DATA, &data_locked);
	ret |= atcab_is_locked(LOCK_ZONE_CONFIG, &config_locked);
	if (ATCA_SUCCESS != ret) {
		LOG(LOG_ERROR, "Unable to retrieve lock information from se\n");
		return -1;
	}
	if (config_locked) {
		LOG(LOG_DEBUG, "SE configuration is locked\n");
	}
	if (data_locked) {
		LOG(LOG_DEBUG,
		    "the SE is already locked. Provisioning not possible "
		    "again\n");
		return -2;
	}
#if (LOCKING_ENABLED == 0)
	LOG(LOG_DEBUG, "SE locking not done.Set LOCKING_ENABLED to lock\n");
#endif
	LOG(LOG_DEBUG, "Locked status retrieved\n");

	/****************************************/
	/* set the slot configurations */
	atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, WRITE_SLOT_CONFIG,
			       slot_config, WRITE_SLOT_CONFIG_SIZE);

	/* read and verify the configuration is as expected.  */
	uint8_t temp_config[WRITE_SLOT_CONFIG_SIZE];

	atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, WRITE_SLOT_CONFIG,
			      temp_config, WRITE_SLOT_CONFIG_SIZE);
	if (memcmp_s(slot_config, sizeof(slot_config), temp_config,
		     WRITE_SLOT_CONFIG_SIZE, &cmp_result) != 0) {
		LOG(LOG_ERROR, "Incorrect configuration placed inside the SE");
		return -1;
	}
	if (0 != cmp_result) {
		LOG(LOG_ERROR, "Incorrect configuration placed inside the SE");
		return -1;
	}

	LOG(LOG_DEBUG, "slot_config write completed\n");

	/* Set key_config.private =1 for slot 0*/
	atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, WRITE_KEY_CONFIG,
			       key_config, WRITE_KEY_CONFIG_SIZE);

	LOG(LOG_DEBUG, "keyconfig write completed\n");

	/* Check if AES operations are enabled in the board.  */
	atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, AES_ENABLED_OFFSET,
			      &aes_enable, 1);
	if (0x1 != (aes_enable & 0x1)) {
		LOG(LOG_ERROR, "AES command is disabled in SE chip.\n");
		return -1;
	}

	/****************************************/
/* LOCK configuration zone */
#if (LOCKING_ENABLED == 1)
	if (false == config_locked) {
		atcab_lock_config_zone();
	}
#endif

	/****************************************/

	/* AES Key write */
	uint8_t local_buffer[32];

	if (ATCA_SUCCESS != atcab_random(local_buffer)) {
		LOG(LOG_ERROR,
		    "Unable to generate random number from the Secure Element");
		return -1;
	}

	if (ATCA_SUCCESS != atcab_write_zone(ATCA_ZONE_DATA, AES_KEY_SLOT, 0, 0,
					     local_buffer, 32)) {
		LOG(LOG_ERROR, "AES key write error from the Secure Element");
		return -1;
	}
	LOG(LOG_DEBUG, " AES key written to the slot\n");
	LOG(LOG_DEBUG, "\nAES key in hex at slot %d\n", AES_KEY_SLOT);

	/****************************************/

	/* Write key from random. */
	uint8_t write_key[32];

	if (ATCA_SUCCESS != atcab_random(write_key)) {
		LOG(LOG_ERROR,
		    "Unable to generate random number from the Secure Element");
		return -1;
	}

	if (ATCA_SUCCESS != atcab_write_zone(ATCA_ZONE_DATA, WRITE_KEY_SLOT, 0,
					     0, write_key, 32)) {
		LOG(LOG_ERROR, "write key write error from the Secure Element");
		return -1;
	}

	LOG(LOG_DEBUG, "write key completed\n");

	LOG(LOG_DEBUG, "\n Write key in hex at slot %d\n", WRITE_KEY_SLOT);

	print_arr(write_key, 32);

	/****************************************/

	/* EC key generation only works after configuration zone is locked. */
	if (ATCA_SUCCESS != atcab_genkey(ECDSA_KEY_SLOT, ecdsa_public_key)) {
		LOG(LOG_ERROR, "Unable to generate EC key in SE\n");
		return -1;
	}

	LOG(LOG_DEBUG, "\nECDSA public key from slot %d in hex\n",
	    ECDSA_KEY_SLOT);

	print_arr(ecdsa_public_key, 64);

	/****************************************/

	/****************************************/
/* LOCK data zone */
#if (LOCKING_ENABLED == 1)
	atcab_lock_data_zone();
#endif

	return 0;
}
