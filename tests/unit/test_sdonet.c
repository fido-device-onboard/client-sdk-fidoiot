/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for AES abstraction routines of SDO library.
 */

#include "safe_lib.h"
#include "util.h"
#include "sdotypes.h"
#include "network_al.h"
#include "sdonet.h"
#include "unity.h"

#ifdef TARGET_OS_LINUX
/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
bool __wrap_cache_host_dns(char *dns);
bool __wrap_cache_host_ip(sdo_ip_address_t *ip);
bool __wrap_cache_host_port(uint16_t port);
int32_t __wrap_sdo_con_dns_lookup(char *dns, sdo_ip_address_t **ip_list,
				  uint32_t *ip_list_size);
sdo_con_handle __wrap_sdo_con_connect(sdo_ip_address_t *ip_addr, uint16_t port,
				      void **ssl);
sdo_byte_array_t *__wrap_sdo_byte_array_alloc(int byte_sz);
bool __wrap_sdor_init(sdor_t *sdor, SDOReceive_fcn_ptr_t rcv, void *rcv_data);
void test_setup_http_proxy(void);
void test_resolve_dn(void);
void test_Connect_toManufacturer(void);
void test_Connect_toRendezvous(void);
void test_Connect_toOwner(void);
void test_sdo_connection_restablish(void);

/*** Unity functions. ***/
/**
 * set_up function is called at the beginning of each test-case in unity
 * framework. Declare, Initialize all mandatory variables needed at the start
 * to execute the test-case.
 * @return none.
 */
void set_up(void)
{
}

void tear_down(void)
{
}
#endif

static bool cache_dns_fail = false;
bool __wrap_cache_host_dns(char *dns)
{
	(void)dns;
	if (cache_dns_fail)
		return false;
	else
		return true;
}

static bool cache_ip_fail = false;
bool __wrap_cache_host_ip(sdo_ip_address_t *ip)
{
	(void)ip;
	if (cache_ip_fail)
		return false;
	else
		return true;
}

static bool cache_port_fail = false;
bool __wrap_cache_host_port(uint16_t port)
{
	(void)port;
	if (cache_port_fail)
		return false;
	else
		return true;
}

static bool dns_lookup_fail = false;
sdo_ip_address_t *dummy_ip = NULL;
int32_t __wrap_sdo_con_dns_lookup(char *dns, sdo_ip_address_t **ip_list,
				  uint32_t *ip_list_size)
{
	(void)dns;
	if (dns_lookup_fail)
		return -1;
	else {
		dummy_ip = sdo_ipaddress_alloc();
		*ip_list = dummy_ip;
		*ip_list_size = 1;
		return 0;
	}
}

static bool connect_fail = false;
sdo_con_handle __real_sdo_con_connect(sdo_ip_address_t *ip_addr, uint16_t port,
				      void **ssl);
sdo_con_handle __wrap_sdo_con_connect(sdo_ip_address_t *ip_addr, uint16_t port,
				      void **ssl)
{
	if (connect_fail)
		return SDO_CON_INVALID_HANDLE;
	else
		return __real_sdo_con_connect(ip_addr, port, ssl);
}

#ifdef TARGET_OS_FREERTOS
/* Re-use same variable name as much as possible across all platforms */
extern bool simul_out_of_mem;
extern bool sdoR_fail;
#endif

#ifdef TARGET_OS_LINUX
/* Re-use same variable name as much as possible across all platforms */
static bool simul_out_of_mem = false;
sdo_byte_array_t *__real_sdo_byte_array_alloc(int byte_sz);
sdo_byte_array_t *__wrap_sdo_byte_array_alloc(int byte_sz)
{
	if (simul_out_of_mem)
		return NULL;

	return __real_sdo_byte_array_alloc(byte_sz);
}

static bool sdoR_fail = false;
bool __real_sdor_init(sdor_t *sdor, SDOReceive_fcn_ptr_t rcv, void *rcv_data);
bool __wrap_sdor_init(sdor_t *sdor, SDOReceive_fcn_ptr_t rcv, void *rcv_data)
{
	if (sdoR_fail)
		return NULL;

	return __real_sdor_init(sdor, rcv, rcv_data);
}
#endif

#ifdef TARGET_OS_FREERTOS
TEST_CASE("setup_http_proxy", "[NET][sdo]")
#else
void test_setup_http_proxy(void)
#endif
{
#ifdef HTTPPROXY
	bool retval;

	simul_out_of_mem = true;
	retval = setup_http_proxy(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(retval);
	simul_out_of_mem = false;

	sdoR_fail = true;
	retval = setup_http_proxy(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(retval);
	sdoR_fail = false;
#endif
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("resolve_dn", "[NET][sdo]")
#else
void test_resolve_dn(void)
#endif
{
	uint16_t port = 8039;
	bool ret = false;
	sdo_ip_address_t *ip = NULL;

	ret = resolve_dn(NULL, &ip, port, NULL, false);
	TEST_ASSERT_FALSE(ret);

	ret = resolve_dn("localhost", NULL, port, NULL, false);
	TEST_ASSERT_FALSE(ret);

#if defined HTTPPROXY
	cache_dns_fail = true;
	ret = resolve_dn("localhost", &ip, port, NULL, true);
	TEST_ASSERT_FALSE(ret);
	cache_dns_fail = false;
#else
	dns_lookup_fail = true;
	ret = resolve_dn("localhost", &ip, port, NULL, false);
	TEST_ASSERT_FALSE(ret);
	dns_lookup_fail = false;

	connect_fail = true;
	ret = resolve_dn("localhost", &ip, port, NULL, false);
	TEST_ASSERT_FALSE(ret);
	connect_fail = false;
#endif
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("connect_to_manufacturer", "[NET][sdo]")
#else
void test_Connect_toManufacturer(void)
#endif
{
	sdo_ip_address_t ip = {
	    0,
	};

	uint16_t port = 8039;
	bool ret = false;
	sdo_con_handle sock = SDO_CON_INVALID_HANDLE;

	ip.length = 4;

	ret = connect_to_manufacturer(NULL, 0, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	cache_ip_fail = true;
	ret = connect_to_manufacturer(&ip, port, &sock, NULL);
	TEST_ASSERT_FALSE(ret);
	cache_ip_fail = false;

	cache_port_fail = true;
	ret = connect_to_manufacturer(&ip, port, &sock, NULL);
	TEST_ASSERT_FALSE(ret);
	cache_port_fail = false;

	connect_fail = true;
	ret = connect_to_manufacturer(NULL, port, &sock, NULL);
	TEST_ASSERT_FALSE(ret);
	connect_fail = false;
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("connect_to_rendezvous", "[NET][sdo]")
#else
void test_Connect_toRendezvous(void)
#endif
{
	sdo_ip_address_t ip = {
	    0,
	};

	uint16_t port = 8041;
	bool ret = false;
	sdo_con_handle sock = SDO_CON_INVALID_HANDLE;

	ip.length = 4;

	ret = connect_to_rendezvous(NULL, 0, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	cache_ip_fail = true;
	ret = connect_to_rendezvous(&ip, port, &sock, NULL);
	TEST_ASSERT_FALSE(ret);
	cache_ip_fail = false;

	cache_port_fail = true;
	ret = connect_to_rendezvous(&ip, port, &sock, NULL);
	TEST_ASSERT_FALSE(ret);
	cache_port_fail = false;

	connect_fail = true;
	ret = connect_to_rendezvous(NULL, port, &sock, NULL);
	TEST_ASSERT_FALSE(ret);
	connect_fail = false;
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("connect_to_owner", "[NET][sdo]")
#else
void test_Connect_toOwner(void)
#endif
{
	sdo_ip_address_t ip = {
	    0,
	};

	uint16_t port = 8042;
	bool ret = false;
	sdo_con_handle sock = SDO_CON_INVALID_HANDLE;

	ip.length = 4;

	ret = connect_to_owner(NULL, 0, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	cache_ip_fail = true;
	ret = connect_to_owner(&ip, port, &sock, NULL);
	TEST_ASSERT_FALSE(ret);
	cache_ip_fail = false;

	cache_port_fail = true;
	ret = connect_to_owner(&ip, port, &sock, NULL);
	TEST_ASSERT_FALSE(ret);
	cache_port_fail = false;

	connect_fail = true;
	ret = connect_to_owner(NULL, port, &sock, NULL);
	TEST_ASSERT_FALSE(ret);
	connect_fail = false;
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_connection_restablish", "[NET][sdo]")
#else
void test_sdo_connection_restablish(void)
#endif
{
	int ret;
	char *dns = "some_dns_url";
	sdo_ip_address_t *ip = sdo_ipaddress_alloc();
	sdo_prot_ctx_t prot_ctx = {
	    0,
	};

	/* dns */
	prot_ctx.host_dns = dns;

	connect_fail = true;
	ret = sdo_connection_restablish(&prot_ctx);
	TEST_ASSERT_EQUAL_INT(-1, ret);
	connect_fail = false;

	/* IP */
	sdo_init_ipv4_address(ip, (uint8_t *)"0.0.0.0");
	prot_ctx.host_ip = ip;

	connect_fail = true;
	ret = sdo_connection_restablish(&prot_ctx);
	TEST_ASSERT_EQUAL_INT(-1, ret);
	connect_fail = false;

	if (ip) {
		sdo_null_ipaddress(ip);
		sdo_free(ip);
	}
}
