/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "util.h"
#include "network_al.h"
#include "fdonet.h"
#include "fdotypes.h"
#include "safe_lib.h"
#include <stdlib.h>
#include "storage_al.h"
#include "rest_interface.h"
#include "safe_str_lib.h"
#include "snprintf_s.h"

#if defined HTTPPROXY
#ifdef TARGET_OS_FREERTOS
#endif // defined HTTPPROXY

#if !defined(TARGET_OS_OPTEE) && !defined(TARGET_OS_MBEDOS)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if defined(PROXY_DISCOVERY)
#include <proxy.h>
#endif
#endif

/* HTTP Proxy parameters */
static fdo_ip_address_t rvproxy_ip;
static uint16_t rvproxy_port;
static fdo_ip_address_t mfgproxy_ip;
static uint16_t mfgproxy_port;
static fdo_ip_address_t ownerproxy_ip;
static uint16_t ownerproxy_port;
#endif // defined HTTPPROXY

CURL *curl;

/**
 * Internal API
 */
bool is_rv_proxy_defined(void)
{
#if defined HTTPPROXY
	if (rvproxy_port != 0) {
		return true;
	}
	LOG(LOG_DEBUG, "Proxy enabled but Not set\n");
#endif // defined HTTPPROXY
	return false;
}

/**
 * Internal API
 */
bool is_mfg_proxy_defined(void)
{
#if defined HTTPPROXY
	if (mfgproxy_port != 0) {
		return true;
	}
	LOG(LOG_DEBUG, "Proxy enabled but Not set\n");
#endif // defined HTTPPROXY
	return false;
}

/**
 * Internal API
 */
bool is_owner_proxy_defined(void)
{
#if defined HTTPPROXY
	if (ownerproxy_port != 0) {
		return true;
	}
	LOG(LOG_DEBUG, "Proxy enabled but Not set\n");
#endif // defined HTTPPROXY
	return false;
}

#ifdef HTTPPROXY

/**
 * Internal API
 */

/* internal api
 * proxydata: proxy data as asscii string. e.g."http://theproxy.mycompany.com:123"
 * return resolved dns, as ip in network format and port
 */
static bool get_netip_port(const char *proxydata, uint8_t proxydatsize,
			   uint8_t *netip, uint16_t *proxy_port)
{
	int i = 0, ret = -1;
	uint32_t num_ofIPs = 0;
	fdo_ip_address_t *ip_list = NULL;
	char *pch = NULL;
	uint8_t *proxy = NULL;
	char proxy_url[40] = {0};
	char *eptr = NULL;

	ret =
	    strstr_s((char *)proxydata, proxydatsize, "://", 3, (char **)&pch);
	if (ret != 0 && ret != ESNOTFND) {
		return false;
	}

	if (pch) {
		proxy = (uint8_t *)pch + 3;
	} else {
		proxy = (uint8_t *)proxydata;
	}

	while (proxy[i] != 0 && proxy[i] != ':') {
		proxy_url[i] = proxy[i];
		i++;
	}

	// resolve dn
	if (fdo_con_dns_lookup(proxy_url, &ip_list, &num_ofIPs) == -1) {
		LOG(LOG_ERROR, "DNS look-up failed!\n");
		goto err;
	}

	/* Copy the network address to proxy */
	/* TODO: iterate for proxy dn (only first one used) */
	if (memcpy_s(netip, ip_list->length, ip_list->addr, ip_list->length) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy failed for ip address copy\n");
		goto err;
	}

	if (proxy[i] == ':') {
		// set to 0 explicitly
		errno = 0;
		*proxy_port = strtol((char *)&proxy[i + 1], &eptr, 10);
		if (!eptr || eptr == (char *)&proxy[i+1] || errno != 0) {
			LOG(LOG_ERROR, "Proxy Port read failed\n");
			goto err;
		}
	}
	ret = 0;
err:
	if (ip_list) {
		fdo_free(ip_list);
	}
	if (ret) {
		return false;
	}
	return true;
}

#if defined(PROXY_DISCOVERY)
/* api use libproxy for automatic proxy resolution
 * using enviromental variables/ wpad protoco.
 * libproxy return proxy url for further processing.
 * get_netip_port do url to network fromated ip. function use that
 * to fill fdoip structure and port no as return value
 */
static bool discover_proxy(fdo_ip_address_t *fdoip, uint16_t *port_num)
{
	int ret = -1;
	uint16_t proxy_port = 0;
	uint8_t proxy[16] = {
	    0,
	}; // Max Characters 255.255.255.255

	size_t nread = 0;

	// Create a proxy factory instance
	px_proxy_factory *pf = px_proxy_factory_new();

	if (!pf) {
		return 1;
	}

	// Get which proxies to use in order to fetch "http://www.google.com"
	char **proxies =
	    px_proxy_factory_get_proxies(pf, "https://www.google.com");

	// Iterate over the returned proxies, attemping to fetch the URL
	for (int i = 0; proxies[i]; i++) {
		nread = strnlen_s(proxies[i], FDO_MAX_STR_SIZE);
		if (!nread || nread == FDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Couldn't find a valid string.\n");
			continue;
		}
		if (get_netip_port(proxies[i], nread, proxy, &proxy_port) ==
		    false) {
			LOG(LOG_ERROR, "cant getip/ port\n");
			continue;
		} else {
			LOG(LOG_DEBUG, "getip port done port\n");
			break;
		}
	}
	if (!proxy_port) {
		LOG(LOG_ERROR, "No proxy ip discovered/ port\n");
		goto err;
	}

#if !defined(OPTEE_ADAPTATION)
	fdo_init_ipv4_address(fdoip, proxy);
#else
	if (strncpy_s((char *)fdoip->addr, sizeof(fdoip->addr), proxy,
		      sizeof(proxy))) {
		return false;
	}
	fdoip->length = sizeof(fdoip->addr);
#endif
	*port_num = proxy_port;

	ret = 0;
err:
	// Free the proxy list
	for (int i = 0; proxies[i]; i++) {
		if (proxies[i]) {
			fdo_free(proxies[i]);
		}
	}
	if (proxies) {
		fdo_free(proxies);
	}

	// Free the proxy factory
	px_proxy_factory_free(pf);

	if (ret) {
		return false;
	}
	return true;
}
#endif

/* setup http proxy from file for further network operation operation */
bool setup_http_proxy(const char *filename, fdo_ip_address_t *fdoip,
		      uint16_t *port_num)
{
	int ret = -1;
	uint16_t proxy_port = 0;
	uint8_t proxy[16] = {
	    0,
	}; // Max Characters 255.255.255.255

	uint8_t *proxydata = NULL;
	size_t nread = 0;

	if (!fdoip || !port_num) {
		LOG(LOG_DEBUG, "HTTP Proxy File not read properly\n");
		return false;
	}

	if (memset_s(fdoip, sizeof(fdo_ip_address_t), 0) != 0) {
		LOG(LOG_ERROR, "Clearing memory failed\n");
		return false;
	}

	nread = fdo_blob_size((char *)filename, FDO_SDK_RAW_DATA);
	if (nread > 0) {
		proxydata = fdo_alloc(nread + 1);
		if (!proxydata) {
			LOG(LOG_ERROR, "Could not allocate memory to read proxy information.\n");
			goto err;
		}
		if (fdo_blob_read((char *)filename, FDO_SDK_RAW_DATA, proxydata,
				  nread) == -1) {
			LOG(LOG_ERROR, "Could not read %s file\n", filename);
			goto err;
		}
		proxydata[nread] = '\0';
	} else {
		LOG(LOG_INFO, "'%s' with proxy info absent\n", filename);
		goto err;
	}

	if (!nread) {
		LOG(LOG_DEBUG,
		    "HTTP Proxy enabled but properties file missing !!\n");
		goto err;
	}

	if (get_netip_port((const char *)proxydata, nread, proxy,
			   &proxy_port) == false) {
		LOG(LOG_ERROR, "cant getip/ port\n");
		goto err;
	}

	fdo_init_ipv4_address(fdoip, proxy);
	*port_num = proxy_port;

	ret = 0;
err:
	if (proxydata) {
		fdo_free(proxydata);
	}
	if (ret) {
		return false;
	}
	return true;
}
#endif
/**
 * Initialize network related states and members.
 */
void fdo_net_init(void)
{
#if defined HTTPPROXY
	if (setup_http_proxy(MFG_PROXY, &mfgproxy_ip, &mfgproxy_port)) {
		LOG(LOG_INFO, "Manufacturer HTTP proxy has been configured\n");
	}
#if defined(PROXY_DISCOVERY)

	else {
		if (discover_proxy(&mfgproxy_ip, &mfgproxy_port)) {
			LOG(LOG_INFO, "Manufacturer HTTP proxy has been "
				      "discovered & configured\n");
		}
	}
#endif

	if (setup_http_proxy(RV_PROXY, &rvproxy_ip, &rvproxy_port)) {
		LOG(LOG_INFO, "Rendezvous HTTP proxy has been configured\n");
	}
#if defined(PROXY_DISCOVERY)
	else {
		if (discover_proxy(&rvproxy_ip, &rvproxy_port)) {
			LOG(LOG_INFO, "Rendezvous HTTP proxy has been "
				      "discovered & configured\n");
		}
	}
#endif

	if (setup_http_proxy(OWNER_PROXY, &ownerproxy_ip, &ownerproxy_port)) {
		LOG(LOG_INFO, "Owner HTTP proxy has been configured\n");
	}
#if defined(PROXY_DISCOVERY)
	else {
		if (discover_proxy(&ownerproxy_ip, &ownerproxy_port)) {
			LOG(LOG_INFO, "Owner HTTP proxy has been discovered & "
				      "configured\n");
		}
	}
#endif

#endif
}

/**
 * Get a valid IP mapping to the dn provided
 *
 * @param dn: Domain name of the server
 * @param ip: A valid IP address mapping to this dn.
 * @param port: A valid port number mapping to this dn.
 * @param tls: flag describing whether HTTP (false) or HTTPS (true) is
 * @param proxy: proxy enabled for this ip access.
 *
 * @return ret
 *         true if successful. false in case of error.
 */
bool resolve_dn(const char *dn, fdo_ip_address_t **ip, uint16_t port,
		bool tls, bool proxy)
{
	bool ret = false;
	uint32_t num_ofIPs = 0;
	fdo_con_handle sock_hdl = FDO_CON_INVALID_HANDLE;
	fdo_ip_address_t *ip_list = NULL;
	rest_ctx_t *rest = NULL;

	if (!dn || !ip) {
		LOG(LOG_ERROR, "Invalid inputs\n");
		goto end;
	}
	/* DNS is non-NULL, */
	LOG(LOG_DEBUG, "using DNS: %s\n", dn);

	if (proxy) {

		/* cache DNS to REST */
		rest = get_rest_context();

		if (!rest) {
			LOG(LOG_ERROR, "REST context is NULL!\n");
			goto end;
		}

		if (!cache_host_dns(dn)) {
			LOG(LOG_ERROR, "REST DNS caching failed!\n");
		} else {
			ret = true;
		}
		goto end;
	}
	// get list of IPs resolved to given DNS
	if (fdo_con_dns_lookup(dn, &ip_list, &num_ofIPs) == -1) {
		LOG(LOG_ERROR, "DNS look-up failed!\n");
		goto end;
	}

	curl = curl_easy_init();

	if (ip_list && num_ofIPs > 0) {
		// Iterate over IP-list to connect
		uint32_t iter = 0;

		while (iter != num_ofIPs &&
		       sock_hdl == FDO_CON_INVALID_HANDLE) {

			sock_hdl = fdo_con_connect((ip_list + iter), port,
						   tls);
			if (sock_hdl == FDO_CON_INVALID_HANDLE) {
				LOG(LOG_ERROR, "Failed to connect to "
					       "server: retrying...\n");
			}
			iter++;
		}

		if (FDO_CON_INVALID_HANDLE != sock_hdl) {
			fdo_con_disconnect(sock_hdl);
			if (!cache_host_dns(dn)) {
				LOG(LOG_ERROR, "REST DNS caching failed!\n");
				goto end;
			}
			*ip = fdo_alloc(sizeof(fdo_ip_address_t));
			if (0 != memcpy_s(*ip, sizeof(fdo_ip_address_t),
					  ip_list + (iter - 1),
					  sizeof(fdo_ip_address_t))) {
				LOG(LOG_ERROR, "Memcpy failed\n");
				goto end;
			}
			ret = true;
			goto end;
		} else {
			*ip = NULL;
			goto end;
		}
	}
end:
	if (ip_list) { // free ip_list
		fdo_free(ip_list);
	}

	return ret;
}

/**
 * Connects device to manufacturer or cred tool. Connection info should be
 * programmed into device by the manufacturer.
 *
 * @param ip:   IP address of the server to connect to.
 * @param port: Port number of the server instance to connect to.
 * @param sock_hdl: Sock struct for subsequent read/write/close.
 * @param tls: flag describing whether HTTP (false) or HTTPS (true) is
 *
 * @return ret
 *         true if successful. false in case of error.
 */
bool connect_to_manufacturer(fdo_ip_address_t *ip, uint16_t port,
			     fdo_con_handle *sock_hdl, bool tls)
{
	bool ret = false;
	int retries = MANUFACTURER_CONNECT_RETRIES;
	curl = curl_easy_init();

	LOG(LOG_DEBUG, "Connecting to manufacturer Server\n");

	if (!ip) {
		goto end;
	}

	if (!sock_hdl) {
		LOG(LOG_ERROR, "Connection handle (socket) is NULL\n");
		goto end;
	}

	/* cache ip/dns and port to REST */
	if (!cache_host_ip(ip)) {
		LOG(LOG_ERROR,
		    "Mfg IP-address caching to REST failed!\n");
		goto end;
	}

	if (!cache_host_port(port)) {
		LOG(LOG_ERROR, "Mfg portno caching to REST failed!\n");
		goto end;
	}

	if (tls) {
		if (!cache_tls_connection()) {
			LOG(LOG_ERROR, "REST TLS caching failed!\n");
			goto end;
		}
	}

	if (is_mfg_proxy_defined()) {
#if defined HTTPPROXY
	if (!fdo_curl_proxy(&mfgproxy_ip, mfgproxy_port)) {
		LOG(LOG_ERROR,
		"Failed to setup Proxy Connection info for Manufacturer server!\n");
		goto end;
	}

	LOG(LOG_DEBUG, "via HTTP proxy <%u.%u.%u.%u:%u>\n",
		    mfgproxy_ip.addr[0], mfgproxy_ip.addr[1],
		    mfgproxy_ip.addr[2], mfgproxy_ip.addr[3], mfgproxy_port);
#endif
	}

	if (ip && ip->length > 0) {
		LOG(LOG_DEBUG, "using IP\n");

		*sock_hdl = fdo_con_connect(ip, port, tls);
		if ((*sock_hdl == FDO_CON_INVALID_HANDLE) &&
		    retries--) {
			LOG(LOG_INFO, "Failed to connect to Manufacturer "
				      "server: retrying...\n");
			fdo_sleep(RETRY_DELAY);
		}
	} else {
		LOG(LOG_ERROR,
		    "Invalid Connection info for Manufacturer server!\n");
		goto end;
	}

	if (FDO_CON_INVALID_HANDLE == *sock_hdl) {
		LOG(LOG_ERROR,
		    "Failed to connect to Manufacturer server: Giving up...\n");
		goto end;
	}
	ret = true;

end:
	return ret;
}
/**
 * Connects device to rendezvous server by picking the connection info
 * from RV list stored in device credentials.
 *
 * @param ip:   IP address of the server to connect to.
 * @param port: Port number of the server instance to connect to.
 * @param sock_hdl: Sock struct for subsequent read/write/close.
 * @param tls: flag describing whether HTTP (false) or HTTPS (true) is
 *
 * @return ret
 *         true if successful. false in case of error.
 */
bool connect_to_rendezvous(fdo_ip_address_t *ip, uint16_t port,
			   fdo_con_handle *sock_hdl, bool tls)
{
	bool ret = false;
	int retries = RENDEZVOUS_CONNECT_RETRIES;
	curl = curl_easy_init();

	LOG(LOG_DEBUG, "Connecting to Rendezvous server\n");

	if (!ip) {
		goto end;
	}

	if (!sock_hdl) {
		LOG(LOG_ERROR, "Connection handle (socket) is NULL\n");
		goto end;
	}

	/* cache ip/dns and port to REST */
	if (!cache_host_ip(ip)) {
		LOG(LOG_ERROR, "REST IP-address caching failed!\n");
		goto end;
	}

	if (!cache_host_port(port)) {
		LOG(LOG_ERROR, "RV portno caching to REST failed!\n");
		goto end;
	}

	if (tls) {
		if (!cache_tls_connection()) {
			LOG(LOG_ERROR, "REST TLS caching failed!\n");
			goto end;
		}
	}

	if (is_rv_proxy_defined()) {
#if defined HTTPPROXY
	if (!fdo_curl_proxy(&rvproxy_ip, rvproxy_port)) {
		LOG(LOG_ERROR,
		"Failed to setup Proxy Connection info for Rendezvous server!\n");
		goto end;
	}

	LOG(LOG_DEBUG, "via HTTP proxy <%u.%u.%u.%u:%u>\n",
		    rvproxy_ip.addr[0], rvproxy_ip.addr[1], rvproxy_ip.addr[2],
		    rvproxy_ip.addr[3], rvproxy_port);
#endif
	}

	if (ip && ip->length > 0) {
		LOG(LOG_DEBUG, "using IP\n");

		*sock_hdl = fdo_con_connect(ip, port, tls);
		if ((*sock_hdl == FDO_CON_INVALID_HANDLE) &&
		    retries--) {
			LOG(LOG_INFO, "Failed to connect to Rendezvous server: "
				      "retrying...\n");
			fdo_sleep(RETRY_DELAY);
		}
	} else {
		LOG(LOG_ERROR,
		    "Invalid Connection info for Rendezvous server!\n");
		goto end;
	}

	if (FDO_CON_INVALID_HANDLE == *sock_hdl) {
		LOG(LOG_ERROR,
		    "Failed to connect to rendezvous: Giving up...\n");
		goto end;
	}
	ret = true;

end:
	return ret;
}

/**
 * onnects device to owner by picking the connection info from info
 * received by Rendezvous stored in device credentials.
 *
 * @param ip:   IP address of the server to connect to.
 * @param port: Port number of the server instance to connect to.
 * @param sock_hdl: Sock struct for subsequent read/write/close.
 * @param tls: flag describing whether HTTP (false) or HTTPS (true) is
 *
 * @return ret
 *         true if successful. false in case of error.
 */
bool connect_to_owner(fdo_ip_address_t *ip, uint16_t port,
		      fdo_con_handle *sock_hdl, bool tls)
{
	bool ret = false;
	int retries = OWNER_CONNECT_RETRIES;
	curl = curl_easy_init();

	LOG(LOG_DEBUG, "Connecting to owner server\n");

	if (!ip) {
		goto end;
	}

	if (!sock_hdl) {
		LOG(LOG_ERROR, "Connection handle (socket) is NULL\n");
		goto end;
	}

	/* cache ip/dns and port to REST */
	if (!cache_host_ip(ip)) {
		LOG(LOG_ERROR,
		    "Owner IP-address caching to REST failed!\n");
		goto end;
	}

	if (!cache_host_port(port)) {
		LOG(LOG_ERROR, "Owner portno caching to REST failed!\n");
		goto end;
	}

	if (tls) {
		if (!cache_tls_connection()) {
			LOG(LOG_ERROR, "REST TLS caching failed!\n");
			goto end;
		}
	}

	if (is_owner_proxy_defined()) {
#if defined HTTPPROXY
	if (!fdo_curl_proxy(&ownerproxy_ip, ownerproxy_port)) {
		LOG(LOG_ERROR,
		"Failed to setup Proxy Connection info for Owner server!\n");
		goto end;
	}

	LOG(LOG_DEBUG, "via HTTP proxy <%u.%u.%u.%u:%u>\n",
		    ownerproxy_ip.addr[0], ownerproxy_ip.addr[1],
		    ownerproxy_ip.addr[2], ownerproxy_ip.addr[3],
		    ownerproxy_port);
#endif
	}

	if (ip && ip->length > 0) {
		LOG(LOG_DEBUG, "using IP\n");

		*sock_hdl = fdo_con_connect(ip, port, tls);
		if ((*sock_hdl == FDO_CON_INVALID_HANDLE) &&
		    retries--) {
			LOG(LOG_INFO,
			    "Failed to connect to Owner server: retrying...\n");
			fdo_sleep(RETRY_DELAY);
		}
	} else {
		LOG(LOG_ERROR, "Invalid Connection info for Owner server!\n");
		goto end;
	}

	if (FDO_CON_INVALID_HANDLE == *sock_hdl) {
		LOG(LOG_ERROR, "Failed to connect to Owner: Giving up...\n");
		goto end;
	}
	ret = true;

end:
	return ret;
}

/**
 * Try reconnecting to server when connection is lost.
 *
 * @param prot_ctx
 *        handle to protocol context containing connection info such as
 * IP/Port
 * handle etc..
 * @retval 0 on success. -1 on failure.
 */
int fdo_connection_restablish(fdo_prot_ctx_t *prot_ctx)
{
	int retries = OWNER_CONNECT_RETRIES;

	/* re-connect using server-IP */
	while (((prot_ctx->sock_hdl = fdo_con_connect(
		     prot_ctx->host_ip, prot_ctx->host_port, prot_ctx->tls)) ==
		FDO_CON_INVALID_HANDLE) &&
	       retries--) {
		LOG(LOG_INFO, "Failed reconnecting to server: retrying...");
		fdo_sleep(RETRY_DELAY);
	}

	if (prot_ctx->sock_hdl == FDO_CON_INVALID_HANDLE) {
		LOG(LOG_ERROR, "Failed reconnecting to server: Giving up...");
		return -1;
	} else {
		return 0;
	}
}
