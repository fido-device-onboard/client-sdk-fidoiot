/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "util.h"
#include "network_al.h"
#include "sdonet.h"
#include "sdotypes.h"
#include "safe_lib.h"
#include <stdlib.h>
#include "storage_al.h"
#include "rest_interface.h"

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
static SDOIPAddress_t rvproxy_ip;
static uint16_t rvproxy_port;
static SDOIPAddress_t mfgproxy_ip;
static uint16_t mfgproxy_port;
static SDOIPAddress_t ownerproxy_ip;
static uint16_t ownerproxy_port;
#endif // defined HTTPPROXY

/**
 * Internal API
 */
bool is_rv_proxy_defined(void)
{
#if defined HTTPPROXY
	if (rvproxy_port != 0)
		return true;
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
	if (mfgproxy_port != 0)
		return true;
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
	if (ownerproxy_port != 0)
		return true;
	LOG(LOG_DEBUG, "Proxy enabled but Not set\n");
#endif // defined HTTPPROXY
	return false;
}

#ifdef HTTPPROXY

/**
 * Internal API
 */

/* internal api
 * proxydata: proxy data as asscii string. e.g."http://theproxy.intel.com:123"
 * return resolved dns, as ip in network format and port
 */
static bool get_netip_port(const char *proxydata, uint8_t proxydatsize,
			   uint8_t *netip, uint16_t *proxy_port)
{
	int i = 0, ret = -1;
	uint32_t numOfIPs = 0;
	SDOIPAddress_t *ipList = NULL;
	uint8_t *pch = NULL;
	uint8_t *proxy = NULL;
	char proxy_url[40] = {0};

	ret =
	    strstr_s((char *)proxydata, proxydatsize, "://", 3, (char **)&pch);
	if (ret != 0 && ret != ESNOTFND)
		return false;

	if (pch)
		proxy = pch + 3;
	else
		proxy = (uint8_t *)proxydata;

	while (proxy[i] != 0 && proxy[i] != ':') {
		proxy_url[i] = proxy[i];
		i++;
	}
#if !defined(OPTEE_ADAPTATION)
	// resolve dn proxy-chain.intel.com
	if (sdoConDnsLookup(proxy_url, &ipList, &numOfIPs) == -1) {
		LOG(LOG_ERROR, "DNS look-up failed!\n");
		goto err;
	}

	/* Copy the network address to proxy */
	/* TODO: iterate for proxy dn (only first one used) */
	if (memcpy_s(netip, ipList->length, ipList->addr, ipList->length) !=
	    0) {
		LOG(LOG_ERROR, "Memcpy failed for ip address copy \n");
		goto err;
	}
#else
	if (strncpy_s((char *)netip, sizeof(sdoip->addr), proxy_url,
		      sizeof(proxy_url)) != 0) {
		LOG(LOG_ERROR, "optee: Memcpy failed for ip address copy \n");
		goto err;
	}
#endif

	if (proxy[i] == ':')
		*proxy_port = atoi((const char *)&proxy[i + 1]);
	ret = 0;
err:
	if (ipList)
		sdoFree(ipList);
	if (ret)
		return false;
	return true;
}

#if defined(PROXY_DISCOVERY)
/* api use libproxy for automatic proxy resolution
 * using enviromental variables/ wpad protoco.
 * libproxy return proxy url for further processing.
 * get_netip_port do url to network fromated ip. function use that
 * to fill sdoip structure and port no as return value */
static bool discover_proxy(SDOIPAddress_t *sdoip, uint16_t *port_num)
{
	int ret = -1;
	uint16_t proxy_port = 0;
	uint8_t proxy[16] = {
	    0,
	}; // Max Characters 255.255.255.255

	size_t nread = 0;

	// Create a proxy factory instance
	pxProxyFactory *pf = px_proxy_factory_new();
	if (!pf)
		return 1;

	// Get which proxies to use in order to fetch "http://www.google.com"
	char **proxies =
	    px_proxy_factory_get_proxies(pf, "https://www.google.com");

	// Iterate over the returned proxies, attemping to fetch the URL
	for (int i = 0; proxies[i]; i++) {
		nread = strnlen_s(proxies[i], SDO_MAX_STR_SIZE);
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
	sdoInitIPv4Address(sdoip, proxy);
#else
	if (strncpy_s((char *)sdoip->addr, sizeof(sdoip->addr), proxy,
		      sizeof(proxy)))
		return false;
	sdoip->length = sizeof(sdoip->addr);
#endif
	*port_num = proxy_port;

	ret = 0;
err:
	// Free the proxy list
	for (int i = 0; proxies[i]; i++) {
		if (proxies[i])
			sdoFree(proxies[i]);
	}
	if (proxies)
		sdoFree(proxies);

	// Free the proxy factory
	px_proxy_factory_free(pf);

	if (ret)
		return false;
	return true;
}
#endif

/* setup http proxy from file for further network operation operation */
bool setup_http_proxy(const char *filename, SDOIPAddress_t *sdoip,
		      uint16_t *port_num)
{
	int ret = -1;
	uint16_t proxy_port = 0;
	uint8_t proxy[16] = {
	    0,
	}; // Max Characters 255.255.255.255

	uint8_t *proxydata = NULL;
	size_t nread = 0;

	if (!sdoip || !port_num) {
		LOG(LOG_DEBUG, "HTTP Proxy File not read properly\n");
		return false;
	}

	if (memset_s(sdoip, sizeof(SDOIPAddress_t), 0) != 0) {
		LOG(LOG_ERROR, "Clearing memory failed\n");
		return false;
	}

	if ((nread = sdoBlobSize((char *)filename, SDO_SDK_RAW_DATA)) > 0) {
		proxydata = sdoAlloc(nread);
		if (sdoBlobRead((char *)filename, SDO_SDK_RAW_DATA, proxydata,
				nread) == -1) {
			LOG(LOG_ERROR, "Could not read %s file\n", filename);
			return false;
		}
	} else {
		LOG(LOG_INFO, "'%s' with proxy info absent\n", filename);
		return false;
	}

	if (!nread) {
		LOG(LOG_DEBUG,
		    "HTTP Proxy enabled but properties file missing !!\n");
		return false;
	}

	if (get_netip_port((const char *)proxydata, nread, proxy,
			   &proxy_port) == false) {
		LOG(LOG_ERROR, "cant getip/ port\n");
		goto err;
	}

#if !defined(OPTEE_ADAPTATION)
	sdoInitIPv4Address(sdoip, proxy);
#else
	if (strncpy_s((char *)sdoip->addr, sizeof(sdoip->addr), proxy,
		      sizeof(proxy)))
		return false;
	sdoip->length = sizeof(sdoip->addr);
#endif
	*port_num = proxy_port;

	ret = 0;
err:
	if (proxydata)
		sdoFree(proxydata);
	if (ret)
		return false;
	return true;
}
#endif
/**
 * Initialize network related states and members.
 */
void sdoNetInit(void)
{
#if defined HTTPPROXY
	if (setup_http_proxy(MFG_PROXY, &mfgproxy_ip, &mfgproxy_port)) {
		LOG(LOG_INFO, "Manufacturer HTTP proxy has been configured\n");
	}
#if defined(PROXY_DISCOVERY)

	else {
		if (discover_proxy(&mfgproxy_ip, &mfgproxy_port))
			LOG(LOG_INFO, "Manufacturer HTTP proxy has been "
				      "discovered & configured\n");
	}
#endif

	if (setup_http_proxy(RV_PROXY, &rvproxy_ip, &rvproxy_port)) {
		LOG(LOG_INFO, "Rendezvous HTTP proxy has been configured\n");
	}
#if defined(PROXY_DISCOVERY)
	else {
		if (discover_proxy(&rvproxy_ip, &rvproxy_port))
			LOG(LOG_INFO, "Rendezvous HTTP proxy has been "
				      "discovered & configured\n");
	}
#endif

	if (setup_http_proxy(OWNER_PROXY, &ownerproxy_ip, &ownerproxy_port)) {
		LOG(LOG_INFO, "Owner HTTP proxy has been configured\n");
	}
#if defined(PROXY_DISCOVERY)
	else {
		if (discover_proxy(&ownerproxy_ip, &ownerproxy_port))
			LOG(LOG_INFO, "Owner HTTP proxy has been discovered & "
				      "configured\n");
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
 * @param ssl: ssl context in case of ssl connection.
 * @param proxy: proxy enabled for this ip access.
 *
 * @return ret
 *         true if successful. false in case of error.
 */
bool ResolveDn(const char *dn, SDOIPAddress_t **ip, uint16_t port, void **ssl,
	       bool proxy)
{
	bool ret = false;
	uint32_t numOfIPs = 0;
	sdoConHandle sock = SDO_CON_INVALID_HANDLE;
	SDOIPAddress_t *ipList = NULL;
	RestCtx_t *rest = NULL;

	if (!dn || !ip) {
		LOG(LOG_ERROR, "Invalid inputs\n");
		goto end;
	}
	/* DNS is non-NULL, */
	LOG(LOG_DEBUG, "using DNS: %s\n", dn);

	if (proxy) {

		/* cache DNS to REST */
		rest = getRESTContext();

		if (!rest) {
			LOG(LOG_ERROR, "REST context is NULL!\n");
			goto end;
		}

		if (!cacheHostDns(dn)) {
			LOG(LOG_ERROR, "REST DNS caching failed!\n");
		} else
			ret = true;
		goto end;
	}
	// get list of IPs resolved to given DNS
	if (sdoConDnsLookup(dn, &ipList, &numOfIPs) == -1) {
		LOG(LOG_ERROR, "DNS look-up failed!\n");
		goto end;
	}

	if (ipList && numOfIPs > 0) {
		// Iterate over IP-list to connect
		uint32_t iter = 0;
		while (iter != numOfIPs && sock == SDO_CON_INVALID_HANDLE) {
			if (((sock =
				  sdoConConnect((ipList + iter), port, ssl)) ==
			     SDO_CON_INVALID_HANDLE)) {
				LOG(LOG_ERROR, "Failed to connect to "
					       "server: retrying...\n");
			}
			iter++;
		}

		if (SDO_CON_INVALID_HANDLE != sock) {
			sdoConDisconnect(sock, (ssl ? *ssl : NULL));
			if (!cacheHostDns(dn)) {
				LOG(LOG_ERROR, "REST DNS caching failed!\n");
				goto end;
			}
			*ip = sdoAlloc(sizeof(SDOIPAddress_t));
			if (0 != memcpy_s(*ip, sizeof(SDOIPAddress_t),
					  ipList + (iter - 1),
					  sizeof(SDOIPAddress_t))) {
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
	if (ipList) // free ipList
		sdoFree(ipList);
	return ret;
}

/**
 * Connects device to manufacturer or cred tool. Connection info should be
 * programmed into device by the manufacturer.
 *
 * @param ip:   IP address of the server to connect to.
 * @param port: Port number of the server instance to connect to.
 * @param sock: Sock fd for subsequent read/write/close.
 * @param ssl:  ssl fd for subsequent read/write/close in case of https.
 *
 * @return ret
 *         true if successful. false in case of error.
 */
bool ConnectToManufacturer(SDOIPAddress_t *ip, uint16_t port, int *sock,
			   void **ssl)
{
	bool ret = false;
	int retries = MANUFACTURER_CONNECT_RETRIES;

	LOG(LOG_DEBUG, "Connecting to manufacturer Server\n");

	if (!sock) {
		LOG(LOG_ERROR, "Connection handle (socket) is NULL\n");
		goto end;
	}

	/* cache ip/dns and port to REST */
	if (ip) {
		if (!cacheHostIP(ip)) {
			LOG(LOG_ERROR,
			    "Mfg IP-address caching to REST failed!\n");
			goto end;
		}
	}

	if (!cacheHostPort(port)) {
		LOG(LOG_ERROR, "Mfg portno caching to REST failed!\n");
		goto end;
	}

	if (is_mfg_proxy_defined()) {
#if defined HTTPPROXY
		ip = &mfgproxy_ip;
		port = mfgproxy_port;

		LOG(LOG_DEBUG, "via HTTP proxy <%u.%u.%u.%u:%u>\n",
		    mfgproxy_ip.addr[0], mfgproxy_ip.addr[1],
		    mfgproxy_ip.addr[2], mfgproxy_ip.addr[3], mfgproxy_port);
#endif
	}

	if (ip && ip->length > 0) {
		LOG(LOG_DEBUG, "using IP\n");
		if (((*sock = (int)sdoConConnect(ip, port, ssl)) ==
		     SDO_CON_INVALID_HANDLE) &&
		    retries--) {
			LOG(LOG_INFO, "Failed to connect to Manufacturer "
				      "server: retrying...\n");
			sdoSleep(RETRY_DELAY);
		}
	} else {
		LOG(LOG_ERROR,
		    "Invalid Connection info for Manufacturer server!\n");
		goto end;
	}

	if (SDO_CON_INVALID_HANDLE == *sock) {
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
 * @param sock: Sock fd for subsequent read/write/close.
 * @param ssl:  ssl fd for subsequent read/write/close in case of https.
 *
 * @return ret
 *         true if successful. false in case of error.
 */
bool ConnectToRendezvous(SDOIPAddress_t *ip, uint16_t port, int *sock,
			 void **ssl)
{
	bool ret = false;
	int retries = RENDEZVOUS_CONNECT_RETRIES;

	LOG(LOG_DEBUG, "Connecting to Rendezvous server\n");

	if (!sock) {
		LOG(LOG_ERROR, "Connection handle (socket) is NULL\n");
		goto end;
	}

	/* cache ip/dns and port to REST */
	if (ip) {
		if (!cacheHostIP(ip)) {
			LOG(LOG_ERROR, "REST IP-address caching failed!\n");
			goto end;
		}
	} else {
	}

	if (!cacheHostPort(port)) {
		LOG(LOG_ERROR, "RV portno caching to REST failed!\n");
		goto end;
	}

	if (ssl)
		if (!cacheTLSConnection()) {
			LOG(LOG_ERROR, "REST TLS caching failed!\n");
			goto end;
		}

	if (is_rv_proxy_defined()) {
#if defined HTTPPROXY
		ip = &rvproxy_ip;
		port = rvproxy_port;
		// When connecting through proxy, the proxy server will
		// establish tls connection. Device opens a normal connection to
		// Proxy server
		ssl = NULL;

		LOG(LOG_DEBUG, "via HTTP proxy <%u.%u.%u.%u:%u>\n",
		    rvproxy_ip.addr[0], rvproxy_ip.addr[1], rvproxy_ip.addr[2],
		    rvproxy_ip.addr[3], rvproxy_port);
#endif
	}

	if (ip && ip->length > 0) {
		LOG(LOG_DEBUG, "using IP\n");
		if (((*sock = sdoConConnect(ip, port, ssl)) ==
		     SDO_CON_INVALID_HANDLE) &&
		    retries--) {
			LOG(LOG_INFO, "Failed to connect to Rendezvous server: "
				      "retrying...\n");
			sdoSleep(RETRY_DELAY);
		}
	} else {
		LOG(LOG_ERROR,
		    "Invalid Connection info for Rendezvous server!\n");
		goto end;
	}

	if (SDO_CON_INVALID_HANDLE == *sock) {
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
 * @param sock: Sock fd for subsequent read/write/close.
 * @param ssl:  ssl fd for subsequent read/write/close in case of https.
 *
 * @return ret
 *         true if successful. false in case of error.
 */
bool ConnectToOwner(SDOIPAddress_t *ip, uint16_t port, int *sock, void **ssl)
{
	bool ret = false;
	int retries = OWNER_CONNECT_RETRIES;

	LOG(LOG_DEBUG, "Connecting to owner server\n");

	if (!sock) {
		LOG(LOG_ERROR, "Connection handle (socket) is NULL\n");
		goto end;
	}

	/* cache ip/dns and port to REST */
	if (ip) {
		if (!cacheHostIP(ip)) {
			LOG(LOG_ERROR,
			    "Owner IP-address caching to REST failed!\n");
			goto end;
		}
	}

	if (!cacheHostPort(port)) {
		LOG(LOG_ERROR, "Owner portno caching to REST failed!\n");
		goto end;
	}

	if (is_owner_proxy_defined()) {
#if defined HTTPPROXY
		ip = &ownerproxy_ip;
		port = ownerproxy_port;

		LOG(LOG_DEBUG, "via HTTP proxy <%u.%u.%u.%u:%u>\n",
		    ownerproxy_ip.addr[0], ownerproxy_ip.addr[1],
		    ownerproxy_ip.addr[2], ownerproxy_ip.addr[3],
		    ownerproxy_port);
#endif
	}

	if (ip && ip->length > 0) {
		LOG(LOG_DEBUG, "using IP\n");
		if (((*sock = sdoConConnect(ip, port, ssl)) ==
		     SDO_CON_INVALID_HANDLE) &&
		    retries--) {
			LOG(LOG_INFO,
			    "Failed to connect to Owner server: retrying...\n");
			sdoSleep(RETRY_DELAY);
		}
	} else {
		LOG(LOG_ERROR, "Invalid Connection info for Owner server!\n");
		goto end;
	}

	if (SDO_CON_INVALID_HANDLE == *sock) {
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
 * IP/Port/ssl
 * handle etc..
 * @retval 0 on success. -1 on failure.
 */
int sdoConnectionRestablish(SDOProtCtx_t *prot_ctx)
{
	int retries = OWNER_CONNECT_RETRIES;

	/* re-connect using server-IP */
	while (((prot_ctx->sock =
		     sdoConConnect(prot_ctx->host_ip, prot_ctx->host_port,
				   prot_ctx->ssl)) == SDO_CON_INVALID_HANDLE) &&
	       retries--) {
		LOG(LOG_INFO, "Failed reconnecting to server: retrying...");
		sdoSleep(RETRY_DELAY);
	}

	if (prot_ctx->sock == SDO_CON_INVALID_HANDLE) {
		LOG(LOG_ERROR, "Failed reconnecting to server: Giving up...");
		return -1;
	} else
		return 0;
}
