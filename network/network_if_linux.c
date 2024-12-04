/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Abstraction Layer Library
 *
 * The file implements an abstraction layer for Linux OS running on PC.
 */

#include <netinet/in.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h> //hostent
#include <arpa/inet.h>

#include "util.h"
#include "network_al.h"
#include "fdo_crypto_hal.h"
#include "fdoprotctx.h"
#include "fdonet.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "rest_interface.h"

// Function used by libcurl to allocate memory to data received from the HTTP
// response
static void init_string(struct MemoryStruct *s)
{
	s->size = 0;
	s->memory = malloc(s->size + 1);
	if (s->memory == NULL) {
		LOG(LOG_ERROR, "malloc() failed\n");
		exit(EXIT_FAILURE);
	}
	s->memory[0] = '\0';
}

// Callback for libcurl. data written to this buffer.
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb,
				  void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	char *ptr = (char *)realloc(mem->memory, mem->size + realsize + 1);
	if (ptr == NULL) {
		LOG(LOG_ERROR, "error: not enough memory\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

/**
 * Read from curl buffer until new-line is encountered.
 *
 * @param out -  out pointer for REST header line.
 * @param size - out REST header line length.
 * @param curl_buf: data buffer to read into msg received by curl.
 * @param curl_buf_offset: pointer to track curl_buf.
 * @retval true if line read was successful, false otherwise.
 */
static bool read_until_new_line(char *out, size_t size, char *curl_buf,
				size_t *curl_buf_offset)
{
	size_t sz;
	char c;

	if (!out || !size) {
		return false;
	}

	--size; // leave room for NULL
	sz = 0;

	for (;;) {
		c = curl_buf[*curl_buf_offset + sz];

		if (sz < size) {
			out[sz++] = c;
		} else {
			// error out even if no new-line is encountered
			// if the sz grows larger than size
			LOG(LOG_ERROR,
			    "Exceeded expected size while reading buffer\n");
			return false;
		}

		if (c == '\n') {
			*curl_buf_offset += sz;
			break;
		}
	}
	out[sz] = 0;
	/* remove \n and \r and don't process invalid string */
	if ((sz < size) && (sz >= 1)) {
		out[--sz] = 0; // remove NL
		if ((sz >= 1) && (out[sz - 1] == '\r')) {
			out[--sz] = 0; // ... remove CRNL
		}
	}

	return true;
}

/**
 * fdo_con_setup Connection Setup.
 *
 * @param medium - specified network medium to connect to
 * @param params - parameters(if any) supported for 'medium'
 * @param count - number of valid string in params
 * @return 0 on success. -1 on failure
 */
int32_t fdo_con_setup(char *medium, char **params, uint32_t count)
{
	/*TODO: make use of input params (if required ?)*/
	(void)medium;
	(void)params;
	(void)count;

	// Initiate REST context
	if (!init_rest_context()) {
		LOG(LOG_ERROR, "init_rest_context() failed!\n");
		return -1;
	}
	return 0;
}

/**
 * Perform a DNS look for a specified host.
 * Note : return ip address in network format.
 * @param url - host's URL.
 * @param ip_list - output IP address list for specified host URL.
 * @param ip_list_size - output number of IP address in ip_list
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_dns_lookup(const char *url, fdo_ip_address_t **ip_list,
			   uint32_t *ip_list_size)
{
	int idx;
	struct addrinfo *result = NULL, *it = NULL;
	struct addrinfo hints;
	struct sockaddr_in *sa_in = NULL;
	fdo_ip_address_t *ip_list_temp = NULL;
	int32_t ret = -1;

	if (!url || !ip_list || !ip_list_size) {
		return ret;
	}

	LOG(LOG_DEBUG, "Resolving DNS-URL: <%s>\n", url);

	if (memset_s(&hints, sizeof(hints), 0) != 0) {
		LOG(LOG_ERROR, "Memset failed\n");
		goto end;
	}

	hints.ai_family = AF_INET; // IPv4
	hints.ai_socktype = SOCK_STREAM;

	// get the list-of IP addresses
	if (getaddrinfo(url, NULL, &hints, &result) != 0) {
		LOG(LOG_ERROR, "getaddrinfo() failed!\n");
		goto end;
	}

	int len = 0;

	// get length of the ip-address LL
	for (it = result; it != NULL; it = it->ai_next) {
		++len;
	}

	ip_list_temp = fdo_alloc(sizeof(fdo_ip_address_t) * len);

	if (!ip_list_temp) {
		LOG(LOG_ERROR, "Malloc failed!\n");
		goto end;
	}

	// iterate and store IP-addresses
	for (idx = 0, it = result; it != NULL; ++idx, it = it->ai_next) {
		sa_in = (struct sockaddr_in *)it->ai_addr;

#if LOG_LEVEL == LOG_MAX_LEVEL
		// for trace purpose
		char host[16];

		inet_ntop(AF_INET, &(sa_in->sin_addr), host, 16);
		LOG(LOG_DEBUG, "Resolved into IP-Address: <%s>\n", host);
#endif
		(ip_list_temp + idx)->length = IPV4_ADDR_LEN;

		if (memcpy_s((ip_list_temp + idx)->addr, ip_list_temp->length,
			     &(sa_in->sin_addr.s_addr),
			     ip_list_temp->length) != 0) {
			LOG(LOG_ERROR, "Memcpy failed\n");
			goto end;
		}
	}

	*ip_list = ip_list_temp;
	*ip_list_size = len;
	ret = 0;

end:
	// avoid leak in case DNS look-up operation was not successful.
	if (ret != 0) {
		*ip_list_size = 0;
		if (ip_list_temp) {
			fdo_free(ip_list_temp);
		}
	}
	if (result) {
		freeaddrinfo(result); // free the addr list always
	}
	return ret;
}

/**
 * fdo_curl_proxy set up the proxy connection via curl API
 *
 * @param ip_addr - pointer to IP address of proxy
 * @param port - proxy port number to connect
 * @return true on success. false value on failure
 */
bool fdo_curl_proxy(fdo_ip_address_t *ip_addr, uint16_t port)
{
	char proxy_url[HTTP_MAX_URL_SIZE] = {0};
	char *ip_ascii = NULL;
	bool ret = false;

	if (!ip_addr) {
		goto err;
	}

	if (ip_addr) {
		ip_ascii = fdo_alloc(IP_TAG_LEN);
		if (!ip_ascii) {
			goto err;
		}

		if (!ip_bin_to_ascii(ip_addr, ip_ascii)) {
			goto err;
		}
	}

	if (snprintf_s_si(proxy_url, HTTP_MAX_URL_SIZE, "%s:%d", ip_ascii,
			  port) < 0) {
		LOG(LOG_ERROR, "Snprintf() failed!\n");
		goto err;
	}

	if (curl) {

		if (curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1) !=
		    CURLE_OK) {
			LOG(LOG_ERROR,
			    "CURL_PROXY: Cannot set HTTP proxy tunnel.\n");
			goto err;
		}

		if (curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1) !=
		    CURLE_OK) {
			LOG(LOG_ERROR, "CURL_PROXY: Cannot redirect proxy.\n");
			goto err;
		}

		if (curl_easy_setopt(curl, CURLOPT_PROXY, proxy_url) !=
		    CURLE_OK) {
			LOG(LOG_ERROR, "CURL_PROXY: Cannot set proxy.\n");
			goto err;
		}
		LOG(LOG_INFO, "CURL_PROXY: Proxy set successfully.\n");
	} else {
		goto err;
	}

	ret = true;
err:
	if (ip_ascii) {
		fdo_free(ip_ascii);
	}

	if (!ret && curl) {
		curl_easy_cleanup(curl);
	}

	return ret;
}

/**
 * fdo_curl_connect connects to the given ip_addr via curl API
 *
 * @param ip_addr - pointer to IP address info
 * @param dn: Domain name of the server
 * @param port - port number to connect
 * @param tls: flag describing whether HTTP (false) or HTTPS (true) is
 * @return 0 on success. -1 on failure
 */
int32_t fdo_curl_connect(fdo_ip_address_t *ip_addr, const char *dn,
			 uint16_t port, bool tls)
{
	CURLcode res;
	CURLcode curlCode = CURLE_OK;
	int ret = -1;
	char temp[2 * HTTP_MAX_URL_SIZE] = {0};
	char url[HTTP_MAX_URL_SIZE] = {0};
	char *ip_ascii = NULL;
	struct curl_slist *host = NULL;
	bool enable_sni = false;

	if (!ip_addr) {
		goto err;
	}

	if (tls) {
		if (strcpy_s(url, HTTP_MAX_URL_SIZE, "https://") != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}
	} else {
		if (strcpy_s(url, HTTP_MAX_URL_SIZE, "http://") != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}
	}

	if (ip_addr) {
		ip_ascii = fdo_alloc(IP_TAG_LEN);
		if (!ip_ascii) {
			goto err;
		}

		if (!ip_bin_to_ascii(ip_addr, ip_ascii)) {
			goto err;
		}
	}

	if (curl) {
		if (tls) {
			// we are directed to enforce TLS
			char *ciphers_list =
			    "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:"
			    "TLS_AES_128_CCM_SHA256:TLS_CHACHA20_POLY1305_"
			    "SHA256:"
			    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-"
			    "GCM-SHA384:"
			    "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-GCM-"
			    "SHA256";

			curl_version_info_data *vinfo =
			    curl_version_info(CURLVERSION_NOW);
			if (CURL_VERSION_SSL ==
			    (vinfo->features & CURL_VERSION_SSL)) {
				// SSL support enabled
				LOG(LOG_DEBUG, "SSL support verified.\n");
			}

			// Add option to force the https TLS connection to TLS
			// v1.2
			curlCode = curl_easy_setopt(curl, CURLOPT_SSLVERSION,
						    CURL_SSLVERSION_TLSv1_2);
			if (curlCode != CURLE_OK) {
				goto err;
			}

			// Add option to allow recommended ciphers list
			curlCode = curl_easy_setopt(
			    curl, CURLOPT_SSL_CIPHER_LIST, ciphers_list);
			if (curlCode != CURLE_OK) {
				goto err;
			}

#if defined(SELF_SIGNED_CERTS_SUPPORTED)
			if (useSelfSignedCerts) {
				// Add options if using self-signed certificates
				curlCode = CURLE_OK;
				curlCode = curl_easy_setopt(
				    curl, CURLOPT_SSL_VERIFYPEER, 0L);
				if (curlCode != CURLE_OK) {
					LOG(LOG_ERROR,
					    "CURL_ERROR: Could not disable "
					    "verify peer.\n");
					goto err;
				}

				curlCode = curl_easy_setopt(
				    curl, CURLOPT_SSL_VERIFYHOST, 0L);
				if (curlCode != CURLE_OK) {
					LOG(LOG_ERROR,
					    "CURL_ERROR: Could not disable "
					    "verify host.\n");
					goto err;
				}
			}
#endif
			curlCode = curl_easy_setopt(curl, CURLOPT_USE_SSL,
						    CURLUSESSL_ALL);
			if (curlCode != CURLE_OK) {
				LOG(LOG_ERROR,
				    "CURL_ERROR: Could not enable ssl.\n");
				goto err;
			}
		}
#if defined(SNI_SUPPORTED)
		if (dn && tls) {
			enable_sni = true;
		}
#endif
		if (enable_sni) {
			LOG(LOG_DEBUG, "Using DNS\n");

			if (snprintf_s_si(temp, HTTP_MAX_URL_SIZE, "%s:%d",
					  (char *)dn, port) < 0) {
				LOG(LOG_ERROR, "Snprintf() failed!\n");
				goto err;
			}
			if (strcat_s(url, HTTP_MAX_URL_SIZE, temp) != 0) {
				LOG(LOG_ERROR, "Strcat() failed!\n");
				goto err;
			}
			if (strcat_s(temp, 2 * HTTP_MAX_URL_SIZE, ":") != 0) {
				LOG(LOG_ERROR, "Strcat() failed!\n");
				goto err;
			}
			if (strcat_s(temp, 2 * HTTP_MAX_URL_SIZE, ip_ascii) !=
			    0) {
				LOG(LOG_ERROR, "Strcat() failed!\n");
				goto err;
			}
			host = curl_slist_append(NULL, temp);
			if (host == NULL) {
				LOG(LOG_ERROR,
				    "CURL_ERROR: failed to append list.\n");
				goto err;
			}
			curlCode =
			    curl_easy_setopt(curl, CURLOPT_RESOLVE, host);
			if (curlCode != CURLE_OK) {
				LOG(LOG_ERROR, "CURL_ERROR: failure to set dns "
					       "resolve config.\n");
				goto err;
			}
		} else {
			(void)dn;
			LOG(LOG_DEBUG, "Using IP\n");
			if (snprintf_s_si(temp, HTTP_MAX_URL_SIZE, "%s:%d",
					  ip_ascii, port) < 0) {
				LOG(LOG_ERROR, "Snprintf() failed!\n");
				goto err;
			}
			if (strcat_s(url, HTTP_MAX_URL_SIZE, temp) != 0) {
				LOG(LOG_ERROR, "Strcat() failed!\n");
				goto err;
			}
		}

		curlCode = curl_easy_setopt(curl, CURLOPT_URL, url);
		if (curlCode != CURLE_OK) {
			LOG(LOG_ERROR, "CURL_ERROR: Unable to pass url.\n");
			goto err;
		}

		curlCode = curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
		if (curlCode != CURLE_OK) {
			LOG(LOG_ERROR,
			    "CURL_ERROR: Unable to connect to host.\n");
			goto err;
		}

#if defined(CA)
		curlCode = curl_easy_setopt(curl, CURLOPT_CAINFO, (char *)SSL_CERT);
		if (curlCode != CURLE_OK) {
			LOG(LOG_ERROR, "CURL_ERROR: Unable to set CA info path.\n");
			goto err;
		}
#endif
		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			LOG(LOG_ERROR, "Error: %s\n", curl_easy_strerror(res));
			goto err;
		}

		if (res == CURLE_OK) {
			LOG(LOG_DEBUG, "Connect OK\n");
			ret = 0;
		}
	} else {
		goto err;
	}

err:
	if (ip_ascii) {
		fdo_free(ip_ascii);
	}
	if (host) {
		curl_slist_free_all(host);
	}
	if (ret < 0 && curl) {
		curl_easy_cleanup(curl);
	}

	return ret;
}

/**
 * fdo_con_connect connects to the network
 *
 * @param ip_addr - pointer to IP address info
 * @param dn: Domain name of the server
 * @param port - port number to connect
 * @param tls: flag describing whether HTTP (false) or HTTPS (true) is
 * @return connection handle on success. -ve value on failure
 */

int32_t fdo_con_connect(fdo_ip_address_t *ip_addr, const char *dn,
			uint16_t port, bool tls)
{
	int connect_ok = -1;

	if (!ip_addr) {
		goto end;
	}

#ifdef USE_MBEDTLS

	if (ssl) {
		char ipv4[IP_TAG_LEN] = {0};
		char port_s[MAX_PORT_SIZE] = {0};
		uint8_t octlet_size =
		    4; // e.g 192.168.0.100, max 3char + 1null/oct.

		if (!ip_addr) {
			goto end;
		}

		/*
		 * Convert ip binary to string format as required by
		 * mbed connect
		 */
		if ((snprintf_s_i(ipv4, octlet_size, "%d", ip_addr->addr[0]) <
		     0) ||
		    (snprintf_s_i((ipv4 + strnlen_s(ipv4, IP_TAG_LEN)),
				  octlet_size + 1, ".%d",
				  ip_addr->addr[1]) < 0) ||
		    (snprintf_s_i((ipv4 + strnlen_s(ipv4, IP_TAG_LEN)),
				  octlet_size + 1, ".%d",
				  ip_addr->addr[2]) < 0) ||
		    (snprintf_s_i((ipv4 + strnlen_s(ipv4, IP_TAG_LEN)),
				  octlet_size + 1, ".%d",
				  ip_addr->addr[3]) < 0)) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto end;
		}
		if (snprintf_s_i(port_s, sizeof(port_s), "%d", port) < 0) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto end;
		}

		*ssl = fdo_ssl_setup_connect(ipv4, port_s);

		if (NULL == *ssl) {
			LOG(LOG_ERROR, "TLS connection "
				       "setup "
				       "failed\n");
			goto end;
		}
		return MBEDTLS_NET_DUMMY_SOCKET;
	}
#endif

#if defined(USE_OPENSSL)
	connect_ok = fdo_curl_connect(ip_addr, dn, port, tls);
	if (connect_ok < 0) {
		goto end;
	}
#endif
end:
	return connect_ok;
}

/**
 * Disconnect the connection for a given connection handle.
 *
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_disconnect(void)
{
	int ret = -1;
#ifdef USE_MBEDTLS
	return 0;
#endif
	// close() returns 0 on success

	if (curl) {
		curl_easy_cleanup(curl);
		ret = 0;
	}
	return ret;
}

/*
 * Check the REST header for given REST response buffer and offset.
 *
 * @param[in] curl_buf: Input buffer that contains the REST header
 * @param[in] header_start_offset: offset in the buffer that points to the start
 * of REST header
 * @retval true if header is valid and complete and false otherwise.
 */
bool has_header(char *buf, size_t header_start_offset)
{
	char tmp[REST_MAX_MSGHDR_SIZE];
	size_t cur_offset = header_start_offset;
	bool ret = false;
	for (;;) {
		if (memset_s(tmp, sizeof(tmp), 0) != 0) {
			LOG(LOG_ERROR, "Memset() failed!\n");
			goto err;
		}
		if (!read_until_new_line(tmp, REST_MAX_MSGHDR_SIZE, buf,
					 &cur_offset)) {
			goto err;
		}

		// end of header
		if ((header_start_offset < cur_offset) &&
		    (tmp[0] == get_rest_hdr_body_separator())) {
			ret = true;
			break;
		}
	}
err:
	return ret;
}

/*
 * Get the message length from the given REST response buffer.
 *
 * @param[in] curl_buf: Input buffer that contains the REST header
 * @param[in/out] cur_offset: offset in the buffer that initially points to the
 * start of REST header. This gets updated to point to start of message body
 * after successful parsing
 * @param[out] msglen:  Message length as specified in the REST header
 * @retval bool returns true for success and false in case of invalid/incomplete
 * content/parsing failure.
 */
bool get_msg_length(char *curl_buf, size_t *cur_offset, uint32_t *msglen)
{
	char hdr[REST_MAX_MSGHDR_SIZE] = {0};
	char tmp[REST_MAX_MSGHDR_SIZE];
	size_t tmplen;
	size_t hdrlen;
	bool ret = false;
	for (;;) {
		if (memset_s(tmp, sizeof(tmp), 0) != 0) {
			LOG(LOG_ERROR, "Memset() failed!\n");
			goto err;
		}

		if (!read_until_new_line(tmp, REST_MAX_MSGHDR_SIZE, curl_buf,
					 cur_offset)) {
			LOG(LOG_ERROR, "read_until_new_line() failed!\n");
			goto err;
		}

		// end of header
		if (tmp[0] == get_rest_hdr_body_separator()) {
			break;
		}

		tmplen = strnlen_s(tmp, REST_MAX_MSGHDR_SIZE);
		if (!tmplen || tmplen == REST_MAX_MSGHDR_SIZE) {
			LOG(LOG_ERROR, "Strlen() failed!\n")
			goto err;
		}

		// accumulate header content
		if (strncat_s(hdr, REST_MAX_MSGHDR_SIZE, tmp, tmplen) != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}

		// append new line for convenient parsing in REST
		if (strcat_s(hdr, REST_MAX_MSGHDR_SIZE, "\n") != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}
	}

	hdrlen = strnlen_s(hdr, REST_MAX_MSGHDR_SIZE);
	if (!hdrlen || hdrlen == REST_MAX_MSGHDR_SIZE) {
		LOG(LOG_ERROR, "hdr is not NULL terminated.\n");
		goto err;
	}

	/* Process REST header and get content-length of body */
	if (!get_rest_content_length(hdr, hdrlen, msglen)) {
		LOG(LOG_ERROR, "REST Header processing failed!!\n");
		*msglen = 0;
		goto err;
	}
	ret = true;
err:
	return ret;
}

/**
 * Receive(read) protocol version, message type and length of rest body
 *
 * @param protocol_version - out FDO protocol version
 * @param message_type - out message type of incoming FDO message.
 * @param msglen - out Number of received bytes.
 * @param hdr_buf: header data buffer to parse msg received by curl.
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_parse_msg_header(uint32_t *protocol_version,
				 uint32_t *message_type, uint32_t *msglen,
				 char *hdr_buf)
{
	int32_t ret = -1;
	size_t hdr_offset = 0;
	rest_ctx_t *rest = NULL;
	char hdr[REST_MAX_MSGHDR_SIZE] = {0};
	char tmp[REST_MAX_MSGHDR_SIZE];
	size_t tmplen;
	size_t hdrlen;

	if (!protocol_version || !message_type || !msglen || !hdr_buf) {
		goto err;
	}

	LOG(LOG_DEBUG, "Parsing received Header.\n");

	for (;;) {
		if (memset_s(tmp, sizeof(tmp), 0) != 0) {
			LOG(LOG_ERROR, "Memset() failed!\n");
			goto err;
		}

		if (!read_until_new_line(tmp, REST_MAX_MSGHDR_SIZE, hdr_buf,
					 &hdr_offset)) {
			LOG(LOG_ERROR, "read_until_new_line() failed!\n");
			goto err;
		}

		if (tmp[0] == get_rest_hdr_body_separator()) {
			break;
		}

		tmplen = strnlen_s(tmp, REST_MAX_MSGHDR_SIZE);
		if (!tmplen || tmplen == REST_MAX_MSGHDR_SIZE) {
			LOG(LOG_ERROR, "Strlen() failed!\n")
			goto err;
		}

		// accumulate header content
		if (strncat_s(hdr, REST_MAX_MSGHDR_SIZE, tmp, tmplen) != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}

		// append new line for convenient parsing in REST
		if (strcat_s(hdr, REST_MAX_MSGHDR_SIZE, "\n") != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}
	}

	hdrlen = strnlen_s(hdr, REST_MAX_MSGHDR_SIZE);
	if (!hdrlen || hdrlen == REST_MAX_MSGHDR_SIZE) {
		LOG(LOG_ERROR, "hdr is not NULL terminated.\n");
		goto err;
	}

	/* Process REST header and get content-length of body */
	if (!get_rest_content_length(hdr, hdrlen, msglen)) {
		LOG(LOG_ERROR, "REST Header processing failed!!\n");
		goto err;
	}

	rest = get_rest_context();
	if (!rest) {
		LOG(LOG_ERROR, "REST context is NULL!\n");
		goto err;
	}

	// copy protver from REST context
	*protocol_version = rest->prot_ver;
	*message_type = rest->msg_type;

	ret = 0;

err:
	return ret;
}

/**
 * Receive(read) Msg_body
 *
 * @param buf - data buffer to read into.
 * @param length - Number of received bytes.
 * @param body_buf: body data buffer to parse msg received by curl.
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_parse_msg_body(uint8_t *buf, size_t length, char *body_buf)
{
	int32_t ret = -1;

	if (!buf || !length || !body_buf) {
		goto err;
	}

	if (memcpy_s(buf, length, body_buf, length)) {
		LOG(LOG_ERROR, "Failed to copy msg data in byte array\n");
		goto err;
	}

	ret = 0;
err:
	return ret;
}

/**
 * Send and Receive data.
 * @param[in] protocol_version: FDO protocol version
 * @param[in] message_type: message type of outgoing FDO message.
 * @param[in] buf: data buffer to write from.
 * @param[in] length: Number of sent bytes.
 * @param[in] tls: flag describing whether HTTP (false) or HTTPS (true) is
 * @param[in] header_buf: header data buffer to read into  msg received by curl.
 * @param[in] body_buf: body data buffer to read into  msg received by curl.
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_send_recv_message(uint32_t protocol_version,
				  uint32_t message_type, const uint8_t *buf,
				  size_t length, bool tls, char *header_buf,
				  char *body_buf)
{
	int ret = -1;
	rest_ctx_t *rest = NULL;
	struct curl_slist *msg_header = NULL;
	struct curl_slist *temp_msg_header = NULL;
	CURLcode curlCode;
	struct MemoryStruct temp_header_buf;
	struct MemoryStruct temp_body_buf;

	init_string(&temp_header_buf);
	init_string(&temp_body_buf);

	if (!buf || !length) {
		goto err;
	}

	rest = get_rest_context();
	if (!rest) {
		LOG(LOG_ERROR, "REST context is NULL!\n");
		goto err;
	}

	// supply info to REST for POST-URL construction
	rest->prot_ver = protocol_version;
	rest->msg_type = message_type;
	rest->content_length = length;
	if (tls) {
		rest->tls = true;
	}

	if (!construct_rest_header(rest, &msg_header) || msg_header == NULL) {
		LOG(LOG_ERROR, "Error during constrcution of REST hdr!\n");
		goto err;
	}

	if (length > REST_MAX_MSGHDR_SIZE) {
		msg_header = curl_slist_append(msg_header, "Expect:");
	}

	curlCode = curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 0L);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Could not disable connect only.\n");
		goto err;
	}

#if defined(MTLS)
	curlCode = curl_easy_setopt(curl, CURLOPT_SSLCERT, (char *)SSL_CERT);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Unable to select client "
			       "certificate.\n");
		goto err;
	}

	curlCode = curl_easy_setopt(curl, CURLOPT_SSLKEY, (char *)SSL_KEY);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Unable to select client key.\n");
		goto err;
	}
#endif

	curlCode = curl_easy_setopt(curl, CURLOPT_URL, msg_header->data);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Unable to pass url.\n");
		goto err;
	}

	curlCode = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, msg_header);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Unable to pass header.\n");
		goto err;
	}

	curlCode = curl_easy_setopt(curl, CURLOPT_POST, 1L);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Could not set POST.\n");
		goto err;
	}

	curlCode = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, length);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Could not set POST length.\n");
		goto err;
	}

	curlCode = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Unable to pass POST data.\n");
		goto err;
	}

	curlCode = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Could not set follow location.\n");
		goto err;
	}

	curlCode =
	    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Unable to pass header "
			       "WriteMemoryCallback.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "\nSending REST header.\n\n");
	LOG(LOG_DEBUG, "REST:header\n");

	temp_msg_header = msg_header;
	while (temp_msg_header != NULL) {
		LOG(LOG_DEBUG, "%s\n", temp_msg_header->data);
		temp_msg_header = temp_msg_header->next;
	}
	LOG(LOG_DEBUG, "\n");

	curlCode = curl_easy_setopt(curl, CURLOPT_HEADERDATA,
				    (void *)&temp_header_buf);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Unable to pass header buffer.\n");
		goto err;
	}

	curlCode =
	    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Unable to pass "
			       "WriteMemoryCallback.\n");
		goto err;
	}

	curlCode =
	    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&temp_body_buf);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Unable to pass body buffer.\n");
		goto err;
	}

	curlCode = curl_easy_setopt(curl, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Unable to suppress connect "
			       "headers.\n");
		goto err;
	}

#ifdef DEBUG_LOGS
	curlCode = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "CURL_ERROR: Could not enable curl logs.\n");
		goto err;
	}
#endif

	curlCode = curl_easy_perform(curl);
	if (curlCode != CURLE_OK) {
		LOG(LOG_ERROR, "Error: %s\n", curl_easy_strerror(curlCode));
		goto err;
	}

	if (memcpy_s(header_buf, temp_header_buf.size, temp_header_buf.memory,
		     temp_header_buf.size)) {
		LOG(LOG_ERROR, "Failed to copy msg data in byte array\n");
		goto err;
	}

	if ((message_type >= FDO_DI_APP_START) &&
	    (message_type < FDO_TYPE_ERROR)) {
		if (memcpy_s(body_buf, temp_body_buf.size, temp_body_buf.memory,
			     temp_body_buf.size)) {
			LOG(LOG_ERROR,
			    "Failed to copy msg data in byte array\n");
			goto err;
		}
	}

	ret = 0;
err:
	if (temp_header_buf.memory) {
		free(temp_header_buf.memory);
		temp_header_buf.size = 0;
	}

	if (temp_body_buf.memory) {
		free(temp_body_buf.memory);
		temp_body_buf.size = 0;
	}

	if (msg_header) {
		curl_slist_free_all(msg_header);
	}

	return ret;
}

/**
 * fdo_con_tear_down connection tear-down.
 *
 * @return 0 on success, -1 on failure
 */
int32_t fdo_con_teardown(void)
{
	/* REST context over */
	exit_rest_context();
	return 0;
}

/**
 * Put the FDO device to low power state
 *
 * @param sec
 *        number of seconds to put the device to low power state
 *
 * @return none
 */
void fdo_sleep(int sec)
{
	sleep(sec);
}

/**
 * Convert from Network to Host byte order
 *
 * @param value
 *        Number in network byte order.
 *
 * @return
 *         Value in Host byte order.
 */
uint32_t fdo_net_to_host_long(uint32_t value)
{
	return ntohl(value);
}

/**
 * Convert from Host to Network byte order
 *
 * @param value
 *         Value in Host byte order.
 *
 * @return
 *        Number in network byte order.
 */
uint32_t fdo_host_to_net_long(uint32_t value)
{
	return htonl(value);
}

/**
 * Convert from ASCII to Network format
 *
 * @param src
 *         Source address in ASCII format.
 * @param addr
 *         Source address in network format.
 *
 * @return
 *        1 on success. -1 on error. 0 if input format is invalie
 */
int32_t fdo_printable_to_net(const char *src, void *addr)
{
	return inet_pton(AF_INET, src, addr);
}

/**
 * get device model
 *
 * @return
 *        returns model as string
 */
const char *get_device_model(void)
{
	return "Intel-FDO-Linux";
}

/**
 *  get device serial number
 *
 * @return
 *        returns device serial number as string.
 */
const char *get_device_serial_number(void)
{
	return "fdo-linux-1234";
}

/**
 * fdo_random generates random number and returns
 *
 * Note: this is only to be used for calculating random
 * network delay for retransmissions and NOT for crypto
 *
 * @return
 *        returns random number
 */
int fdo_random(void)
{
	return rand();
}
