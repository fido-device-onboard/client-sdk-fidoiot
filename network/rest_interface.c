/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * REST Layer
 *
 * The file implements REST layer for FDO.
 */

#include "util.h"
#include "network_al.h"
#include "fdoCryptoHal.h"
#include "fdoprotctx.h"
#include <stdlib.h>
#include "fdonet.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "rest_interface.h"

// Global REST context is allocated ?
#define isRESTContext_active() ((rest) ? true : false)

// Global REST context
static rest_ctx_t *rest = NULL;

/**
 * Initialize REST context.
 *
 * @retval true if allocation was successful, false on realloc/failure.
 */
bool init_rest_context(void)
{
	if (rest) {
		LOG(LOG_ERROR, "rest context is already active\n");
		return false;
	} else {
		return (rest = fdo_alloc(sizeof(rest_ctx_t))) ? true : false;
	}
}

/**
 * Return REST context.
 * This API expects init_rest_context() to be called in advance.
 *
 * @retval NULL if init_rest_context() was not called in advance, current REST
 * context otherwise.
 */
rest_ctx_t *get_rest_context(void)
{
	return rest;
}

/**
 * Cache HOST DNS from NW hal/FDO. This info will be used during POST URL
 * construction.
 *
 * @param dns - HOST's domain URL.
 * @retval true if caching was successful, false otherwise.
 */
bool cache_host_dns(const char *dns)
{
	bool ret = false;

	if (!dns) {
		goto err;
	}

	size_t len = strnlen_s(dns, FDO_MAX_STR_SIZE);
	if (!len || len == FDO_MAX_STR_SIZE) {
		goto err;
	}

	if (!isRESTContext_active()) {
		LOG(LOG_ERROR, "Rest Context is not active!\n");
		goto err;
	}

	if (rest->host_dns) {
		fdo_free(rest->host_dns);
	}

	rest->host_dns = fdo_alloc(len + 1);
	if (!rest->host_dns) {
		goto err;
	}

	if (strcpy_s(rest->host_dns, len + 1, dns) != 0) {
		goto err;
	}

	ret = true;

err:
	return ret;
}

/**
 * Cache HOST IP from NW hal/FDO. This info will be used while POST URL
 * construction.
 *
 * @param ip - HOST's IP address.
 * @retval true if caching was successful, false otherwise.
 */
bool cache_host_ip(fdo_ip_address_t *ip)
{
	bool ret = false;

	if (!ip) {
		goto err;
	}

	if (!isRESTContext_active()) {
		LOG(LOG_ERROR, "Rest Context is not active!\n");
		goto err;
	}

	if (rest->host_ip) {
		fdo_free(rest->host_ip);
	}

	rest->host_ip = fdo_alloc(sizeof(fdo_ip_address_t));
	if (!rest->host_ip) {
		goto err;
	}

	if (memcpy_s(rest->host_ip, sizeof(fdo_ip_address_t), ip,
		     sizeof(fdo_ip_address_t)) != 0) {
		fdo_free(rest->host_ip);
		goto err;
	}
	ret = true;
err:
	return ret;
}

/**
 * Cache HOST port from NW hal/FDO. This info will be used while POST URL
 * construction.
 *
 * @param port - HOST's port no.
 */
bool cache_host_port(uint16_t port)
{
	bool ret = false;

	if (!isRESTContext_active()) {
		LOG(LOG_ERROR, "Rest Context is not active!\n");
		goto err;
	}

	if (port < FDO_PORT_MIN_VALUE || port > FDO_PORT_MAX_VALUE) {
		LOG(LOG_ERROR, "Invalid port value.\n");
		goto err;
	}

	rest->portno = port;
	ret = true;

err:
	return ret;
}

/**
 * Cache if TLS connection is applicable
 *
 *
 */
bool cache_tls_connection(void)
{
	bool ret = false;

	if (!isRESTContext_active()) {
		LOG(LOG_ERROR, "Rest Context is not active!\n");
		goto err;
	}

	rest->tls = true;
	ret = true;

err:
	return ret;
}

/**
 * Internal API for converting Binary IP address to string format.
 *
 * @param ip - HOST's IP address.
 * @param ip_ascii - IP address output in string format.
 * @retval true if conversion was successful, false otherwise.
 */
bool ip_bin_to_ascii(fdo_ip_address_t *ip, char *ip_ascii)
{
	char temp[IP_TAG_LEN + 1] = {0};
	uint8_t octlet_size = 4; // e.g 192.168.0.100, max 3char +1 null/oct.

	if (!ip || !ip_ascii) {
		goto err;
	}

	size_t temp_len = 0;
	for (int i = 0; i < 4; i++) {
		if (snprintf_s_i(temp + temp_len, octlet_size + 1, "%d.",
				ip->addr[i]) < 0) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto err;
		}

		temp_len = strnlen_s(temp, IP_TAG_LEN + 1);
		if (!temp_len || temp_len == IP_TAG_LEN + 1) {
			LOG(LOG_ERROR,
				"temp string is not NULL terminated.\n");
			goto err;
		}
	}

	// Remove the last '.'
	temp[temp_len-1] = '\0';

	if (strcpy_s(ip_ascii, temp_len, temp) != 0) {
		LOG(LOG_ERROR, "Strcpy() failed!\n");
		goto err;
	}

	return true;
err:
	return false;
}

/**
 * REST header (POST URL) construction based on current REST context.
 *
 * @param rest_ctx - current REST context.
 * @param g_URL - post URL output.
 * @param post_url_len - post URL max length.
 * @retval true if header onstruction was successful, false otherwise.
 */
bool construct_rest_header(rest_ctx_t *rest_ctx, char *g_URL,
			   size_t post_url_len)
{
	char *ip_ascii = NULL;
	char temp[HTTP_MAX_URL_SIZE] = {0};
	char temp1[256] = {0};
	char msgequals[] = "";
	bool ret = false;

	if (!rest_ctx || !g_URL || !post_url_len) {
		LOG(LOG_ERROR, "Invalid input!\n");
		goto err;
	}

	if (rest_ctx->host_ip) {
		ip_ascii = fdo_alloc(IP_TAG_LEN);
		if (!ip_ascii) {
			goto err;
		}

		if (!ip_bin_to_ascii(rest_ctx->host_ip, ip_ascii)) {
			goto err;
		}
	}

	if (rest_ctx->tls) {
		if (strcpy_s(g_URL, post_url_len, "POST https://") != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}
	} else {
		if (strcpy_s(g_URL, post_url_len, "POST http://") != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}
	}

	if (rest_ctx->host_dns) {
		/* DNS */
		if (snprintf_s_si(temp, sizeof(temp), "%s:%d",
				  rest_ctx->host_dns, rest_ctx->portno) < 0) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto err;
		}
	} else if (rest_ctx->host_ip && ip_ascii) {
		/* IP */
		if (snprintf_s_si(temp, sizeof(temp), "%s:%d", ip_ascii,
				  rest_ctx->portno) < 0) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto err;
		}
	} else {
		LOG(LOG_ERROR, "Host IP and DNS both are NULL!\n");
		goto err;
	}

	if (strcat_s(g_URL, post_url_len, temp) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (snprintf_s_i(temp, sizeof(temp), "/fdo/%d", rest_ctx->prot_ver) <
	    0) {
		LOG(LOG_ERROR, "Snprintf failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, post_url_len, temp) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (snprintf_s_i(temp, sizeof(temp), "/msg/%d", rest_ctx->msg_type) <
	    0) {
		LOG(LOG_ERROR, "Snprintf failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, post_url_len, temp) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, post_url_len, " HTTP/1.1\r\n") != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (memset_s(temp, sizeof(temp), 0) != 0) {
		ret = false;
		goto err;
	}

	if (rest_ctx->host_dns) {
		/* DNS */
		if (snprintf_s_si(temp, sizeof(temp), "HOST:%s:%d\r\n",
				  rest_ctx->host_dns, rest_ctx->portno) < 0) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto err;
		}
	} else if (rest_ctx->host_ip && ip_ascii) {
		/* IP */
		if (snprintf_s_si(temp, sizeof(temp), "HOST:%s:%d\r\n",
				  ip_ascii, rest_ctx->portno) < 0) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto err;
		}
	}

	if (strcat_s(g_URL, post_url_len, temp) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (snprintf_s_i(temp1, sizeof(temp1),
			 "Content-type:application/cbor\r\n"
			 "Content-length:%u\r\n_connection: keep-alive\r\n",
			 rest_ctx->content_length) < 0) {
		LOG(LOG_ERROR, "Snprintf() failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, post_url_len, temp1) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (rest_ctx->authorization) {
		if (strcat_s(g_URL, post_url_len, "Authorization:") != 0) {
			LOG(LOG_ERROR, "Strcpy() failed!\n");
			goto err;
		}

		if (strcat_s(g_URL, post_url_len, rest_ctx->authorization) !=
		    0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}

		if (strcat_s(g_URL, post_url_len, "\r\n") != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}
	}

	if (strcat_s(g_URL, post_url_len, "\r\n") != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, post_url_len, msgequals) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	ret = true;

err:
	if (ip_ascii) {
		fdo_free(ip_ascii);
	}
	return ret;
}

/**
 * Parse/Process REST header elements (including HTTP Response) and return
 * content-length of REST body.
 *
 * @param hdr - pointer to REST header.
 * @param hdrlen - REST header length.
 * @param cont_len - output pointer to content-length of REST body.
 * @retval true if HTTP 200 response is seen and parsing/processing was
 * successful, false otherwise.
 */
bool get_rest_content_length(char *hdr, size_t hdrlen, uint32_t *cont_len)
{
	bool ret = false;
	char *rem = NULL, *p1 = NULL, *p2 = NULL;
	size_t remlen = 0;
	char tmp[BUFF_SIZE_1K_BYTES] = {0};
	char *eptr = NULL;
	size_t tmplen = 0;
	long rcode = 0;
	int result_strcmpcase = 0;
	size_t counter = 0;

	/* REST context must be active */
	if (!isRESTContext_active()) {
		LOG(LOG_ERROR, "Rest Context is not active!\n");
		goto err;
	}

	if (!hdr || !hdrlen || !cont_len) {
		LOG(LOG_ERROR, "Input argument can't be NULL or 0.\n");
		goto err;
	}

	for (counter = 0; counter < hdrlen; counter ++) {
		if (!ISASCII(hdr[counter])) {
			LOG(LOG_ERROR, "Header contains non-ASCII values\n");
			goto err;
		}
	}
	rest->msg_type = 0;

	// GET HTTP reponse from header
	if(strstr_s(hdr, hdrlen, "\n", 1, &rem)){
		LOG(LOG_ERROR, "Error parsing resonse\n");
		goto err;
	}

	if (rem) {
		remlen = strnlen_s(rem, FDO_MAX_STR_SIZE);
		if (!remlen || remlen == FDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Strlen() failed!\n");
			goto err;
		}

		tmplen = hdrlen - remlen;

		if (strncpy_s(tmp, tmplen + 1, hdr, tmplen) != 0) {
			LOG(LOG_ERROR, "Strcpy() failed!\n");
			goto err;
		}

		hdr += tmplen;
		hdrlen -= tmplen;
		LOG(LOG_DEBUG, "REST: HTTP response line: %s\n", tmp);

		// validate HTTP response
		if(strstr_s(tmp, tmplen, " ", 1, &p1)){
			LOG(LOG_ERROR,
			    "fdo_rest_run: Response line parse error\n");
			goto err;
		}

		*p1++ = 0;
		// set to 0 explicitly
		errno = 0;
		rcode = strtol(p1, &eptr, 10);
		if (!eptr || eptr == p1 || errno != 0) {
			LOG(LOG_ERROR, "Invalid value read for Response Code\n");
			goto err;
		}

		size_t p1_len = strnlen_s(p1, FDO_MAX_STR_SIZE);
		if (!p1_len || p1_len == FDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Error parsing response.\n");
			goto err;
		}

		if(strstr_s(p1, p1_len, " ", 1, &p2)) {
			LOG(LOG_DEBUG, "Response code %03ld\n", rcode);
		} else {
			*p2++ = 0;
			LOG(LOG_DEBUG, "Response code %03ld received (%s)\n",
			    rcode, p2);
		}

		if (rcode != HTTP_SUCCESS_OK) {
			LOG(LOG_ERROR, "HTTP reponse is not 200(OK)!\n");
			rest->msg_type = FDO_TYPE_ERROR;
		}
		// consume \n
		++hdr;
		--hdrlen;
	}

	// parse and process other header elements
	while (1) {
		if(strstr_s(hdr, hdrlen, "\n", 1, &rem)) {
			break;
		}

		remlen = strnlen_s(rem, FDO_MAX_STR_SIZE);
		if (!remlen || remlen == FDO_MAX_STR_SIZE) {
			LOG(LOG_ERROR, "Strlen() failed!\n");
			goto err;
		}

		tmplen = hdrlen - remlen;

		if (strncpy_s(tmp, tmplen + 1, hdr, tmplen) != 0) {
			LOG(LOG_ERROR, "Strcpy() failed!\n");
			goto err;
		}

		hdr += tmplen;
		hdrlen -= tmplen;

		if(strstr_s(tmp, tmplen, ":", 1, &p1)) {
			LOG(LOG_ERROR, "REST: HEADER parse error\n");
			goto err;
		}

		*p1++ = 0;
		while (*p1 == ' ') {
			++p1;
		}

		if ((strcasecmp_s(tmp, tmplen, "content-length",
				  &result_strcmpcase) == 0) &&
		    result_strcmpcase == 0) {
			// set to 0 explicitly
			errno = 0;
			rest->content_length = strtol(p1, &eptr, 10);
			if (!eptr || eptr == p1 || errno != 0) {
				LOG(LOG_ERROR, "Invalid value read for Content-length\n");
				goto err;
			}
			LOG(LOG_DEBUG, "Content-length: %zu\n",
			    rest->content_length);
		} else if ((strcasecmp_s(tmp, tmplen, "content-type",
					 &result_strcmpcase) == 0) &&
			   result_strcmpcase == 0) {
			LOG(LOG_DEBUG, "Content type: %s\n", p1);
		} else if ((strcasecmp_s(tmp, tmplen, "connection",
					 &result_strcmpcase) == 0) &&
			   result_strcmpcase == 0) {
			if ((strcasecmp_s(p1, strnlen_s(p1, FDO_MAX_STR_SIZE),
					  "keep-alive",
					  &result_strcmpcase) == 0) &&
			    result_strcmpcase == 0) {
				rest->keep_alive = true;
			} else {
				rest->keep_alive = false;
			}
			LOG(LOG_DEBUG, "Keep alive: %u\n", rest->keep_alive);
		} else if (strcasecmp_s(tmp, tmplen, "authorization",
					&result_strcmpcase) == 0 &&
			   result_strcmpcase == 0) {
			if (rest->authorization) {
				// currently received token can be compared against previously
				// received token.
				// however, do nothing for now since specification doesn't mandate us to
				// the ONLY requirement is that the Client MUST cache the received token once
				// and transmit the same in subsequent messages.
			} else {
				rest->authorization = strdup(p1);
			}
			if (rest->authorization) {
				LOG(LOG_DEBUG, "Authorization: %s\n",
				    rest->authorization);
			}
		} else if (rest->x_token_authorization == NULL &&
			   strcasecmp_s(tmp, tmplen, "X-Token",
					&result_strcmpcase) == 0 &&
			   result_strcmpcase == 0) {
			rest->x_token_authorization = strdup(p1);
			if (rest->x_token_authorization) {
				LOG(LOG_DEBUG, "X-Token: %s\n",
				    rest->x_token_authorization);
			}
		} else if (strcasecmp_s(tmp, tmplen, "message-type",
					&result_strcmpcase) == 0 &&
			   result_strcmpcase == 0) {
			// set to 0 explicitly
			errno = 0;
			rest->msg_type = strtol(p1, &eptr, 10);
			if (!eptr || eptr == p1 || errno != 0) {
				LOG(LOG_ERROR, "Invalid value read for Message-Type\n");
				goto err;
			}
			LOG(LOG_DEBUG, "Message-Type: %"PRIu32"\n",
				rest->msg_type);
		} else {
			/* TODO: This looks like dead code, remove this
			 */
			/*
			 * If in protocol error fdo_rest_free is not
			 * called
			 * this can lead to memory leak, hence fdo_free
			 * if
			 * allocated
			 */
			if (rest->x_token_authorization) {
				fdo_free(rest->x_token_authorization);
			}
			rest->x_token_authorization = strdup(p1);
			LOG(LOG_DEBUG, "Body: %s\n", tmp);
		}
		// consume \n
		++hdr;
		--hdrlen;
	}

	if (rest->content_length > REST_MAX_MSGBODY_SIZE) {
		LOG(LOG_ERROR, "Invalid content-length!\n");
		goto err;
	}

	*cont_len = rest->content_length;
	ret = true;

err:
	return ret;
}

/**
 * Return REST header body separator
 *
 * @return token that separates protocol header with protocol body.
 */
char get_rest_hdr_body_separator(void)
{
	return '\0';
}

/**
 * undo of init_rest_context()
 *
 */
void exit_rest_context(void)
{
	if (rest) {
		if (rest->authorization) {
			fdo_free(rest->authorization);
		}
		if (rest->x_token_authorization) {
			fdo_free(rest->x_token_authorization);
		}
		if (rest->host_ip) {
			fdo_free(rest->host_ip);
		}
		if (rest->host_dns) {
			fdo_free(rest->host_dns);
		}
		fdo_free(rest);
	}
}
