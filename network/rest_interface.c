/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * REST Layer
 *
 * The file implements REST layer for SDO.
 */

#include "util.h"
#include "network_al.h"
#include "sdoCryptoHal.h"
#include "sdoprotctx.h"
#include <stdlib.h>
#include "sdonet.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "rest_interface.h"

// Global REST context is allocated ?
#define isRESTContext_active() ((rest) ? true : false)

// Global REST context
static rest_ctx_t *rest;

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
		return (rest = sdo_alloc(sizeof(rest_ctx_t))) ? true : false;
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
 * Cache HOST DNS from NW hal/SDO. This info will be used during POST URL
 * construction.
 *
 * @param dns - HOST's domain URL.
 * @retval true if caching was successful, false otherwise.
 */
bool cache_host_dns(const char *dns)
{
	bool ret = false;

	if (!dns)
		goto err;

	size_t len = strnlen_s(dns, SDO_MAX_STR_SIZE);

	if (!len || len == SDO_MAX_STR_SIZE)
		goto err;

	if (!isRESTContext_active()) {
		LOG(LOG_ERROR, "Rest Context is not active!\n");
		goto err;
	}

	if (rest->host_dns) {
		sdo_free(rest->host_dns);
	}

	rest->host_dns = sdo_alloc(len + 1);
	if (!rest->host_dns) {
		goto err;
	}

	if (strcpy_s(rest->host_dns, len + 1, dns) != 0)
		goto err;

	ret = true;

err:
	return ret;
}

/**
 * Cache HOST IP from NW hal/SDO. This info will be used while POST URL
 * construction.
 *
 * @param ip - HOST's IP address.
 * @retval true if caching was successful, false otherwise.
 */
bool cache_host_ip(sdo_ip_address_t *ip)
{
	bool ret = false;

	if (!ip)
		goto err;

	if (!isRESTContext_active()) {
		LOG(LOG_ERROR, "Rest Context is not active!\n");
		goto err;
	}

	if (rest->host_ip) {
		sdo_free(rest->host_ip);
	}

	rest->host_ip = sdo_alloc(sizeof(sdo_ip_address_t));
	if (!rest->host_ip) {
		goto err;
	}

	if (memcpy_s(rest->host_ip, sizeof(sdo_ip_address_t), ip,
		     sizeof(sdo_ip_address_t)) != 0) {
		sdo_free(rest->host_ip);
		goto err;
	}
	ret = true;
err:
	return ret;
}

/**
 * Cache HOST port from NW hal/SDO. This info will be used while POST URL
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
static bool ip_bin_to_ascii(sdo_ip_address_t *ip, char *ip_ascii)
{
	char temp[IP_TAG_LEN] = {0};
	uint8_t octlet_size = 4; // e.g 192.168.0.100, max 3char +1 null/oct.

	if (!ip || !ip_ascii)
		goto err;

	if ((snprintf_s_i(temp, octlet_size, "%d", ip->addr[0]) < 0) ||
	    (snprintf_s_i((temp + strnlen_s(temp, IP_TAG_LEN)), octlet_size + 1,
			  ".%d", ip->addr[1]) < 0) ||
	    (snprintf_s_i((temp + strnlen_s(temp, IP_TAG_LEN)), octlet_size + 1,
			  ".%d", ip->addr[2]) < 0) ||
	    (snprintf_s_i((temp + strnlen_s(temp, IP_TAG_LEN)), octlet_size + 1,
			  ".%d", ip->addr[3]) < 0)) {
		LOG(LOG_ERROR, "Snprintf() failed!\n");
		goto err;
	}

	if (strcpy_s(ip_ascii, strnlen(temp, IP_TAG_LEN) + 1, temp) != 0) {
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
 * @param POST_URL_LEN - post URL max length.
 * @retval true if header onstruction was successful, false otherwise.
 */
bool construct_rest_header(rest_ctx_t *rest_ctx, char *g_URL,
			   size_t POST_URL_LEN)
{
	char *ip_ascii = NULL;
	char temp[HTTP_MAX_URL_SIZE] = {0};
	char temp1[256] = {0};
	char msgequals[] = ""; //!!! todo: "msg=";
	bool ret = false;

	if (!rest_ctx || !g_URL || !POST_URL_LEN) {
		LOG(LOG_ERROR, "Invalid input!\n");
		goto err;
	}

	if (rest_ctx->host_ip) {
		ip_ascii = sdo_alloc(IP_TAG_LEN);

		if (!ip_ascii)
			goto err;

		if (!ip_bin_to_ascii(rest_ctx->host_ip, ip_ascii))
			goto err;
	}

	// TLS needed ?
	if (rest_ctx->tls) {
		if (strcpy_s(g_URL, POST_URL_LEN, "POST https://") != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}
	} else {
		if (strcpy_s(g_URL, POST_URL_LEN, "POST http://") != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}
	}

	if (/* rest_ctx->is_dns  && */ rest_ctx->host_dns) {
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

	if (strcat_s(g_URL, POST_URL_LEN, temp) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (snprintf_s_i(temp, sizeof(temp), "/mp/%d", rest_ctx->prot_ver) <
	    0) {
		LOG(LOG_ERROR, "Snprintf failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, POST_URL_LEN, temp) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (snprintf_s_i(temp, sizeof(temp), "/msg/%d", rest_ctx->msg_type) <
	    0) {
		LOG(LOG_ERROR, "Snprintf failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, POST_URL_LEN, temp) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, POST_URL_LEN, " HTTP/1.1\r\n") != 0) {
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

	if (strcat_s(g_URL, POST_URL_LEN, temp) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (snprintf_s_i(temp1, sizeof(temp1),
			 "Content-type:application/json\r\n"
			 "Content-length:%u\r\n_connection: keep-alive\r\n",
			 rest_ctx->content_length) < 0) {
		LOG(LOG_ERROR, "Snprintf() failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, POST_URL_LEN, temp1) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (rest_ctx->authorization) {
		if (strcat_s(g_URL, POST_URL_LEN, "Authorization:") != 0) {
			LOG(LOG_ERROR, "Strcpy() failed!\n");
			goto err;
		}

		if (strcat_s(g_URL, POST_URL_LEN, rest_ctx->authorization) !=
		    0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}

		if (strcat_s(g_URL, POST_URL_LEN, "\r\n") != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}
	}

	if (strcat_s(g_URL, POST_URL_LEN, "\r\n") != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, POST_URL_LEN, msgequals) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	ret = true;

err:
	if (ip_ascii)
		sdo_free(ip_ascii);
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
	char *rem, *p1, *p2;
	size_t remlen;
	char tmp[512];
	size_t tmplen;
	int rcode, result_strcmpcase;

	/* REST context must be active */
	if (!isRESTContext_active()) {
		LOG(LOG_ERROR, "Rest Context is not active!\n");
		goto err;
	}

	rest->msg_type = 0;

	// GET HTTP reponse from header
	rem = strchr(hdr, '\n');

	if (rem) {
		remlen = strnlen_s(rem, SDO_MAX_STR_SIZE);

		if (!remlen || remlen == SDO_MAX_STR_SIZE) {
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
		p1 = strchr(tmp, ' ');
		if (p1 == NULL) {
			LOG(LOG_ERROR,
			    "sdo_rest_run: Response line parse error\n");
			goto err;
		}
		*p1++ = 0;
		rcode = atoi(p1);
		p2 = strchr(p1, ' ');
		if (p2 == NULL) {
			LOG(LOG_DEBUG, "Response code %03d\n", rcode);
		} else {
			*p2++ = 0;
			LOG(LOG_DEBUG, "Response code %03d received (%s)\n",
			    rcode, p2);
		}

		if (rcode != HTTP_SUCCESS_OK) {
			LOG(LOG_ERROR, "HTTP reponse is not 200(OK)!\n");
			rest->msg_type = SDO_TYPE_ERROR;
		}
		// consume \n
		++hdr;
		--hdrlen;
	}

	// parse and process other header elements
	while ((rem = strchr(hdr, '\n')) != NULL) {
		remlen = strnlen_s(rem, SDO_MAX_STR_SIZE);

		if (!remlen || remlen == SDO_MAX_STR_SIZE) {
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

		p1 = strchr(tmp, ':');
		if (p1 == NULL) {
			LOG(LOG_ERROR, "REST: HEADER parse error\n");
			goto err;
		}

		*p1++ = 0;
		while (*p1 == ' ')
			++p1;

		if ((strcasecmp_s(tmp, tmplen, "content-length",
				  &result_strcmpcase) == 0) &&
		    result_strcmpcase == 0) {
			rest->content_length = atoi(p1);
			LOG(LOG_DEBUG, "Content-length: %zu\n",
			    rest->content_length);
		} else if ((strcasecmp_s(tmp, tmplen, "content-type",
					 &result_strcmpcase) == 0) &&
			   result_strcmpcase == 0) {
			LOG(LOG_DEBUG, "Content type: %s\n", p1);
		} else if ((strcasecmp_s(tmp, tmplen, "connection",
					 &result_strcmpcase) == 0) &&
			   result_strcmpcase == 0) {
			if ((strcasecmp_s(p1, strnlen_s(p1, SDO_MAX_STR_SIZE),
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
			if (rest->authorization)
				sdo_free(rest->authorization);
			rest->authorization = strdup(p1);
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
		} else {
			/* TODO: This looks like dead code, remove this
			 */
			/*
			 * If in protocol error sdo_rest_free is not
			 * called
			 * this can lead to memory leak, hence sdo_free
			 * if
			 * allocated
			 */
			if (rest->x_token_authorization)
				sdo_free(rest->x_token_authorization);
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
		if (rest->authorization)
			sdo_free(rest->authorization);
		if (rest->x_token_authorization)
			sdo_free(rest->x_token_authorization);
		if (rest->host_ip)
			sdo_free(rest->host_ip);
		if (rest->host_dns)
			sdo_free(rest->host_dns);
		sdo_free(rest);
	}
}
