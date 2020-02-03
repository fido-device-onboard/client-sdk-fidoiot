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
#define isRESTContextActive() ((rest) ? true : false)

// Global REST context
static RestCtx_t *rest;

/**
 * Initialize REST context.
 *
 * @retval true if allocation was successful, false on realloc/failure.
 */
bool initRESTContext(void)
{
	if (rest) {
		LOG(LOG_ERROR, "rest context is already active\n");
		return false;
	} else {
		return (rest = sdoAlloc(sizeof(RestCtx_t))) ? true : false;
	}
}

/**
 * Return REST context.
 * This API expects initRESTContext() to be called in advance.
 *
 * @retval NULL if initRESTContext() was not called in advance, current REST
 * context otherwise.
 */
RestCtx_t *getRESTContext(void)
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
bool cacheHostDns(const char *dns)
{
	bool ret = false;

	if (!dns)
		goto err;

	size_t len = strnlen_s(dns, SDO_MAX_STR_SIZE);

	if (!len || len == SDO_MAX_STR_SIZE)
		goto err;

	if (!isRESTContextActive()) {
		LOG(LOG_ERROR, "Rest Context is not active!\n");
		goto err;
	}

	if (!rest->hostDNS) {
		rest->hostDNS = sdoAlloc(len + 1);
		if (!rest->hostDNS)
			goto err;
	} else {
		if (memset_s(rest->hostDNS, sizeof(rest->hostDNS), 0) != 0) {
			ret = false;
			goto err;
		}
	}
	if (strcpy_s(rest->hostDNS, len + 1, dns) != 0)
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
bool cacheHostIP(SDOIPAddress_t *ip)
{
	bool ret = false;

	if (!ip)
		goto err;

	if (!isRESTContextActive()) {
		LOG(LOG_ERROR, "Rest Context is not active!\n");
		goto err;
	}

	if (!rest->hostIP) {
		rest->hostIP = sdoAlloc(sizeof(SDOIPAddress_t));
		if (!rest->hostIP)
			goto err;
	} else {
		if (memset_s(rest->hostIP, sizeof(rest->hostIP), 0) != 0)
			goto err;
	}

	if (memcpy_s(rest->hostIP, sizeof(SDOIPAddress_t), ip,
		     sizeof(SDOIPAddress_t)) != 0) {
		sdoFree(rest->hostIP);
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
bool cacheHostPort(uint16_t port)
{
	bool ret = false;

	if (!isRESTContextActive()) {
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
bool cacheTLSConnection(void)
{
	bool ret = false;

	if (!isRESTContextActive()) {
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
static bool ipBinToAscii(SDOIPAddress_t *ip, char *ip_ascii)
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
 * @param rest - current REST context.
 * @param g_URL - post URL output.
 * @param POST_URL_LEN - post URL max length.
 * @retval true if header onstruction was successful, false otherwise.
 */
bool constructRESTHeader(RestCtx_t *rest, char *g_URL, size_t POST_URL_LEN)
{
	char *ip_ascii = NULL;
	char temp[HTTP_MAX_URL_SIZE] = {0};
	char temp1[256] = {0};
	char msgequals[] = ""; //!!! todo: "msg=";
	bool ret = false;

	if (!rest || !g_URL || !POST_URL_LEN) {
		LOG(LOG_ERROR, "Invalid input!\n");
		goto err;
	}

	if (rest->hostIP) {
		ip_ascii = sdoAlloc(IP_TAG_LEN);

		if (!ip_ascii)
			goto err;

		if (!ipBinToAscii(rest->hostIP, ip_ascii))
			goto err;
	}

	// TLS needed ?
	if (rest->tls) {
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

	if (/* rest->isDNS  && */ rest->hostDNS) {
		/* DNS */
		if (snprintf_s_si(temp, sizeof(temp), "%s:%d", rest->hostDNS,
				  rest->portno) < 0) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto err;
		}
	} else if (rest->hostIP && ip_ascii) {
		/* IP */
		if (snprintf_s_si(temp, sizeof(temp), "%s:%d", ip_ascii,
				  rest->portno) < 0) {
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

	if (snprintf_s_i(temp, sizeof(temp), "/mp/%d", rest->protVer) < 0) {
		LOG(LOG_ERROR, "Snprintf failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, POST_URL_LEN, temp) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (snprintf_s_i(temp, sizeof(temp), "/msg/%d", rest->msgType) < 0) {
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

	if (rest->hostDNS) {
		/* DNS */
		if (snprintf_s_si(temp, sizeof(temp), "HOST:%s:%d\r\n",
				  rest->hostDNS, rest->portno) < 0) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto err;
		}
	} else if (rest->hostIP && ip_ascii) {
		/* IP */
		if (snprintf_s_si(temp, sizeof(temp), "HOST:%s:%d\r\n",
				  ip_ascii, rest->portno) < 0) {
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
			 "Content-length:%u\r\nConnection: keep-alive\r\n",
			 rest->contentLength) < 0) {
		LOG(LOG_ERROR, "Snprintf() failed!\n");
		goto err;
	}

	if (strcat_s(g_URL, POST_URL_LEN, temp1) != 0) {
		LOG(LOG_ERROR, "Strcat() failed!\n");
		goto err;
	}

	if (rest->authorization) {
		if (strcat_s(g_URL, POST_URL_LEN, "Authorization:") != 0) {
			LOG(LOG_ERROR, "Strcpy() failed!\n");
			goto err;
		}

		if (strcat_s(g_URL, POST_URL_LEN, rest->authorization) != 0) {
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
		sdoFree(ip_ascii);
	return ret;
}

/**
 * Parse/Process REST header elements (including HTTP Response) and return
 * content-length of REST body.
 *
 * @param hdr - pointer to REST header.
 * @param hdrlen - REST header length.
 * @param contLen - output pointer to content-length of REST body.
 * @retval true if HTTP 200 response is seen and parsing/processing was
 * successful, false otherwise.
 */
bool getRESTContentLength(char *hdr, size_t hdrlen, uint32_t *contLen)
{
	bool ret = false;
	char *rem, *p1, *p2;
	size_t remlen;
	char tmp[512];
	size_t tmplen;
	int rcode, result_strcmpcase;

	/* REST context must be active */
	if (!isRESTContextActive()) {
		LOG(LOG_ERROR, "Rest Context is not active!\n");
		goto err;
	}

	rest->msgType = 0;

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
			    "sdoRestRun: Response line parse error\n");
			goto err;
		}
		*p1++ = 0;
		rcode = atoi(p1);
		p2 = strchr(p1, ' ');
		if (p2 == NULL) {
			LOG(LOG_DEBUG, "Response code %03d \n", rcode);
		} else {
			*p2++ = 0;
			LOG(LOG_DEBUG, "Response code %03d received (%s)\n",
			    rcode, p2);
		}

		if (rcode != HTTP_SUCCESS_OK) {
			LOG(LOG_ERROR, "HTTP reponse is not 200(OK)!\n");
			rest->msgType = SDO_TYPE_ERROR;
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
			rest->contentLength = atoi(p1);
			LOG(LOG_DEBUG, "Content-length: %zu\n",
			    rest->contentLength);
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
				rest->keepAlive = true;
			} else {
				rest->keepAlive = false;
			}
			LOG(LOG_DEBUG, "Keep alive: %u\n", rest->keepAlive);
		} else if (strcasecmp_s(tmp, tmplen, "authorization",
					&result_strcmpcase) == 0 &&
			   result_strcmpcase == 0) {
			if (rest->authorization)
				sdoFree(rest->authorization);
			rest->authorization = strdup(p1);
			if (rest->authorization) {
				LOG(LOG_DEBUG, "Authorization: %s\n",
				    rest->authorization);
			}
		} else if (rest->xTokenAuthorization == NULL &&
			   strcasecmp_s(tmp, tmplen, "X-Token",
					&result_strcmpcase) == 0 &&
			   result_strcmpcase == 0) {
			rest->xTokenAuthorization = strdup(p1);
			if (rest->xTokenAuthorization) {
				LOG(LOG_DEBUG, "X-Token: %s\n",
				    rest->xTokenAuthorization);
			}
		} else {
			/* TODO: This looks like dead code, remove this
			 */
			/*
			 * If in protocol error sdoRestFree is not
			 * called
			 * this can lead to memory leak, hence sdoFree
			 * if
			 * allocated
			 */
			if (rest->xTokenAuthorization)
				sdoFree(rest->xTokenAuthorization);
			rest->xTokenAuthorization = strdup(p1);
			LOG(LOG_DEBUG, "Body: %s\n", tmp);
		}
		// consume \n
		++hdr;
		--hdrlen;
	}

	if (rest->contentLength > REST_MAX_MSGBODY_SIZE) {
		LOG(LOG_ERROR, "Invalid content-length!\n");
		goto err;
	}

	*contLen = rest->contentLength;
	ret = true;

err:
	return ret;
}

/**
 * Return REST header body separator
 *
 * @return token that separates protocol header with protocol body.
 */
char getRESTHdrBodySeparator(void)
{
	return '\0';
}

/**
 * undo of initRESTContext()
 *
 */
void exitRESTContext(void)
{
	if (rest) {
		if (rest->authorization)
			sdoFree(rest->authorization);
		if (rest->xTokenAuthorization)
			sdoFree(rest->xTokenAuthorization);
		if (rest->hostIP)
			sdoFree(rest->hostIP);
		if (rest->hostDNS)
			sdoFree(rest->hostDNS);
		sdoFree(rest);
	}
}
