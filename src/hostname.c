/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "utils.h"
#include "hostname.h"

#ifndef isblank
#define isblank(c) (c == ' ' || c == '\t')
#endif

static int parse_http_headers(const char *, size_t, const char *, size_t, char **);
static size_t fetch_http_header_next(const char **, size_t *);
static int parse_tls_extensions(const char *, size_t, char **);
static int parse_server_name_extension(const char *, size_t, char **);

/**
 * - http_hostname
 *   Parses a HTTP request for the Host: header
 * - tls_hostname
 *   Parse a TLS packet for the Server Name Indication extension in the client
 *   hello handshake, returning the first servername found (pointer to static
 *   array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  HTTP_ERR_INCOMPLETE   - Incomplete request
 *  HTTP_ERR_NO_HOSTHDR   - No Host header included in this request
 *  HTTP_ERR_INVALID_HOSTNAME   - Invalid hostname pointer
 *  HTTP_ERR_MALLOC   - malloc failure
 *  HTTP_ERR_INVALID_HLO - Invalid TLS client hello
 **/

int
http_hostname(const char *data, size_t data_len, char **hostname)
{
    int result, i;

    if (hostname == NULL)
        return HTTP_ERR_INVALID_HOSTNAME;

    char tag[] = "Host:";
    result = parse_http_headers(tag, sizeof(tag) - 1, data, data_len, hostname);
    if (result < 0)
        return result;

    /*
     *  if the user specifies the port in the request, it is included here.
     *  Host: example.com:80
     *  Host: [2001:db8::1]:8080
     *  so we trim off port portion
     */
    for (i = result - 1; i >= 0; i--)
        if ((*hostname)[i] == ':') {
            (*hostname)[i] = '\0';
            result = i;
            break;
        } else if (!isdigit((*hostname)[i])) {
            break;
        }

    return result;
}

static int
parse_http_headers(const char *header, size_t header_len,
                   const char *data, size_t data_len, char **value)
{
    size_t len;

    /* loop through headers stopping at first blank line */
    while ((len = fetch_http_header_next(&data, &data_len)) != 0)
        if (len > header_len && strncasecmp(header, data, header_len) == 0) {
            /* Eat leading whitespace */
            while (header_len < len && isblank((unsigned char)data[header_len]))
                header_len++;

            *value = malloc(len - header_len + 1);
            if (*value == NULL)
                return HTTP_ERR_MALLOC;

            strncpy(*value, data + header_len, len - header_len);
            (*value)[len - header_len] = '\0';

            return len - header_len;
        }

    /* If there is no data left after reading all the headers then we do not
     * have a complete HTTP request, there must be a blank line */
    if (data_len == 0)
        return HTTP_ERR_INCOMPLETE;

    return HTTP_ERR_NO_HOSTHDR;
}

static size_t
fetch_http_header_next(const char **data, size_t *len)
{
    size_t header_len = 0;

    /* perhaps we can optimize this to reuse the value of header_len, rather
     * than scanning twice.
     * Walk our data stream until the end of the header */
    while (*len > 2 && (*data)[0] != '\r' && (*data)[1] != '\n') {
        (*len)--;
        (*data)++;
    }

    /* advanced past the <CR><LF> pair */
    *data += 2;
    *len -= 2;

    /* Find the length of the next header */
    while (*len > header_len + 1
            && (*data)[header_len] != '\r'
            && (*data)[header_len + 1] != '\n')
        header_len++;

    return header_len;
}

int
tls_hostname(const char *data, size_t data_len, char **hostname)
{
    uint8_t tls_content_type;
    uint8_t tls_version_major;
    uint8_t tls_version_minor;
    size_t pos = TLS_HEADER_LEN;
    size_t len;

    if (hostname == NULL)
        return HTTP_ERR_INVALID_HOSTNAME;

    /* Check that our TCP payload is at least large enough for a TLS header */
    if (data_len < TLS_HEADER_LEN)
        return HTTP_ERR_INCOMPLETE;

    /* SSL 2.0 compatible Client Hello
     *
     * High bit of first byte (length) and content type is Client Hello
     *
     * See RFC5246 Appendix E.2
     */
    if (data[0] & 0x80 && data[2] == 1)
        return HTTP_ERR_NO_HOSTHDR;

    tls_content_type = data[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE)
        return HTTP_ERR_INVALID_HLO;

    tls_version_major = data[1];
    tls_version_minor = data[2];
    if (tls_version_major < 3)
        return HTTP_ERR_NO_HOSTHDR;

    /* TLS record length */
    len = ((unsigned char)data[3] << 8) +
          (unsigned char)data[4] + TLS_HEADER_LEN;
    data_len = min(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len)
        return HTTP_ERR_INCOMPLETE;

    /*
     * Handshake
     */
    if (pos + 1 > data_len) {
        return HTTP_ERR_INVALID_HLO;
    }
    if (data[pos] != TLS_HANDSHAKE_TYPE_HLO)
        return HTTP_ERR_INVALID_HLO;

    /* Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
     */
    pos += 38;

    /* Session ID */
    if (pos + 1 > data_len)
        return HTTP_ERR_INVALID_HLO;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len)
        return HTTP_ERR_INVALID_HLO;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len)
        return HTTP_ERR_INVALID_HLO;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0)
        return HTTP_ERR_NO_HOSTHDR;

    /* Extensions */
    if (pos + 2 > data_len)
        return HTTP_ERR_INVALID_HLO;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2;

    if (pos + len > data_len)
        return HTTP_ERR_INVALID_HLO;

    return parse_tls_extensions(data + pos, len, hostname);
}

static int
parse_tls_extensions(const char *data, size_t data_len, char **hostname)
{
    size_t pos = 0;
    size_t len;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        len = ((unsigned char)data[pos + 2] << 8) +
              (unsigned char)data[pos + 3];

        /* Check if it's a server name extension */
        if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
            /* There can be only one extension of each type, so we break
               our state and move p to beinnging of the extension here */
            if (pos + 4 + len > data_len)
                return HTTP_ERR_INVALID_HLO;
            return parse_server_name_extension(data + pos + 4, len, hostname);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return HTTP_ERR_INVALID_HLO;

    return HTTP_ERR_NO_HOSTHDR;
}

static int
parse_server_name_extension(const char *data, size_t data_len, char **hostname)
{
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < data_len) {
        len = ((unsigned char)data[pos + 1] << 8) +
              (unsigned char)data[pos + 2];

        if (pos + 3 + len > data_len)
            return HTTP_ERR_INVALID_HLO;

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                *hostname = malloc(len + 1);
                if (*hostname == NULL)
                    return HTTP_ERR_MALLOC;

                strncpy(*hostname, (const char *)(data + pos + 3), len);
                (*hostname)[len] = '\0';

                return len;
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return HTTP_ERR_INVALID_HLO;

    return HTTP_ERR_NO_HOSTHDR;
}

int
gquic_hostname(const char *data, size_t data_len, char **hostname)
{
    // Base offset, skip to packet number
    u_int16_t base_offset = 13, offset;

    if (data_len != QUIC_DATA_LEN)
        return HTTP_ERR_INCOMPLETE;
    // Packet Number must be 1
    if (data[base_offset] != 1)
        return HTTP_ERR_INVALID_HLO;
    offset = base_offset + 17; // Skip data length

    /* Only continue if this is a client hello */
    if (strncmp(&data[offset], "CHLO", 4) == 0)
    {
        u_int32_t prev_end_offset = 0;
        u_int32_t tag_offset = 0, tag_end_offset;
        u_int16_t tag_number;
        int match;

        offset += 4; // Size of tag
        memcpy(&tag_number, &data[offset], 2);

        offset += 4; // Size of tag number + padding
        base_offset = offset;
        for (int i = 0; i < tag_number; i++)
        {
            match = strncmp("SNI", &data[offset + tag_offset], 4);

            tag_offset += 4;
            memcpy(&tag_end_offset, &data[offset + tag_offset], 4);
            tag_offset += 4;

            if (match == 0) {
                size_t len = tag_end_offset - prev_end_offset;
                *hostname = malloc(len + 1);
                strncpy(*hostname, &data[base_offset + tag_number * 8 + prev_end_offset], len);
                (*hostname)[len] = '\0';
                return len;
            } else {
                prev_end_offset = tag_end_offset;
            }
        }
    }

    return HTTP_ERR_INVALID_HLO;
}
