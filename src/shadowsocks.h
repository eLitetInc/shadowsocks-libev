/*
 * shadowsocks.h - Header files of library interfaces
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _SHADOWSOCKS_H
#define _SHADOWSOCKS_H

#include "utils.h"
#include "crypto.h"
#include "netutils.h"

enum {
    SSOCKS_ATYP_IPV4   = 0x01,
    SSOCKS_ATYP_DOMAIN = 0x03,
    SSOCKS_ATYP_IPV6   = 0x04,
    SSOCKS_ATYP_MUX    = 0x05,
    SSOCKS_OPT_ASSOC   = 0x01
} addrtype;

typedef enum ssocks_module {
    module_local,
    module_redir,
    module_tunnel,
    module_remote
} ssocks_module_t;

typedef struct {
    uint8_t len;
    char *dname;
} dname_t;

typedef struct ssocks_hdr {
    uint8_t atyp;
    union { uint8_t id; };
    union {
        struct in_addr _4;
        struct {
            uint8_t len;
            char dname[];
        };
        struct in6_addr _6;
    };
    uint16_t port;
} PACKED ssocks_hdr_t;

typedef struct ssocks_mux {
    uint8_t atyp;
    uint8_t id;
} PACKED ssocks_mux_t;
#define ssocks_mux_hdr(id) (ssocks_mux_t) { .atyp = SSOCKS_ATYP_MUX, .id = id }
#define ssocks_readable(destaddr) \
    (destaddr)->dname ? hostname_readable((destaddr)->dname, (destaddr)->dname_len, (destaddr)->port) : \
                        sockaddr_readable("%a:%p", (destaddr)->addr)

#define MAX_HOSTNAME_LEN 256
static const int SSOCKS_HDR_SIZE =
    sizeof(ssocks_hdr_t) + MAX_HOSTNAME_LEN - 1;

typedef struct ssocks_addr {
    int id;
    char  *dname;
    size_t dname_len;
    struct sockaddr_storage *addr;
    uint16_t port;
} ssocks_addr_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ss_callback_t)(int socket, int socket_u, void *data);

/*
 * Create and start a shadowsocks local server, specifying a callback.
 *
 * The callback is invoked when the local server has started successfully. It passes the SOCKS
 * server and UDP relay file descriptors, along with any supplied user data.
 *
 * Returns -1 on failure.
 */
int new_shadowsocks_(ssocks_module_t module, jconf_t *conf,
                     ss_callback_t callback, void *data);
/*
 * Create and start a shadowsocks local server.
 *
 * Calling this function will block the current thread forever if the server
 * starts successfully.
 *
 * Make sure start the server in a separate process to avoid any potential
 * memory and socket leak.
 *
 * If failed, -1 is returned. Errors will output to the log file.
 */
static inline int
new_shadowsocks(ssocks_module_t module, jconf_t *conf) {
    return new_shadowsocks_(module, conf, NULL, NULL);
}

static inline ssocks_addr_t *
new_ssocks_addr()
{
    ssocks_addr_t *destaddr
                    = ss_calloc(1, sizeof(*destaddr));
    destaddr->addr  = ss_calloc(1, sizeof(*destaddr->addr));
    return destaddr;
}

static inline void
free_ssocks_addr(ssocks_addr_t *destaddr)
{
    if (destaddr->dname != NULL) {
        ss_free(destaddr->dname);
    }
    if (destaddr->addr != NULL) {
        ss_free(destaddr->addr);
    }
    ss_free(destaddr);
}

/**
 * Standard shadowsocks/socks5 address header builder.
 * ------------------------------
 *
 * parse_ssocks_header
 * create_ssocks_header
 *
 * CAVEATS: The domain name is not null-terminated
 *
 * / Pre-encryption //////////////////////
 * - Shadowsocks Request
 *   +------+----------+----------+----------+
 *   | ATYP | DST.ADDR | DST.PORT |   DATA   |
 *   +------+----------+----------+----------+
 *   |  1   | Variable |    2     | Variable |
 *   +------+----------+----------+----------+
 *
 * - Shadowsocks Response
 *   +------+----------+----------+----------+
 *   | ATYP | DST.ADDR | DST.PORT |   DATA   |
 *   +------+----------+----------+----------+
 *   |  1   | Variable |    2     | Variable |
 *   +------+----------+----------+----------+
 *
 * / Post-encryption /////////////////////
 * - Shadowsocks Request and Response
 *   +-------+--------------+
 *   |  IV   |    PAYLOAD   |
 *   +-------+--------------+
 *   | Fixed |   Variable   |
 *   +-------+--------------+
 *
*/
static inline int
parse_ssocks_header(buffer_t *buf, ssocks_addr_t *destaddr, int offset)
{
    uint8_t atyp = buf->data[offset++];

assoc:
    // get remote addr and port
    switch (atyp) {
        case SSOCKS_ATYP_IPV4: {
            size_t in_addr_len = sizeof(struct in_addr);
            if (buf->len < in_addr_len + offset) {
                return -1;
            }

            struct sockaddr_in *addr
                             = ss_calloc(1, sizeof(*addr));
            addr->sin_family = AF_INET;

            addr->sin_addr   = *(struct in_addr *)(buf->data + offset);
            offset += in_addr_len;

            addr->sin_port   = *(uint16_t *)(buf->data + offset);

            destaddr->addr   = (struct sockaddr_storage *)addr;
            destaddr->port   = addr->sin_port;
        } break;
        case SSOCKS_ATYP_DOMAIN: {
            size_t dname_len = *(uint8_t *)(buf->data + offset);
            if (buf->len < dname_len + 1 + offset) {
                return -1;
            }

            char *dname = ss_malloc(dname_len);
            memcpy(dname, buf->data + offset + 1, dname_len);
            offset += dname_len + 1;

            destaddr->dname = dname;
            destaddr->dname_len = dname_len;
            destaddr->port = *(uint16_t *)(buf->data + offset);
        } break;
        case SSOCKS_ATYP_IPV6: {
            size_t in6_addr_len = sizeof(struct in_addr);
            if (buf->len < in6_addr_len + offset) {
                return -1;
            }

            struct sockaddr_in6 *addr
                              = ss_calloc(1, sizeof(*addr));
            addr->sin6_family = AF_INET6;

            addr->sin6_addr   = *(struct in6_addr *)(buf->data + offset);
            offset += in6_addr_len;

            addr->sin6_port   = *(uint16_t *)(buf->data + offset);

            destaddr->addr    = (struct sockaddr_storage *)addr;
            destaddr->port    = addr->sin6_port;
        } break;
        case SSOCKS_ATYP_MUX: {
            destaddr->id = buf->data[offset++];
        } return offset;
        default:
        if (!destaddr->id) {
            atyp >>= SSOCKS_OPT_ASSOC;
            destaddr->id = buf->data[offset++];
            goto assoc;
        } return -1;
    }

    offset += 2;
    return offset;
}

static inline void
create_ssocks_header(buffer_t *buf, ssocks_addr_t *destaddr)
{
    uint8_t *atyp = (uint8_t *)&buf->data[buf->len++];
    uint8_t option = 0;
    if (destaddr->id) {
        option = SSOCKS_OPT_ASSOC;
        buf->data[buf->len++] = destaddr->id;
    }

    if (destaddr->dname != NULL) {
        *atyp = SSOCKS_ATYP_DOMAIN << option;
        buf->data[buf->len++] = destaddr->dname_len > 0 ? destaddr->dname_len : strlen(destaddr->dname);
        memcpy(buf->data + buf->len, destaddr->dname, destaddr->dname_len);
        buf->len += destaddr->dname_len;
        if (!destaddr->port && destaddr->addr) {
            destaddr->port = sockaddr_port((struct sockaddr *)destaddr->addr);
        }
    } else {
        struct sockaddr_storage *storage = destaddr->addr;
        switch (storage->ss_family) {
            case AF_INET: {
                *atyp = SSOCKS_ATYP_IPV4 << option; // Type 1 is IPv4 address
                struct sockaddr_in *addr = (struct sockaddr_in *)storage;
                memcpy(buf->data + buf->len, &addr->sin_addr, sizeof(struct in_addr));
                buf->len += sizeof(struct in_addr);
                destaddr->port = addr->sin_port;
            } break;
            case AF_INET6: {
                *atyp = SSOCKS_ATYP_IPV6 << option; // Type 4 is IPv6 address
                struct sockaddr_in6 *addr = (struct sockaddr_in6 *)storage;
                memcpy(buf->data + buf->len, &addr->sin6_addr, sizeof(struct in6_addr));
                buf->len += sizeof(struct in6_addr);
                destaddr->port = addr->sin6_port;
            } break;
        }
    }

    memcpy(buf->data + buf->len, &destaddr->port, sizeof(destaddr->port));
    buf->len += sizeof(destaddr->port);
}

#ifdef __cplusplus
}
#endif

/**
 * Footnote
 * ----------------------------
 * To stop the service on POSIX system, just kill
 * the daemon process.
 *
 * kill(pid, SIGKILL);
 *
 * Otherwise, if you start the service in a thread,
 * you may need to send a signal SIGUSER1 to the thread.
 *
 * pthread_kill(pthread_t, SIGUSR1);
 *
*/

#endif // _SHADOWSOCKS_H
