/*
 * relay.h - Define relay's buffers and callbacks
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
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

#ifndef _RELAY_H
#define _RELAY_H

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#include "common.h"
#include "crypto.h"
#include "jconf.h"
#include "shadowsocks.h"

extern int
    acl,
    verbose,
    ipv6first,
    remote_dns,
    fast_open,
    no_delay,
    reuse_conn;

typedef struct remote_cnf {
    char *iface;
    crypto_t *crypto;
    struct sockaddr_storage *addr;
    struct cache *sockets;
} remote_cnf_t;

typedef struct listen_ctx {
    ev_io io;
    int fd;
    int timeout;
    int tos;
    int mptcp;
    int reuse_port;
    int mtu;
    char *iface;

#ifdef MODULE_LOCAL
    int remote_num;
    struct remote_cnf **remotes;
#ifdef MODULE_TUNNEL
    struct ssocks_addr destaddr;
#endif
#elif MODULE_REMOTE
    crypto_t *crypto;
#ifndef __MINGW32__
    ev_timer stat_watcher;
#endif
    struct cork_dllist_item entries;
    struct ev_loop *loop;
#endif
    struct sockaddr_storage *addr;
} listen_ctx_t;

int create_and_bind(struct sockaddr_storage *storage,
                    int protocol, listen_ctx_t *listen_ctx);
int bind_and_listen(struct sockaddr_storage *storage,
                    int protocol, listen_ctx_t *listen_ctx);
#ifdef HAVE_LAUNCHD
int launch_or_create(struct sockaddr_storage *storage,
                     int protocol, listen_ctx_t *listen_ctx);
#endif

#ifdef __ANDROID__
int protect_socket(int fd);
int send_traffic_stat(uint64_t tx, uint64_t rx);
#endif

#endif // _RELAY_H
