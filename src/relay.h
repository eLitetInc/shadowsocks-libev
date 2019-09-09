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

#ifndef MAX_FRAG
#define MAX_FRAG 1
#endif

#ifdef USE_NFCONNTRACK_TOS
#ifndef MARK_MAX_PACKET
#define MARK_MAX_PACKET 10
#endif
#ifndef MARK_MASK_PREFIX
#define MARK_MASK_PREFIX 0xDC00
#endif
#endif

static const int
    MIN_TCP_IDLE_TIMEOUT = 24 * 3600;

#define MAX_CONNECT_TIMEOUT 10
#define MAX_REQUEST_TIMEOUT 30
#define MIN_UDP_TIMEOUT     10

#ifdef MODULE_REMOTE
#define MAX_UDP_SOCKET_NUM 512
#else
#define MAX_UDP_SOCKET_NUM 256
#endif

#if defined MODULE_CTX_TCP // MODULE_CTX_TCP /////////////
#ifdef MODULE_REMOTE
#include "resolv.h"
#ifdef USE_NFCONNTRACK_TOS
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

struct dscptracker {
    struct nf_conntrack *ct;
    long unsigned int mark;
    unsigned int dscp;
    unsigned int packet_count;
};
#endif
#endif

typedef struct server_ctx {
    ev_io io;
#ifdef MODULE_REMOTE
    ev_timer watcher;
#endif
    int connected;
    struct server *server;
} server_ctx_t;

typedef struct server {
    int fd;
    int stage;

    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct listen_ctx *listen_ctx;
    struct remote *remote;

    buffer_t *buf;

#ifdef MODULE_REMOTE
    int frag;

    crypto_t *crypto;
    cipher_ctx_t *e_ctx;
    cipher_ctx_t *d_ctx;

#ifdef USE_NFCONNTRACK_TOS
    struct dscptracker *tracker;
#endif
#endif

    struct cork_dllist_item entries;
} server_t;

typedef struct remote_ctx {
    ev_io io;
#ifdef MODULE_LOCAL
    ev_timer watcher;
#endif
    int connected;
    struct remote *remote;
} remote_ctx_t;

typedef struct remote {
    int fd;
#ifdef TCP_FASTOPEN_WINSOCK
    OVERLAPPED olap;
    int connect_ex_done;
#endif

    buffer_t *buf;

#ifdef MODULE_LOCAL
    crypto_t *crypto;
    cipher_ctx_t *e_ctx;
    cipher_ctx_t *d_ctx;
#endif

    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
    struct sockaddr_storage *addr;
} remote_t;
#elif defined MODULE_CTX_UDP // MODULE_CTX_UDP /////////////
#ifdef MODULE_REMOTE
typedef struct query {
    buffer_t *buf;
    struct remote *remote;
} query_t;
#endif

typedef struct server {
    ev_io io;
    int fd;

    struct remote *remote;
    struct listen_ctx *listen_ctx;

    // socket pool/cache
    struct cache *remotes;
} server_t;

typedef struct remote {
    ev_io io;
    ev_timer watcher;
    int fd, sfd;

#ifdef MODULE_LOCAL
    crypto_t *crypto;
#ifdef MODULE_SOCKS
    buffer_t *abuf;
#endif
#endif

    server_t *server;
    struct cork_dllist_item entries;
    struct sockaddr *saddr;
} remote_t;
#endif ///////////////////////////////

typedef struct remote_cnf {
    char *iface;
    crypto_t *crypto;
    struct sockaddr_storage *addr;
#ifdef MODULE_CTX_TCP
    cork_array(remote_t *) *remotes;
#endif
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

#define ev_callback_f(T, declname)  \
    typedef void (declname)(EV_P_ T *, int)

ev_callback_f(ev_io, ev_io_callback);
ev_callback_f(ev_timer, ev_timer_callback);

int create_and_bind(struct sockaddr_storage *, int, listen_ctx_t *);
int bind_and_listen(struct sockaddr_storage *, int, listen_ctx_t *);
#ifdef HAVE_LAUNCHD
int launch_or_create(struct sockaddr_storage *, int, listen_ctx_t *);
#endif

#ifdef __ANDROID__
int protect_socket(int fd);
int send_traffic_stat(uint64_t tx, uint64_t rx);
#endif

#endif // _RELAY_H
