/*
 * relay.h - Define TCP relay's buffers and callbacks
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

#ifndef _TCP_RELAY_H
#define _TCP_RELAY_H

#include <time.h>

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#include "common.h"
#include "shadowsocks.h"
#include "crypto.h"
#include "jconf.h"
#define MODULE_CTX_TCP
#include "relay.h"

enum {
    STAGE_ERROR   = -1, /* Error detected                   */
    STAGE_TIMEOUT = -1, /* Connection timed out             */
    STAGE_INIT,         /* Initial stage                    */
    STAGE_HANDSHAKE,    /* Handshake with client            */
    STAGE_SNI,          /* Parse HTTP/SNI header            */
    STAGE_RESOLVE,      /* Resolve the hostname             */
    STAGE_STREAM,       /* Stream between client and server */
    STAGE_STOP,         /* Server stop to respond           */
    STAGE_MULTIPLEX     /* Server multiplexing              */
};

remote_t *new_remote(server_t *);
server_t *new_server(int, listen_ctx_t *);

ev_io_callback accept_cb,
    server_recv_cb, server_send_cb,
    remote_recv_cb, remote_send_cb;

void free_remote(remote_t *remote);
void close_and_free_remote(EV_P_ remote_t *remote);
void free_server(server_t *server);
void close_and_free_server(EV_P_ server_t *server);

int remote_connected(remote_t *);

#ifdef MODULE_REMOTE
ev_timer_callback server_timeout_cb;
void server_timeout_cb(EV_P_ ev_timer *, int);
int create_remote(EV_P_ remote_t *, struct sockaddr_storage *);
void setTosFromConnmark(remote_t *, server_t *);
#elif defined MODULE_LOCAL
ev_timer_callback remote_timeout_cb;
int sendto_remote(remote_t *, buffer_t *);
remote_t *create_remote(EV_P_ server_t *, buffer_t *,
                              ssocks_addr_t *, int);
#endif

int start_relay(jconf_t *, ss_callback_t, void *);

void init_udprelay(EV_P_ listen_ctx_t *);
void free_udprelay(struct ev_loop *);

#endif // _RELAY_H
