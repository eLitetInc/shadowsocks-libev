/*
 * relay.c -
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

#include <math.h>
#include <fcntl.h>
#include <errno.h>

#include <libcork/core.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef __MINGW32__
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#ifdef __linux__
#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#else
#include <linux/if.h>
#endif
#endif

#include "netutils.h"
#include "utils.h"
#include "common.h"
#include "relay.h"

int acl = false,
    verbose    = false,
    ipv6first  = false,
    remote_dns = false, // resolve hostname remotely
    fast_open  = false,
    no_delay   = false,
    reuse_conn = false;

struct ev_loop *loop;


int
create_and_bind(struct sockaddr_storage *storage,
                int protocol, listen_ctx_t *listen_ctx)
{
    int fd = socket(storage->ss_family,
                    protocol == IPPROTO_TCP ?
                        SOCK_STREAM : SOCK_DGRAM,
                    protocol);
    if (fd == -1) {
        return fd;
    }

    int ipv6only = storage->ss_family == AF_INET6;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if (listen_ctx != NULL) {
        if (listen_ctx->reuse_port
            && set_reuseport(fd))
        {
            ERROR("failed to enable port reuse");
        }

#ifdef MODULE_REMOTE
        if (protocol == IPPROTO_TCP
            && listen_ctx->mptcp && set_mptcp(fd))
        {
            ERROR("failed to enable multipath TCP");
        }
#elif MODULE_REDIR
        if (protocol == IPPROTO_UDP
            && tproxy_socket(fd, storage->ss_family)) {
            ERROR("tproxy_socket");
            FATAL("failed to enable transparent proxy");
        }
#endif
    }

    int s = bind(fd, (struct sockaddr *)storage, sockaddr_len((struct sockaddr *)storage));
    if (s == 0) {
        return fd;
    } else {
        ERROR("bind");
        FATAL("failed to bind address %s", sockaddr_readable("%a:%p", storage));
        close(fd);
    }
    return -1;
}

int
bind_and_listen(struct sockaddr_storage *storage,
                int protocol, listen_ctx_t *listen_ctx)
{
    int listenfd = create_and_bind(storage, protocol, listen_ctx);

    if (listenfd != -1) {
        setnonblocking(listenfd);
        listen_ctx->fd = listenfd;
        if (protocol == IPPROTO_TCP
            && listen(listenfd, SOMAXCONN) == -1)
        {
            ERROR("listen");
            FATAL("failed to listen on address %s", sockaddr_readable("%a:%p", storage));
            close(listenfd);
            return -1;
        }
    }

    return listenfd;
}

#ifdef HAVE_LAUNCHD
int
launch_or_create(struct sockaddr_storage *storage,
                 int protocol, listen_ctx_t *listen_ctx)
{
    int *listenfd;
    size_t cnt;
    int error = launch_activate_socket("Listeners", &listenfd, &cnt);
    if (error == 0) {
        if (cnt == 1) {
            if (*listenfd == -1) {
                FATAL("[launchd] bind() error");
            }
            if (listen(*listenfd, SOMAXCONN) == -1) {
                FATAL("[launchd] listen() error");
            }
            setnonblocking(*listenfd);
            listen_ctx->fd = listenfd;
            return listenfd;
        } else {
            FATAL("[launchd] please don't specify multi entry");
        }
    } else if (error == ESRCH || error == ENOENT) {
        /**
         * ESRCH:  The calling process is not managed by launchd(8).
         * ENOENT: The socket name specified does not exist
         *         in the caller's launchd.plist(5).
         */
        return bind_and_listen(storage, protocol, listen_ctx);
    } else {
        FATAL("[launchd] launch_activate_socket() error");
    }
    return -1;
}

#endif
