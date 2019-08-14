/*
 * udprelay.c - Setup UDP relay for both client and server
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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#ifndef __MINGW32__
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#endif
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include <libcork/core.h>

#include "utils.h"
#include "netutils.h"
#include "udprelay.h"
#include "winsock.h"
#include "acl.h"
#include "shadowsocks.h"

static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents);

#ifdef MODULE_REMOTE
static void resolv_free_cb(void *data);
static void resolv_cb(struct sockaddr *addr, void *data);
#endif

static remote_t *new_remote(int fd, int timeout);
static remote_t *create_remote(EV_P_ struct sockaddr_storage *addr, server_t *server);
static int remote_socket(struct sockaddr_storage *addr, const char *iface);
static void close_and_free_remote(EV_P_ remote_t *remote);

#if defined MODULE_REMOTE || defined __ANDROID__
extern uint64_t tx, rx;
#ifdef __ANDROID__
extern int vpn;
extern void stat_update_cb();
#endif
#endif

extern int acl;
extern int verbose;
extern int ipv6first;
#ifdef MODULE_LOCAL
extern int remote_dns;
#endif

static int packet_size  = DGRAM_PKT_SIZE;
static int buf_size     = DGRAM_BUF_SIZE;

static int server_num   = 0;
static server_t *servers[MAX_REMOTE_NUM] = { NULL };

#ifdef MODULE_REMOTE
static void
report_addr(struct sockaddr_storage *addr, const char *info)
{
    if (verbose) {
        LOGE("[udp] terminating data transmission with %s: %s",
             sockaddr_readable("%a", addr), info);
    }
}

static void
resolv_free_cb(void *data)
{
    query_t *query = (query_t *)data;

    if (query->buf != NULL) {
        free_buffer(query->buf);
    }
    ss_free(query);
}

static void
resolv_cb(struct sockaddr *addr, void *data)
{
    query_t  *query  = (query_t *)data;
    remote_t *remote = query->remote;
    server_t *server = remote->server;

    if (server == NULL)
        return;

    struct ev_loop *loop = server->listen_ctx->loop;

    if (addr == NULL) {
        LOGE("[udp] unable to resolve");
    } else {
        int s = connect(remote->fd, addr, get_sockaddr_len(addr));

        if (s == -1) {
            ERROR("connect");
            close_and_free_remote(EV_A_ remote);
            return;
        }

        s = send(remote->fd, query->buf->data, query->buf->len, 0);
        if (s == -1) {
            ERROR("[udp] sendto_remote");
            close_and_free_remote(EV_A_ remote);
            return;
        }

        // start remote io
        ev_io_start(EV_A_ & remote->io);
    }
}

#elif defined MODULE_REDIR
static int
create_tproxy(struct sockaddr_storage *destaddr)
{
    int sourcefd = socket(destaddr->ss_family, SOCK_DGRAM, 0);
    if (sourcefd < 0) {
        return -1;
    }

    int opt = 1;
    if (setsockopt(sourcefd, destaddr->ss_family == AF_INET6 ? SOL_IPV6 : SOL_IP,
                   IP_TRANSPARENT, &opt, sizeof(opt)))
    {
        close(sourcefd);
        return -1;
    }

    if (setsockopt(sourcefd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        close(sourcefd);
        return -1;
    }
#ifdef IP_TOS
    // Set QoS flag
    int tos = 46;
    setsockopt(sourcefd,
               destaddr->ss_family == AF_INET6 ? IPPROTO_IP: IPPROTO_IPV6,
               IP_TOS, &tos, sizeof(tos));
#endif

    if (bind(sourcefd, (struct sockaddr *)destaddr,
             get_sockaddr_len((struct sockaddr *)destaddr)) != 0)
    {
        ERROR("[udp] remote_recv_bind");
        close(sourcefd);
        return -1;
    }
    return sourcefd;
}

#endif

static int
remote_socket(struct sockaddr_storage *addr, const char *iface)
{
    socklen_t addrlen = 0;
    struct sockaddr_storage *destaddr = addr;
    if (destaddr == NULL) {
        destaddr = ss_calloc(1, sizeof(struct sockaddr_storage));
        // Try binding IPv6 first
        if (ipv6first) {
            addrlen = sizeof(struct sockaddr_in);
            *(struct sockaddr_in6 *)destaddr = (struct sockaddr_in6) {
                .sin6_family = AF_INET6,
                .sin6_addr   = in6addr_any
            };
        } else {
            addrlen = sizeof(struct sockaddr_in6);
            *(struct sockaddr_in *)destaddr = (struct sockaddr_in) {
                .sin_family  = AF_INET,
                .sin_addr.s_addr = INADDR_ANY
            };
        }
    } else {
        struct sockaddr_storage *storage = NULL;
        switch (destaddr->ss_family) {
            case AF_INET:
                addrlen = sizeof(struct sockaddr_in);
                storage = (struct sockaddr_storage *)&(struct sockaddr_in) {
                    .sin_family = AF_INET,
                    .sin_addr = ((struct sockaddr_in *)destaddr)->sin_addr
                };
                break;
            case AF_INET6:
                addrlen = sizeof(struct sockaddr_in6);
                storage = (struct sockaddr_storage *)&(struct sockaddr_in6) {
                    .sin6_family = AF_INET6,
                    .sin6_addr = ((struct sockaddr_in6 *)destaddr)->sin6_addr
                };
                break;
            default:
                return -1;
        }
        destaddr = storage;
    }

    int remotefd = socket(destaddr->ss_family, SOCK_DGRAM, 0);

    if (remotefd == -1) {
        ERROR("[udp] cannot create socket");
    } else {
        int opt = 1;
        setnonblocking(remotefd);
#ifdef SO_BROADCAST
        setsockopt(remotefd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
#endif
#ifdef SO_NOSIGPIPE
        setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
#ifdef IP_TOS
        // Set QoS flag
        int tos = 46;
        setsockopt(remotefd,
                   destaddr->ss_family == AF_INET6 ? IPPROTO_IP : IPPROTO_IPV6,
                   IP_TOS, &tos, sizeof(tos));
#endif
#ifdef SET_INTERFACE
        if (iface) {
            if (setinterface(remotefd, iface) == -1)
                ERROR("setinterface");
        }
#endif

        if (bind(remotefd, (struct sockaddr *)destaddr, addrlen) != 0) {
            FATAL("[udp] cannot bind remote");
            return -1;
        }

#ifdef MODULE_LOCAL
#ifdef __ANDROID__
        if (vpn && protect_socket(remotefd) == -1) {
            ERROR("protect_socket");
            close(remotefd);
            return -1;
        }
#endif
#endif
    }
    return remotefd;
}

static remote_t *
create_remote(EV_P_ struct sockaddr_storage *addr, server_t *server)
{
    listen_ctx_t *listen_ctx = server->listen_ctx;
    struct cork_dllist_item *remote_itm = cork_dllist_head(&server->remotes);
    remote_t *remote
        = remote_itm ? cork_container_of(remote_itm, remote_t, entries) : NULL;

    if (remote != NULL) {
        // remote is now active and
        // now we need to remove it from the "idlers' list"
        cork_dllist_remove(&remote->entries);
        ev_timer_again(EV_A_ & remote->watcher);
    } else {
        // Bind to any port
        int remotefd = remote_socket(addr, listen_ctx->iface);
        if (remotefd < 0) {
            ERROR("[udp] udprelay bind() error");
            return NULL;
        }

        // Init remote
        remote = new_remote(remotefd, listen_ctx->timeout);
        remote->server = server;

        ev_timer_start(EV_A_ & remote->watcher);
    }

    return remote;
}

static remote_t *
new_remote(int fd, int timeout)
{
    remote_t *remote = ss_calloc(1, sizeof(remote_t));
    remote->fd = fd;

    ev_io_init(&remote->io, remote_recv_cb, fd, EV_READ);
    ev_timer_init(&remote->watcher, remote_timeout_cb,
                  max(timeout, MIN_UDP_TIMEOUT), 0);
    return remote;
}

static void
close_and_free_remote(EV_P_ remote_t *remote)
{
    if (remote != NULL) {
        /**
         *  WATCH OUT!
         *  ---------------------------
         *  The code below removes the target watcher from the "idlers' list,"
         *  ONLY if it's no longer active. Please keep in mind that the watchers
         *  that are currenly active do not count.
         *  They have ALREADY been (and are REQUIRED to be) removed from the list.
         */
        if (!ev_is_active(&remote->io))
            cork_dllist_remove(&remote->entries);
        ev_timer_stop(EV_A_ & remote->watcher);
        ev_io_stop(EV_A_ & remote->io);

        close(remote->fd);
#ifdef MODULE_SOCKS
        if (remote->abuf != NULL)
            free_buffer(remote->abuf);
#endif
        ss_free(remote);
    }
}

static server_t *
new_server(int fd, listen_ctx_t *listener)
{
    server_t *server   = ss_calloc(1, sizeof(server_t));
    server->fd         = fd;
    server->listen_ctx = listener;

    ev_io_init(&server->io, server_recv_cb, fd, EV_READ);

    if (server_num < MAX_REMOTE_NUM)
        servers[server_num++] = server;
    cork_dllist_init(&server->remotes);

    return server;
}

static void
close_and_free_server(EV_P_ server_t *server)
{
    if (server != NULL) {
        ev_io_stop(EV_A_ & server->io);
        close(server->fd);

        remote_t *remote = NULL;
        struct cork_dllist_item *curr, *next;
        cork_dllist_foreach(&server->remotes, curr, next,
                            remote_t, remote, entries) {
            close_and_free_remote(EV_A_ remote);
        }

        ss_free(server);
    }
}

static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_t *remote = (remote_t *)w;
    server_t *server = remote->server;

    // server has been closed
    if (server == NULL) {
        LOGE("[udp] invalid server");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    buffer_t *buf = new_buffer(buf_size);
    ssize_t r = recv(remote->fd, buf->data, buf_size, 0);

    if (r == -1) {
        ERROR("[udp] remote_recv_recvfrom");
        goto CLEAN_UP;
    }

    if (verbose) {
        LOGI("[udp] remote received a packet");
        if (r > packet_size) {
            LOGI("[udp] remote_recv_recvfrom fragmentation, "
                 "      MTU should at least be: " SSIZE_FMT, r + DGRAM_PKT_HDR_SIZE);
        }
    }

    buf->len = r;

#ifdef MODULE_LOCAL
    crypto_t *crypto = remote->crypto;
    int err = crypto->decrypt_all(buf, crypto->cipher, buf_size);
    if (err) {
        // drop the packet silently
        goto CLEAN_UP;
    }

#ifdef MODULE_SOCKS
    bprepend(buf, remote->abuf, buf_size);
#ifdef __ANDROID__
    rx += buf->len;
    stat_update_cb();
#endif
#endif

#elif defined MODULE_REMOTE
    rx += buf->len;
    crypto_t *crypto = server->listen_ctx->crypto;
    int err = crypto->encrypt_all(buf, crypto->cipher, buf_size);
    if (err) {
        // drop the packet silently
        goto CLEAN_UP;
    }

#endif

    int s = sendto(server->sfd, buf->data, buf->len, 0,
                   remote->saddr, get_sockaddr_len(remote->saddr));

    if (s == -1) {
        ERROR("[udp] remote_recv_sendto");
        close_and_free_remote(EV_A_ remote);
        goto CLEAN_UP;
    }

    // UDP packet handled successfully,
    // trigger the timer and add remote back to cache
    ev_timer_again(EV_A_ & remote->watcher);
    ev_io_stop(EV_A_ & remote->io);
    cork_dllist_add(&server->remotes, &remote->entries);

CLEAN_UP:
#ifdef MODULE_REDIR
    close(server->sfd);
#endif
    free_buffer(buf);
}

static void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    remote_t *remote
        = cork_container_of(watcher, remote_t, watcher);

    if (verbose) {
        LOGI("[udp] transmission timed out");
    }

    close_and_free_remote(EV_A_ remote);
}

static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_t *server = (server_t *)w;
    buffer_t *buf    = new_buffer(buf_size);

    ssocks_addr_t *destaddr = &(ssocks_addr_t) {};
    struct sockaddr_storage *saddr = ss_calloc(1, sizeof(*saddr));

#ifdef MODULE_REDIR
    char control_buffer[64] = { 0 };

    struct msghdr msg = {
        .msg_name       = saddr,
        .msg_namelen    = sizeof(*saddr),
        .msg_control    = control_buffer,
        .msg_controllen = sizeof(control_buffer),
        .msg_iov = (struct iovec []) {
            (struct iovec) {
                .iov_base = buf->data,
                .iov_len  = buf_size
            }
        },
        .msg_iovlen = 1
    };

    buf->len = recvmsg(server->fd, &msg, 0);
    if (buf->len == -1) {
        ERROR("[udp] server_recvmsg");
        goto CLEAN_UP;
    }

    destaddr->addr = &(struct sockaddr_storage) {};
    if (getdestaddr_dgram(&msg, destaddr->addr)) {
        LOGE("[udp] unable to determine destination address");
        goto CLEAN_UP;
    }

    int sourcefd = create_tproxy(destaddr->addr);
    if (sourcefd < 0) {
        ERROR("[udp] server_recvmsg_socket");
        goto CLEAN_UP;
    }

    server->sfd = sourcefd;
#else
    ssize_t r = recvfrom(server->fd, buf->data, buf_size,
                         0, (struct sockaddr *)saddr,
                         &(socklen_t) { sizeof(*saddr) });

    if (r == -1) {
        ERROR("[udp] server_recv_recvfrom");
        goto CLEAN_UP;
    }

    buf->len = r;
    server->sfd = server->fd;
#endif

    if (verbose) {
        LOGI("[udp] server received a packet");
        if (buf->len > packet_size) {
            LOGI("[udp] server_recv fragmentation, "
                 "      MTU should at least be: " SSIZE_FMT, buf->len + DGRAM_PKT_HDR_SIZE);
        }
    }

#ifdef MODULE_REMOTE
// ssocks module ////////////
    tx += buf->len;

    crypto_t *crypto = server->listen_ctx->crypto;

    int err = crypto->decrypt_all(buf, crypto->cipher, buf_size);
    if (err) {
        // drop the packet silently
        goto CLEAN_UP;
    }

    int offset = parse_ssocks_header(buf, destaddr, 0);

    if (offset < 0 || buf->len < offset) {
        report_addr(saddr, "invalid request length");
        goto CLEAN_UP;
    }

    buf->len -= offset;
    memmove(buf->data, buf->data + offset, buf->len);

    if (verbose && buf->len > packet_size) {
        LOGI("[udp] server_recv_sendto fragmentation, "
             "      MTU should at least be: " SSIZE_FMT, buf->len + DGRAM_PKT_HDR_SIZE);
    }

    remote_t *remote =
        create_remote(EV_A_ NULL/*listen_ctx->addr*/, server);

    if (remote == NULL)
        goto CLEAN_UP;

    remote->saddr = (struct sockaddr *)saddr;

    if (destaddr->dname != NULL) {
        null_terminate(destaddr->dname, destaddr->dname_len);

        if (acl && search_acl(ACL_ATYP_DOMAIN,
                              &(dname_t) { destaddr->dname_len, destaddr->dname }, ACL_BLOCKLIST))
        {
            if (verbose)
                LOGI("[udp] blocking access to %s", destaddr->dname);
            goto CLEAN_UP;
        }
        if (verbose) {
            LOGI("[udp] connecting to %s:%d", destaddr->dname, ntohs(destaddr->port));
        }

        query_t *query = ss_malloc(sizeof(*query));
        query->buf     = buf;
        query->remote  = remote;

        resolv_start(destaddr->dname, destaddr->port,
                     resolv_cb, resolv_free_cb, query);
        return;
    } else {
        if (acl && search_acl(ACL_ATYP_IP, destaddr->addr, ACL_BLOCKLIST)) {
            if (verbose)
                LOGI("[udp] blocking access to %s",
                    sockaddr_readable("%a:%p", destaddr->addr));
            goto CLEAN_UP;
        }
        if (verbose) {
            LOGI("[udp] connecting to %s",
                sockaddr_readable("%a:%p", destaddr->addr));
        }

        resolv_cb((struct sockaddr *)destaddr->addr,
                  &(query_t){ buf, remote });
    }
/////////////////////////////
#elif defined MODULE_LOCAL
    listen_ctx_t *listen_ctx = server->listen_ctx;
    struct sockaddr_storage *remote_addr = NULL;
    remote_t *remote = create_remote(EV_A_ NULL, server);

    if (remote == NULL)
        goto CLEAN_UP;

// tproxy module ////////////
#ifdef MODULE_TUNNEL
    destaddr = &listen_ctx->destaddr;
// socks5 module ////////////
#elif defined MODULE_SOCKS
#ifdef __ANDROID__
    tx += buf->len;
#endif
    uint8_t frag = *(uint8_t *)(buf->data + 2);
    if (frag) {
        LOGE("[udp] fragmentation not supported");
        LOGE("[udp] dropping packet with non-zero frag number %d", frag);
        goto CLEAN_UP;
    }

    int offset = parse_ssocks_header(buf, destaddr, 3);
    if (offset < 0) {
        LOGE("[udp] invalid socks5 header");
        goto CLEAN_UP;
    }

    buf->len -= offset;
    memmove(buf->data, buf->data + offset, buf->len);
#endif
/////////////////////////////

    int acl_enabled = (acl
#ifdef __ANDROID__
        && !(vpn && port_service(destaddr->port) == PORT_DOMAIN_SERVICE)
#endif
        );

    if (remote_dns && destaddr->dname) {
        switch (port_service(destaddr->port)) {
            default:
            case PORT_HTTP_SERVICE:
            case PORT_HTTPS_SERVICE: {
                LOGE("[udp] QUIC protocol not supported yet");
            } break;
        }
    }

    if (destaddr->dname_len <= 0 ||
        destaddr->dname_len >= MAX_HOSTNAME_LEN)
    {
        destaddr->dname = NULL;
    }

    remote->direct = acl_enabled ?
                     search_acl(ACL_ATYP_SSOCKS, destaddr, ACL_UNSPCLIST) : 0;

    if (verbose) {
        LOGI("%s %s", remote->direct ? "bypassing" : "connecting to",
             destaddr->dname ? hostname_readable(destaddr->dname, destaddr->dname_len, destaddr->port)
                             : sockaddr_readable("%a:%p", destaddr->addr));
    }

    if (!remote->direct)
bailed: {
        int remote_idx = acl_enabled ?
                         search_acl(ACL_ATYP_SSOCKS, destaddr, ACL_DELEGATION) :
                         rand() % listen_ctx->remote_num;

        buffer_t *abuf   = new_buffer(buf_size);
        remote_cnf_t *remote_cnf
                         = listen_ctx->remotes[remote_idx];
        crypto_t *crypto = remote_cnf->crypto;

        create_ssocks_header(abuf, destaddr);
        bprepend(buf, abuf, buf_size);

#ifdef MODULE_SOCKS
        remote->abuf = abuf;
        // reconstruct packet
        brealloc(abuf, abuf->len + 3, buf_size);
        memmove(abuf->data + 3, abuf->data, abuf->len);
        memset(abuf->data, 0, 3);
        abuf->len += 3;
#else
        free_buffer(abuf);
#endif

        if (crypto->encrypt_all(buf, crypto->cipher, buf_size)) {
            goto CLEAN_UP;        // drop the packet silently
        }

        remote->crypto = crypto;
        remote_addr = remote_cnf->addr;
    } else {
        remote_addr = destaddr->addr;
        if (destaddr->dname && !remote_addr &&
            (remote_addr = ss_calloc(1, sizeof(*remote_addr))) &&
            get_sockaddr_r(destaddr->dname, NULL,
                           destaddr->port, remote_addr, 1, ipv6first) == -1)
        {
            remote->direct = 0;
            LOGE("failed to resolve %s", destaddr->dname);
            goto bailed;
        }
    }

    int s = connect(remote->fd, (struct sockaddr *)remote_addr, sizeof(*remote_addr));
    if (s == -1) {
        ERROR("connect");
        close_and_free_remote(EV_A_ remote);
        goto CLEAN_UP;
    }

    s = send(remote->fd, buf->data, buf->len, 0);
    if (s == -1) {
        ERROR("[udp] server_recv_sendto");
        close_and_free_remote(EV_A_ remote);
    } else {
        remote->saddr = (struct sockaddr *)saddr;
        // start remote io
        ev_io_start(EV_A_ & remote->io);
    }
#endif

CLEAN_UP:
    free_buffer(buf);
}

void
init_udprelay(EV_P_ listen_ctx_t *listener)
{
    if (listener->mtu > 0) {
        packet_size = listener->mtu - DGRAM_PKT_HDR_SIZE;
        buf_size    = packet_size * 2;
    }

    server_t *server = new_server(listener->fd, listener);
    ev_io_start(EV_A_ & server->io);
}

void
free_udprelay(struct ev_loop *loop)
{
    while (server_num > 0) {
        close_and_free_server(loop, servers[--server_num]);
        servers[server_num] = NULL;
    }
}
