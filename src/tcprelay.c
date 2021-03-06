/*
 * relay.c - Define TCP relay's buffers and callbacks
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
#include <sys/un.h>

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

#include "common.h"
#include "utils.h"
#include "netutils.h"
#include "winsock.h"
#include "hostname.h"
#include "acl.h"
#include "plugin.h"
#include "tcprelay.h"
#include "cache.h"

#ifdef __ANDROID__
extern int vpn;
#endif

#ifdef MODULE_REMOTE
static int remote_conn = 0;
static int server_conn = 0;
static char *manager_addr = NULL;
static struct cork_dllist listeners;
extern uint64_t tx, rx;
#ifndef __MINGW32__
ev_timer stat_watcher;
#endif
#endif
static struct cork_dllist connections;

struct ev_signal sigint_watcher;
struct ev_signal sigterm_watcher;
#ifndef __MINGW32__
struct ev_signal sigchld_watcher;
#endif

static int ret_val = 0;

remote_t *
new_remote(server_t *server) {
    remote_t *remote = ss_calloc(1, sizeof(*remote));

    remote->fd = -1;
    remote->recv_ctx = ss_calloc(1, sizeof(remote_ctx_t));
    remote->send_ctx = ss_calloc(1, sizeof(remote_ctx_t));
    remote->buf = new_buffer(SOCKET_BUF_SIZE);

    remote->recv_ctx->remote = remote;
    remote->send_ctx->remote = remote;

    remote->server = server;
#ifdef MODULE_LOCAL
    remote->addr = NULL;
    remote->recv_ctx->dlen = SOCKET_BUF_SIZE;
#endif

    return remote;
}

server_t *
new_server(int fd, listen_ctx_t *listener) {
    server_t *server = ss_calloc(1, sizeof(*server));

    server->fd = fd;
    server->recv_ctx = ss_calloc(1, sizeof(server_ctx_t));
    server->send_ctx = ss_calloc(1, sizeof(server_ctx_t));
    server->buf = new_buffer(SOCKET_BUF_SIZE);

    server->stage = STAGE_INIT;
    server->recv_ctx->server = server;
    server->send_ctx->server = server;
    server->listen_ctx = listener;

    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

#ifdef MODULE_REMOTE
    crypto_t *crypto = listener->crypto;

    server->crypto   = crypto;
    server->e_ctx    = ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx    = ss_malloc(sizeof(cipher_ctx_t));
    crypto->ctx_init(crypto->cipher, server->e_ctx, 1);
    crypto->ctx_init(crypto->cipher, server->d_ctx, 0);

    if (reuse_conn) {
        server->remotes = new_cache(-1, NULL/*remote_free_cb*/);
        server->send_ctx->remotes = new_cache(-1, NULL);
    }

    int request_timeout = min(MAX_REQUEST_TIMEOUT, listener->timeout)
                          + rand() % MAX_REQUEST_TIMEOUT,
        repeat_interval = max(MIN_TCP_IDLE_TIMEOUT, listener->timeout)
                          + rand() % listener->timeout;

    ev_timer_init(&server->recv_ctx->watcher, server_timeout_cb,
                  request_timeout, repeat_interval);

    if (verbose)
        server_conn++;
#endif

            cork_dllist_add(&connections, &server->entries);

    return server;
}

int
remote_connected(remote_t *remote) {
#ifdef TCP_FASTOPEN_WINSOCK
    if (fast_open) {
        // Check if ConnectEx is done
        if (!remote->connect_ex_done) {
            DWORD numBytes, flags;
            // Non-blocking way to fetch ConnectEx result
            if (WSAGetOverlappedResult(remote->fd, &remote->olap,
                                       &numBytes, FALSE, &flags)) {
                remote->buf->len -= numBytes;
                remote->buf->idx += numBytes;
                remote->connect_ex_done = 1;
            } else if (WSAGetLastError() == WSA_IO_INCOMPLETE) {
                // XXX: ConnectEx still not connected, wait for next time
                errno = EINPROGRESS;
                return false;
            } else {
                ERROR("WSAGetOverlappedResult");
                return false;
            }
        }

        // Make getpeername work
        if (setsockopt(remote->fd, SOL_SOCKET,
                       SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
            ERROR("setsockopt");
        }
    }
#endif
    int r = 0;

    if (!remote->addr) {
        struct sockaddr_storage addr;
        r = getpeername(remote->fd, (struct sockaddr *) &addr, &(socklen_t) {sizeof(addr)});
    }

    return r == 0 ? true : false;
}

void
close_and_free_remote(EV_P_ remote_t *remote) {
    if (remote != NULL) {
#ifdef MODULE_LOCAL
        if (reuse_conn) {
            if (remote->server &&
                remote->server->stage != STAGE_ERROR) {
                return;
            }
            cork_dllist_remove(&remote->entries);
        }
        ev_timer_stop(EV_A_ &remote->send_ctx->watcher);
#endif
        LOGE("close_and_free_remote");

        ev_io_stop(EV_A_ &remote->send_ctx->io);
        ev_io_stop(EV_A_ &remote->recv_ctx->io);

        close(remote->fd);

#ifdef MODULE_REMOTE
        if (verbose)
            remote_conn--;
#elif defined MODULE_LOCAL
        if (remote->e_ctx != NULL) {
            remote->crypto->ctx_release(remote->e_ctx);
            ss_free(remote->e_ctx);
        }
        if (remote->d_ctx != NULL) {
            remote->crypto->ctx_release(remote->d_ctx);
            ss_free(remote->d_ctx);
        }
#endif
        server_t *server = remote->server;
        if (server != NULL) {
#ifdef MODULE_REMOTE
            if (server->remotes)
                cache_remove(server->remotes,
                             &remote->cid, sizeof(remote->cid));
            if (server->send_ctx->remotes)
                uniqset_remove(server->send_ctx->remotes, remote);
#endif
            server->remote = NULL;
        }
#ifdef MODULE_LOCAL
        if (remote->servers != NULL) {
            struct cache_entry *element;
            cache_foreach(remote->servers, element) {
                server_t *server = element->value;
                server->remote = NULL;
            }
            ss_free(remote->servers);
        }
#endif
        if (remote->buf != NULL) {
            free_buffer(remote->buf);
        }
        ss_free(remote->recv_ctx);
        ss_free(remote->send_ctx);
        ss_free(remote);
    }
}

void
close_and_free_server(EV_P_ server_t *server) {
    if (server != NULL) {
#ifdef MODULE_REMOTE
        if (reuse_conn &&
            server->stage != STAGE_ERROR) {
            return;
        }
        if (verbose)
            LOGI("current server connection: %d", --server_conn);
        ev_timer_stop(EV_A_ & server->recv_ctx->watcher);
#endif
        ev_io_stop(EV_A_ &server->send_ctx->io);
        ev_io_stop(EV_A_ &server->recv_ctx->io);
        if (server->stage != STAGE_STOP)
            close(server->fd);
        LOGE("close_and_free_server");

#ifdef MODULE_REMOTE
        if (server->remotes) {
            struct cache_entry *element;
            LOGE("=====");
            cache_foreach(server->remotes, element) {
                LOGE("%d", *(uint8_t *)((remote_t *)element->key));
                close_and_free_remote(EV_A_
                    (remote_t *)element->value);
            }
            LOGE("=====");
            ss_free(server->remotes);
        }
        if (server->e_ctx != NULL) {
            server->crypto->ctx_release(server->e_ctx);
            ss_free(server->e_ctx);
        }
        if (server->d_ctx != NULL) {
            server->crypto->ctx_release(server->d_ctx);
            ss_free(server->d_ctx);
        }
        if (server->send_ctx &&
            server->send_ctx->remotes) {
            ss_free(server->send_ctx->remotes);
        }
#ifdef USE_NFCONNTRACK_TOS
        if (server->tracker) {
            struct dscptracker *tracker = server->tracker;
            if (tracker->ct)
                nfct_destroy(tracker->ct);
            ss_free(tracker);
        }
#endif
#endif
        cork_dllist_remove(&server->entries);

        if (server->remote != NULL) {
#ifdef MODULE_LOCAL
            if (reuse_conn) {
                cache_remove(server->remote->servers,
                             &server->fd, sizeof(uint8_t));
                uniqset_remove(server->remote->send_ctx->servers, server);
            }
#endif
            server->remote->server = NULL;
        }
        if (server->buf != NULL) {
            bfree(server->buf);
            ss_free(server->buf);
        }
        if (server->abuf != NULL) {
            bfree(server->abuf);
            ss_free(server->abuf);
        }
        ss_free(server->recv_ctx);
        ss_free(server->send_ctx);
        ss_free(server);
    }
}

#ifdef MODULE_LOCAL

void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents) {
    remote_ctx_t *remote_ctx
            = cork_container_of(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;

    if (verbose) {
        LOGI("TCP connection timed out");
    }

    server->stage = STAGE_TIMEOUT;
    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

int
sendto_remote(remote_t *remote, buffer_t *buf) {
    ssize_t s = sendto_idempotent(remote->fd,
                                  buf->data + buf->idx, buf->len,
                                  (struct sockaddr *) remote->addr
#ifdef TCP_FASTOPEN_WINSOCK
            , &remote->olap, &remote->connect_ex_done
#endif
    );

    if (remote->addr)
        remote->addr = NULL;

    if (s == -1 && errno != CONNECT_IN_PROGRESS) {
        if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
            errno == ENOPROTOOPT) {
            fast_open = 0;  // just turn it off
            LOGE("fast open not supported on this platform");
        }
    }

    return s;
}

int
init_remote(EV_P_ remote_t *remote, remote_cnf_t *conf) {
    server_t *server = remote->server;
    listen_ctx_t *listen_ctx = server->listen_ctx;
    struct sockaddr_storage *remote_addr = conf->addr;

    if (conf->crypto) {
        crypto_t *crypto =
                remote->crypto = conf->crypto;

        crypto->ctx_init(crypto->cipher,
                         remote->e_ctx = ss_malloc(sizeof(cipher_ctx_t)), 1);
        crypto->ctx_init(crypto->cipher,
                         remote->d_ctx = ss_malloc(sizeof(cipher_ctx_t)), 0);
    }

    int remotefd = socket(remote_addr->ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (remotefd == -1) {
        ERROR("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // Enable TCP keepalive
    setsockopt(remotefd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

    // Set non blocking
    setnonblocking(remotefd);

    if (listen_ctx->tos >= 0 &&
        setsockopt(remotefd, IPPROTO_IP, IP_TOS,
                   &listen_ctx->tos, sizeof(listen_ctx->tos)) != 0) {
        ERROR("setsockopt IP_TOS");
    }

    // Enable MPTCP
    if (listen_ctx->mptcp) {
        set_mptcp(remotefd);
    }

#ifdef __ANDROID__
    if (vpn
        && !is_addr_loopback((struct sockaddr *)remote_addr)
        && protect_socket(remotefd) == -1)
    {
        ERROR("protect_socket");
        close(remotefd);
        return -1;
    }
#endif

    if (!fast_open) {
        // connecting, wait until connected
        if (connect(remotefd, (struct sockaddr *) remote_addr,
                    sizeof(*remote_addr)) == -1 &&
            errno != CONNECT_IN_PROGRESS) {
            ERROR("connect");
            return -1;
        }
    } else {
        // save remote addr for fast open
        remote->addr = remote_addr;
    }

    remote->fd = remotefd;
    if (reuse_conn) {
        remote->servers = new_cache(-1, NULL);
        remote->send_ctx->servers = new_cache(-1, NULL);

        if (conf->remotes)
                    cork_dllist_add (conf->remotes, &remote->entries);
    }

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, remotefd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, remotefd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT, listen_ctx->timeout), 0);

    return 0;
}

remote_t *
create_remote(EV_P_ server_t *server, buffer_t *buf,
              ssocks_addr_t *destaddr, int acl_enabled) {
    if (buf != NULL && remote_dns && !destaddr->dname) {
        switch (port_service(
                elvis(destaddr->port,
                      sockaddr_port((struct sockaddr *) destaddr->addr)))) {
            case PORT_HTTP_SERVICE: {
                destaddr->dname_len =
                        http_hostname(buf->data + buf->idx, buf->len, &destaddr->dname);
            }
                break;
            case PORT_HTTPS_SERVICE: {
                destaddr->dname_len =
                        tls_hostname(buf->data + buf->idx, buf->len, &destaddr->dname);
            }
                break;
            default:
                break;
        }
    }

    if (destaddr->dname_len <= 0 ||
        destaddr->dname_len >= MAX_HOSTNAME_LEN) {
        if (verbose &&
            destaddr->dname_len == -1) {
            LOGE("partial http request detected");
        }
        destaddr->dname = NULL;
    }

    int direct = acl_enabled ?
                 search_acl(ACL_ATYP_SSOCKS, destaddr, ACL_UNSPCLIST) : 0;

    if (verbose) {
        LOGI("%s %s", direct ? "bypassing" : "connecting to",
             destaddr->dname ? hostname_readable(destaddr->dname, destaddr->dname_len, destaddr->port)
                             : sockaddr_readable("%a:%p", destaddr->addr));
    }

    remote_t *remote = NULL;
    remote_cnf_t *remote_cnf = NULL;
    listen_ctx_t *listener = server->listen_ctx;

    if (!direct)
        bailed:
        {
            int remote_idx = acl_enabled ?
                             search_acl(ACL_ATYP_SSOCKS, destaddr, ACL_DELEGATION) :
                             rand() % listener->remote_num;

            if (buf != NULL) {
                buffer_t *abuf = new_buffer(SSOCKS_HDR_SIZE);
                if (reuse_conn)
                    destaddr->id = server->fd;
                create_ssocks_header(abuf, destaddr);
                bprepend(buf, abuf, SOCKET_BUF_SIZE);
                free_buffer(abuf);
            }

            remote_cnf = listener->remotes[remote_idx];

            if (reuse_conn) {
                cork_dllist_pop(remote_cnf->remotes, remote, entries, false);
                //cork_dllist_poll(remote_cnf->remotes, remote, entries);
                if (remote) {
                    if (verbose)
                        LOGI("session successfully reused");
                    return remote;
                }
            }
        }
    else {
        if (destaddr->dname && !destaddr->addr &&
            (destaddr->addr = ss_calloc(1, sizeof(*destaddr->addr))) &&
            get_sockaddr_r(destaddr->dname, NULL,
                           destaddr->port, destaddr->addr, 1, ipv6first) == -1) {
            LOGE("failed to resolve %s", destaddr->dname);
            goto bailed;
        }
    }

    return init_remote(EV_A_
                       remote = new_remote(server),
                       elvis(remote_cnf, (&(remote_cnf_t) {
                               .addr  = destaddr->addr,
                               .iface = listener->iface,
                       }))) == 0 ? remote : NULL;
}

#elif defined MODULE_REMOTE
void
server_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    server_ctx_t *server_ctx
        = cork_container_of(watcher, server_ctx_t, watcher);

    server_t *server = server_ctx->server;
    remote_t *remote = server->remote;

    if (verbose) {
        LOGI("TCP connection timed out");
    }

    server->stage = STAGE_TIMEOUT;
    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

int
create_remote(EV_P_ remote_t *remote,
              struct sockaddr_storage *addr)
{
    server_t *server = remote->server;
    listen_ctx_t *listen_ctx = server->listen_ctx;

    // initialize remote socks
    int remotefd = socket(addr->ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (remotefd == -1) {
        ERROR("socket");
        close(remotefd);
        return -1;
    }

    int opt = 1;
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    setsockopt(remotefd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (setnonblocking(remotefd) == -1)
        ERROR("setnonblocking");

    if (listen_ctx->addr) {
        if (bind(remotefd, (struct sockaddr *)listen_ctx->addr,
                 sizeof(*listen_ctx->addr)) != 0)
        {
            ERROR("bind");
            close(remotefd);
            return -1;
        }
    }

#ifdef SET_INTERFACE
    if (listen_ctx->iface) {
        if (setinterface(remotefd, listen_ctx->iface) == -1) {
            ERROR("setinterface");
            close(remotefd);
            return -1;
        }
    }
#endif

    remote->fd = remotefd;

    if (fast_open) {
        ssize_t s = sendto_idempotent(remote->fd,
                                      remote->buf->data + remote->buf->idx,
                                      remote->buf->len, (struct sockaddr *)remote->addr
#ifdef TCP_FASTOPEN_WINSOCK
                                      , &remote->olap, &remote->connect_ex_done
#endif
        );

        if (s == -1) {
            if (errno == CONNECT_IN_PROGRESS) {
                // The remote server doesn't support tfo or it's the first connection to the server.
                // It will automatically fall back to conventional TCP.
            } else if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                       errno == ENOPROTOOPT) {
                // Disable fast open as it's not supported
                fast_open = 0;
                LOGE("fast open is not supported on this platform");
            } else {
                ERROR("fast_open_connect");
            }
        } else {
            server->buf->len -= s;
            server->buf->idx += s;
        }
    } else {
        int r = connect(remotefd, (struct sockaddr *)addr,
                        sockaddr_len((struct sockaddr *)addr));

        if (r == -1 && errno != CONNECT_IN_PROGRESS) {
            ERROR("connect");
            return -1;
        }
    }

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, remotefd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, remotefd, EV_WRITE);

    return remotefd;
}

#ifndef __MINGW32__
static void
stat_update_cb(EV_P_ ev_timer *watcher, int revents)
{
    listen_ctx_t *listen_ctx
        = cork_container_of(watcher, listen_ctx_t, stat_watcher);
    struct sockaddr_storage addr;

    if (getsockname(listen_ctx->fd,
                    (struct sockaddr *)&addr, NULL) != 0) {
        return;
    }

    struct sockaddr_un svaddr, claddr;
    int sfd = -1;
    size_t msgLen;
    char resp[SOCKET_BUF_SIZE];

    if (verbose) {
        LOGI("update traffic stat: tx: %" PRIu64 " rx: %" PRIu64 "", tx, rx);
    }

    snprintf(resp, SOCKET_BUF_SIZE, "stat: {\"%s\":%" PRIu64 "}", sockaddr_readable("%p", &addr), tx + rx);
    msgLen = strlen(resp) + 1;

    ss_addr_t ip_addr = { .host = NULL, .port = NULL };
    parse_addr(manager_addr, &ip_addr);

    if (ip_addr.host == NULL || ip_addr.port == NULL) {
        sfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (sfd == -1) {
            ERROR("stat_socket");
            return;
        }

        memset(&claddr, 0, sizeof(struct sockaddr_un));
        claddr.sun_family = AF_UNIX;
        snprintf(claddr.sun_path, sizeof(claddr.sun_path), "/tmp/shadowsocks.%s", sockaddr_readable("%p", &addr));

        unlink(claddr.sun_path);

        if (bind(sfd, (struct sockaddr *)&claddr, sizeof(struct sockaddr_un)) == -1) {
            ERROR("stat_bind");
            close(sfd);
            return;
        }

        memset(&svaddr, 0, sizeof(struct sockaddr_un));
        svaddr.sun_family = AF_UNIX;
        strncpy(svaddr.sun_path, manager_addr, sizeof(svaddr.sun_path) - 1);

        if (sendto(sfd, resp, strlen(resp) + 1, 0, (struct sockaddr *)&svaddr,
                   sizeof(struct sockaddr_un)) != msgLen) {
            ERROR("stat_sendto");
            close(sfd);
            return;
        }

        unlink(claddr.sun_path);
    } else {
        struct sockaddr_storage storage = {};
        if (get_sockaddr(ip_addr.host, ip_addr.port, &storage, 1, ipv6first) == -1) {
            ERROR("failed to parse the manager addr");
            return;
        }

        sfd = socket(storage.ss_family, SOCK_DGRAM, 0);

        if (sfd == -1) {
            ERROR("stat_socket");
            return;
        }

        if (sendto(sfd, resp, strlen(resp) + 1, 0, (struct sockaddr *)&storage,
                   sockaddr_len((struct sockaddr *)&storage)) != msgLen) {
            ERROR("stat_sendto");
            close(sfd);
            return;
        }
    }

    close(sfd);
}

#endif

static void
free_listeners()
{
    listen_ctx_t *listener = NULL;
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach(&listeners, curr, next,
                        listen_ctx_t, listener, entries) {
        if (listener != NULL) {
#ifndef __MINGW32__
            if (manager_addr != NULL)
                ev_timer_stop(EV_A_ & stat_watcher);
#endif
            ev_io_stop(EV_A_ & listener->io);
            close(listener->fd);
        }
    }
}

#ifdef USE_NFCONNTRACK_TOS
int
setMarkDscpCallback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
    server_t *server            = (server_t *)data;
    struct dscptracker *tracker = server->tracker;

    tracker->mark = nfct_get_attr_u32(ct, ATTR_MARK);
    if ((tracker->mark & 0xff00) == MARK_MASK_PREFIX) {
        // Extract DSCP value from mark value
        tracker->dscp = tracker->mark & 0x00ff;
        int tos = (tracker->dscp) << 2;
        if (setsockopt(server->fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) != 0) {
            ERROR("iptable setsockopt IP_TOS");
        }
    }
    return NFCT_CB_CONTINUE;
}

void
conntrackQuery(server_t *server)
{
    struct dscptracker *tracker = server->tracker;
    if (tracker && tracker->ct) {
        // Trying query mark from nf conntrack
        struct nfct_handle *h = nfct_open(CONNTRACK, 0);
        if (h) {
            nfct_callback_register(h, NFCT_T_ALL, setMarkDscpCallback, (void *)server);
            int x = nfct_query(h, NFCT_Q_GET, tracker->ct);
            if (x == -1) {
                LOGE("QOS: Failed to retrieve connection mark %s", strerror(errno));
            }
            nfct_close(h);
        } else {
            LOGE("QOS: Failed to open conntrack handle for upstream netfilter mark retrieval.");
        }
    }
}

void
setTosFromConnmark(remote_t *remote, server_t *server)
{
    if (server->tracker && server->tracker->ct) {
        if (server->tracker->mark == 0 && server->tracker->packet_count < MARK_MAX_PACKET) {
            server->tracker->packet_count++;
            conntrackQuery(server);
        }
    } else {
        struct sockaddr_storage sin;
        if (getsockname(remote->fd, (struct sockaddr *)&sin, &(socklen_t) { sizeof(sin) }) == 0) {
            struct sockaddr_storage from_addr;
            if (getpeername(remote->fd, (struct sockaddr *)&from_addr, &(socklen_t) { sizeof(from_addr) }) == 0) {
                if ((server->tracker = (struct dscptracker *)ss_malloc(sizeof(struct dscptracker)))) {
                    if ((server->tracker->ct = nfct_new())) {
                        // Build conntrack query SELECT
                        if (from_addr.ss_family == AF_INET) {
                            struct sockaddr_in *src = (struct sockaddr_in *)&from_addr;
                            struct sockaddr_in *dst = (struct sockaddr_in *)&sin;

                            nfct_set_attr_u8(server->tracker->ct, ATTR_L3PROTO, AF_INET);
                            nfct_set_attr_u32(server->tracker->ct, ATTR_IPV4_DST, dst->sin_addr.s_addr);
                            nfct_set_attr_u32(server->tracker->ct, ATTR_IPV4_SRC, src->sin_addr.s_addr);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_DST, dst->sin_port);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_SRC, src->sin_port);
                        } else if (from_addr.ss_family == AF_INET6) {
                            struct sockaddr_in6 *src = (struct sockaddr_in6 *)&from_addr;
                            struct sockaddr_in6 *dst = (struct sockaddr_in6 *)&sin;

                            nfct_set_attr_u8(server->tracker->ct, ATTR_L3PROTO, AF_INET6);
                            nfct_set_attr(server->tracker->ct, ATTR_IPV6_DST, dst->sin6_addr.s6_addr);
                            nfct_set_attr(server->tracker->ct, ATTR_IPV6_SRC, src->sin6_addr.s6_addr);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_DST, dst->sin6_port);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_SRC, src->sin6_port);
                        }
                        nfct_set_attr_u8(server->tracker->ct, ATTR_L4PROTO, IPPROTO_TCP);
                        conntrackQuery(server);
                    } else {
                        LOGE("Failed to allocate new conntrack for upstream netfilter mark retrieval.");
                        server->tracker->ct = NULL;
                    }
                }
            }
        }
    }
}

#endif
#endif

void
free_connections() {
    server_t *server = NULL;
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach(&connections, curr, next,
                        server_t, server, entries) {
        if (server != NULL) {
            server->stage = STAGE_TIMEOUT;
            close_and_free_remote(EV_A_ server->remote);
            close_and_free_server(EV_A_ server);
        }
    }
}

static void
signal_cb(EV_P_ ev_signal *w, int revents) {
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
#ifndef __MINGW32__
            case SIGCHLD:
                if (!is_plugin_running()) {
                    LOGE("plugin service exit unexpectedly");
                    ret_val = -1;
                } else
                    return;
#endif
            case SIGINT:
            case SIGTERM:
                ev_signal_stop(EV_A_ &sigint_watcher);
                ev_signal_stop(EV_A_ &sigterm_watcher);
#ifndef __MINGW32__
                ev_signal_stop(EV_A_ &sigchld_watcher);
#endif
                ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

int
start_relay(jconf_t *conf,
            ss_callback_t callback, void *data) {
    int plugin_enabled = 0;

    if (conf->remote_num <= 0) {
        LOGE("at least one server should be specified");
        return -1;
    }

    if (conf->log) {
        USE_LOGFILE(conf->log);
        LOGI("enabled %slogging %s", conf->verbose ? "verbose " : "", conf->log);
    }

    if (conf->mtu > 0) {
        LOGI("setting MTU to %d", conf->mtu);
    }

    if (conf->mptcp) {
        LOGI("enabled multipath TCP");
    }

    if (conf->no_delay) {
        LOGI("enabled TCP no-delay");
    }

    if (conf->ipv6_first) {
        LOGI("prioritized IPv6 addresses in domain resolution");
    }

#ifndef MODULE_TUNNEL
    if (conf->acl != NULL) {
        LOGI("initializing acl...");
        if (!(acl = !init_acl(conf))) LOGE("failed to enable acl");
    }
#endif

#ifdef HAVE_SETRLIMIT
    /*
     * No need to check the return value here.
     * We will show users an error message if setrlimit(2) fails.
     */
    if (conf->nofile > 1024) {
        if (conf->verbose) {
            LOGI("setting NOFILE to %d", conf->nofile);
        }
        set_nofile(conf->nofile);
    }
#endif

    if (conf->fast_open) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        conf->fast_open = 0;
#endif
    }

    if (conf->reuse_conn) {
        LOGI("enabled connection reuse");
    }

#ifdef __MINGW32__
    winsock_init();
#endif

#ifndef __MINGW32__
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    // Setup proxy context
    loop = EV_DEFAULT;

    // Setup signal handler
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_A_ &sigint_watcher);
    ev_signal_start(EV_A_ &sigterm_watcher);
#ifndef __MINGW32__
    ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
    ev_signal_start(EV_A_ &sigchld_watcher);
#endif

#ifdef MODULE_LOCAL

#ifndef HAVE_LAUNCHD
    if (conf->local_port == NULL) {
        conf->local_port = "0";
        LOGE("warning: random local port will be assigned");
    }
#endif

#ifndef MODULE_TUNNEL
    remote_dns = conf->remote_dns;
    if (!conf->remote_dns) {
        LOGI("disabled remote domain resolution");
    }
#endif

    listen_ctx_t *listen_ctx = ss_new(
            listen_ctx_t, {
        .mtu = conf->mtu,
        .mptcp = conf->mptcp,
        .reuse_port = conf->reuse_port,
        .remote_num = conf->remote_num,
        .remotes = ss_calloc(conf->remote_num, sizeof(remote_cnf_t *)),
        .timeout = atoi(conf->timeout),
    });

#ifdef MODULE_TUNNEL
    ss_addr_t *tunnel_addr = &conf->tunnel_addr;
    if (tunnel_addr->host == NULL ||
        tunnel_addr->port == NULL) {
        FATAL("tunnel address either undefined or invalid");
    }

    ssocks_addr_t *destaddr = &listen_ctx->destaddr;
    destaddr->addr = ss_calloc(1, sizeof(struct sockaddr_storage));
    if (get_sockaddr(tunnel_addr->host, tunnel_addr->port,
                     destaddr->addr, !conf->remote_dns, conf->ipv6_first) == -1)
    {
        destaddr->dname = tunnel_addr->host;
        destaddr->dname_len = strlen(tunnel_addr->host);
        destaddr->port  = htons(atoi(tunnel_addr->port));
    }
#endif
    port_service_init();

    for (int i = 0; i < conf->remote_num; i++) {
        ss_remote_t *r = conf->remotes[i];

        char *host = r->addr,
                *port = elvis(r->port, conf->remote_port),
                *password = elvis(r->password, conf->password),
                *key = elvis(r->key, conf->key),
                *method = elvis(r->method, conf->method),
                *iface = elvis(r->iface, conf->iface),
                *plugin = elvis(r->plugin, conf->plugin),
                *plugin_opts
                = elvis(r->plugin_opts, conf->plugin_opts);

        if (host == NULL || port == NULL ||
            (password == NULL && key == NULL)) {
            usage();
            exit(EXIT_FAILURE);
        }

        LOGI("[%d/%d] server %s %s:%s",
             i + 1, conf->remote_num, elvis(r->tag, "-"), host, port);

        LOGI("initializing ciphers... %s", method);
        crypto_t *crypto = crypto_init(password, key, method);
        if (crypto == NULL) FATAL("failed to initialize ciphers");

        struct sockaddr_storage *storage
                = ss_calloc(1, sizeof(struct sockaddr_storage));
        if (get_sockaddr(host, port, storage, 1, conf->ipv6_first) == -1) {
            FATAL("failed to resolve %s", host);
        }

        if (plugin != NULL) {
            if (!plugin_enabled) {
                init_plugin(MODE_CLIENT);
                plugin_enabled = 1;
            }

            uint16_t plugin_port = get_local_port();
            switch (storage->ss_family) {
                case AF_INET: {
                    *(struct sockaddr_in *) storage = (struct sockaddr_in) {
                            .sin_addr =
                            (struct in_addr){ htonl(INADDR_LOOPBACK) },
                            .sin_port = plugin_port
                    };
                }
                    break;
                case AF_INET6: {
                    *(struct sockaddr_in6 *) storage = (struct sockaddr_in6) {
                            .sin6_addr = in6addr_loopback,
                            .sin6_port = plugin_port
                    };
                }
                    break;
            }

            if (plugin_port == 0) FATAL("failed to find a free port");

            LOGI("plugin \"%s\" enabled", plugin);

            int err = start_plugin(plugin, plugin_opts,                 // user-defined plugin options
                                   host, port,                          // user-defined destination address
                                   sockaddr_readable("%a", storage),
                                   sockaddr_readable("%p", storage));
            if (err) FATAL("failed to start plugin %s", plugin);
        }

        listen_ctx->remotes[i] = ss_new(
                remote_cnf_t, {
            .iface = iface,
            .addr = storage,
            .crypto = crypto
        });

        if (conf->reuse_conn) {
            remote_cnf_t *remote_cnf = listen_ctx->remotes[i];
            struct cork_dllist *remotes =
                    remote_cnf->remotes = ss_calloc(1, sizeof(*remotes));
            cork_dllist_init(remotes);
        }
    }

    ss_dscp_t **dscp = conf->dscp;
    char *local_addr = conf->local_addr,
            *local_port = conf->local_port;

    listen_ctx_t *listen_ctx_current = memdup(listen_ctx, sizeof(*listen_ctx));
    do {
        struct sockaddr_storage *storage = &(struct sockaddr_storage) {};
        if (get_sockaddr(local_addr, local_port,
                         storage, 1, conf->ipv6_first) == -1) {
            FATAL("failed to resolve %s", local_addr);
        }

        if (listen_ctx_current->tos) {
            LOGI("listening on %s (TOS 0x%x)",
                 sockaddr_readable("%a:%p", storage), listen_ctx_current->tos);
        } else {
            LOGI("listening on %s",
                 sockaddr_readable("%a:%p", storage));
        }

        int socket = -1, socket_u = -1;
        if (conf->mode != UDP_ONLY) {
            // Setup socket
            socket =
#ifdef HAVE_LAUNCHD
                    launch_or_create(storage, listen_ctx_current);
#else
                    bind_and_listen(storage, IPPROTO_TCP, listen_ctx_current);
#endif
            if (socket != -1) {
                if (conf->fast_open)
                    set_fastopen_passive(socket);
                ev_io_init(&listen_ctx_current->io, accept_cb, listen_ctx_current->fd, EV_READ);
                ev_io_start(EV_A_ &listen_ctx_current->io);
            }
        }

        if (conf->mode != TCP_ONLY) {
            listen_ctx_t *listen_ctx_dgram =
                    memdup(listen_ctx_current, sizeof(*listen_ctx_current));
            int socket_u = bind_and_listen(storage, IPPROTO_UDP, listen_ctx_dgram);
            if ((listen_ctx_dgram->fd = socket_u) != -1) {
                init_udprelay(EV_A_ listen_ctx_dgram);
            }
        }

        if (callback != NULL) {
            callback(socket, socket_u, data);
        }

        if (conf->mode == UDP_ONLY) {
            LOGI("disabled TCP relay");
        }

        // Handle additional TOS/DSCP listening ports
        if (*dscp != NULL) {
            listen_ctx_current = memdup(listen_ctx, sizeof(*listen_ctx));
            local_port = (*dscp)->port;
            listen_ctx_current->tos = (*dscp)->dscp << 2;
        }
    } while (*(dscp++) != NULL);

#elif MODULE_REMOTE
    if (conf->nameserver != NULL)
        LOGI("using nameserver: %s", conf->nameserver);
    resolv_init(EV_A_ conf->nameserver, conf->ipv6_first);

    struct sockaddr_storage *laddr = NULL;
    if (conf->local_addr != NULL) {
        laddr = ss_calloc(1, sizeof(*laddr));
        if (get_sockaddr(conf->local_addr, conf->local_port,
                         laddr, 1, conf->ipv6_first) == -1)
        {
            FATAL("failed to resolve %s", conf->local_addr);
        }
    }

    port_service_init();
    cork_dllist_init(&listeners);

    for (int i = 0; i < conf->remote_num; i++) {
        ss_remote_t *r = conf->remotes[i];
        char *host     = r->addr,
             *port     = elvis(r->port, conf->remote_port),
             *password = elvis(r->password, conf->password),
             *key      = elvis(r->key, conf->key),
             *method   = elvis(r->method, conf->method),
             *iface    = elvis(r->iface, conf->iface),
             *plugin   = elvis(r->plugin, conf->plugin),
             *plugin_opts
                       = elvis(r->plugin_opts, conf->plugin_opts);

        if (port == NULL || method == NULL ||
            (password == NULL && key == NULL))
        {
            usage();
            exit(EXIT_FAILURE);
        }

        LOGI("[%d/%d] listening on %s:%s", i + 1, conf->remote_num, host, port);

        LOGI("initializing ciphers... %s", method);
        crypto_t *crypto = crypto_init(password, key, method);
        if (crypto == NULL)
            FATAL("failed to initialize ciphers");

        /**
         * "If node(host) is NULL, then the network address
         * will be set to the loopback interface address," meaning that
         * by default the server will bind to `lo' instead of 0.0.0.0.
         *
         * On Linux, when net.ipv6.bindv6only = 0 (the default),
         * getaddrinfo(NULL) with AI_PASSIVE returns 0.0.0.0 and :: (in this order).
         * AI_PASSIVE was meant to return a list of addresses to listen on,
         * but it is impossible to listen on 0.0.0.0 and :: at the same time,
         * unless `bindv6only' is enabled.
         */
        struct sockaddr_storage *storage
                = &(struct sockaddr_storage) {};
        if (get_sockaddr(host, port, storage, 1, conf->ipv6_first) == -1) {
            FATAL("failed to resolve %s", host);
        }

        if (plugin != NULL) {
            if (!plugin_enabled) {
                init_plugin(MODE_SERVER);
                plugin_enabled = 1;
            }

            uint16_t plugin_port = get_local_port();
            switch (storage->ss_family) {
                case AF_INET: {
                    *(struct sockaddr_in *)storage = (struct sockaddr_in) {
                        .sin_addr =
                            (struct in_addr) { htonl(INADDR_LOOPBACK) },
                        .sin_port = plugin_port
                    };
                } break;
                case AF_INET6: {
                    *(struct sockaddr_in6 *)storage = (struct sockaddr_in6) {
                        .sin6_addr = in6addr_loopback,
                        .sin6_port = plugin_port
                    };
                } break;
            }

            if (plugin_port == 0)
                FATAL("failed to find a free port");

            LOGI("plugin \"%s\" enabled", plugin);

            int err = start_plugin(plugin, plugin_opts,                 // user-defined plugin options
                                   sockaddr_readable("%a", storage),
                                   sockaddr_readable("%p", storage),    // plugin destination override
                                   host, port);
            if (err)
                FATAL("failed to start the plugin");
        }

        listen_ctx_t *listen_ctx = ss_new(
            listen_ctx_t, {
            .iface   = iface,
            .addr    = laddr,
            .crypto  = crypto,
            .timeout = atoi(conf->timeout)
        });

#ifndef __MINGW32__
        manager_addr = conf->manager_addr;
        if (conf->manager_addr != NULL) {
            ev_timer_init(&listen_ctx->stat_watcher, stat_update_cb,
                          UPDATE_INTERVAL, UPDATE_INTERVAL);
            ev_timer_start(EV_A_ & listen_ctx->stat_watcher);
        }
#endif

        int socket = -1, socket_u = -1;
        if (conf->mode != UDP_ONLY) {
            int socket = bind_and_listen(storage, IPPROTO_TCP, listen_ctx);
            if (socket != -1) {
                if (conf->fast_open)
                    set_fastopen_passive(socket);
                ev_io_init(&listen_ctx->io, accept_cb, listen_ctx->fd, EV_READ);
                ev_io_start(EV_A_ & listen_ctx->io);
                cork_dllist_add(&listeners, &listen_ctx->entries);
            }
        }

        if (conf->mode != TCP_ONLY) {
            listen_ctx_t *listen_ctx_dgram = memdup(listen_ctx, sizeof(*listen_ctx));
            int socket_u = bind_and_listen(storage, IPPROTO_UDP, listen_ctx_dgram);
            if ((listen_ctx_dgram->fd = socket_u) != -1) {
                init_udprelay(EV_A_ listen_ctx_dgram);
            }
        }

        if (callback != NULL) {
            callback(socket, socket_u, data);
        }
    }
#endif

    no_delay = conf->no_delay;
    fast_open = conf->fast_open;
    verbose = conf->verbose;
    ipv6first = conf->ipv6_first;
    reuse_conn = conf->reuse_conn;

    // init connections
    cork_dllist_init(&connections);

    // start ev loop
    ev_run(EV_A_ 0);

    if (conf->verbose) {
        LOGI("closed gracefully");
    }

#ifdef MODULE_LOCAL
    if (conf->mode != UDP_ONLY) {
        ev_io_stop(EV_A_ &listen_ctx->io);
        free_connections();
    }

    if (listen_ctx->remotes != NULL) {
        for (int i = 0; i < listen_ctx->remote_num; i++) {
            remote_cnf_t *remote_cnf = listen_ctx->remotes[i];
            if (remote_cnf != NULL) {
                if (remote_cnf->iface) ss_free(remote_cnf->iface);
                // TODO: hey yo! free() the whole struct, pls
                if (remote_cnf->crypto) ss_free(remote_cnf->crypto);
                if (remote_cnf->addr) ss_free(remote_cnf->addr);
                if (remote_cnf->remotes) {
                    remote_t *remote;
                    cork_dllist_each(remote_cnf->remotes, remote, entries)close_and_free_remote(EV_A_ remote);
                    ss_free(remote_cnf->remotes);
                }
                ss_free(remote_cnf);
            }
        }
        ss_free(listen_ctx->remotes);
    }

#elif MODULE_REMOTE
#ifndef __MINGW32__
    if (conf->manager_addr) {
        ev_timer_stop(EV_A_ & stat_watcher);
    }
#endif
    resolv_shutdown(loop);
    if (conf->mode != UDP_ONLY) {
        free_listeners();
        free_connections();
    }
#endif

    if (conf->mode != TCP_ONLY) {
        free_udprelay();
    }

    if (plugin_enabled)
        stop_plugin();

    if (conf->log)
        CLOSE_LOGFILE();

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    return ret_val;
}
