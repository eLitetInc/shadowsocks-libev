/*
 * server.c - Provide shadowsocks service
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#ifndef __MINGW32__
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/un.h>
#endif
#include <libcork/core.h>

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "netutils.h"
#include "utils.h"
#include "acl.h"
#include "plugin.h"
#include "winsock.h"
#include "tcprelay.h"
#include "relay.h"

uint64_t tx = 0, rx = 0;

static void
report_addr(EV_P_ server_t *server, const char *info)
{
    if (verbose) {
        struct sockaddr_storage addr = {};
        if (getpeername(server->fd, (struct sockaddr *)&addr, &(socklen_t) { sizeof(addr) }) == 0) {
            LOGE("failed to handshake with %s: %s", sockaddr_readable("%a", &addr), info);
        }
    }

    server->stage = STAGE_STOP;
    close_and_free_server(EV_A_ server);
}

static void
resolv_cb(struct sockaddr *addr, void *data)
{
    server_t *server = (server_t *)data;
    if (server == NULL)
        return;

    remote_t *remote     = server->remote;
    struct ev_loop *loop = server->listen_ctx->loop;

    if (remote == NULL) {
        close_and_free_server(EV_A_ server);
        return;
    }

    if (addr == NULL) {
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
    } else {
        int r = create_remote(EV_A_ remote,
                    (struct sockaddr_storage *)addr);

        if (r == -1) {
            server->stage = STAGE_ERROR;
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
        } else {
            // listen to remote connected event
            if (server->stage == STAGE_MULTIPLEX &&
                cache_insert(server->remotes,
                    &remote->cid, sizeof(remote->cid), remote)) {
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
    }
}

void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server = server_recv_ctx->server;
    crypto_t *crypto = server->crypto;
    remote_t *remote = elvis(server->remote, new_remote(server));

    buffer_t *buf = server->buf;
    ssize_t r = recv(server->fd, buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        if (server->stage != STAGE_MULTIPLEX) {
            // connection closed
            if (verbose) {
                LOGI("server_recv closing the connection");
            }

            server->stage = STAGE_TIMEOUT;
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
        }        
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("server recv");
            server->stage = STAGE_ERROR;
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    tx += r;
    buf->len = r;

    int err = crypto->decrypt(buf, server->d_ctx, SOCKET_BUF_SIZE);

    switch (err) {
        case CRYPTO_ERROR:
            report_addr(EV_A_ server, "authentication error");
            return;
        case CRYPTO_NEED_MORE: {
            if (server->stage != STAGE_STREAM &&
                server->frag > MAX_FRAG)
            {
                report_addr(EV_A_ server, "malicious fragmentation");
                return;
            }
            server->frag++;
        } return;
    }

    // handshake and transmit data
    switch (server->stage) {
        case STAGE_MULTIPLEX:
        case STAGE_INIT: {
            ssocks_addr_t destaddr = {};
            int offset = parse_ssocks_header(buf, &destaddr, 0);

            if (offset < 0 || buf->len < offset) {
            LOGE("len %d idx %d", (int)server->buf->len, (int)server->buf->idx);
            LOGE("atyp %d id %d", (uint8_t)server->buf->data[0], (uint8_t)server->buf->data[1]);

                report_addr(EV_A_ server, "invalid request");
                return;
            }

            if (reuse_conn) {
                if (destaddr.id &&
                    server->stage != STAGE_MULTIPLEX)
                {
                    server->stage = STAGE_MULTIPLEX;
                }
            } else {
                if (destaddr.id) {
                    LOGE("connection multiplexing not enabled");
                    close_and_free_server(EV_A_ server);
                    return;
                }
                server->remote = remote;
            }

            buf->len -= offset;
            buf->idx += offset;

            if (destaddr.dname) {
                null_terminate(destaddr.dname, destaddr.dname_len);

                if (acl && search_acl(ACL_ATYP_DOMAIN,
                        &(dname_t){ destaddr.dname_len, destaddr.dname }, ACL_BLOCKLIST)) {
                    if (verbose)
                        LOGI("blocking access to %s", destaddr.dname);
                    close_and_free_server(EV_A_ server);
                    return;
                }
                if (verbose) {
                    LOGI("connecting to %s:%d", destaddr.dname, ntohs(destaddr.port));
                }

                if (server->stage == STAGE_MULTIPLEX) {
                    remote->cid = destaddr.id;
                } else {
                    server->stage = STAGE_RESOLVE;
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                }

                resolv_start(destaddr.dname, destaddr.port, resolv_cb, NULL, server);
            } else if (destaddr.addr) {
                if (acl && search_acl(ACL_ATYP_IP, destaddr.addr, ACL_BLOCKLIST)) {
                    if (verbose)
                        LOGI("blocking access to %s",
                             sockaddr_readable("%a:%p", destaddr.addr));
                    close_and_free_server(EV_A_ server);
                    return;
                }
                if (verbose) {
                    LOGI("connecting to %s",
                         sockaddr_readable("%a:%p", destaddr.addr));
                }

                if (server->stage == STAGE_MULTIPLEX) {
                    remote->cid = destaddr.id;
                } else {
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                }

                resolv_cb((struct sockaddr *)destaddr.addr, server);
            } else {
                if (server->stage == STAGE_MULTIPLEX && destaddr.id) {
                    if (cache_lookup(server->remotes,
                            &destaddr.id, sizeof(destaddr.id), &remote)) {
                        close_and_free_remote(EV_A_ remote);
                        close_and_free_server(EV_A_ server);
                        return;
                    }
                    goto TAG_STAGE_STREAM;
                }
            }
        } return;
        case STAGE_STREAM:
        TAG_STAGE_STREAM:
        {
            ev_timer_again(EV_A_ & server->recv_ctx->watcher);

            int s = send(remote->fd, buf->data, buf->len, 0);
            if (s == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // no data, wait for send
                    buf->idx = 0;
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                } else {
                    ERROR("server_recv_send");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                }
            } else if (s < buf->len) {
                buf->len -= s;
                buf->idx += s;
                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
            }
        } return;
    }
    // should not reach here
    FATAL("server context error");
}

void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;

    struct cache_entry *lremote = NULL;
    if (server->stage == STAGE_MULTIPLEX) {
        lremote = cache_head(server_send_ctx->remotes);
        if (!lremote) {
            ev_io_stop(EV_A_ & server_send_ctx->io);
            return;
        }
        remote = *(remote_t **)lremote->key;
    }

    if (remote == NULL) {
        LOGE("invalid server");
        close_and_free_server(EV_A_ server);
        return;
    }

    if (remote->buf->len == 0) {
        // close and free
        if (verbose) {
            LOGI("server_send closing the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
    } else {
        // has data to send
        ssize_t s = send(server->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);

        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_send");
                server->stage = STAGE_ERROR;
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }         
        } else if (s < remote->buf->len) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            if (server->stage == STAGE_MULTIPLEX) {
                bprepend(remote->buf, remote->abuf, SOCKET_BUF_SIZE);
            }
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;

            if (server->stage == STAGE_MULTIPLEX) {
                if (cache_remove_r(server_send_ctx->remotes, lremote))
                {
                    LOGE("failed to remove session");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                }
            } else
                ev_io_stop(EV_A_ & server_send_ctx->io);

            if (remote != NULL) {
                ev_io_start(EV_A_ & remote->recv_ctx->io);
            } else {
                LOGE("invalid remote");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
        }
    }
}

void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;
    crypto_t *crypto              = server->crypto;

    if (server == NULL) {
        LOGE("invalid server");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    ev_timer_again(EV_A_ & server->recv_ctx->watcher);

    if (server->stage == STAGE_MULTIPLEX) {
        if (remote->cid && !remote->abuf) {
            buffer_t *abuf = remote->abuf
                           = new_buffer(sizeof(uint8_t));

            abuf->data[abuf->len++] =
            remote->buf->data[remote->buf->len++] = remote->cid;

            int err = crypto->encrypt(abuf, server->e_ctx, abuf->capacity);

            if (err) {
                LOGE("invalid password or cipher");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }

    ssize_t r = recv(remote->fd, remote->buf->data + remote->buf->len,
                     SOCKET_BUF_SIZE - remote->buf->len, 0);

    if (r == 0) {
        // connection closed
        if (verbose) {
            LOGI("remote_recv closing the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    rx += r;

    remote->buf->len += r;
    int err = crypto->encrypt(remote->buf, server->e_ctx, SOCKET_BUF_SIZE);

    if (err) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

#ifdef USE_NFCONNTRACK_TOS
    setTosFromConnmark(remote, server);
#endif
    int s = send(server->fd, remote->buf->data, remote->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            if (server->stage == STAGE_MULTIPLEX)
                uniqset_add(server->send_ctx->remotes, remote);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("remote_recv_send");
            server->stage = STAGE_ERROR;
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < remote->buf->len) {
        remote->buf->len -= s;
        remote->buf->idx += s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        if (server->stage == STAGE_MULTIPLEX)
            uniqset_add(server->send_ctx->remotes, remote);
        ev_io_start(EV_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected && !no_delay) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;

    if (server == NULL) {
        LOGE("invalid server");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    if (!remote_send_ctx->connected) {
        if (remote_connected(remote)) {
            remote_send_ctx->connected = 1;

            if (server->buf->len == 0) {
                server->stage = STAGE_STREAM;
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                ev_io_start(EV_A_ & server->recv_ctx->io);
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            }
        } else {
            ERROR("getpeername");
            // not connected
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (server->buf->len == 0) {
        // close and free
        if (verbose) {
            LOGI("remote_send closing the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
        } else if (s < server->buf->len) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            if (server != NULL) {
                ev_io_start(EV_A_ & server->recv_ctx->io);
                if (server->stage != STAGE_STREAM &&
                    server->stage != STAGE_MULTIPLEX) {
                    server->stage = STAGE_STREAM;
                    ev_io_start(EV_A_ & remote->recv_ctx->io);
                }
            } else {
                LOGE("invalid server");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
        }
    }
}

void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    int serverfd           = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }

    if (acl) {
        struct sockaddr_storage addr;
        int r = getpeername(serverfd, (struct sockaddr *)&addr, &(socklen_t) { sizeof(addr) });
        if (r == 0) {
            if (search_acl(ACL_ATYP_IP, &addr, ACL_UNSPCLIST))
            {
                if (verbose)
                    LOGE("blocking all requests from %s",
                         sockaddr_readable("%a", &addr));
                return;
            }
        }
    }

    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    setnonblocking(serverfd);

    if (verbose) {
        LOGI("accepted a connection");
    }

    server_t *server = new_server(serverfd, listener);

    ev_io_start(EV_A_ & server->recv_ctx->io);
    ev_timer_start(EV_A_ & server->recv_ctx->watcher);
}

int
main(int argc, char **argv)
{
    USE_TTY();
    srand(time(NULL));

    int pid_flags = 0;
    jconf_t conf  = jconf_default;

    if (parse_argopts(&conf, argc, argv) != 0) {
        usage();
        exit(EXIT_FAILURE);
    }

    pid_flags = conf.pid_path != NULL;
    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(conf.pid_path);
    }

#ifndef __MINGW32__
    // setuid
    if (conf.user && !run_as(conf.user)) {
        FATAL("failed to switch user");
    }

    if (geteuid() == 0) {
        LOGI("running from root user");
    }
#endif

    return start_relay(&conf, NULL, NULL);
}
