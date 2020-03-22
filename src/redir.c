/*
 * redir.c - Provide a transparent TCP proxy through remote shadowsocks
 *           server
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
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>

#include <libcork/core.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plugin.h"
#include "netutils.h"
#include "utils.h"
#include "common.h"
#include "acl.h"
#include "cache.h"
#include "tcprelay.h"
#include "relay.h"
#include "cache.h"

void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;

    ssize_t r = recv(server->fd, server->buf->data + server->buf->len,
                     SOCKET_BUF_SIZE - server->buf->len, 0);

    if (r == 0) {
        // connection closed
        LOGE("stage %d", server->stage);
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf->len += r;

    if (remote == NULL) {
        ssocks_addr_t destaddr = {
            .addr = &(struct sockaddr_storage){}
        };

        if (reuse_conn)
            destaddr.id = server->fd;

        if (getdestaddr(server->fd, destaddr.addr)) {
            ERROR("getdestaddr");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }

        if ((remote = create_remote(EV_A_ server,
                        server->buf, &destaddr, acl))) {
            server->remote = remote;

            // TODO fixme
            // TODO fix the enc !!!!!!!!
            LOGE("len %d idx %d", (int)server->buf->len, (int)server->buf->idx);
            LOGE("atyp %d id %d", (uint8_t)server->buf->data[0], (uint8_t)server->buf->data[1]);

            if (reuse_conn &&
                cache_insert(remote->servers, &server->fd,
                             sizeof(uint8_t), server))
            {
                LOGE("failed to register remote session");
                close_and_free_server(EV_A_ server);
                return;
            }
        } else {
            if (verbose &&
                destaddr.dname_len == -1) {
                LOGE("partial HTTP/s request detected");
            }
            server->stage = STAGE_ERROR;
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (remote->crypto) {
        crypto_t *crypto = remote->crypto;
        int err = crypto->encrypt(server->buf, remote->e_ctx, SOCKET_BUF_SIZE);

        if (err) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }

        // TODO fixme
        if (reuse_conn && !server->abuf) {
            buffer_t *abuf = server->abuf
                           = new_buffer(sizeof(ssocks_mux_t));
            ssocks_mux_t *mux = (ssocks_mux_t *)abuf->data;
            mux->atyp = SSOCKS_ATYP_MUX;
            mux->id   = server->fd;
            abuf->len = sizeof(*mux);

            //err = crypto->encrypt(abuf, remote->e_ctx, sizeof(*mux));

            if (err) {
                LOGE("invalid password or cipher");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }

    if (!remote->send_ctx->connected ||
        server->stage != STAGE_STREAM)
    {
        ev_io_stop(EV_A_ & server_recv_ctx->io);
        if (reuse_conn)
            uniqset_add(remote->send_ctx->servers, server);
        ev_io_start(EV_A_ & remote->send_ctx->io);
        ev_timer_start(EV_A_ & remote->send_ctx->watcher);
        return;
    }

    if (reuse_conn)
        bprepend(server->buf, server->abuf, SOCKET_BUF_SIZE);

    int s = send(remote->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            if (reuse_conn)
                uniqset_add(remote->send_ctx->servers, server);
            ev_io_start(EV_A_ & remote->send_ctx->io);
        } else {
            ERROR("send");
            server->stage = STAGE_ERROR;
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
        }
    } else if (s < server->buf->len) {
        server->buf->len -= s;
        server->buf->idx += s;
        ev_io_stop(EV_A_ & server_recv_ctx->io);
        if (reuse_conn) {
            bprepend(server->buf, server->abuf, SOCKET_BUF_SIZE);
            uniqset_add(remote->send_ctx->servers, server);
        }
        ev_io_start(EV_A_ & remote->send_ctx->io);
    } else {
        server->buf->len = 0;
        server->buf->idx = 0;
    }
}

void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;

    if (remote->buf->len == 0) {
        // close and free
        LOGE("server_send_cb stage %d", server->stage);
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
    } else {
        // has data to send
        ssize_t s = send(server->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
        } else if (s < remote->buf->len) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            ev_io_start(EV_A_ & remote->recv_ctx->io);
        }
    }
}

void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;

    ssize_t r = recv(remote->fd, remote->buf->data + remote->buf->idx + remote->buf->len,
                     remote_recv_ctx->dlen - remote->buf->len, 0);

    if (r == 0) {
        // connection closed
        //LOGE("remote_recv_cb stage %d", server->stage);
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
            server->stage = STAGE_ERROR;
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    remote->buf->len += r;

    if (remote->crypto) {
        crypto_t *crypto = remote->crypto;
        int err = crypto->decrypt(remote->buf, remote->d_ctx, SOCKET_BUF_SIZE);
        if (err == CRYPTO_ERROR) {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        } else if (err == CRYPTO_NEED_MORE) {
            return; // Wait for more
        }
    }

    // TODO init recvd more than remote_recv_ctx->dlen? SOCKET_BUF_SIZE init val?
    // TODO recv header first
    // TODO seperate code base
    // TODO buffer_t memmove
    size_t rlen = 0;
    if (reuse_conn) {
        // TODO pkt size && id
        if (remote_recv_ctx->dlen == SOCKET_BUF_SIZE) {
            remote_recv_ctx->dlen = *(uint16_t *)remote->buf->data;
            if (cache_lookup(remote->servers,
                remote->buf->data + sizeof(uint16_t),
                sizeof(uint8_t), &server) != 0)
            {
                LOGE("invalid session id");
                return;
            }
            LOGE("server->fd=%d", server->fd);
            remote->server = server;
            remote->buf->len -= sizeof(uint16_t) + sizeof(uint8_t);
            remote->buf->idx += sizeof(uint16_t) + sizeof(uint8_t);
        }

        int remaining = remote->buf->len - remote_recv_ctx->dlen;
        LOGE("remote->buf->len==%d remote_recv_ctx->dlen==%d remaining=%d", (int)remote->buf->len, (int)remote_recv_ctx->dlen, (int)remaining);
        if (remaining >= 0) {
            rlen = remaining;
            remote_recv_ctx->dlen = SOCKET_BUF_SIZE;
        } else {
            return; // TODO optimize
        }
    }

    int s = send(server->fd, remote->buf->data + remote->buf->idx, remote->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            remote->buf->idx = 0;
            if (!reuse_conn)
                ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < remote->buf->len) {
        remote->buf->len -= s;
        remote->buf->idx += s;
        if (!reuse_conn)
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
    } else {
        LOGE("rlen=%d", (int)rlen);
        remote->buf->len = rlen;
        remote->buf->idx = 0;
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

    ev_timer_stop(EV_A_ & remote_send_ctx->watcher);

    struct cache_entry *lserver = NULL;
    if (reuse_conn) {
        if (!(lserver = cache_head(remote_send_ctx->servers)))
        {
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            return;
        }
        server = *(server_t **)uniqset_element(lserver);
    }

    if (!remote_send_ctx->connected) {
        if (remote_connected(remote)) {
            server->stage = STAGE_STREAM;
            remote_send_ctx->connected = 1;

            if (!reuse_conn)
                ev_io_stop(EV_A_ & remote_send_ctx->io);
            ev_io_stop(EV_A_ & server->recv_ctx->io);
            ev_io_start(EV_A_ & remote->recv_ctx->io);
        } else {
            if (errno != CONNECT_IN_PROGRESS) {
                ERROR("getpeername");
                // not connected
                server->stage = STAGE_ERROR;
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        }
    }

    if (server->buf->len == 0) {
        // close and free
        LOGE("remote_send");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
    } else {
        // has data to send
        ssize_t s = sendto_remote(remote, server->buf);

        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("send");
                // close and free
                server->stage = STAGE_ERROR;
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
        } else if (s < server->buf->len) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            if (reuse_conn)
                bprepend(server->buf, server->abuf, SOCKET_BUF_SIZE);
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            if (reuse_conn) {
                if (cache_remove_r(remote_send_ctx->servers, lserver))
                {
                    LOGE("failed to remove session");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            } else
                ev_io_stop(EV_A_ & remote_send_ctx->io);
            ev_io_start(EV_A_ & server->recv_ctx->io);
        }
    }
}

void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;

    int serverfd = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }

    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    setnonblocking(serverfd);

    server_t *server = new_server(serverfd, listener);

    ev_io_start(EV_A_ & server->recv_ctx->io);
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
