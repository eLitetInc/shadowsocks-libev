/*
 * plugin.c - Manage plugins
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

#include <string.h>
#ifndef __MINGW32__
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#endif

#include "utils.h"
#include "plugin.h"
#include "winsock.h"
#include "relay.h"

#define CMD_RESRV_LEN 128

#ifndef __MINGW32__
#define TEMPDIR "/tmp/"
#else
#define TEMPDIR
#endif

static int exit_code;
enum plugin_mode mode;

static struct cork_env *env        = NULL;
static struct cork_exec *exec      = NULL;

#ifdef __MINGW32__
extern struct ev_signal sigint_watcher;
extern struct ev_signal sigterm_watcher;

typedef struct plugin_watcher {
    ev_io io;
    SOCKET fd;
} plugin_watcher_t;

void cork_subprocess_set_control(struct cork_subprocess *self, uint16_t port);

static void
plugin_watcher_cb(EV_P_ ev_io *w, int revents)
{
    plugin_watcher_t *plugin_watcher = (plugin_watcher_t *)w;
    char buf[1];
    SOCKET fd = accept(plugin_watcher->fd, NULL, NULL);
    if (fd == INVALID_SOCKET) {
        return;
    }
    recv(fd, buf, 1, 0);
    closesocket(fd);
    LOGE("plugin service exit unexpectedly");
    ret_val = -1;
    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
    ev_io_stop(EV_DEFAULT, &plugin_watcher->io);
    ev_unloop(EV_A_ EVUNLOOP_ALL);
}

#endif

static int
plugin_log__data(struct cork_stream_consumer *vself,
                 const void *buf, size_t size, bool is_first)
{
    size_t bytes_written = fwrite(buf, 1, size, stderr);
    /*  If there was an error writing to the file, then signal this
     *  to the producer */
    if (bytes_written == size) {
        return 0;
    } else {
        cork_system_error_set();
        return -1;
    }
}

static int
plugin_log__eof(struct cork_stream_consumer *vself)
{
    /*  We don't close the file, so there's nothing special to do at
     *  end-of-stream. */
    return 0;
}

static void
plugin_log__free(struct cork_stream_consumer *vself)
{
    return;
}

struct cork_stream_consumer plugin_log = {
    .data = plugin_log__data,
    .eof  = plugin_log__eof,
    .free = plugin_log__free,
};

static int
start_ss_plugin(plugin_t *plugin,
                const char *plugin_name,
                const char *plugin_opts,
#ifdef __MINGW32__
                uint16_t control_port,
#endif
                const char *remote_host,
                const char *remote_port,
                const char *local_host,
                const char *local_port)
{
    cork_env_add(env, "SS_REMOTE_HOST", remote_host);
    cork_env_add(env, "SS_REMOTE_PORT", remote_port);

    cork_env_add(env, "SS_LOCAL_HOST", local_host);
    cork_env_add(env, "SS_LOCAL_PORT", local_port);

    if (plugin_opts != NULL)
        cork_env_add(env, "SS_PLUGIN_OPTIONS", plugin_opts);

    exec = cork_exec_new(plugin_name);
    cork_exec_add_param(exec, plugin_name);  // argv[0]
    if (fast_open) cork_exec_add_param(exec, "--fast-open");
#ifdef __ANDROID__
    if (vpn) cork_exec_add_param(exec, "-V");
#endif

    cork_exec_set_env(exec, env);

    struct cork_subprocess *sub
        = cork_subprocess_new_exec(exec, NULL, NULL, &exit_code);
#ifdef __MINGW32__
    cork_subprocess_set_control(sub, control_port);
#endif
    plugin->proc = sub;
    cork_dllist_add(&plugins, &plugin->entries);
    return cork_subprocess_start(sub);
}

#define OBFSPROXY_OPTS_MAX  4096
/*
 * For obfsproxy, we use standalone mode for now.
 * Managed mode needs to use SOCKS5 proxy as forwarder, which is not supported
 * yet.
 *
 * The idea of using standalone mode is quite simple, just assemble the
 * internal port into obfsproxy parameters.
 *
 * Using manually ran scramblesuit as an example:
 * obfsproxy \
 * --data-dir /tmp/ss_libev_plugin_with_suffix \
 * scramblesuit \
 * --password SOMEMEANINGLESSPASSWORDASEXAMPLE \
 * --dest some.server.org:12345 \
 * client \
 * 127.0.0.1:54321
 *
 * In above case, @plugin = "obfsproxy",
 * @plugin_opts = "scramblesuit --password SOMEMEANINGLESSPASSWORDASEXAMPLE"
 * For obfs3, it's even easier, just pass @plugin = "obfsproxy"
 * @plugin_opts = "obfs3"
 *
 * And the rest parameters are all assembled here.
 * Some old obfsproxy will not be supported as it doesn't even support
 * "--data-dir" option
 */
static int
start_obfsproxy(plugin_t *plugin,
                const char *plugin_name,
                const char *plugin_opts,
#ifdef __MINGW32__
                uint16_t control_port,
#endif
                const char *remote_host,
                const char *remote_port,
                const char *local_host,
                const char *local_port)
{
    char *pch;
    char *opts_dump = NULL;
    char *buf       = NULL;
    int ret, buf_size = 0;

    if (plugin_opts != NULL) {
        opts_dump = strndup(plugin_opts, OBFSPROXY_OPTS_MAX);
        if (!opts_dump) {
            ERROR("start_obfsproxy strndup failed");
            if (env != NULL) {
                cork_env_free(env);
            }
            return -ENOMEM;
        }
    }
    exec = cork_exec_new(plugin_name);

    /* The first parameter will be skipped, so pass @plugin again */
    cork_exec_add_param(exec, plugin_name);

    cork_exec_add_param(exec, "--data-dir");
    buf_size = 20 + strlen(plugin_name) + strlen(remote_host)
               + strlen(remote_port) + strlen(local_host) + strlen(local_port);
    buf = ss_malloc(buf_size);
    snprintf(buf, buf_size, TEMPDIR "%s_%s:%s_%s:%s", plugin_name,
             remote_host, remote_port, local_host, local_port);
    cork_exec_add_param(exec, buf);

    /*
     * Iterate @plugin_opts by space
     */
    if (opts_dump != NULL) {
        pch = strtok(opts_dump, " ");
        while (pch) {
            cork_exec_add_param(exec, pch);
            pch = strtok(NULL, " ");
        }
    }

    /* The rest options */
    if (mode == MODE_CLIENT) {
        /* Client mode */
        cork_exec_add_param(exec, "--dest");
        snprintf(buf, buf_size, "%s:%s", remote_host, remote_port);
        cork_exec_add_param(exec, buf);
        cork_exec_add_param(exec, "client");
        snprintf(buf, buf_size, "%s:%s", local_host, local_port);
        cork_exec_add_param(exec, buf);
    } else {
        /* Server mode */
        cork_exec_add_param(exec, "--dest");
        snprintf(buf, buf_size, "%s:%s", local_host, local_port);
        cork_exec_add_param(exec, buf);
        cork_exec_add_param(exec, "server");
        snprintf(buf, buf_size, "%s:%s", remote_host, remote_port);
        cork_exec_add_param(exec, buf);
    }

    cork_exec_set_env(exec, env);
    struct cork_subprocess *sub
        = cork_subprocess_new_exec(exec, NULL, NULL, &exit_code);
#ifdef __MINGW32__
    cork_subprocess_set_control(sub, control_port);
#endif
    plugin->proc = sub;
    cork_dllist_add(&plugins, &plugin->entries);
    ret = cork_subprocess_start(sub);
    ss_free(opts_dump);
    free(buf);
    return ret;
}

void
init_plugin(enum plugin_mode plugin_mode)
{
    mode = plugin_mode;
    cork_dllist_init(&plugins);
}

int
start_plugin(const char *plugin_name,
             const char *plugin_opts,
             const char *remote_host,
             const char *remote_port,
             const char *local_host,
             const char *local_port)
{
    int ret;

    if (plugin_name == NULL)
        return -1;

    if (strlen(plugin_name) == 0)
        return 0;

    plugin_t plugin;
#ifdef __MINGW32__
    uint16_t control_port = get_local_port();

    if (control_port == 0) {
        LOGE("failed to assign a control port for plugin");
    } else {
        SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd != INVALID_SOCKET) {
            struct sockaddr_in addr = {
                .sin_family = AF_INET;
                .sin_addr   = (in_addr_t) { htonl(INADDR_LOOPBACK) };
                .sin_port   = htons(control_port);
            };
            if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
                LOGE("failed to bind plugin control port");
                closesocket(fd);
            }
            if (listen(fd, 1)) {
                LOGE("failed to listen on plugin control port");
                closesocket(fd);
            }
            plugin.plugin_watcher.fd = fd;
            ev_io_init(&plugin.plugin_watcher.io, plugin_watcher_cb, fd, EV_READ);
            ev_io_start(EV_DEFAULT, &plugin.plugin_watcher.io);
        }
    }
#else
    /*
     * Add current dir to PATH, so we can search plugin in current dir
     */
    char *new_path = NULL;
    const char *current_path;
    size_t new_path_len;
    env          = cork_env_clone_current();
    current_path = cork_env_get(env, "PATH");
    if (current_path != NULL) {
#ifdef HAVE_GET_CURRENT_DIR_NAME
        char *cwd = get_current_dir_name();
        if (cwd) {
#else
        char cwd[PATH_MAX];
        if (!getcwd(cwd, PATH_MAX)) {
#endif
            new_path_len = strlen(current_path) + strlen(cwd) + 2;
            new_path     = ss_malloc(new_path_len);
            snprintf(new_path, new_path_len, "%s:%s", cwd, current_path);
#ifdef HAVE_GET_CURRENT_DIR_NAME
            free(cwd);
#endif
        }
    }
    if (new_path != NULL)
        cork_env_add(env, "PATH", new_path);
#endif

    if (!strncmp(plugin_name, "obfsproxy", strlen("obfsproxy")))
        ret = start_obfsproxy(&plugin,
                              plugin_name, plugin_opts,
#ifdef __MINGW32__
                              control_port,
#endif
                              remote_host, remote_port,
                              local_host, local_port);
    else
        ret = start_ss_plugin(&plugin,
                              plugin_name, plugin_opts,
#ifdef __MINGW32__
                              control_port,
#endif
                              remote_host, remote_port,
                              local_host, local_port);
#ifndef __MINGW32__
    ss_free(new_path);
#endif
    env = NULL;
    return ret;
}

uint16_t
get_local_port()
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return 0;
    }

    struct sockaddr_in serv_addr;
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port        = 0;
    if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        return 0;
    }

    socklen_t len = sizeof(serv_addr);
    if (getsockname(sock, (struct sockaddr *)&serv_addr, &len) == -1) {
        return 0;
    }
    if (close(sock) < 0) {
        return 0;
    }

    return ntohs(serv_addr.sin_port);
}

void
stop_plugin()
{
    plugin_t *plugin = NULL;
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach(&plugins, curr, next,
                        plugin_t, plugin, entries) {
        if (plugin != NULL) {
            if (plugin->proc != NULL) {
                cork_subprocess_abort(plugin->proc);
#ifndef __MINGW32__
                if (cork_subprocess_wait(plugin->proc) == -1) {
                    LOGI("error terminating plugin");
                }
#endif
                cork_subprocess_free(plugin->proc);
            }
#ifdef __MINGW32__
            closesocket(plugin->watcher->fd);
            ev_io_stop(EV_DEFAULT, &plugin->watcher->io);
#endif
        }
    }
}

int
is_plugin_running()
{
    plugin_t *plugin;
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach(&plugins, curr, next,
                        plugin_t, plugin, entries) {
        if (plugin != NULL && plugin->proc != NULL
            && !cork_subprocess_is_finished(plugin->proc)) {
            return 1;
        }
    }
    return 0;
}
