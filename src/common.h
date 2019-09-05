/*
 * common.h - Provide global definitions
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

#ifndef _COMMON_H
#define _COMMON_H

#include <libcork/ds.h>

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#ifdef __MINGW32__
#include "winsock.h"
#endif

#include "crypto.h"
#include "jconf.h"

#if defined MODULE_SOCKS  || \
    defined MODULE_TUNNEL || \
    defined MODULE_REDIR
#define MODULE_LOCAL
#endif

#if defined MODULE_LOCAL && \
    defined MODULE_REMOTE
#error "MODULE_LOCAL and MODULE_REMOTE should not be both defined"
#endif

#endif // _COMMON_H
