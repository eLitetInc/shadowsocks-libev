/*
 * cache.h - Define the cache manager interface
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

/*
 * Original Author:  Oliver Lorenz (ol), olli@olorenz.org, https://olorenz.org
 * License:  This is licensed under the same terms as uthash itself
 */

#ifndef _CACHE_
#define _CACHE_

#include "uthash.h"

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

typedef void (*cache_free_cb)(void *, void *);
/**
 * A cache entry
 */
struct cache_entry {
    void *key;         /**< Key         */
    void *value;       /**< Payload     */
    ev_tstamp ts;      /**< Timestamp   */
    UT_hash_handle hh; /**< Hash Handle */
};

/**
 * A cache object
 */
struct cache {
    size_t max_entries;              /**< Maximum number of entries      */
    struct cache_entry *entries;     /**< Head pointer                   */
    cache_free_cb free_cb;           /**< Function to free cache entries */
};

#define cache_foreach(cache, entry)    \
    struct cache_entry *tmp;           \
    HASH_ITER(hh, (cache)->entries, (entry), (tmp))

struct cache *new_cache(const size_t, cache_free_cb);
int cache_create(struct cache **, const size_t, cache_free_cb);
int cache_delete(struct cache *, int);
int cache_clear(struct cache *, ev_tstamp);
int cache_free(struct cache *, struct cache_entry *);
int cache_lookup(struct cache *, void *, size_t, void *);
int cache_insert(struct cache *, void *, size_t, void *);
int cache_remove(struct cache *, void *, size_t);
int cache_key_exist(struct cache *, void *, size_t);
void *cache_popfront(struct cache *, bool);

#endif
