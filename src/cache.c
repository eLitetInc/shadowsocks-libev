/*
 * cache.c - Manage the connection cache for UDPRELAY
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>

#include "cache.h"
#include "utils.h"

struct cache *
new_cache(const size_t capacity,
          cache_free_cb free_cb)
{
    struct cache *ret = NULL;
    cache_create(&ret, capacity, free_cb);
    return ret;
}

/** Creates a new cache object
 *
 *  @param dst
 *  Where the newly allocated cache object will be stored in
 *
 *  @param capacity
 *  The maximum number of elements this cache object can hold
 *
 *  @return EINVAL if dst is NULL, ENOMEM if malloc fails, 0 otherwise
 */
int
cache_create(struct cache **dst, const size_t capacity,
             cache_free_cb free_cb)
{
    struct cache *new = NULL;

    if (!dst) {
        return EINVAL;
    }

    if ((new = malloc(sizeof(*new))) == NULL) {
        return ENOMEM;
    }

    new->max_entries = capacity;
    new->entries     = NULL;
    new->free_cb     = free_cb;
    *dst             = new;
    return 0;
}

/** Frees an allocated cache object
 *
 *  @param cache
 *  The cache object to free
 *
 *  @param keep_data
 *  Whether to free contained data or just delete references to it
 *
 *  @return EINVAL if cache is NULL, 0 otherwise
 */
int
cache_delete(struct cache *cache, int keep_data)
{
    struct cache_entry *entry;

    if (!cache) {
        return EINVAL;
    }

    if (keep_data) {
        HASH_CLEAR(hh, cache->entries);
    } else {
        cache_foreach(cache, entry) {
            HASH_DEL(cache->entries, entry);
            cache_free(cache, entry);
        }
    }

    ss_free(cache);
    return 0;
}

/** Clear old cache object
 *
 *  @param cache
 *  The cache object to clear
 *
 *  @param age
 *  Clear only objects older than the age (sec)
 *
 *  @return EINVAL if cache is NULL, 0 otherwise
 */
int
cache_clear(struct cache *cache, ev_tstamp age)
{
    if (!cache) {
        return EINVAL;
    }

    ev_tstamp now = ev_time();
    struct cache_entry *entry;

    cache_foreach(cache, entry) {
        if (now - entry->ts > age) {
            HASH_DEL(cache->entries, entry);
            cache_free(cache, entry);
        }
    }

    return 0;
}

/** Free a cache entry
 *
 *  @param cache
 *  The cache object
 *
 *  @param entries
 *  The entry to free
 *
 *  @return EINVAL if cache/entries is NULL, 0 otherwise
 */
int
cache_free(struct cache *cache, struct cache_entry *entries)
{
    if (!cache || !entries)
        return EINVAL;

    if (entries->value != NULL) {
        if (cache->free_cb) {
            cache->free_cb(entries->key, entries->value);
        }
    }
    ss_free(entries->key);
    ss_free(entries);

    return 0;
}

/** Removes a cache entry
 *
 *  @param cache
 *  The cache object
 *
 *  @param key
 *  The key of the entry to remove
 *
 *  @param key_len
 *  The length of key
 *
 *  @return EINVAL if cache is NULL, 0 otherwise
 */
int
cache_remove(struct cache *cache, void *key, size_t key_len)
{
    if (!cache || !key) {
        return EINVAL;
    }

    struct cache_entry *entry;
    HASH_FIND(hh, cache->entries, key, key_len, entry);

    if (entry) {
        HASH_DEL(cache->entries, entry);
        return cache_free(cache, entry);
    }

    return 0;
}

/** Checks if a given key is in the cache
 *
 *  @param cache
 *  The cache object
 *
 *  @param key
 *  The key to look-up
 *
 *  @param key_len
 *  The length of key
 *
 *  @param result
 *  Where to store the result if key is found.
 *
 *  A warning: Even though result is just a pointer,
 *  you have to call this function with a **ptr,
 *  otherwise this will blow up in your face.
 *
 *  @return EINVAL if cache is NULL or the key doesn't exist, 0 otherwise
 */
int
cache_lookup(struct cache *cache, void *key, size_t key_len, void *value)
{
    struct cache_entry *tmp = NULL;

    if (!cache || !key || !value) {
        return EINVAL;
    }

    HASH_FIND(hh, cache->entries, key, key_len, tmp);
    if (tmp) {
        HASH_DELETE(hh, cache->entries, tmp);
        tmp->ts = ev_time();
        HASH_ADD_KEYPTR(hh, cache->entries, tmp->key, key_len, tmp);
        *(void **)value = tmp->value;    // okay no memcpy here sweetie
        return 0;
    }

    return -1;
}

int
cache_key_exist(struct cache *cache, void *key, size_t key_len)
{
    struct cache_entry *tmp = NULL;

    if (!cache || !key) {
        return 0;
    }

    HASH_FIND(hh, cache->entries, key, key_len, tmp);
    if (tmp) {
        HASH_DELETE(hh, cache->entries, tmp);
        tmp->ts = ev_time();
        HASH_ADD_KEYPTR(hh, cache->entries, tmp->key, key_len, tmp);
        return 1;
    } else {
        return 0;
    }

    return 0;
}

/** Inserts a given <key, value> pair into the cache
 *
 *  @param cache
 *  The cache object
 *
 *  @param key
 *  The key that identifies <value>
 *
 *  @param key_len
 *  The length of key
 *
 *  @param data
 *  Data associated with <key>
 *
 *  @return EINVAL if cache is NULL, ENOMEM if malloc fails, 0 otherwise
 */
int
cache_insert(struct cache *cache, void *key, size_t key_len, void *value)
{
    struct cache_entry *entry     = NULL;

    if (!cache) {
        return EINVAL;
    }

    if ((entry = malloc(sizeof(*entry))) == NULL) {
        return ENOMEM;
    }

    entry->key = ss_malloc(key_len);
    memcpy(entry->key, key, key_len);

    entry->ts = ev_time();
    entry->value = value;
    HASH_ADD_KEYPTR(hh, cache->entries, entry->key, key_len, entry);

    if (cache->max_entries > 0 &&
        HASH_COUNT(cache->entries) >= cache->max_entries)
    {
        cache_foreach(cache, entry) {
            HASH_DELETE(hh, cache->entries, entry);
            return cache_free(cache, entry);
        }
    }

    return 0;
}

void *
cache_popfront(struct cache *cache, bool keyval)
{
    if (cache == NULL)
        return NULL;

    struct cache_entry *element = cache->entries;
    if (element != NULL) {
        HASH_DEL(cache->entries, element);
        return keyval ? element->key : element->value;
    }

    return NULL;
}