/*
 * cache.h — process-wide LRU cache of decrypted plaintext, keyed by the lower
 * file's identity (dev, ino, mtime, size).  A GCM container is one message, so
 * the first read decrypts the whole file once; the cache serves the rest and is
 * shared across all opens/clients the daemon handles.  Entries in use are
 * pinned (refcount) so they are never evicted mid-read.  See ../DESIGN.md.
 */
#ifndef FUSEFS_CACHE_H
#define FUSEFS_CACHE_H

#include <stddef.h>
#include <sys/stat.h>

struct cache_entry;

void cache_init(size_t budget_bytes);

/*
 * Look up the plaintext for the lower file identified by `st`.  On hit returns
 * a pinned entry (call cache_release when done).  On miss returns NULL; the
 * caller decrypts and inserts via cache_insert.
 */
struct cache_entry *cache_lookup(const struct stat *st);

/*
 * Insert `plain` (ownership transferred; freed by the cache on eviction) for
 * the lower file `st`.  Returns a pinned entry, or NULL on allocation failure
 * (in which case the caller still owns `plain`).  If a concurrent inserter won
 * the race, the existing entry is returned and `plain` is freed.
 */
struct cache_entry *cache_insert(const struct stat *st,
				 unsigned char *plain, size_t plain_len);

/* Accessors for a pinned entry. */
const unsigned char *cache_data(const struct cache_entry *e);
size_t cache_len(const struct cache_entry *e);

/* Unpin an entry obtained from cache_lookup / cache_insert. */
void cache_release(struct cache_entry *e);

#endif /* FUSEFS_CACHE_H */
