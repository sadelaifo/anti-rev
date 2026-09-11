/*
 * cache.c — LRU plaintext cache.  A doubly-linked list ordered most-recent
 * first; eviction walks from the tail skipping pinned entries.  Lookup is a
 * linear scan, which is fine: with FOPEN_KEEP_CACHE the kernel page cache
 * absorbs repeat reads, so the daemon's read path is cold after first fault.
 */
#include "cache.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct cache_entry {
	struct cache_entry *prev, *next;
	dev_t dev;
	ino_t ino;
	struct timespec mtime;
	off_t size;			/* lower size when decrypted (staleness) */
	unsigned char *plain;
	size_t plain_len;
	unsigned refcnt;
};

static struct cache_entry *g_head, *g_tail;
static size_t g_budget = 512UL * 1024 * 1024;
static size_t g_used;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void cache_init(size_t budget_bytes)
{
	if (budget_bytes)
		g_budget = budget_bytes;
}

static void unlink_entry(struct cache_entry *e)
{
	if (e->prev) e->prev->next = e->next; else g_head = e->next;
	if (e->next) e->next->prev = e->prev; else g_tail = e->prev;
	e->prev = e->next = NULL;
}

/* push to front (most-recent) */
static void link_front(struct cache_entry *e)
{
	e->prev = NULL;
	e->next = g_head;
	if (g_head) g_head->prev = e;
	g_head = e;
	if (!g_tail) g_tail = e;
}

static int same_file(const struct cache_entry *e, const struct stat *st)
{
	return e->dev == st->st_dev && e->ino == st->st_ino &&
	       e->size == st->st_size &&
	       e->mtime.tv_sec == st->st_mtim.tv_sec &&
	       e->mtime.tv_nsec == st->st_mtim.tv_nsec;
}

/* caller holds g_lock */
static void evict_to_budget(void)
{
	struct cache_entry *e = g_tail;
	while (e && g_used > g_budget) {
		struct cache_entry *prev = e->prev;
		if (e->refcnt == 0) {
			unlink_entry(e);
			g_used -= e->plain_len;
			free(e->plain);
			free(e);
		}
		e = prev;
	}
}

struct cache_entry *cache_lookup(const struct stat *st)
{
	struct cache_entry *e;

	pthread_mutex_lock(&g_lock);
	for (e = g_head; e; e = e->next) {
		if (same_file(e, st)) {
			e->refcnt++;
			if (e != g_head) { unlink_entry(e); link_front(e); }
			pthread_mutex_unlock(&g_lock);
			return e;
		}
	}
	pthread_mutex_unlock(&g_lock);
	return NULL;
}

struct cache_entry *cache_insert(const struct stat *st,
				 unsigned char *plain, size_t plain_len)
{
	struct cache_entry *e;

	pthread_mutex_lock(&g_lock);
	/* someone may have inserted while we decrypted */
	for (e = g_head; e; e = e->next) {
		if (same_file(e, st)) {
			e->refcnt++;
			if (e != g_head) { unlink_entry(e); link_front(e); }
			pthread_mutex_unlock(&g_lock);
			free(plain);		/* drop our duplicate */
			return e;
		}
	}
	e = calloc(1, sizeof(*e));
	if (!e) {
		pthread_mutex_unlock(&g_lock);
		return NULL;			/* caller keeps ownership of plain */
	}
	e->dev = st->st_dev;
	e->ino = st->st_ino;
	e->mtime = st->st_mtim;
	e->size = st->st_size;
	e->plain = plain;
	e->plain_len = plain_len;
	e->refcnt = 1;
	link_front(e);
	g_used += plain_len;
	evict_to_budget();
	pthread_mutex_unlock(&g_lock);
	return e;
}

const unsigned char *cache_data(const struct cache_entry *e) { return e->plain; }
size_t cache_len(const struct cache_entry *e) { return e->plain_len; }

void cache_release(struct cache_entry *e)
{
	if (!e)
		return;
	pthread_mutex_lock(&g_lock);
	if (e->refcnt)
		e->refcnt--;
	pthread_mutex_unlock(&g_lock);
}
