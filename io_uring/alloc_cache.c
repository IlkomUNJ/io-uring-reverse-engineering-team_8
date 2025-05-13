// SPDX-License-Identifier: GPL-2.0

#include "alloc_cache.h"


/*this func frees all entries in the allocation cache by repeatedly retrieving entries
 and calling the provided 'free' func on each. After freeing the entries, it dellocates the memory
from the 'entries' array and sets the pointer to NULL */
void io_alloc_cache_free(struct io_alloc_cache *cache,
			 void (*free)(const void *))
{
	void *entry;

	if (!cache->entries)
		return;

	while ((entry = io_alloc_cache_get(cache)) != NULL)
		free(entry);

	kvfree(cache->entries);
	cache->entries = NULL;
}

/* this func initializes the allocation cache by allocating an array of pointers for cached entries
It sets various parameters (max number of cached entries, size of each element, num of bytes to clear the allocation)
returns false if the cache was initialized properly */
bool io_alloc_cache_init(struct io_alloc_cache *cache,
			 unsigned max_nr, unsigned int size,
			 unsigned int init_bytes)
{
	cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);
	if (!cache->entries)
		return true;

	cache->nr_cached = 0;
	cache->max_cached = max_nr;
	cache->elem_size = size;
	cache->init_clear = init_bytes;
	return false;
}

/* this func allocates a new object using 'kmalloc' based on the element size
if the allocation successful and the 'init_clear' is set, it clears the allocated memory
and then returning to the new object */
void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp)
{
	void *obj;

	obj = kmalloc(cache->elem_size, gfp);
	if (obj && cache->init_clear)
		memset(obj, 0, cache->init_clear);
	return obj;
}
