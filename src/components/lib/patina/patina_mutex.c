/**
 * Redistribution of this file is permitted under the BSD two clause license.
 *
 * Copyright 2020, The George Washington University
 * Author: Bite Ye, bitye@gwu.edu
 */

#include <llprint.h>
#include <patina_mutex.h>
#include <patina_types.h>
#include <static_slab.h>

/**
 * This is a wrapper of patina's native crt lib.
 * For detail API usage guide, please check source codes
 * under 'src/components/lib/crt/'
 */

SS_STATIC_SLAB(lock, struct crt_lock, PATINA_MAX_NUM_MUTEX);

/**
 * Create a mutex
 * Currently we don't support any flags
 *
 * Arguments:
 * - @flags: no effect
 *
 * @return id of the mutex
 */
patina_mutex_t
patina_mutex_create(size_t flags)
{
	struct crt_lock *l = ss_lock_alloc();
	if (!l) { return -1; }

	assert(!crt_lock_init(l));

	  ss_lock_activate(l);

	patina_mutex_t mid = (patina_mutex_t)l | PATINA_T_MUTEX;

	return mid;
}

/**
 * Lock a mutex (blocking)
 *
 * Arguments:
 * - @mid: id of the mutex
 *
 * @return always success
 */
int
patina_mutex_lock(patina_mutex_t mid)
{
	assert(mid);

	struct crt_lock *l = (struct crt_lock *)(mid & PATINA_T_MASK);

	crt_lock_take(l);

	return 0;
}

/**
 * Try to lock a mutex (non-blocking)
 *
 * Arguments:
 * - @mid: id of the mutex
 *
 * @return always success
 */
int
patina_mutex_try_lock(patina_mutex_t mid)
{
	assert(mid);

	struct crt_lock *l = (struct crt_lock *)(mid & PATINA_T_MASK);

	crt_lock_try_take(l);

	return 0;
}

/**
 * Unlock a mutex
 *
 * Arguments:
 * - @mid: id of the mutex
 *
 * @return always success
 */
int
patina_mutex_unlock(patina_mutex_t mid)
{
	assert(mid);

	struct crt_lock *l = (struct crt_lock *)(mid & PATINA_T_MASK);

	crt_lock_release(l);

	return 0;
}

/**
 * Destroy a mutex
 *
 * Arguments:
 * - @mid: id of the mutex
 *
 * @return always success
 */
int
patina_mutex_destroy(patina_mutex_t mid)
{
	assert(mid);

	struct crt_lock *l = (struct crt_lock *)(mid & PATINA_T_MASK);

	crt_lock_teardown(l);
	ss_lock_free(l);

	return 0;
}
