/**
 * Redistribution of this file is permitted under the BSD two clause license.
 *
 * Copyright 2020, The George Washington University
 * Author: Bite Ye, bitye@gwu.edu
 */

#include <llprint.h>
#include <patina_sem.h>
#include <patina_types.h>
#include <static_slab.h>

/**
 * This is a wrapper of patina's native crt lib.
 * For detail API usage guide, please check source codes
 * under 'src/components/lib/crt/'
 */

SS_STATIC_SLAB(sem, struct crt_sem, PATINA_MAX_NUM_SEM);

/**
 * Create a semaphore
 * Currently we don't support any flags
 *
 * Arguments:
 * - @init_value: initial value
 * - @flags: no effect
 *
 * @return id of the semaphore
 */
patina_sem_t
patina_sem_create(size_t init_value, size_t flags)
{
	assert(init_value >= 0);

	struct crt_sem *s = ss_sem_alloc();
	if (!s) { return -1; }

	assert(!crt_sem_init(s, (unsigned long)init_value));

	ss_sem_activate(s);

	patina_sem_t sid = (patina_sem_t)s | PATINA_T_SEM;

	return sid;
}

/**
 * Take a sempahore (blocking)
 *
 * Arguments:
 * - @mid: id of the semaphore
 *
 * @return always success
 */
int
patina_sem_take(patina_sem_t sid)
{
	assert(sid);

	struct crt_sem *s = (struct crt_sem *)(sid & PATINA_T_MASK);

	crt_sem_take(s);

	return 0;
}

/**
 * Try to take a sempahore (non-blocking)
 *
 * Arguments:
 * - @mid: id of the semaphore
 *
 * @return always success
 */
int
patina_sem_try_take(patina_sem_t sid)
{
	assert(sid);

	struct crt_sem *s = (struct crt_sem *)(sid & PATINA_T_MASK);

	crt_sem_try_take(s);

	return 0;
}

/**
 * Give a sempahore
 *
 * Arguments:
 * - @mid: id of the semaphore
 *
 * @return always success
 */
int
patina_sem_give(patina_sem_t sid)
{
	assert(sid);

	struct crt_sem *s = (struct crt_sem *)(sid & PATINA_T_MASK);

	crt_sem_give(s);

	return 0;
}

/**
 * Destroy a sempahore
 *
 * Arguments:
 * - @mid: id of the semaphore
 *
 * @return always success
 */
int
patina_sem_destroy(patina_sem_t sid)
{
	assert(sid);

	struct crt_sem *s = (struct crt_sem *)(sid & PATINA_T_MASK);

	crt_sem_teardown(s);
	ss_sem_free(s);

	return 0;
}
