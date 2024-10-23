#ifndef PATINA_MUTEX_H
#define PATINA_MUTEX_H

#include <cos_types.h>
#include <crt_lock.h>

#define PATINA_MAX_NUM_MUTEX 32

typedef size_t patina_mutex_t;

patina_mutex_t patina_mutex_create(size_t flags);
int            patina_mutex_lock(patina_mutex_t mid);
int            patina_mutex_try_lock(patina_mutex_t mid);
int            patina_mutex_unlock(patina_mutex_t mid);
int            patina_mutex_destroy(patina_mutex_t mid);

#endif
