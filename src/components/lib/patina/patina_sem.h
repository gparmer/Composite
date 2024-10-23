#ifndef PATINA_SEM_H
#define PATINA_SEM_H

#include <cos_types.h>
#include <crt_sem.h>

#define PATINA_MAX_NUM_SEM 32

typedef size_t patina_sem_t;

patina_sem_t patina_sem_create(size_t init_value, size_t flags);
int          patina_sem_take(patina_sem_t sid);
int          patina_sem_try_take(patina_sem_t sid);
int          patina_sem_give(patina_sem_t sid);
int          patina_sem_destroy(patina_sem_t sid);

#endif
