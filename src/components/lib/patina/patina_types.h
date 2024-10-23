#ifndef PATINA_TYPES_H
#define PATINA_TYPES_H

#define PATINA_T_MASK 0xFFFFFFFFFFFFFFFC

typedef enum
{
	PATINA_T_MUTEX  = 0,
	PATINA_T_SEM    = 0,
	PATINA_T_TIMER  = 0,
	PATINA_T_CHAN   = 1,
	PATINA_T_CHAN_R = 2,
	PATINA_T_CHAN_S = 3,
	PATINA_T_EVENT  = 0,
} patina_types_t;

#endif
