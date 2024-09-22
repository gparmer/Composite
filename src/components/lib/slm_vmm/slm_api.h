#ifndef SLM_API_H
#define SLM_API_H

#include <slm.h>

/***
 * This file encodes the main means of communication that bind the
 * different modules of `slm` together. The core modules are:
 *
 * 1. *slm* - the scheduler "core" logic that provides critical
 *     sections, and coordinates thread state transitions, and
 *     interacts with the nuances of the kernel's API.
 * 2. *timer policy* - which is the timer policy and drives the timeout APIs
 *     of `slm`, and tracks all timeouts, and their association with
 *     threads.
 * 3. *scheduler policy* - which drives the scheduling decisions of
 *     the system by defining the scheduler policy.
 * 4. *slm adapter* - the highest-level API that allocates and tracks
 *     threads, and coordinates the coordination between the previous
 *     three modules. This API bridges the higher level (e.g. `sched`)
 *     API to the slm.
 */

/* These should be defined in their own policy files. */
struct slm_timer_thd;
struct slm_sched_thd;
struct slm_resources_thd;

/***
 * The adapter layer coordinating API must define the following. These
 * functions are used by the various modules to get access to their
 * own structures that should be stored along with the `slm_thd`
 * structure.
 */
struct slm_timer_thd *slm_thd_timer_policy(struct slm_thd *t);
struct slm_sched_thd *slm_thd_sched_policy(struct slm_thd *t);
struct slm_thd *slm_thd_from_timer(struct slm_timer_thd *t);
struct slm_thd *slm_thd_from_sched(struct slm_sched_thd *t);
struct slm_thd *slm_thd_lookup(thdid_t id);

/***
 * This is the timer API. Timer policy must define all of these
 * functions that are used by the `slm` to expire timeouts (via
 * `slm_timer_expire`), and for the adapter to create and cancel
 * timers.
 */

/**
 * This function is triggered by the `slm` core when a timeout
 * expires. This function (and others) will likely want to use the
 * `slm_timeout_set` (and `slm_timeout_clear`) function to set the
 * timer as this value is what will eventually result in this function
 * being called.
 *
 * - @now - the current cycle count, passed here to avoid the costs of
 *          retrieving it from hardware registers (e.g. 30 cycles on
 *          x86)
 */
void slm_timer_expire(cycles_t now);

/**
 * The API that the scheduler uses to interact with slm. Initialize
 * and remove threads, add specific thread timeouts, remove them,
 * etc... `cancel` cancels an active timeout for this thread.
 */
int slm_timer_thd_init(struct slm_thd *t);
void slm_timer_thd_deinit(struct slm_thd *t);

int slm_timer_add(struct slm_thd *t, cycles_t absolute_cyc);
int slm_timer_cancel(struct slm_thd *t);

int slm_timer_init(void);

/***
 * The API that the scheduling policy must implement.
 *
 * Module specifications:
 *
 * - The thread allocation and indexing interfaces that allocate the
 *   thread representation in memory (thus it should be paired with
 *   the policy if the policy needs additional fields), and converts
 *   between thread ids, and that memory representation.
 * - Scheduling policy hooks to implement the policy, and implements
 *   the thread state machine going through initialization, setting up
 *   parameters (modification), execution, blocking, and waking to
 *   execute again, and removal from the system.
 * - The low-level resource allocation APIs that are either backed by
 *   an in-component mechanism (e.g. crt), or via invocation of other
 *   components that have the privileges to do so.
 *
 * These do not need to be implemented by the same body of code, but
 * do need to be compiled into the binary in some manner.
 */

#include <res_spec.h>

/**
 * Initialize the general scheduler toolkit.
 */
void slm_sched_init(void);
/**
 * Initialize a new thread (but don't yet add to scheduler queues).
 */
int slm_sched_thd_init(struct slm_thd *t);
/**
 * Prepare for thread deletion.
 */
void slm_sched_thd_deinit(struct slm_thd *t);
/**
 * Take a list of scheduler parameters, and apply them to a thread.
 * Update the thread in the scheduler data-structures corresponding to
 * these parameters.
 */
int slm_sched_thd_update(struct slm_thd *t, sched_param_type_t param, unsigned int v);

/**
 * Block the *current* thread, denoted by `t`.
 */
int slm_sched_block(struct slm_thd *t);
/**
 * Add the thread, `t`, for consideration for execution.
 */
int slm_sched_wakeup(struct slm_thd *t);

/**
 * Return the next thread (e.g. highest priority thread) that should
 * execute. Can return `NULL` if no thread is runnable.
 */
struct slm_thd *slm_sched_schedule(void);
/**
 * Called to notify the scheduler that some amount of execution for
 * thread t has elapsed.
 */
void slm_sched_execution(struct slm_thd *t, cycles_t cycles);

/***
 * Resource APIs.
 */

typedef void (*thd_fn_t)(void *);


/*
 * Macros to create the uniform functions that are used to coordinate
 * between slm modules (scheduling policy, timer policy, and
 * resource/memory management).
 *
 * ```c
 * #include <slm_compose.h>
 * #include <quantum.h>
 * #include <fprr.h>
 * #include <static_slab.h>
 * SLM_MODULES_COMPOSE_FNS(quantum, fprr, static_sched);
 * ```
 *
 * `static_slab.h` has to include `SLM_MODULES_COMPOSE_DATA();` after
 * `struct slm_resources_thd` has been defined, but before the
 * implementation requires `struct slm_thd_container`.
 *
 * This code creates the scheduler logic that uses a quantum-based
 * timer with fixed-priority, round-robin scheduling, and static
 * memory layout and resources.
 *
 * The thread structure created as a side-effect of this is a
 * container including
 *
 * - core slm thread
 * - scheduling policy data
 * - timer policy data
 * - resources allocated from the kernel via `crt`
 *
 * TODO: remove the requirement to have the resource policy module as
 * part of all of this by enabling the kernel to return a pointer on
 * event notification, rather than a thread id. The event retrieval is
 * the only place that slm requires this mapping.
 */

#define SLM_MODULES_COMPOSE_FNS(timepol, schedpol, respol)		\
	void slm_timer_expire(cycles_t now)				\
	{ slm_timer_##timepol##_expire(now); }				\
	int slm_timer_thd_init(struct slm_thd *t)			\
	{ return slm_timer_##timepol##_thd_init(t); }			\
	void slm_timer_thd_deinit(struct slm_thd *t)			\
	{ slm_timer_##timepol##_thd_deinit(t); }			\
	int slm_timer_add(struct slm_thd *t, cycles_t when)		\
	{ return slm_timer_##timepol##_add(t, when); }			\
	int slm_timer_cancel(struct slm_thd *t)				\
	{ return slm_timer_##timepol##_cancel(t); }			\
	int slm_timer_init(void)					\
	{ return slm_timer_##timepol##_init(); }			\
									\
	void slm_sched_init(void)					\
	{ slm_sched_##schedpol##_init(); }				\
	int slm_sched_thd_init(struct slm_thd *t)			\
	{ return slm_sched_##schedpol##_thd_init(t); }			\
	void slm_sched_thd_deinit(struct slm_thd *t)			\
	{ slm_sched_##schedpol##_thd_deinit(t); }			\
	int slm_sched_thd_update(struct slm_thd *t, sched_param_type_t p, unsigned int v) \
	{ return slm_sched_##schedpol##_thd_update(t, p, v); }		\
	int slm_sched_block(struct slm_thd *t)				\
	{ return slm_sched_##schedpol##_block(t); }			\
	int slm_sched_wakeup(struct slm_thd *t)				\
	{ return slm_sched_##schedpol##_wakeup(t); }			\
	void slm_sched_yield(struct slm_thd *t, struct slm_thd *yield_to) \
	{ return slm_sched_##schedpol##_yield(t, yield_to); }   	\
	struct slm_thd *slm_sched_schedule(void)			\
 	{ return slm_sched_##schedpol##_schedule(); }			\
	void slm_sched_execution(struct slm_thd *t, cycles_t c)		\
	{ slm_sched_##schedpol##_execution(t, c); }			\
									\
	struct slm_thd *slm_thd_lookup(thdid_t id)			\
	{ return slm_thd_##respol##_lookup(id); }

#define SLM_MODULES_POLICY_PROTOTYPES(schedpol)				\
	void slm_sched_##schedpol##_execution(struct slm_thd *t, cycles_t cycles); \
	struct slm_thd *slm_sched_##schedpol##_schedule(void);		\
	int slm_sched_##schedpol##_block(struct slm_thd *t);		\
	int slm_sched_##schedpol##_wakeup(struct slm_thd *t);		\
	void slm_sched_##schedpol##_yield(struct slm_thd *t, struct slm_thd *yield_to);	\
	int slm_sched_##schedpol##_thd_init(struct slm_thd *t);		\
	void slm_sched_##schedpol##_thd_deinit(struct slm_thd *t);	\
	int slm_sched_##schedpol##_thd_update(struct slm_thd *t, sched_param_type_t type, unsigned int v); \
	void slm_sched_##schedpol##_init(void);

#define SLM_MODULES_TIMER_PROTOTYPES(timerpol)				\
	void slm_timer_##timerpol##_expire(cycles_t now);		\
	int slm_timer_##timerpol##_add(struct slm_thd *t, cycles_t absolute_timeout); \
	int slm_timer_##timerpol##_cancel(struct slm_thd *t);		\
	int slm_timer_##timerpol##_thd_init(struct slm_thd *t);		\
	void slm_timer_##timerpol##_thd_deinit(struct slm_thd *t);	\
	int slm_timer_##timerpol##_init(void);

#define SLM_MODULES_COMPOSE_DATA()					\
	struct slm_thd_container {					\
		struct slm_thd           thd;				\
		struct slm_sched_thd     sched;				\
		struct slm_timer_thd     timer;				\
		struct slm_resources_thd resources;			\
	};								\
									\
	struct slm_timer_thd *slm_thd_timer_policy(struct slm_thd *t)	\
	{ return &ps_container(t, struct slm_thd_container, thd)->timer; } \
	struct slm_sched_thd *slm_thd_sched_policy(struct slm_thd *t)	\
	{ return &ps_container(t, struct slm_thd_container, thd)->sched; } \
	struct slm_thd *slm_thd_from_timer(struct slm_timer_thd *t)	\
	{ return &ps_container(t, struct slm_thd_container, timer)->thd; } \
	struct slm_thd *slm_thd_from_sched(struct slm_sched_thd *t)	\
	{ return &ps_container(t, struct slm_thd_container, sched)->thd; }
#endif	/* SLM_API_H */
