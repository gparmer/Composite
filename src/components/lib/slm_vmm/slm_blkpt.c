#include <slm.h>
#include <slm_blkpt.h>
#include <stacklist.h>

#define NBLKPTS 40960
struct blkpt_mem {
	sched_blkpt_id_t      id;
	sched_blkpt_epoch_t   epoch;
	struct stacklist_head blocked;
	struct ps_lock lock;
};
static struct blkpt_mem __blkpts[NBLKPTS];
static int __blkpt_offset = 1;

#define BLKPT_EPOCH_BLKED_BITS ((sizeof(sched_blkpt_epoch_t) * 8)
#define BLKPT_EPOCH_DIFF       (BLKPT_EPOCH_BLKED_BITS - 2)/2)

/*
 * Is cmp > e? This is more complicated than it seems it should be
 * only because of wrap-around. We have to consider the case that we
 * have, and that we haven't wrapped around.
 * 
 * @return: true if cmp >= e (cmp is newer than e), false otherwise
 */
static int
blkpt_epoch_is_higher(sched_blkpt_epoch_t e, sched_blkpt_epoch_t cmp)
{
	/* FIXME: x86-32 could have wrap-around problem */
	return cmp >= e;
}

static struct blkpt_mem *
blkpt_get(sched_blkpt_id_t id)
{
	if (id - 1 == NBLKPTS) return NULL;

	return &__blkpts[id-1];
}

sched_blkpt_id_t
slm_blkpt_alloc(struct slm_thd *current)
{
	sched_blkpt_id_t id;
	struct blkpt_mem *m;
	sched_blkpt_id_t ret = SCHED_BLKPT_NULL;

	slm_cs_enter(current, SLM_CS_NONE);

	id = (sched_blkpt_id_t)__blkpt_offset;
	m  = blkpt_get(id);
	if (!m) ERR_THROW(SCHED_BLKPT_NULL, unlock);

	m->id    = id;
	ret      = id;
	m->epoch = 0;
	stacklist_init(&m->blocked);
	ps_lock_init(&m->lock);
	__blkpt_offset++;
unlock:
	slm_cs_exit(NULL, SLM_CS_NONE);

	return ret;
}

int
slm_blkpt_free(sched_blkpt_id_t id)
{
	/* alloc only for now */
	return 0;
}

int
slm_blkpt_trigger(sched_blkpt_id_t blkpt, struct slm_thd *current, sched_blkpt_epoch_t epoch, int single)
{
	thdid_t tid;
	struct blkpt_mem *m;
	int ret = 0;
	struct stacklist *sl;
	struct slm_thd *t;

	slm_cs_enter(current, SLM_CS_NONE);

	m = blkpt_get(blkpt);
	if (!m) ERR_THROW(-1, unlock);
	ps_lock_take(&m->lock);
	/* is the new epoch more recent than the existing? */
	while (1) {
		sched_blkpt_epoch_t pre = ps_load(&m->epoch);

		if (!blkpt_epoch_is_higher(pre, epoch)) {
			ps_lock_release(&m->lock);
			ERR_THROW(0, unlock); 
		}
		if (ps_cas(&m->epoch, pre, epoch)) break;
	}

	while ((sl = stacklist_dequeue(&m->blocked)) != NULL) {
		t = sl->data;
		slm_thd_wakeup(t, 0); /* ignore retval: process next thread */
		if (single) break;
	}
	ps_lock_release(&m->lock);
	/* most likely we switch to a woken thread here */
	slm_cs_exit_reschedule(current, SLM_CS_NONE);

	return 0;
unlock:
	slm_cs_exit(NULL, SLM_CS_NONE);

	return ret;
}

int
slm_blkpt_block(sched_blkpt_id_t blkpt, struct slm_thd *current, sched_blkpt_epoch_t epoch, thdid_t dependency)
{
	struct blkpt_mem *m;
	struct stacklist sl; 	/* The stack-based structure we'll use to track ourself */
	struct stacklist *_sl;
	int ret = 0;
	sched_blkpt_epoch_t pre;

	slm_cs_enter(current, SLM_CS_NONE);

	m = blkpt_get(blkpt);
	if (!m) {
		ERR_THROW(-1, unlock);
	}

	ps_lock_take(&m->lock);
	/* Outdated event? don't block! */
	pre = ps_load(&m->epoch);
	if (!blkpt_epoch_is_higher(pre, epoch)) {
		ps_lock_release(&m->lock);
		ERR_THROW(0, unlock);
	}

	/* Block! */
	stacklist_add(&m->blocked, &sl, current);

	/* To solve a risk condition when a stacklist_dequeue happens before the stacklist_add. */
	if (!blkpt_epoch_is_higher(ps_load(&m->epoch), pre)) {
		if ((_sl = stacklist_dequeue(&m->blocked)) != NULL) {
			/*
			 * FIXME: should dequeue everything from the stacklist and wakeup those are not added by this call.
			 * Then inform slm_blkpt_trigger by using CAS to update the epoch.
			 */
			assert(_sl == &sl);
		}
		assert(stacklist_is_removed(&sl));
		ps_lock_release(&m->lock);
		ERR_THROW(0, unlock);
	}

	if (slm_thd_block(current)) {
		ps_lock_release(&m->lock);
		ERR_THROW(0, unlock);
	}
	ps_lock_release(&m->lock);
	slm_cs_exit_reschedule(current, SLM_CS_NONE);
	assert(stacklist_is_removed(&sl));

	return 0;
unlock:
	slm_cs_exit(NULL, SLM_CS_NONE);

	return ret;
}
