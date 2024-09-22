#ifndef SLM_BLKPT_H
#define SLM_BLKPT_H

#include <slm.h>

typedef u32_t sched_blkpt_id_t;
#define SCHED_BLKPT_NULL 0
typedef word_t sched_blkpt_epoch_t;

sched_blkpt_id_t slm_blkpt_alloc(struct slm_thd *current);
int slm_blkpt_free(sched_blkpt_id_t id);
int slm_blkpt_trigger(sched_blkpt_id_t blkpt, struct slm_thd *current, sched_blkpt_epoch_t epoch, int single);
int slm_blkpt_block(sched_blkpt_id_t blkpt, struct slm_thd *current, sched_blkpt_epoch_t epoch, thdid_t dependency);

#endif	/* SLM_BLKPT_H */
