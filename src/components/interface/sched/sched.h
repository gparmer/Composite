/*
 * Redistribution of this file is permitted under the BSD two clause license.
 *
 * Copyright 2018, The George Washington University
 * Author: Phani Gadepalli, phanikishoreg@gwu.edu
 */

#ifndef SCHED_H
#define SCHED_H

/***
 * Components implementing the `sched` API provide threads, and thread
 * multiplexing, synchronization, and timing services.
 */

#include <cos_kernel_api.h>
#include <cos_defkernel_api.h>
#include <res_spec.h>
#include <cos_types.h>
#include <cos_stubs.h>

typedef u32_t sched_blkpt_id_t;
#define SCHED_BLKPT_NULL 0
typedef word_t sched_blkpt_epoch_t;

int      sched_thd_yield_to(thdid_t t);
int      COS_STUB_DECL(sched_thd_yield_to)(thdid_t t);
int      sched_thd_yield(void);
int      COS_STUB_DECL(sched_thd_yield)(void);
int      sched_thd_wakeup(thdid_t t);
int      COS_STUB_DECL(sched_thd_wakeup)(thdid_t t);
int      sched_debug_thd_state(thdid_t t);
int      COS_STUB_DECL(sched_debug_thd_state)(thdid_t t);
int      sched_thd_block(thdid_t dep_id);
int      COS_STUB_DECL(sched_thd_block)(thdid_t dep_id);
cycles_t sched_thd_block_timeout(thdid_t dep_id, cycles_t abs_timeout);
cycles_t COS_STUB_DECL(sched_thd_block_timeout)(thdid_t dep_id, cycles_t abs_timeout);

void     sched_set_tls(void* tls_addr);
unsigned long sched_get_cpu_freq(void);

thdid_t sched_thd_create(cos_thd_fn_t fn, void *data); /* lib.c */
thdid_t sched_thd_create_nf_rx(cos_thd_fn_t fn, void *data); /* lib.c */
thdid_t sched_thd_create_closure(thdclosure_index_t idx);
thdid_t sched_thd_create_closure_nf_rx(thdclosure_index_t idx);
thdid_t COS_STUB_DECL(sched_thd_create_closure)(cos_thd_fn_t fn, void *data);

sched_blkpt_id_t sched_blkpt_alloc(void);
int sched_blkpt_free(sched_blkpt_id_t id);
int sched_blkpt_trigger(sched_blkpt_id_t blkpt, sched_blkpt_epoch_t epoch, int single);
int sched_blkpt_block(sched_blkpt_id_t blkpt, sched_blkpt_epoch_t epoch, thdid_t dependency);

thdid_t sched_aep_create(struct cos_aep_info *aep, cos_aepthd_fn_t fn, void *data, int owntc, cos_channelkey_t key, microsec_t ipiwin, u32_t ipimax); /* lib.c */
thdid_t sched_aep_create_closure(thdclosure_index_t id, int owntc, cos_channelkey_t key, microsec_t ipiwin, u32_t ipimax, arcvcap_t *rcv);
thdid_t COS_STUB_DECL(sched_aep_create_closure)(thdclosure_index_t idx, int owntc, cos_channelkey_t key, microsec_t ipiwin, u32_t ipimax, arcvcap_t *rcv);

int sched_thd_param_set(thdid_t tid, sched_param_t p);
int COS_STUB_DECL(sched_thd_param_set)(thdid_t tid, sched_param_t p);

int sched_thd_delete(thdid_t tid);
int COS_STUB_DECL(sched_thd_delete)(thdid_t tid);

int sched_thd_exit(void);
int COS_STUB_DECL(sched_thd_exit)(void);

/* TODO: lock i/f */

#endif /* SCHED_H */
