/**
 * Redistribution of this file is permitted under the BSD two clause license.
 *
 * Copyright 2018, The George Washington University
 * Author: Phani Gadepalli, phanikishoreg@gwu.edu & Gabe Parmer gparmer@gwu.edu
 */

#include <cos_asm_stubs.h>

cos_asm_stub(sched_get_cpu_freq);
cos_asm_stub(sched_thd_yield_to);
cos_asm_stub(sched_thd_yield);
cos_asm_stub(sched_thd_wakeup);
cos_asm_stub(sched_debug_thd_state);
cos_asm_stub(sched_thd_block);
cos_asm_stub(sched_blkpt_alloc);
cos_asm_stub(sched_blkpt_free);
cos_asm_stub(sched_blkpt_trigger) ;
cos_asm_stub(sched_blkpt_block) ;
cos_asm_stub_indirect(sched_thd_block_timeout);
cos_asm_stub(sched_thd_create_closure);
cos_asm_stub(sched_thd_create_closure_nf_rx);
cos_asm_stub_indirect(sched_aep_create_closure);
cos_asm_stub(sched_thd_param_set);
cos_asm_stub(sched_thd_exit);
cos_asm_stub(sched_thd_delete);
cos_asm_stub(sched_set_tls);
