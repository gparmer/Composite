/*
 * Redistribution of this file is permitted under the BSD two clause license.
 *
 * Copyright 2018, The George Washington University
 * Author: Phani Gadepalli, phanikishoreg@gwu.edu
 */

#ifndef CONTIGMEM_H
#define CONTIGMEM_H

#include <cos_types.h>
#include <cos_component.h>
#include <cos_stubs.h>

vaddr_t contigmem_alloc(unsigned long npages);
cbuf_t contigmem_shared_alloc_aligned(unsigned long npages, unsigned long align, vaddr_t *pgaddr);
cbuf_t contigmem_ro_shared_alloc_aligned(unsigned long npages, unsigned long align, vaddr_t *pgaddr);
#endif /* MEMMGR_H */
