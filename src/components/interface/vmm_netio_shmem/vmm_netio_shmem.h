#ifndef VMM_NETIO_SHMEM_H
#define VMM_NETIO_SHMEM_H

#include <cos_types.h>
#include <cos_component.h>
#include <cos_stubs.h>
#include <shm_bm.h>

void vmm_netio_shmem_map(cbuf_t shm_id);
void vmm_netio_shmem_svc_update(int svc_id, u32_t vm);

#endif
