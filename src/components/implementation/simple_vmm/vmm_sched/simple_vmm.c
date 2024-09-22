#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cos_debug.h>
#include <llprint.h>
#include <cos_component.h>
#include <cos_kernel_api.h>
#include <static_slab.h>
#include <sched.h>
#include <contigmem.h>
#include <shm_bm.h>
#include <vmrt.h>
#include <instr_emul.h>
#include <acrn_common.h>
#include <netshmem.h>
#include <vmm_netio_rx.h>
#include <vmm_netio_tx.h>
#include <vmm_netio_shmem.h>
#include <nic_netio_rx.h>
#include <nic_netio_tx.h>
#include <nic_netio_shmem.h>

#include <vlapic.h>
#include <vioapic.h>
#include <sync_lock.h>
#include <cos_time.h>
#include <nf_session.h>
#include <sync_sem.h>
#include <arpa/inet.h>

#define NF_THD_PRIORITY 31

#define NO_NF_TEST 1

#define RX_BATCH 1
#define TX_BATCH 1

#define RX_PROCESSING 0
#define TX_PROCESSING 0

thdid_t rx_tid = 0;
thdid_t tx_tid = 0;

thdid_t virtio_tx_tid = 0;

char tx_nf_buffer[4096];
char rx_nf_buffer[4096];


INCBIN(vmlinux, "guest/vmlinux.img")
INCBIN(bios, "guest/guest.img")

/* Currently only have one VM component globally managed by this VMM */
static struct vmrt_vm_comp *g_vm;
static struct vmrt_vm_comp *g_vm1;

struct vmrt_vm_comp *vm_list[2] = {0};

#define VM_MAX_COMPS (2)
#define GUEST_MEM_SZ (310*1024*1024)

SS_STATIC_SLAB(vm_comp, struct vmrt_vm_comp, VM_MAX_COMPS);
SS_STATIC_SLAB(vm_lapic, struct acrn_vlapic, VM_MAX_COMPS * VMRT_VM_MAX_VCPU);
SS_STATIC_SLAB(vcpu_inst_ctxt, struct instr_emul_ctxt, VM_MAX_COMPS * VMRT_VM_MAX_VCPU);
SS_STATIC_SLAB(vm_io_apic, struct acrn_vioapics, VM_MAX_COMPS);
SS_STATIC_SLAB(vcpu_mmio_req, struct acrn_mmio_request, VM_MAX_COMPS * VMRT_VM_MAX_VCPU);

struct sync_lock vm_boot_lock;

void 
pause_handler(struct vmrt_vm_vcpu *vcpu)
{
	sched_thd_yield();
	GOTO_NEXT_INST(vcpu->shared_region);
}

void 
hlt_handler(struct vmrt_vm_vcpu *vcpu)
{
	sched_thd_yield();
	GOTO_NEXT_INST(vcpu->shared_region);
}

void
mmio_init(struct vmrt_vm_vcpu *vcpu)
{
	vcpu->mmio_request = ss_vcpu_mmio_req_alloc();
	assert(vcpu->mmio_request);

	ss_vcpu_mmio_req_activate(vcpu->mmio_request);
}

void
ioapic_init(struct vmrt_vm_comp *vm)
{
	vm->ioapic = ss_vm_io_apic_alloc();
	assert(vm->ioapic);

	vioapic_init(vm);
	ss_vm_io_apic_activate(vm->ioapic);
}

void
iinst_ctxt_init(struct vmrt_vm_vcpu *vcpu)
{
	vcpu->inst_ctxt = ss_vcpu_inst_ctxt_alloc();
	assert(vcpu->inst_ctxt);

	ss_vcpu_inst_ctxt_activate(vcpu->inst_ctxt);
}

void
lapic_init(struct vmrt_vm_vcpu *vcpu)
{
	struct acrn_vlapic *vlapic = ss_vm_lapic_alloc();
	assert(vlapic);

	/* A vcpu can only have one vlapic */
	assert(vcpu->vlapic == NULL);

	vcpu->vlapic = vlapic;
	vlapic->apic_page = vcpu->lapic_page;
	vlapic->vcpu = vcpu;

	/* Status: enable APIC and vector be 0xFF */
	vlapic_reset(vlapic);

	ss_vm_lapic_activate(vlapic);
	return;
}

struct vmrt_vm_comp *
vm_comp_create(void)
{
	u64_t guest_mem_sz = GUEST_MEM_SZ;
	u64_t num_vcpu = 1;
	void *start;
	void *end;
	cbuf_t shm_id;
	void  *mem, *vm_mem;
	size_t sz;

	struct vmrt_vm_comp *vm = ss_vm_comp_alloc();
	assert(vm);
	
	vmrt_vm_create(vm, "vmlinux-5.15", num_vcpu, guest_mem_sz);

	/* Allocate memory for the VM */
	shm_id	= memmgr_shared_page_allocn_aligned(guest_mem_sz / PAGE_SIZE_4K, PAGE_SIZE_4K, (vaddr_t *)&mem);
	/* Make the memory accessible to VM */
	int ret = memmgr_shared_page_map_aligned_in_vm(shm_id, PAGE_SIZE_4K, (vaddr_t *)&vm_mem, vm->comp_id);
	vmrt_vm_mem_init(vm, mem);
	printc("created VM with %u cpus, memory size: %luMB, at host vaddr: %p\n", vm->num_vcpu, vm->guest_mem_sz/1024/1024, vm->guest_addr);

	ss_vm_comp_activate(vm);

	start = &incbin_bios_start;
	end = &incbin_bios_end;
	sz = end - start + 1;

	printc("BIOS image start: %p, end: %p, size: %lu(%luKB)\n", start, end, sz, sz/1024);
	vmrt_vm_data_copy_to(vm, start, sz, PAGE_SIZE_4K);
	
	start = &incbin_vmlinux_start;
	end = &incbin_vmlinux_end;
	sz = end - start + 1;

	printc("Guest Linux image start: %p, end: %p, size: %lu(%luMB)\n", start, end, sz, sz/1024/1024);
	#define GUEST_IMAGE_ADDR 0x100000
	vmrt_vm_data_copy_to(vm, start, sz, GUEST_IMAGE_ADDR);

	ioapic_init(vm);

	printc("Guest(%s) image has been loaded into the VM component\n", vm->name);

	return vm;
}

#if 0
static void
tx_task(void)
{
	u16_t pkt_len;
	shm_bm_objid_t objid;

	// vmm_netio_shmem_map(netshmem_get_shm_id());
	nic_netio_shmem_map(netshmem_get_shm_id());

	shm_bm_objid_t           first_objid;
	struct netshmem_pkt_buf   *first_obj;
	struct netshmem_pkt_pri   *first_obj_pri;
	struct netshmem_meta_tuple *pkt_arr;
	u8_t tx_batch_ct = 0;
	struct netshmem_pkt_buf *tx_obj;

	nic_netio_shmem_bind_port(0, 1);

	shm_bm_t tx_shmemd = 0;
	tx_shmemd = netshmem_get_shm();

	while(1) {
#if !TX_BATCH
		objid = vmm_netio_rx_packet(&pkt_len);
		nic_netio_tx_packet(objid, 0, pkt_len);

#else
		u8_t batch_ct = 32;

		first_objid = objid = vmm_netio_rx_packet_batch(batch_ct);
		first_obj = shm_bm_transfer_net_pkt_buf(tx_shmemd, objid);
		first_obj_pri = netshmem_get_pri(first_obj);
		pkt_arr = (struct netshmem_meta_tuple *)&(first_obj_pri->pkt_arr);
		tx_batch_ct = first_obj_pri->batch_len;

#if TX_PROCESSING
		for (u8_t i = 0; i < tx_batch_ct; i++) {
			pkt_len = pkt_arr[i].pkt_len;
			objid = pkt_arr[i].obj_id;
			tx_obj = shm_bm_transfer_net_pkt_buf(tx_shmemd, objid);
			memcpy(tx_nf_buffer, netshmem_get_data_buf(tx_obj), pkt_len);
		}
#endif
		nic_netio_tx_packet_batch(first_objid);
#endif
	}
}
#endif

static void
rx_task(void)
{
	/* TODO: port NF applications here   */
	shm_bm_objid_t           objid;
	struct netshmem_pkt_buf *rx_obj;
	shm_bm_objid_t           first_objid;
	struct netshmem_pkt_buf   *first_obj;
	struct netshmem_pkt_pri   *first_obj_pri;
	struct netshmem_meta_tuple *pkt_arr;
	u16_t pkt_len;
	u32_t ip;

	u8_t batch_ct = 50;

	// vmm_netio_shmem_map(netshmem_get_shm_id());
	nic_netio_shmem_map(netshmem_get_shm_id());
	ip = inet_addr("10.10.1.1");

	nic_netio_shmem_bind_port(ip, 0);

	int i = 0;
	u64_t times = 0;
	u64_t overhead = 0;

	shm_bm_t rx_shmemd = 0;

	rx_shmemd = netshmem_get_shm();
	while(1)
	{
		u8_t rx_batch_ct = 0;
#if !RX_BATCH
		objid = nic_netio_rx_packet(&pkt_len);
		vmm_netio_tx_packet(objid, pkt_len);
#else
		first_objid = nic_netio_rx_packet_batch(batch_ct);

		first_obj = shm_bm_transfer_net_pkt_buf(rx_shmemd, first_objid);
		first_obj_pri = netshmem_get_pri(first_obj);
		pkt_arr = (struct netshmem_meta_tuple *)&(first_obj_pri->pkt_arr);
		rx_batch_ct = first_obj_pri->batch_len;
#if RX_PROCESSING
		for (u8_t i = 0; i < rx_batch_ct; i++) {
			pkt_len = pkt_arr[i].pkt_len;
			objid = pkt_arr[i].obj_id;
			rx_obj = shm_bm_transfer_net_pkt_buf(rx_shmemd, objid);
			memcpy(rx_nf_buffer, netshmem_get_data_buf(rx_obj), pkt_len);
		}
#endif

		vmm_netio_tx_packet_batch(first_objid);
#endif
	}
}

static void
tx_task(void)
{
	u16_t pkt_len;
	shm_bm_objid_t objid;

	nic_netio_shmem_map(netshmem_get_shm_id());

	shm_bm_objid_t           first_objid;
	struct netshmem_pkt_buf   *first_obj;
	struct netshmem_pkt_pri   *first_obj_pri;
	struct netshmem_meta_tuple *pkt_arr;
	u8_t tx_batch_ct = 0;
	struct netshmem_pkt_buf *tx_obj;
	u32_t ip;

	shm_bm_t tx_shmemd = 0;
	tx_shmemd = netshmem_get_shm();
	ip = inet_addr("10.10.1.1");

	nic_netio_shmem_bind_port(ip, 1);
	int svc_id = 0;

	nf_svc_update(cos_compid(), cos_thdid(), svc_id, g_vm);

	struct nf_session *session;
	session = get_nf_session(svc_id);
	nf_session_tx_update(session, tx_shmemd, cos_thdid());
	sync_sem_init(&session->tx_sem, 0);

	nf_tx_ring_buf_init(&session->nf_tx_ring_buf, NF_TX_PKT_RBUF_NUM, NF_TX_PKT_RING_SZ);

	virtio_tx_task(0);
}

void
cos_init(void)
{

		nf_svc_init();
		nf_sessions_init();

		struct vmrt_vm_vcpu *vcpu;
		g_vm = vm_comp_create();
		printc("created vm done:%d, %p\n", g_vm->comp_id, g_vm);
		g_vm->vm_mac_id = 0;

		vm_list[0] = g_vm;
}

void
cos_parallel_init(coreid_t cid, int init_core, int ncores)
{
	struct vmrt_vm_vcpu *vcpu;

	if (cid == 0) {
		rx_tid = sched_thd_create((void *)rx_task, NULL);
		netshmem_create(rx_tid);
		tx_tid = sched_thd_create((void *)tx_task, NULL);
		netshmem_create(tx_tid);
		printc("NF rx tid:%ld, tx tid:%ld\n", rx_tid, tx_tid);

		vmrt_vm_vcpu_init(g_vm, 0);
		vcpu = vmrt_get_vcpu(g_vm, 0);

		lapic_init(vcpu);
		iinst_ctxt_init(vcpu);
		mmio_init(vcpu);

	}

	return;
}

void
parallel_main(coreid_t cid)
{
	struct vmrt_vm_vcpu *vcpu;
	
	if (cid == 0) {
		sched_thd_block_timeout(0, time_now() + time_usec2cyc(10000000));
		vcpu = vmrt_get_vcpu(g_vm, 0);
		vmrt_vm_vcpu_start(vcpu);

		sched_thd_param_set(rx_tid, sched_param_pack(SCHEDP_PRIO, NF_THD_PRIORITY));
		sched_thd_param_set(tx_tid, sched_param_pack(SCHEDP_PRIO, NF_THD_PRIORITY));

	} 

	while (1)
	{
		sched_thd_block(0);
		/* Should not be here, or there is a bug in the scheduler! */
		assert(0);
	}
	

}
