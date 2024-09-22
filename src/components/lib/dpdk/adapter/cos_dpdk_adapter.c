#include <llprint.h>
#include <pci.h>
#include <io.h>
#include <cos_kernel_api.h>
#include <cos_defkernel_api.h>
#include <memmgr.h>

#include <rte_bus_pci.h>

#include "cos_dpdk_adapter.h"

static struct pci_dev cos_pci_devices[PCI_DEVICE_NUM];
static int pci_dev_nb = 0;

#define PRINT_BUF_SZ 512

int
cos_printc(const char *fmt, va_list ap)
{
	size_t  ret;
	char print_buffer[PRINT_BUF_SZ];

	ret = vsnprintf(print_buffer, PRINT_BUF_SZ, fmt, ap);
	cos_llprint(print_buffer, ret);

	return ret;
}

int
cos_printf(const char *fmt,...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = cos_printc(fmt, ap);
	va_end(ap);
	return ret;
}

int
cos_bus_scan(void)
{
	int ret;

	pci_dev_nb	= pci_dev_count();
	ret		= pci_scan(cos_pci_devices, pci_dev_nb);

	pci_dev_print(cos_pci_devices, pci_dev_nb);

	return ret;
}

/* Write PCI config space. */
int
cos_pci_write_config(const struct rte_pci_device *device,
		const void *buf, size_t len, off_t offset)
{
	uint32_t buffer = 0, w = 0, w_once;
	int _len = (int)len;

	if (!buf) return -1;

	do
	{
		buffer = pci_config_read(device->addr.bus, device->addr.devid,
				device->addr.function, offset);

		w_once = _len > COS_PCI_IO_SIZE ? COS_PCI_IO_SIZE:_len;
		memcpy(&buffer, buf, w_once);

		pci_config_write(device->addr.bus, device->addr.devid,
				device->addr.function, offset, buffer);

		w	+= w_once;
		offset	+= COS_PCI_IO_SIZE;
		_len	-= COS_PCI_IO_SIZE;
		buf	+= w_once;
	} while (_len > 0);

	return w;
}

int
cos_pci_read_config(const struct rte_pci_device *device,
		void *buf, size_t len, off_t offset)
{
	uint32_t buffer, r = 0, r_once;
	int _len = (int)len;

	if (!buf) return -1;

	do
	{
		buffer = pci_config_read(device->addr.bus, device->addr.devid,
				device->addr.function, (uint32_t)offset);
		r_once = _len > COS_PCI_IO_SIZE ? COS_PCI_IO_SIZE:_len;
		memcpy(buf, &buffer, r_once);

		r +=	r_once;
		offset	+= COS_PCI_IO_SIZE;
		_len	-= COS_PCI_IO_SIZE;
	} while (_len > 0);
	
	return r;
}
/* declare dpdk private functions to avoid compiler warnings */
void rte_pci_add_device(struct rte_pci_device *pci_dev);
void pci_name_set(struct rte_pci_device *dev);

int
cos_pci_scan(void)
{
	int i, j;
	struct rte_pci_device *pci_device_list, *rte_dev;
	struct pci_dev *cos_dev;

	cos_printf("cos pci sanning\n");
	cos_bus_scan();

	pci_device_list = malloc(sizeof(*rte_dev) * pci_dev_nb);

	if (!pci_device_list) return -1;

	memset(pci_device_list, 0, sizeof(*rte_dev) * pci_dev_nb);

	for (i = 0; i < pci_dev_nb; i++) {
		rte_dev = &pci_device_list[i];
		cos_dev = &cos_pci_devices[i];

		/* skip non-device type pci, DPDK does not care them */
		if (cos_dev->pci_type != PCI_TYPE_DEVICE) continue;

		rte_dev->addr.bus               = cos_dev->bus;
		rte_dev->addr.devid             = cos_dev->dev;
		rte_dev->addr.function          = cos_dev->func;
		rte_dev->id.class_id            = cos_dev->classcode;
		rte_dev->id.vendor_id           = cos_dev->vendor;
		rte_dev->id.device_id           = cos_dev->device;
		rte_dev->id.subsystem_vendor_id = cos_dev->subsystem_vendor_id;
		rte_dev->id.subsystem_device_id = cos_dev->subsystem_device_id;

		for (j = 0; j < PCI_MAX_RESOURCE; j++) {
			if (!cos_dev->bar[j].accessibility) continue;

			rte_dev->mem_resource[j].phys_addr = cos_dev->bar[j].paddr;
			rte_dev->mem_resource[j].len       = cos_dev->bar[j].len;

			/* The virtual memory of this bar's space has yet to be mapped */
			rte_dev->mem_resource[j].addr      = NULL;
		}

		rte_dev->max_vfs = 0;
		rte_dev->kdrv = RTE_PCI_KDRV_UIO_GENERIC;

		pci_name_set(rte_dev);
		rte_pci_add_device(rte_dev);
	}

	return 0;
}

cos_vaddr_t
cos_map_phys_to_virt(paddr_t paddr, size_t size)
{
	return memmgr_map_phys_to_virt(paddr, size);
}

cos_paddr_t
cos_map_virt_to_phys(cos_vaddr_t addr)
{
	#define USER_ADDR_SPACE_MASK 0x00007ffffffff000

	unsigned long ret;
	cos_vaddr_t vaddr = addr;

	assert((vaddr & 0xfff) == 0);

	ret = memmgr_virt_to_phys((vaddr_t)vaddr);

	return ret & USER_ADDR_SPACE_MASK;
}

/* Fixme: need to replace this later because a normal compoent with DPDK does not have hw capability */
unsigned long
cos_get_tsc_freq(void)
{
	return sched_get_cpu_freq() * 1000000;
}

unsigned
cos_curr_lcore(void) {
	return cos_cpuid();
}

COS_DPDK_DECLARE_NIC_MODULE(net_e1000_em);
//COS_DPDK_DECLARE_NIC_MODULE(net_i40e);
COS_DPDK_DECLARE_NIC_MODULE(mempool_ring);
COS_DPDK_DECLARE_NIC_MODULE(net_ice);
COS_DPDK_DECLARE_NIC_MODULE(net_ice_dcf);
COS_DPDK_DECLARE_NIC_MODULE(net_vmxnet3);
