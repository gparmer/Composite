#ifndef KERNEL_H
#define KERNEL_H

#include <shared/cos_config.h>
#include <shared/cos_types.h>
#include <shared/util.h>
#include "chal.h"
#include "multiboot2.h"

#include "chal_asm_inc.h"
#include <thd.h>
#include <hw.h>

#ifdef ENABLE_SERIAL
void serial_init(void);
#endif

#define PRINTK(format, ...) printk("%d: " format, get_cpuid(), ## __VA_ARGS__)

typedef enum {
	INIT_BOOTED,   /* initial boot */
	INIT_CPU,      /* bare minimum CPU initialization (tss, gdt, idt, etc...) */
	INIT_MEM_MAP,  /* interpret the grub memory map to understand phys mem layout */
	INIT_DATA_STRUCT,	/* initialize data-structures */
	INIT_UT_MEM,   /* initialized and allocated vaddr for untyped memory  */
	INIT_KMEM,     /* kernel virtual memory mappings are frozen */
	INIT_COMP_MEM_ALLOC,
	INIT_MULTICORE_INIT,
	INIT_BOOT_COMP
} boot_state_t;

extern boot_state_t initialization_state;
/*
 * This is a #define so that we maintain the line number where this
 * fails for better error reporting
 */
#define boot_state_assert(s) assert(initialization_state == s)
void boot_state_transition(boot_state_t from, boot_state_t to);

/* These numbers map directly to actual timers in the HPET */
typedef enum {
	TIMER_PERIODIC = 0,
	TIMER_ONESHOT  = 1,
} timer_type_t;

#define TIMER_DEFAULT_US_INTERARRIVAL 1000 /* US = microseconds */

void *device_pa2va(paddr_t dev_addr);
void *device_map_mem(paddr_t dev_addr, unsigned int pt_extra_flags);

void  timer_set(timer_type_t timer_type, u64_t cycles);
void  timer_init(void);
u64_t timer_find_hpet(void *timer);
void  timer_thd_init(struct thread *t);
void *timer_initialize_hpet(void *timer);

void  tss_init(const cpuid_t cpu_id);
void  idt_init(const cpuid_t cpu_id);
void  gdt_init(const cpuid_t cpu_id);
void  user_init(void);
void  paging_init(void);

void  acpi_init(void);
void *acpi_find_rsdt(void);
void *acpi_find_timer(void);
void  acpi_set_rsdt_page(u32_t);
void  kern_paging_map_init(void *pa);

void *acpi_find_apic(void);
void  acpi_shutdown(void);

int   lapic_find_localaddr(void *l);
void  lapic_timer_init(void);
void  lapic_init(void);
void  lapic_set_timer(int timer_type, cycles_t deadline);
u32_t lapic_get_ccr(void);
void  lapic_timer_calibration(u32_t ratio);
int   lapic_timer_calibrated(void);
void  lapic_asnd_ipi_send(const cpuid_t cpu_id);
void  lapic_selfipi(u8_t vector);

void smp_init(volatile int *cores_ready);

void tls_update(u32_t addr);

// void printk(const char *fmt, ...);
int printk_register_handler(void (*handler)(const char *));
void print_pt_regs(struct pt_regs *r);

void khalt(void);

#endif /* KERNEL_H */
