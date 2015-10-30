#include "kernel.h"
#include "string.h"
#include "isr.h"
#include "io.h"

/* Information taken from: http://wiki.osdev.org/PIC */
/* FIXME:  Remove magic numbers and replace with this */
#define PIC1            0x20
#define PIC2            0xA0
#define PIC1_COMMAND    PIC1
#define PIC1_DATA       (PIC1 + 1)
#define PIC2_COMMAND    PIC2
#define PIC2_DATA       (PIC2 + 1)

/* reinitialize the PIC controllers, giving them specified vector offsets
   rather than 8 and 70, as configured by default */

#define ICW1_ICW4       0x01        /* ICW4 (not) needed */
#define ICW1_SINGLE     0x02        /* Single (cascade) mode */
#define ICW1_INTERVAL4  0x04        /* Call address interval 4 (8) */
#define ICW1_LEVEL      0x08        /* Level triggered (edge) mode */
#define ICW1_INIT       0x10        /* Initialization - required! */

#define ICW4_8086       0x01        /* 8086/88 (MCS-80/85) mode */
#define ICW4_AUTO       0x02        /* Auto (normal) EOI */
#define ICW4_BUF_SLAVE  0x08        /* Buffered mode/slave */
#define ICW4_BUF_MASTER 0x0C        /* Buffered mode/master */
#define ICW4_SFNM       0x10        /* Special fully nested (not) */
#define ICW1_ICW4       0x01

struct idt_entry {
	u16_t base_lo;   // Lower 16 bits of address to jump too after int
	u16_t sel;       // Kernel segment selector
	u8_t zero;       // Must always be zero
	u8_t flags;      // flags
	u16_t base_hi;   // Upper 16 bits of addres to jump too
} __attribute__((packed));

struct idt_ptr {
	u16_t limit;
	u32_t base;     // Addres of first element
} __attribute__((packed));

// Always must be 256
#define NUM_IDT_ENTRIES 256

extern void idt_flush(u32_t);

struct idt_entry idt_entries[NUM_IDT_ENTRIES];
struct idt_ptr   idt_ptr;

static void
idt_set_gate(u8_t num, u32_t base, u16_t sel, u8_t flags)
{
	idt_entries[num].base_lo = base & 0xFFFF;
	idt_entries[num].base_hi = (base >> 16) & 0xFFFF;

	idt_entries[num].sel  = sel;
	idt_entries[num].zero = 0;

	/* FIXME: This does not yet allow for mode switching */
	idt_entries[num].flags = flags /* | 0x60 */;
	// The OR is used for ring once we get usermode up and running
}

#if 0
static inline void
remap_irq_table(void)
{
	u8_t pic1_mask;
	u8_t pic2_mask;

	// Save masks
	pic1_mask = inb(PIC1_DATA);
	pic2_mask = inb(PIC2_DATA);
}
#endif

void
idt_init(void)
{
	idt_ptr.limit = (sizeof(struct idt_entry) * NUM_IDT_ENTRIES) - 1;
	idt_ptr.base  = (u32_t)&idt_entries;
	memset(&idt_entries, 0, sizeof(struct idt_entry) * NUM_IDT_ENTRIES);

	outb(0x20, 0x11);
	outb(0xA0, 0x11);
	outb(0x21, 0x20);
	outb(0xA1, 0x28);
	outb(0x21, 0x04);
	outb(0xA1, 0x02);
	outb(0x21, 0x01);
	outb(0xA1, 0x01);
	outb(0x21, 0x0);
	outb(0xA1, 0x0);

	idt_set_gate(IRQ_DOUBLE_FAULT, (u32_t)double_fault_irq, 0x08, 0x8E);
	idt_set_gate(IRQ_PAGE_FAULT,   (u32_t)page_fault_irq, 0x08, 0x8E);
	/* idt_set_gate(IRQ_PIT,        (u32_t)timer_irq, 0x08, 0x8E); */
	idt_set_gate(IRQ_KEYBOARD,     (u32_t)keyboard_irq, 0x08, 0x8E);
	idt_set_gate(IRQ_SERIAL,       (u32_t)serial_irq, 0x08, 0x8E);
	idt_set_gate(IRQ_PERIODIC,     (u32_t)periodic_irq, 0x08, 0x8E);
	idt_set_gate(IRQ_ONESHOT,      (u32_t)oneshot_irq, 0x08, 0x8E);

	struct {
		unsigned short length;
		unsigned long base;
	} __attribute__((__packed__)) idtr;

	idtr.length = idt_ptr.limit;
	idtr.base = (unsigned long)idt_entries;

	asm volatile("lidt (%0)" : : "p"(&idtr));
}
