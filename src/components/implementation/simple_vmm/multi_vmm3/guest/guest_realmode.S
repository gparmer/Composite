#define SEG_NULLASM                                             \
        .word 0, 0;                                             \
        .byte 0, 0, 0, 0
#define SEG_ASM(type,base,lim)                                  \
        .word (((lim) >> 12) & 0xffff), ((base) & 0xffff);      \
        .byte (((base) >> 16) & 0xff), (0x90 | (type)),         \
                (0xC0 | (((lim) >> 28) & 0xf)), (((base) >> 24) & 0xff)

#define STA_X     0x8       // Executable segment
#define STA_E     0x4       // Expand down (non-executable segments)
#define STA_C     0x4       // Conforming code segment (executable only)
#define STA_W     0x2       // Writeable (non-executable segments)
#define STA_R     0x2       // Readable (executable segments)
#define STA_A     0x1       // Accessed

#define CR0_PE          0x00000001      // Protection Enable
#define CR0_WP          0x00010000      // Write Protect
#define CR0_PG          0x80000000      // Paging

#define SEL_KCSEG 0x08                 /* Kernel code selector. */
#define SEL_KDSEG 0x10                 /* Kernel data selector. */

.global guest_real_mode_entry
/* code start entry */
.section .guest_kernel_initfn
.code16
guest_real_mode_entry:
	ljmp $0x0, $start
	
start:
	cli
	lgdt	smpgdtdesc
	movl	%cr0, %eax
	orl	$CR0_PE, %eax
	movl	%eax, %cr0
	ljmpl	$(SEL_KCSEG), $smpstart32
.align 0x10
.code32
smpstart32:
	movw	$(SEL_KDSEG), %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss
	movw	$0, %ax
	movw	%ax, %fs
	movw	%ax, %gs
	
	/* jmp to vmlinux bootloader at the specific address */
	ljmpl	$(SEL_KCSEG), $0x100000
	jmp .

.p2align 2
smpgdt:
  SEG_NULLASM
  SEG_ASM(STA_X|STA_R, 0, 0xffffffff) /* code segment for protected mode, mapping 0-4G memory */
  SEG_ASM(STA_W, 0, 0xffffffff) /* data segment for protected mode, mapping 0-4G memory */

smpgdtdesc:
  .word   (smpgdtdesc - smpgdt - 1)
  .long   smpgdt
