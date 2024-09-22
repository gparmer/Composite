/*-
 * Copyright (c) 2012 Sandvine, Inc.
 * Copyright (c) 2012 NetApp, Inc.
 * Copyright (c) 2017-2022 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <instr_emul.h>
#include <acrn_common.h>

#include <vmrt.h>

#define CPU_REG_FIRST			CPU_REG_RAX
#define CPU_REG_LAST			CPU_REG_GDTR
#define CPU_REG_GENERAL_FIRST		CPU_REG_RAX
#define CPU_REG_GENERAL_LAST		CPU_REG_R15
#define CPU_REG_NONGENERAL_FIRST	CPU_REG_CR0
#define CPU_REG_NONGENERAL_LAST	CPU_REG_GDTR
#define CPU_REG_NATURAL_FIRST		CPU_REG_CR0
#define CPU_REG_NATURAL_LAST		CPU_REG_RFLAGS
#define CPU_REG_64BIT_FIRST		CPU_REG_EFER
#define CPU_REG_64BIT_LAST		CPU_REG_PDPTE3
#define CPU_REG_SEG_FIRST		CPU_REG_ES
#define CPU_REG_SEG_LAST		CPU_REG_GS

#define	PSL_C		0x00000001U	/* carry bit */
#define	PSL_PF		0x00000004U	/* parity bit */
#define	PSL_AF		0x00000010U	/* bcd carry bit */
#define	PSL_Z		0x00000040U	/* zero bit */
#define	PSL_N		0x00000080U	/* negative bit */
#define	PSL_D		0x00000400U	/* string instruction direction bit */
#define	PSL_V		0x00000800U	/* overflow bit */
#define	PSL_AC		0x00040000U	/* alignment checking */

/*
 * Protections are chosen from these bits, or-ed together
 */
#define	PROT_READ	0x01U	/* pages can be read */
#define	PROT_WRITE	0x02U	/* pages can be written */

/* struct vie_op.op_type */
#define VIE_OP_TYPE_NONE	0U
#define VIE_OP_TYPE_MOV		1U
#define VIE_OP_TYPE_MOVSX	2U
#define VIE_OP_TYPE_MOVZX	3U
#define VIE_OP_TYPE_AND		4U
#define VIE_OP_TYPE_OR		5U
#define VIE_OP_TYPE_SUB		6U
#define VIE_OP_TYPE_TWO_BYTE	7U
#define VIE_OP_TYPE_PUSH	8U
#define VIE_OP_TYPE_CMP		9U
#define VIE_OP_TYPE_POP		10U
#define VIE_OP_TYPE_MOVS	11U
#define VIE_OP_TYPE_GROUP1	12U
#define VIE_OP_TYPE_STOS	13U
#define VIE_OP_TYPE_BITTEST	14U
#define VIE_OP_TYPE_TEST	15U
#define VIE_OP_TYPE_XCHG	16U

/* struct vie_op.op_flags */
#define VIE_OP_F_IMM		(1U << 0U)  /* 16/32-bit immediate operand */
#define VIE_OP_F_IMM8		(1U << 1U)  /* 8-bit immediate operand */
#define VIE_OP_F_MOFFSET	(1U << 2U)  /* 16/32/64-bit immediate moffset */
#define VIE_OP_F_NO_MODRM	(1U << 3U)
#define VIE_OP_F_CHECK_GVA_DI	(1U << 4U)  /* for movs, need to check DI */
/*
 * The VIE_OP_F_BYTE_OP only set when the instruction support
 * Encoding of Operand Size (w) Bit and the w bit of opcode is 0.
 * according B.2 GENERAL-PURPOSE INSTRUCTION FORMATS AND ENCODINGS
 * FOR NON-64-BIT MODES, Vol 2, Intel SDM.
 */
#define VIE_OP_F_BYTE_OP	(1U << 5U)  /* 8-bit operands. */
#define VIE_OP_F_WORD_OP	(1U << 6U)  /* 16-bit operands. */

static const struct instr_emul_vie_op two_byte_opcodes[256] = {
	[0xB6] = {
		.op_type = VIE_OP_TYPE_MOVZX,
		.op_flags = VIE_OP_F_BYTE_OP,
	},
	[0xB7] = {
		.op_type = VIE_OP_TYPE_MOVZX,
		.op_flags = VIE_OP_F_WORD_OP,
	},
	[0xBA] = {
		.op_type = VIE_OP_TYPE_BITTEST,
		.op_flags = VIE_OP_F_IMM8,
	},
	[0xBE] = {
		.op_type = VIE_OP_TYPE_MOVSX,
		.op_flags = VIE_OP_F_BYTE_OP,
	},
};

static const struct instr_emul_vie_op one_byte_opcodes[256] = {
	[0x0F] = {
		.op_type = VIE_OP_TYPE_TWO_BYTE
	},
	[0x2B] = {
		.op_type = VIE_OP_TYPE_SUB,
	},
	[0x39] = {
		.op_type = VIE_OP_TYPE_CMP,
	},
	[0x3B] = {
		.op_type = VIE_OP_TYPE_CMP,
	},
	[0x88] = {
		.op_type = VIE_OP_TYPE_MOV,
		.op_flags = VIE_OP_F_BYTE_OP,
	},
	[0x89] = {
		.op_type = VIE_OP_TYPE_MOV,
	},
	[0x8A] = {
		.op_type = VIE_OP_TYPE_MOV,
		.op_flags = VIE_OP_F_BYTE_OP,
	},
	[0x8B] = {
		.op_type = VIE_OP_TYPE_MOV,
	},
	[0xA1] = {
		.op_type = VIE_OP_TYPE_MOV,
		.op_flags = VIE_OP_F_MOFFSET | VIE_OP_F_NO_MODRM,
	},
	[0xA3] = {
		.op_type = VIE_OP_TYPE_MOV,
		.op_flags = VIE_OP_F_MOFFSET | VIE_OP_F_NO_MODRM,
	},
	[0xA4] = {
		.op_type = VIE_OP_TYPE_MOVS,
		.op_flags = VIE_OP_F_NO_MODRM | VIE_OP_F_CHECK_GVA_DI | VIE_OP_F_BYTE_OP,
	},
	[0xA5] = {
		.op_type = VIE_OP_TYPE_MOVS,
		.op_flags = VIE_OP_F_NO_MODRM | VIE_OP_F_CHECK_GVA_DI,
	},
	[0xAA] = {
		.op_type = VIE_OP_TYPE_STOS,
		.op_flags = VIE_OP_F_NO_MODRM | VIE_OP_F_BYTE_OP,
	},
	[0xAB] = {
		.op_type = VIE_OP_TYPE_STOS,
		.op_flags = VIE_OP_F_NO_MODRM
	},
	[0xC6] = {
		/* XXX Group 11 extended opcode - not just MOV */
		.op_type = VIE_OP_TYPE_MOV,
		.op_flags = VIE_OP_F_IMM8 | VIE_OP_F_BYTE_OP,
	},
	[0xC7] = {
		.op_type = VIE_OP_TYPE_MOV,
		.op_flags = VIE_OP_F_IMM,
	},
	[0x23] = {
		.op_type = VIE_OP_TYPE_AND,
	},
	[0x80] = {
		/* Group 1 extended opcode */
		.op_type = VIE_OP_TYPE_GROUP1,
		.op_flags = VIE_OP_F_IMM8,
	},
	[0x81] = {
		/* Group 1 extended opcode */
		.op_type = VIE_OP_TYPE_GROUP1,
		.op_flags = VIE_OP_F_IMM,
	},
	[0x83] = {
		/* Group 1 extended opcode */
		.op_type = VIE_OP_TYPE_GROUP1,
		.op_flags = VIE_OP_F_IMM8,
	},
	[0x84] = {
		.op_type = VIE_OP_TYPE_TEST,
		.op_flags = VIE_OP_F_BYTE_OP,
	},
	[0x85] = {
		.op_type = VIE_OP_TYPE_TEST,
	},
	[0x86] = {
		.op_type = VIE_OP_TYPE_XCHG,
	},
	[0x87] = {
		.op_type = VIE_OP_TYPE_XCHG,
	},
	[0x08] = {
		.op_type = VIE_OP_TYPE_OR,
		.op_flags = VIE_OP_F_BYTE_OP,
	},
	[0x09] = {
		.op_type = VIE_OP_TYPE_OR,
	},
};

/* struct vie.mod */
#define	VIE_MOD_INDIRECT		0U
#define	VIE_MOD_INDIRECT_DISP8		1U
#define	VIE_MOD_INDIRECT_DISP32		2U
#define	VIE_MOD_DIRECT			3U

/* struct vie.rm */
#define	VIE_RM_SIB			4U
#define	VIE_RM_DISP32			5U

static uint64_t size2mask[9] = {
	[1] = (1UL << 8U) - 1UL,
	[2] = (1UL << 16U) - 1UL,
	[4] = (1UL << 32U) - 1UL,
	[8] = ~0UL,
};

#define VMX_INVALID_VMCS_FIELD  0xffffffffU

/*
 * This struct vmcs_seg_field is defined separately to hold the vmcs field
 * address of segment selector.
 */
struct vmcs_seg_field {
	uint32_t	base_field;
	uint32_t	limit_field;
	uint32_t	access_field;
};

/*
 * The 'access' field has the format specified in Table 21-2 of the Intel
 * Architecture Manual vol 3b.
 *
 * XXX The contents of the 'access' field are architecturally defined except
 * bit 16 - Segment Unusable.
 */
struct seg_desc {
	uint64_t	base;
	uint32_t	limit;
	uint32_t	access;
};

static inline struct acrn_mmio_request *vcpu_mmio_req(struct vmrt_vm_vcpu *vcpu)
{
	return (struct acrn_mmio_request *)(vcpu->mmio_request);
}

static inline uint32_t seg_desc_type(uint32_t access)
{
	return (access & 0x001fU);
}

static uint64_t vm_get_register(struct vmrt_vm_vcpu *vcpu, enum cpu_reg_name reg)
{
	volatile struct vm_vcpu_shared_region *regs = vcpu->shared_region;
	uint64_t reg_val = 0UL;

	switch (reg)
	{
	case CPU_REG_RAX:
		reg_val = regs->ax; 
		break;
	case CPU_REG_RCX:
		reg_val = regs->cx; 
		break;
	case CPU_REG_RDX:
		reg_val = regs->dx; 
		break;
	case CPU_REG_RBX:
		reg_val = regs->bx; 
		break;
	case CPU_REG_RSP:
		reg_val = regs->sp; 
		break;
	case CPU_REG_RBP:
		reg_val = regs->bp; 
		break;
	case CPU_REG_RSI:
		reg_val = regs->si; 
		break;
	case CPU_REG_RDI:
		reg_val = regs->di; 
		break;
	case CPU_REG_R8:
		reg_val = regs->r8; 
		break;
	case CPU_REG_R9:
		reg_val = regs->r9; 
		break;
	case CPU_REG_R10:
		reg_val = regs->r10; 
		break;
	case CPU_REG_R11:
		reg_val = regs->r11; 
		break;
	case CPU_REG_R12:
		reg_val = regs->r12; 
		break;
	case CPU_REG_R13:
		reg_val = regs->r13; 
		break;
	case CPU_REG_R14:
		reg_val = regs->r14; 
		break;
	case CPU_REG_R15:
		reg_val = regs->r15; 
		break;		
	default:
		VM_PANIC(vcpu);
		break;
	}

	return reg_val;
}

static void vm_set_register(struct vmrt_vm_vcpu *vcpu, enum cpu_reg_name reg,
								uint64_t val)
{
	volatile struct vm_vcpu_shared_region *regs = vcpu->shared_region;

	switch (reg)
	{
	case CPU_REG_RAX:
		regs->ax = val; 
		break;
	case CPU_REG_RCX:
		regs->cx = val; 
		break;
	case CPU_REG_RDX:
		regs->dx = val; 
		break;
	case CPU_REG_RBX:
		regs->bx = val; 
		break;
	case CPU_REG_RSP:
		regs->sp = val; 
		break;
	case CPU_REG_RBP:
		regs->bp = val; 
		break;
	case CPU_REG_RSI:
		regs->si = val; 
		break;
	case CPU_REG_RDI:
		regs->di = val; 
		break;
	case CPU_REG_R8:
		regs->r8 = val; 
		break;
	case CPU_REG_R9:
		regs->r9 = val; 
		break;
	case CPU_REG_R10:
		regs->r10 = val; 
		break;
	case CPU_REG_R11:
		regs->r11 = val; 
		break;
	case CPU_REG_R12:
		regs->r12 = val; 
		break;
	case CPU_REG_R13:
		regs->r13 = val; 
		break;
	case CPU_REG_R14:
		regs->r14 = val; 
		break;
	case CPU_REG_R15:
		regs->r15 = val; 
		break;		
	default:
		VM_PANIC(vcpu);
		break;
	}
}

static int32_t vie_canonical_check(uint64_t gla)
{
	int32_t ret = 0;
	uint64_t mask;

	/*
	 * The value of the bit 47 in the 'gla' should be replicated in the
	 * most significant 16 bits.
	 */
	mask = ~((1UL << 48U) - 1UL);
	if ((gla & (1UL << 47U)) != 0U) {
		ret = ((gla & mask) != mask) ? 1 : 0;
	} else {
		ret = ((gla & mask) != 0U) ? 1 : 0;
	}

	return ret;
}

/*
 * @pre vcpu != NULL
 */
static inline void vie_mmio_read(struct vmrt_vm_vcpu *vcpu, uint64_t *rval)
{
	*rval = vcpu_mmio_req(vcpu)->value;
}

/*
 * @pre vcpu != NULL
 */
static inline void vie_mmio_write(struct vmrt_vm_vcpu *vcpu, uint64_t wval)
{
	vcpu_mmio_req(vcpu)->value = wval;
}

static void vie_calc_bytereg(const struct instr_emul_vie *vie,
					enum cpu_reg_name *reg, int32_t *lhbr)
{
	*lhbr = 0;
	*reg = (enum cpu_reg_name)(vie->reg);

	/*
	 * 64-bit mode imposes limitations on accessing legacy high byte
	 * registers (lhbr).
	 *
	 * The legacy high-byte registers cannot be addressed if the REX
	 * prefix is present. In this case the values 4, 5, 6 and 7 of the
	 * 'ModRM:reg' field address %spl, %bpl, %sil and %dil respectively.
	 *
	 * If the REX prefix is not present then the values 4, 5, 6 and 7
	 * of the 'ModRM:reg' field address the legacy high-byte registers,
	 * %ah, %ch, %dh and %bh respectively.
	 */
	if (vie->rex_present == 0U) {
		if ((vie->reg & 0x4U) != 0U) {
			*lhbr = 1;
			*reg = (enum cpu_reg_name)(vie->reg & 0x3U);
		}
	}
}

static uint8_t vie_read_bytereg(struct vmrt_vm_vcpu *vcpu, const struct instr_emul_vie *vie)
{
	int32_t lhbr;
	uint64_t val;
	uint8_t reg_val;
	enum cpu_reg_name reg;

	vie_calc_bytereg(vie, &reg, &lhbr);
	val = vm_get_register(vcpu, reg);

	/*
	 * To obtain the value of a legacy high byte register shift the
	 * base register right by 8 bits (%ah = %rax >> 8).
	 */
	if (lhbr != 0) {
		reg_val = (uint8_t)(val >> 8U);
	} else {
		reg_val = (uint8_t)val;
	}

	return reg_val;
}

static void vie_write_bytereg(struct vmrt_vm_vcpu *vcpu, const struct instr_emul_vie *vie,
								uint8_t byte)
{
	uint64_t origval, val, mask;
	enum cpu_reg_name reg;
	int32_t lhbr;

	vie_calc_bytereg(vie, &reg, &lhbr);
	origval = vm_get_register(vcpu, reg);

	val = byte;
	mask = 0xffU;
	if (lhbr != 0) {
		/*
		 * Shift left by 8 to store 'byte' in a legacy high
		 * byte register.
		 */
		val <<= 8U;
		mask <<= 8U;
	}
	val |= origval & ~mask;
	vm_set_register(vcpu, reg, val);
}

/**
 * @pre vcpu != NULL
 * @pre size = 1, 2, 4 or 8
 * @pre ((reg <= CPU_REG_LAST) && (reg >= CPU_REG_FIRST))
 * @pre ((reg != CPU_REG_CR2) && (reg != CPU_REG_IDTR) && (reg != CPU_REG_GDTR))
 */
static void vie_update_register(struct vmrt_vm_vcpu *vcpu, enum cpu_reg_name reg,
					uint64_t val_arg, uint8_t size)
{
	uint64_t origval;
	uint64_t val = val_arg;

	switch (size) {
	case 1U:
	case 2U:
		origval = vm_get_register(vcpu, reg);
		val &= size2mask[size];
		val |= origval & ~size2mask[size];
		break;
	case 4U:
		val &= 0xffffffffUL;
		break;
	default: /* size == 8 */
		break;
	}

	vm_set_register(vcpu, reg, val);
}

#define	RFLAGS_STATUS_BITS    (PSL_C | PSL_PF | PSL_AF | PSL_Z | PSL_N | PSL_V)

static void vie_update_rflags(struct vmrt_vm_vcpu *vcpu, uint64_t rflags2, uint64_t psl)
{
	uint8_t size;
	uint64_t rflags;

	rflags = vm_get_register(vcpu, CPU_REG_RFLAGS);

	rflags &= ~RFLAGS_STATUS_BITS;
	rflags |= rflags2 & psl;
	size = 8U;

	vie_update_register(vcpu, CPU_REG_RFLAGS, rflags, size);
}

/*
 * Return the status flags that would result from doing (x - y).
 */
#define build_getcc(name, type)					\
static uint64_t name(type x, type y)				\
{								\
	uint64_t rflags;					\
								\
	__asm __volatile("sub %2,%1; pushfq; popq %0" :		\
			"=r" (rflags), "+r" (x) : "m" (y));	\
	return rflags;						\
}
build_getcc(getcc8, uint8_t)
build_getcc(getcc16, uint16_t)
build_getcc(getcc32, uint32_t)
build_getcc(getcc64, uint64_t)

/**
 * @pre opsize = 1, 2, 4 or 8
 */
static uint64_t getcc(uint8_t opsize, uint64_t x, uint64_t y)
{
	uint64_t rflags;
	switch (opsize) {
	case 1U:
		rflags = getcc8((uint8_t) x, (uint8_t) y);
		break;
	case 2U:
		rflags = getcc16((uint16_t) x, (uint16_t) y);
		break;
	case 4U:
		rflags = getcc32((uint32_t) x, (uint32_t) y);
		break;
	default:	/* opsize == 8 */
		rflags = getcc64(x, y);
		break;
	}

	return rflags;
}

static int32_t emulate_mov(struct vmrt_vm_vcpu *vcpu, const struct instr_emul_vie *vie)
{
	int32_t error;
	uint8_t size;
	enum cpu_reg_name reg;
	uint8_t byte;
	uint64_t val;

	size = vie->opsize;
	error = 0;
	switch (vie->opcode) {
	case 0x88U:
	/*
	 * MOV byte from reg (ModRM:reg) to mem (ModRM:r/m)
	 * 88/r:	mov r/m8, r8
	 * REX + 88/r:	mov r/m8, r8 (%ah, %ch, %dh, %bh not available)
	 */
		byte = vie_read_bytereg(vcpu, vie);
		vie_mmio_write(vcpu, byte);
		break;
	case 0x89U:
		/*
		 * MOV from reg (ModRM:reg) to mem (ModRM:r/m)
		 * 89/r:	mov r/m16, r16
		 * 89/r:	mov r/m32, r32
		 * REX.W + 89/r	mov r/m64, r64
		 */

		reg = (enum cpu_reg_name)(vie->reg);
		val = vm_get_register(vcpu, reg);
		val &= size2mask[size];
		vie_mmio_write(vcpu, val);
		break;
	case 0x8AU:
		/*
		 * MOV byte from mem (ModRM:r/m) to reg (ModRM:reg)
		 * 8A/r:	mov r8, r/m8
		 * REX + 8A/r:	mov r8, r/m8
		 */
		vie_mmio_read(vcpu, &val);
		vie_write_bytereg(vcpu, vie, (uint8_t)val);
		break;
	case 0x8BU:
		/*
		 * MOV from mem (ModRM:r/m) to reg (ModRM:reg)
		 * 8B/r:	mov r16, r/m16
		 * 8B/r:	mov r32, r/m32
		 * REX.W 8B/r:	mov r64, r/m64
		 */
		vie_mmio_read(vcpu, &val);
		reg = (enum cpu_reg_name)(vie->reg);
		vie_update_register(vcpu, reg, val, size);
		break;
	case 0xA1U:
		/*
		 * MOV from seg:moffset to AX/EAX/RAX
		 * A1:		mov AX, moffs16
		 * A1:		mov EAX, moffs32
		 * REX.W + A1:	mov RAX, moffs64
		 */
		vie_mmio_read(vcpu, &val);
		reg = CPU_REG_RAX;
		vie_update_register(vcpu, reg, val, size);
		break;
	case 0xA3U:
		/*
		 * MOV from AX/EAX/RAX to seg:moffset
		 * A3:		mov moffs16, AX
		 * A3:		mov moffs32, EAX
		 * REX.W + A3:	mov moffs64, RAX
		 */
		val = vm_get_register(vcpu, CPU_REG_RAX);
		val &= size2mask[size];
		vie_mmio_write(vcpu, val);
		break;
	case 0xC6U:
		/*
		 * MOV from imm8 to mem (ModRM:r/m)
		 * C6/0		mov r/m8, imm8
		 * REX + C6/0	mov r/m8, imm8
		 */
		vie_mmio_write(vcpu, (uint64_t)vie->immediate);
		break;
	case 0xC7U:
		/*
		 * MOV from imm16/imm32 to mem (ModRM:r/m)
		 * C7/0		mov r/m16, imm16
		 * C7/0		mov r/m32, imm32
		 * REX.W + C7/0	mov r/m64, imm32
		 *		(sign-extended to 64-bits)
		 */
		val = (uint64_t)(vie->immediate) & size2mask[size];
		vie_mmio_write(vcpu, val);
		break;
	default:
		/*
		 * For the opcode that is not handled (an invalid opcode), the
		 * error code is assigned to a default value (-EINVAL).
		 * Gracefully return this error code if prior case clauses have
		 * not been met.
		 */
		error = -EINVAL;
		break;
	}

	return error;
}

static void copy_from_gva(struct vmrt_vm_vcpu *vcpu, void *buf, u64_t gva, u32_t len)
{
	void *src = GPA2HVA(vmrt_vm_gva2gpa(vcpu, gva), vcpu->vm);
	memcpy(buf, src, len);
}

static int32_t vie_init(struct instr_emul_vie *vie, struct vmrt_vm_vcpu *vcpu)
{
	volatile struct vm_vcpu_shared_region *regs = vcpu->shared_region;
	u64_t inst_len = regs->inst_length;
	int32_t ret;

	if ((inst_len > VIE_INST_SIZE) || (inst_len == 0U)) {
		VM_PANIC(vcpu);
	} else {
		(void)memset(vie, 0U, sizeof(struct instr_emul_vie));

		/* init register fields in vie. */
		vie->base_register = CPU_REG_LAST;
		vie->index_register = CPU_REG_LAST;
		vie->segment_register = CPU_REG_LAST;

		copy_from_gva(vcpu, vie->inst, regs->ip, inst_len);
		/*
		 * Use this to print the inst binary to verify if the decodeed inst is correct
		 *
			printc("inst to be decode: ");
			for (u64_t i = 0; i < inst_len; i++) {
				printc("%x ", vie->inst[i]);
			}
			printc("\ninst vie init done\n");
		*/
		
		vie->num_valid = (uint8_t)inst_len;
		ret = 0;
	}

	return ret;
}

static int32_t vie_peek(const struct instr_emul_vie *vie, uint8_t *x)
{
	int32_t ret;
	if (vie->num_processed < vie->num_valid) {
		*x = vie->inst[vie->num_processed];
		ret = 0;
	} else {
		ret = -1;
	}
	return ret;
}

static void vie_advance(struct instr_emul_vie *vie)
{

	vie->num_processed++;
}

static bool segment_override(uint8_t x, enum cpu_reg_name *seg)
{
	bool override = true;
	switch (x) {
	case 0x2EU:
		*seg = CPU_REG_CS;
		break;
	case 0x36U:
		*seg = CPU_REG_SS;
		break;
	case 0x3EU:
		*seg = CPU_REG_DS;
		break;
	case 0x26U:
		*seg = CPU_REG_ES;
		break;
	case 0x64U:
		*seg = CPU_REG_FS;
		break;
	case 0x65U:
		*seg = CPU_REG_GS;
		break;
	default:
		override = false;
		break;
	}
	return override;
}

static void decode_op_and_addr_size(struct instr_emul_vie *vie)
{
	/*
	 * Section "Operand-Size And Address-Size Attributes", Intel SDM, Vol 1
	 */

	/*
	 * Default address size is 64-bits and default operand size
	 * is 32-bits.
	 */
	vie->addrsize = ((vie->addrsize_override != 0U) ? 4U : 8U);
	if (vie->rex_w != 0U) {
		vie->opsize = 8U;
	} else if (vie->opsize_override != 0U) {
		vie->opsize = 2U;
	} else {
		vie->opsize = 4U;
	}
}
static int32_t decode_prefixes(struct instr_emul_vie *vie)
{
	uint8_t x, i;
	int32_t ret  = 0;

	for (i = 0U; i < VIE_PREFIX_SIZE; i++) {
		if (vie_peek(vie, &x) != 0) {
			ret = -1;
			break;
		} else {
			if (x == 0x66U) {
				vie->opsize_override = 1U;
			} else if (x == 0x67U) {
				vie->addrsize_override = 1U;
			} else if (x == 0xF3U) {
				vie->repz_present = 1U;
			} else if (x == 0xF2U) {
				vie->repnz_present = 1U;
			} else if (segment_override(x, &vie->segment_register)) {
				vie->seg_override = 1U;
			} else {
				break;
			}

			vie_advance(vie);
		}
	}

	if (ret == 0) {
		/*
		 * From section 2.2.1, "REX Prefixes", Intel SDM Vol 2:
		 * - Only one REX prefix is allowed per instruction.
		 * - The REX prefix must immediately precede the opcode byte or the
		 *   escape opcode byte.
		 * - If an instruction has a mandatory prefix (0x66, 0xF2 or 0xF3)
		 *   the mandatory prefix must come before the REX prefix.
		 */
		if ( (x >= 0x40U) && (x <= 0x4FU)) {
			vie->rex_present = 1U;
			vie->rex_w = (x >> 0x3U) & 1U;
			vie->rex_r = (x >> 0x2U) & 1U;
			vie->rex_x = (x >> 0x1U) & 1U;
			vie->rex_b = (x >> 0x0U) & 1U;
			vie_advance(vie);
		}
		decode_op_and_addr_size(vie);
	}

	return ret;
}

static int32_t decode_two_byte_opcode(struct instr_emul_vie *vie)
{
	int32_t ret = 0;
	uint8_t x;

	if (vie_peek(vie, &x) != 0) {
		ret = -1;
	} else {
		vie->opcode = x;
		vie->op = two_byte_opcodes[x];

		if (vie->op.op_type == VIE_OP_TYPE_NONE) {
			ret = -1;
		} else {
			vie_advance(vie);
		}
	}

	return ret;
}

static int32_t decode_opcode(struct instr_emul_vie *vie)
{
	int32_t ret = 0;
	uint8_t x;

	if (vie_peek(vie, &x) != 0) {
		ret = -1;
	} else {
		vie->opcode = x;
		vie->op = one_byte_opcodes[x];

		if (vie->op.op_type == VIE_OP_TYPE_NONE) {
			ret = -1;
		} else {
			vie_advance(vie);

			if (vie->op.op_type == VIE_OP_TYPE_TWO_BYTE) {
				ret = decode_two_byte_opcode(vie);
			}
		}
	}

	return ret;
}

static int32_t decode_modrm(struct instr_emul_vie *vie)
{
	uint8_t x;
	int32_t ret;

	if ((vie->op.op_flags & VIE_OP_F_NO_MODRM) != 0U) {
		ret = 0;
	} else if (vie_peek(vie, &x) != 0) {
		ret = -1;
	} else {
		vie->mod = (x >> 6U) & 0x3U;
		vie->rm =  (x >> 0U) & 0x7U;
		vie->reg = (x >> 3U) & 0x7U;

		/*
		 * A direct addressing mode makes no sense in the context of an EPT
		 * fault. There has to be a memory access involved to cause the
		 * EPT fault.
		 */
		if (vie->mod == VIE_MOD_DIRECT) {
			ret = -1;
		} else {
			if (((vie->mod == VIE_MOD_INDIRECT) && (vie->rm == VIE_RM_DISP32)) ||
					((vie->mod != VIE_MOD_DIRECT) && (vie->rm == VIE_RM_SIB))) {
				/*
				 * Table 2-5: Special Cases of REX Encodings
				 *
				 * mod=0, r/m=5 is used in the compatibility mode to
				 * indicate a disp32 without a base register.
				 *
				 * mod!=3, r/m=4 is used in the compatibility mode to
				 * indicate that the SIB byte is present.
				 *
				 * The 'b' bit in the REX prefix is don't care in
				 * this case.
				 */
			} else {
				vie->rm |= (vie->rex_b << 3U);
			}

			vie->reg |= (vie->rex_r << 3U);

			/* SIB */
			if ((vie->mod != VIE_MOD_DIRECT) && (vie->rm == VIE_RM_SIB)) {
				/* done */
			} else {
				vie->base_register = (enum cpu_reg_name)vie->rm;

				switch (vie->mod) {
				case VIE_MOD_INDIRECT_DISP8:
					vie->disp_bytes = 1U;
					break;
				case VIE_MOD_INDIRECT_DISP32:
					vie->disp_bytes = 4U;
					break;
				case VIE_MOD_INDIRECT:
					if (vie->rm == VIE_RM_DISP32) {
						vie->disp_bytes = 4U;
						/*
						 * Table 2-7. RIP-Relative Addressing
						 *
						 * In 64-bit mode mod=00 r/m=101 implies [rip] + disp32
						 * whereas in compatibility mode it just implies disp32.
						 */

						vie->base_register = CPU_REG_RIP;
						printc("VM exit with RIP as indirect access");
						assert(0);
					}
					break;
				default:
					/* VIE_MOD_DIRECT */
					break;
				}

			}
			vie_advance(vie);

			ret = 0;
		}
	}

	return ret;
}

static int32_t decode_sib(struct instr_emul_vie *vie)
{
	uint8_t x;
	int32_t ret;

	/* Proceed only if SIB byte is present */
	if ((vie->mod == VIE_MOD_DIRECT) || (vie->rm != VIE_RM_SIB)) {
		ret = 0;
	} else if (vie_peek(vie, &x) != 0) {
		ret = -1;
	} else {

		/* De-construct the SIB byte */
		vie->ss = (x >> 6U) & 0x3U;
		vie->index = (x >> 3U) & 0x7U;
		vie->base = (x >> 0U) & 0x7U;

		/* Apply the REX prefix modifiers */
		vie->index |= vie->rex_x << 3U;
		vie->base |= vie->rex_b << 3U;

		switch (vie->mod) {
		case VIE_MOD_INDIRECT_DISP8:
			vie->disp_bytes = 1U;
			break;
		case VIE_MOD_INDIRECT_DISP32:
			vie->disp_bytes = 4U;
			break;
		default:
			/*
			 * All possible values of 'vie->mod':
			 * 1. VIE_MOD_DIRECT
			 *    has been handled at the start of this function
			 * 2. VIE_MOD_INDIRECT_DISP8
			 *    has been handled in prior case clauses
			 * 3. VIE_MOD_INDIRECT_DISP32
			 *    has been handled in prior case clauses
			 * 4. VIE_MOD_INDIRECT
			 *    will be handled later after this switch statement
			 */
			break;
		}

		if ((vie->mod == VIE_MOD_INDIRECT) && ((vie->base == 5U) || (vie->base == 13U))) {
			/*
			 * Special case when base register is unused if mod = 0
			 * and base = %rbp or %r13.
			 *
			 * Documented in:
			 * Table 2-3: 32-bit Addressing Forms with the SIB Byte
			 * Table 2-5: Special Cases of REX Encodings
			 */
			vie->disp_bytes = 4U;
		} else {
			vie->base_register = (enum cpu_reg_name)vie->base;
		}

		/*
		 * All encodings of 'index' are valid except for %rsp (4).
		 *
		 * Documented in:
		 * Table 2-3: 32-bit Addressing Forms with the SIB Byte
		 * Table 2-5: Special Cases of REX Encodings
		 */
		if (vie->index != 4U) {
			vie->index_register = (enum cpu_reg_name)vie->index;
		}

		/* 'scale' makes sense only in the context of an index register */
		if (vie->index_register < CPU_REG_LAST) {
			vie->scale = 1U << vie->ss;
		}

		vie_advance(vie);

		ret = 0;
	}

	return ret;
}

static int32_t decode_displacement(struct instr_emul_vie *vie)
{
	uint8_t n, i, x;
	int32_t ret = 0;

	union {
		uint8_t	buf[4];
		int8_t	signed8;
		int32_t	signed32;
	} u;

	n = vie->disp_bytes;
	if (n != 0U) {
		if ((n != 1U) && (n != 4U)) {
			printc("%s: decode_displacement: invalid disp_bytes %d", __func__, n);
			ret = -EINVAL;
		} else {

			for (i = 0U; i < n; i++) {
				if (vie_peek(vie, &x) != 0) {
					ret = -1;
					break;
				}

				u.buf[i] = x;
				vie_advance(vie);
			}

			if (ret == 0) {
				if (n == 1U) {
					vie->displacement = u.signed8;		/* sign-extended */
				} else {
					vie->displacement = u.signed32;		/* sign-extended */
				}
			}
		}
	}

	return ret;
}

static int32_t decode_immediate(struct instr_emul_vie *vie)
{
	uint8_t i, n, x;
	int32_t ret = 0;
	union {
		uint8_t	buf[4];
		int8_t	signed8;
		int16_t	signed16;
		int32_t	signed32;
	} u;

	/* Figure out immediate operand size (if any) */
	if ((vie->op.op_flags & VIE_OP_F_IMM) != 0U) {
		/*
		 * Section 2.2.1.5 "Immediates", Intel SDM:
		 * In 64-bit mode the typical size of immediate operands
		 * remains 32-bits. When the operand size if 64-bits, the
		 * processor sign-extends all immediates to 64-bits prior
		 * to their use.
		 */
		if ((vie->opsize == 4U) || (vie->opsize == 8U)) {
			vie->imm_bytes = 4U;
		}
		else {
			vie->imm_bytes = 2U;
		}
	} else if ((vie->op.op_flags & VIE_OP_F_IMM8) != 0U) {
		vie->imm_bytes = 1U;
	} else {
		/* No op_flag on immediate operand size */
	}

	n = vie->imm_bytes;
	if (n != 0U) {
		if ((n != 1U) && (n != 2U) && (n != 4U)) {
			printc("%s: invalid number of immediate bytes: %d", __func__, n);
			ret = -EINVAL;
		} else {
			for (i = 0U; i < n; i++) {
				if (vie_peek(vie, &x) != 0) {
					ret = -1;
					break;
				}

				u.buf[i] = x;
				vie_advance(vie);
			}

			if (ret == 0) {
				/* sign-extend the immediate value before use */
				if (n == 1U) {
					vie->immediate = u.signed8;
				} else if (n == 2U) {
					vie->immediate = u.signed16;
				} else {
					vie->immediate = u.signed32;
				}
			}
		}
	}

	return ret;
}

static int32_t decode_moffset(struct instr_emul_vie *vie)
{
	uint8_t i, n, x;
	int32_t ret = 0;
	union {
		uint8_t  buf[8];
		uint64_t u64;
	} u;

	if ((vie->op.op_flags & VIE_OP_F_MOFFSET) != 0U) {
		/*
		 * Section 2.2.1.4, "Direct Memory-Offset MOVs", Intel SDM:
		 * The memory offset size follows the address-size of the instruction.
		 */
		n = vie->addrsize;
		if ((n != 2U) && (n != 4U) && (n != 8U)) {
			printc("%s: invalid moffset bytes: %hhu", __func__, n);
			ret = -EINVAL;
		} else {
			u.u64 = 0UL;
			for (i = 0U; i < n; i++) {
				if (vie_peek(vie, &x) != 0) {
					ret = -1;
					break;
				}

				u.buf[i] = x;
				vie_advance(vie);
			}
			if (ret == 0) {
				vie->displacement = (int64_t)u.u64;
			}
		}
	}

	return ret;
}

static int32_t local_decode_instruction(struct instr_emul_vie *vie)
{
	int32_t ret;

	if (decode_prefixes(vie) != 0) {
		ret = -1;
	} else if (decode_opcode(vie) != 0) {
		ret = -1;
	} else if (decode_modrm(vie) != 0) {
		ret = -1;
	} else if (decode_sib(vie) != 0) {
		ret = -1;
	} else if (decode_displacement(vie) != 0) {
		ret = -1;
	} else if (decode_immediate(vie) != 0) {
		ret = -1;
	} else if (decode_moffset(vie) != 0) {
		ret = -1;
	} else {
		vie->decoded = 1U;	/* success */
		ret = 0;
	}

	return ret;
}

static int32_t instr_check_gva(struct vmrt_vm_vcpu *vcpu)
{
	int32_t ret = 0;
	uint64_t base, segbase, idx, gva;
	enum cpu_reg_name seg;
	struct instr_emul_vie *vie = &((struct instr_emul_ctxt *)vcpu->inst_ctxt)->vie;

	base = 0UL;
	if (vie->base_register != CPU_REG_LAST) {
		base = vm_get_register(vcpu, vie->base_register);

		/* RIP relative addressing starts from the
		 * following instruction
		 */
		if (vie->base_register == CPU_REG_RIP) {
			base += vie->num_processed;
		}

	}

	idx = 0UL;
	if (vie->index_register != CPU_REG_LAST) {
		idx = vm_get_register(vcpu, vie->index_register);
	}

	/* "Specifying a Segment Selector" of SDM Vol1 3.7.4
	 *
	 * In legacy IA-32 mode, when ESP or EBP register is used as
	 * base, the SS segment is default segment.
	 *
	 * All data references, except when relative to stack or
	 * string destination, DS is default segment.
	 *
	 * segment override could overwrite the default segment
	 *
	 * 64bit mode, segmentation is generally disabled. The
	 * exception are FS and GS.
	 */
	if (vie->seg_override != 0U) {
		seg = vie->segment_register;
	} else if ((vie->base_register == CPU_REG_RSP) ||
			(vie->base_register == CPU_REG_RBP)) {
		seg = CPU_REG_SS;
	} else {
		seg = CPU_REG_DS;
	}

	if ((seg != CPU_REG_FS) &&
			(seg != CPU_REG_GS)) {
		segbase = 0UL;
	} else {
		struct seg_desc desc;

		VM_PANIC(vcpu);
		segbase = desc.base;
	}

	gva = segbase + base + (uint64_t)vie->scale * idx + (uint64_t)vie->displacement;

	vie->gva = gva;

	if (vie_canonical_check(gva) != 0) {
		VM_PANIC(vcpu);
	} else {
		#define PAGE_FAULT_WR_FLAG	0x00000002U

		vmrt_vm_gva2gpa(vcpu, gva);
		ret = 0;
		if (ret < 0) {
			VM_PANIC(vcpu);
		} else {
			ret = 0;
		}
	}

	return ret;
}

int32_t decode_instruction(struct vmrt_vm_vcpu *vcpu)
{
	struct instr_emul_ctxt *emul_ctxt;
	uint32_t csar;
	int32_t retval;

	emul_ctxt = vcpu->inst_ctxt;
	retval = vie_init(&emul_ctxt->vie, vcpu);

	if (retval < 0) {
		VM_PANIC(vcpu);
	} else {
		retval = local_decode_instruction(&emul_ctxt->vie);

		if (retval != 0) {
				VM_PANIC(vcpu);
		} else {
			/*
			 * We do operand check in instruction decode phase and
			 * inject exception accordingly. In late instruction
			 * emulation, it will always success.
			 *
			 * We only need to do dst check for movs. For other instructions,
			 * they always has one register and one mmio which trigger EPT
			 * by access mmio. With VMX enabled, the related check is done
			 * by VMX itself before hit EPT violation.
			 *
			 */
			if ((emul_ctxt->vie.op.op_flags & VIE_OP_F_CHECK_GVA_DI) != 0U) {
				VM_PANIC(vcpu);
			} else {
				retval = instr_check_gva(vcpu);
			}

			if (retval >= 0) {
				/* return the Memory Operand byte size */
				if ((emul_ctxt->vie.op.op_flags & VIE_OP_F_BYTE_OP) != 0U) {
					retval = 1;
				} else if ((emul_ctxt->vie.op.op_flags & VIE_OP_F_WORD_OP) != 0U) {
					retval = 2;
				} else {
					retval = (int32_t)emul_ctxt->vie.opsize;
				}
			}
		}
	}

	return retval;
}

int32_t emulate_instruction(struct vmrt_vm_vcpu *vcpu)
{
	struct instr_emul_vie *vie = &((struct instr_emul_ctxt *)vcpu->inst_ctxt)->vie;
	int32_t error;

	if (vie->decoded != 0U) {
		switch (vie->op.op_type) {
		case VIE_OP_TYPE_MOV:
			error = emulate_mov(vcpu, vie);
			break;
		default:
			VM_PANIC(vcpu);
			error = -EINVAL;
			break;
		}
	} else {
		VM_PANIC(vcpu);
		error = -EINVAL;
	}

	return error;
}
