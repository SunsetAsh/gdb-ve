/* Common target dependent code for GDB on ARM systems.
   Copyright (C) 1988-2016 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */
/* Changes by NEC Corporation for the VE port, 2017-2018 */

#ifndef VE_H
#define VE_H

/* Register numbers of various important registers.  */

enum gdb_regnum {
  VE_SP_REGNUM = 40,		/* Contains address of top of stack */
  VE_FP_REGNUM = 38,		/* Frame pointer register */
  VE_LR_REGNUM = 39,		/* address to return to from a function call */
  VE_ARG0_REGNUM = 29,		/* first integer-like argument */
  VE_ARG7_REGNUM = 36,		/* last integer-like argument */
  VE_PC_REGNUM = 19,		/* Contains program counter(IC) */
  VE_PS_REGNUM = 17,		/* Contains processor status(PSW) */

  VE_S0_REGNUM = 29,		/* Top of scalar registers */
  VE_S63_REGNUM = VE_S0_REGNUM + 63,
  VE_VM0_REGNUM,		/* Top of vector mask registers */
  VE_VM15_REGNUM = VE_VM0_REGNUM + 15,
  VE_V0_REGNUM,			/* Top of vector registers */
  VE_V63_REGNUM = VE_V0_REGNUM + 63,

  VE_NUM_REGS,		/* sum of register */

  /* Other useful registers.  */
  VE_LAST_ARG_REGNUM = VE_ARG7_REGNUM,	/* last integer-like argument */

	/* REVISIT */
  VE_FPS_REGNUM = VE_VM0_REGNUM,
  VE_IC_REGNUM = VE_PC_REGNUM,
  VE_IP_REGNUM = VE_PC_REGNUM,
  VE_D0_REGNUM = VE_V0_REGNUM,
  VE_A1_REGNUM = VE_ARG0_REGNUM,
  VE_F0_REGNUM = VE_V0_REGNUM,
  VE_WCGR0_REGNUM = VE_V0_REGNUM,
  VE_WR0_REGNUM = VE_V0_REGNUM,
  VE_WC0_REGNUM = VE_V0_REGNUM,
};

/* Instruction condition field values.  */
#define INST_EQ		0x0
#define INST_NE		0x1
#define INST_CS		0x2
#define INST_CC		0x3
#define INST_MI		0x4
#define INST_PL		0x5
#define INST_VS		0x6
#define INST_VC		0x7
#define INST_HI		0x8
#define INST_LS		0x9
#define INST_GE		0xa
#define INST_LT		0xb
#define INST_GT		0xc
#define INST_LE		0xd
#define INST_AL		0xe
#define INST_NV		0xf

#define FLAG_N		0x80000000
#define FLAG_Z		0x40000000
#define FLAG_C		0x20000000
#define FLAG_V		0x10000000

#define CPSR_T		0x20

#define XPSR_T		0x01000000

/* Size of integer registers.  */
#define INT_REGISTER_SIZE		8

/* Support routines for instruction parsing.  */
#define submask(x) ((1L << ((x) + 1)) - 1)
#define bits(obj,st,fn) (((obj) >> (st)) & submask ((fn) - (st)))
#define bit(obj,st) (((obj) >> (st)) & 1)
#define sbits(obj,st,fn) \
  ((long) (bits(obj,st,fn) | ((long) bit(obj,fn) * ~ submask (fn - st))))
#define BranchDest(addr,instr) \
  ((CORE_ADDR) (((unsigned long) (addr)) + 8 + (sbits (instr, 0, 23) << 2)))

/* VE Specific Ptrace Request which will
 *  * stop the VE Process.
 *   */
#define PTRACE_STOP_VE  25

#define SR_NUM          64      /* Number of Scalar Registers */
#define VR_NUM          64      /* Number of Vector Registers */
#define AUR_MVL         256     /* MAX Length of Vector */

typedef uint64_t reg_t;

typedef uint64_t ve_elf_greg_t;

/**
 * @brief VE Process user registers.
 */
typedef struct {
	/* Performance Counters */
	reg_t USRCC;                    /*     0x0 -     0x7 */
	reg_t PMC[16];                  /*     0x8 -    0x87 */
	uint8_t pad0[0x1000 - 0x88];    /*    0x88 -   0xFFF */
	/* Control Registers */
	reg_t PSW;                      /*  0x1000 -  0x1007 */
	reg_t EXS;                      /*  0x1008 -  0x100F */
	reg_t IC;                       /*  0x1010 -  0x1017 */
	reg_t ICE;                      /*  0x1018 -  0x101F */
	reg_t VIXR;                     /*  0x1020 -  0x1027 */
	reg_t VL;                       /*  0x1028 -  0x102F */
	reg_t SAR;                      /*  0x1030 -  0x1047 */
	reg_t PMMR;                     /*  0x1038 -  0x103F */
	reg_t PMCR[4];                  /*  0x1040 -  0x105F */
	uint8_t pad1[0x1400 - 0x1060];  /*  0x1060 -  0x13FF */
	/* Scalar Registers */
	reg_t SR[SR_NUM];               /*  0x1400 -  0x15FF */
	uint8_t pad2[0x1800 - 0x1600];  /*  0x1600 -  0x17FF */
} ve_elf_gregset_t;

typedef uint64_t ve_elf_fpreg_t;
/**
 * @brief VE Process vector registers.
 */
typedef struct {
	/* Vector Mask Registers */
	reg_t VMR[16][4];               /*  0x0 -  0x1FF */
	uint8_t pad3[0x40000 - 0x1A00]; /*  0x200 - 0x3E7FE */
	/* Vector Registers */
	reg_t VR[VR_NUM][AUR_MVL];      /* 0x3E800 - 0x5FFFF */
	uint8_t pad4[0x80000 - 0x60000];/* 0x5E800 - 0x7E7FF */
} ve_elf_fpregset_t;

#ifndef GDB_GREGSET_T
#define GDB_GREGSET_T ve_elf_gregset_t
#endif
#ifndef GDB_FPREGSET_T
#define GDB_FPREGSET_T ve_elf_fpregset_t
#endif

#endif
