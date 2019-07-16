/* opcodes for NEC VE machine.

   Copyright (C) 2014 NEC Corporation.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.
*/

#ifndef __OPCODES_VE_H__
#define __OPCODES_VE_H__

/* Bit flags */
#define VE_PF_ALL	0

typedef struct ve_opcode {
  char *name;			/* mnemonic */
  unsigned char opcode;		/* opcode 1 byte */
  short format;			/* instruction and opcode format */
  unsigned int flag;		/* instruction flags */
  struct {
    unsigned short x;
    unsigned short y;
    unsigned short z;
    unsigned short w;
    unsigned short m;
    unsigned short d;
  } field;
  unsigned short family;
} ve_opcode;

extern const struct ve_opcode ve_opcodes[];
extern const int ve_num_opcodes;

/*
 * VE instructions are 8 bytes long.
 * The opcode is in the first byte, qualifiers and field details follow.
 * The VE is a little endian machine, therefore loading the instructions
 * into the structure depends on the host machine's endianness.
 */
/* General type */
struct ve_instr_general {
  union {
    struct {
      unsigned char vw;
      unsigned char vz;
      unsigned char vy;
      unsigned char vx;
    } w3;
    int d;
  } lower;
  union {
    struct {
      unsigned char z;
      unsigned char y;
      unsigned char x;
      unsigned char op;
    } w1;
    unsigned int w2;
    unsigned char c[4];
  } upper;
};

/* RR type */
struct ve_instr_rr {
  union {
    unsigned char w;
    struct {
      unsigned char cfw:4;
      unsigned char _dummy:1;
      unsigned char cr:1;
      unsigned char cw2:1;
      unsigned char cw:1;
    } bitw;
  } w;
  unsigned char vz;
  unsigned char _dummy;
  unsigned char vx;
  union {
    unsigned char z;
    struct {
      unsigned char rz:7;
      unsigned char cz:1;
    } bitz;
  } z;
  union {
    unsigned char y;
    struct {
      unsigned char ry:7;
      unsigned char cy:1;
    } bity;
  } y;
  union {
    unsigned char x;
    struct {
      unsigned char rx:7;
      unsigned char cx:1;
    } bitx;
  } x;
  unsigned char op;
};

/* RM type */
struct ve_instr_rm {
  int disp;
  union {
    unsigned char z;
    struct {
      unsigned char rz:7;
      unsigned char cz:1;
    } bitz;
  } z;
  union {
    unsigned char y;
    struct {
      unsigned char ry:7;
      unsigned char cy:1;
    } bity;
  } y;
  union {
    unsigned char x;
    struct {
      unsigned char rx:7;
      unsigned char cx:1;
    } bitx;
  } x;
  unsigned char op;
};

/* RW type */
struct ve_instr_rw {
  int _dummy;
  union {
    unsigned char z;
    struct {
      unsigned char rz:7;
      unsigned char cz:1;
    } bitz;
  } z;
  union {
    unsigned char y;
    struct {
      unsigned char ry:7;
      unsigned char cy:1;
    } bity;
  } y;
  union {
    unsigned char x;
    struct {
      unsigned char rx:7;
      unsigned char cx:1;
    } bitx;
  } x;
  unsigned char op;
};

/* RRM type */
struct ve_instr_rrm {
  int _dummy;
  union {
    unsigned char z;
    struct {
      unsigned char rz:7;
      unsigned char cz:1;
    } bitz;
  } z;
  union {
    unsigned char y;
    struct {
      unsigned char ry:7;
      unsigned char cy:1;
    } bity;
  } y;
  union {
    unsigned char x;
    struct {
      unsigned char rx:7;
      unsigned char cx:1;
    } bitx;
  } x;
  unsigned char op;
};

/* CF type */
struct ve_instr_cf {
  int disp;
  union {
    unsigned char z;
    struct {
      unsigned char rz:7;
      unsigned char cz:1;
    } bitz;
  } z;
  union {
    unsigned char y;
    struct {
      unsigned char ry:7;
      unsigned char cy:1;
    } bity;
  } y;
  union {
    unsigned char x;
    struct {
      unsigned char cf:4;
      unsigned char bpf:2;
      unsigned char cx2:1;
      unsigned char cx:1;
    } bitx;
  } x;
  unsigned char op;
};

/* RVM type */
struct ve_instr_rvm {
  unsigned char vw;
  unsigned char _dummy;
  unsigned char vy;
  unsigned char vx;
  union {
    unsigned char z;
    struct {
      unsigned char rz:7;
      unsigned char cz:1;
    } bitz;
  } z;
  union {
    unsigned char y;
    struct {
      unsigned char ry:7;
      unsigned char cy:1;
    } bity;
  } y;
  union {
    unsigned char x;
    struct {
      unsigned char m:4;
      unsigned char _dummy:1;
      unsigned char cs:1;
      unsigned char vc:1;
      unsigned char cx:1;
    } bitx;
  } x;
  unsigned char op;
};

/* RV type */
struct ve_instr_rv {
  unsigned char vw;
  unsigned char vz;
  unsigned char vy;
  unsigned char vx;
  union {
    unsigned char z;
    struct {
      unsigned char rz:7;
      unsigned char cz:1;
    } bitz;
  } z;
  union {
    unsigned char y;
    struct {
      unsigned char ry:7;
      unsigned char cy:1;
    } bity;
  } y;
  union {
    unsigned char x;
    struct {
      unsigned char m:4;
      unsigned char cs2:1;
      unsigned char cs:1;
      unsigned char cx2:1;
      unsigned char cx:1;
    } bitx;
  } x;
  unsigned char op;
};

typedef union {
  /* General structure */
  struct ve_instr_general gen;

  /* format specific structures */
  struct ve_instr_rr rr;
  struct ve_instr_rw rw;
  struct ve_instr_rv rv;
  struct ve_instr_rm rm;
  struct ve_instr_cf cf;
  struct ve_instr_rrm rrm;
  struct ve_instr_rvm rvm;
} ve_instr;

/* ===================================== */

typedef unsigned char Opcode;

#define O_DUMMY00       0x00
#define O_LDS           0x01	/* load scalar */
#define O_LDU           0x02	/* load scalar upper (0-31) bits */
#define O_LDL           0x03	/* load scalar lower (32-63) bits */
#define O_LD2B          0x04	/* load 2 byte */
#define O_LD1B          0x05	/* load 1 byte */
#define O_LEA           0x06	/* load effective address */
#define O_DUMMY07	0x07
#define O_BSIC          0x08	/* branch and save IC */
#define O_DLDS          0x09	/* dismissable load scalar */
#define O_DLDU          0x0A	/* dismissable load scalar upper (0-31) bits */
#define O_DLDL          0x0B	/* dismissable load scalar lower (32-63) bits */
#define O_PFCH          0x0C	/* prefetch */
#define O_DUMMY0D	0x0D
#define O_DUMMY0E       0x0E
#define O_CVD           0x0F	/* convert to double */
#define O_DUMMY10       0x10
#define O_STS           0x11	/* store scalar */
#define O_STU           0x12	/* store scalar upper (0-31) bits */
#define O_STL           0x13	/* store scalar lower (32-63) bits */
#define O_ST2B          0x14	/* store 2 byte */
#define O_ST1B          0x15	/* store 1 byte */
#define O_DUMMY16	0x16
#define O_DUMMY17	0x17
#define O_BCR           0x18	/* branch on condition relative */
#define O_BC            0x19	/* branch on condition 8 byte */
#define O_DUMMY1A	0x1A
#define O_BCS           0x1B	/* branch on condition 4 byte */
#define O_BCF           0x1C	/* branch on condition floating point */
#define O_DUMMY1D	0x1D
#define O_DUMMY1E       0x1E
#define O_CVS           0x1F	/* convert to single */
#define O_FENCE         0x20	/* fence */
#define O_LHM		0x21	/* load host memory */
#define O_SMIR          0x22	/* save miscellaneous register */
#define O_DUMMY23	0x23
#define O_DUMMY24	0x24
#define O_DUMMY25	0x25
#define O_DUMMY26	0x26
#define O_DUMMY27	0x27
#define O_SIC           0x28	/* save IC */
#define O_SFR           0x29	/* save flag register */
#define O_SPM           0x2A	/* save program mode flags */
#define O_BSWP          0x2B	/* byte swap */
#define O_DUMMY2C	0x2C
#define O_CVQ           0x2D	/* convert to quadruple */
#define O_SMVL          0x2E	/* save maximum vector length */
#define O_SVL           0x2F	/* save vector length */
#define O_SVOB          0x30	/* set vector overtaking boundary */
#define O_SHM		0x31	/* load host memory */
#define O_DUMMY32	0x32
#define O_DUMMY33	0x33
#define O_DUMMY34	0x34
#define O_DUMMY35	0x35
#define O_DUMMY36	0x36
#define O_DUMMY37	0x37
#define O_PCNT          0x38	/* population count */
#define O_BRV           0x39	/* bit reverse */
#define O_LPM           0x3A	/* load program mode flags */
#define O_CMOV          0x3B	/* conditional move */
#define O_DUMMY3C       0x3C
#define O_SQRT          0x3D	/* floating point square root */
#define O_FCM           0x3E	/* floating point compare and select Max/Min */
#define O_MONC          0x3F	/* monitor call */
#define O_LCR           0x40	/* load communication register */
#define O_TSCR		0x41	/* test and set commumication register */
#define O_TS1AM         0x42	/* test and set (1AM) */
#define O_TS2AM         0x43	/* test and set (2AM) */
#define O_AND           0x44	/* logical and */
#define O_OR            0x45	/* logical or */
#define O_XOR           0x46	/* logical xor */
#define O_EQV           0x47	/* logical equivalence */
#define O_ADD           0x48	/* add unsigned */
#define O_MPY           0x49	/* multiply unsigned */
#define O_ADS           0x4A	/* add 4 byte */
#define O_MPS           0x4B	/* multiply 4 byte */
#define O_FAD           0x4C	/* floating point add */
#define O_FMP           0x4D	/* floating point multiply */
#define O_FIX           0x4E	/* convert to 4 byte fixed point */
#define O_FIXX          0x4F	/* convert to 8 byte fixed point */
#define O_SCR		0x50	/* store communication register */
#define O_FIDCR		0x51	/* fetch and increment/decrement CR */
#define O_TS3AM         0x52	/* test and set (3AM) */
#define O_ATMAM         0x53	/* atomic arithmetic manipulation */
#define O_NND           0x54	/* logical negate and */
#define O_CMP           0x55	/* compare unsigned */
#define O_MRG           0x56	/* bit merge */
#define O_SLAX          0x57	/* shift left arithmetic 8 byte */
#define O_SUB           0x58	/* subtract unsigned */
#define O_ADX           0x59	/* add 8 byte */
#define O_SBS           0x5A	/* subtract 4 byte */
#define O_SBX           0x5B	/* subtract 8 byte */
#define O_FSB           0x5C	/* floating point subtract */
#define O_FDV           0x5D	/* floating point divide */
#define O_FLT           0x5E	/* convert from 4 byte fixed point */
#define O_FLTX          0x5F	/* convert from 8 byte fixed point */
#define O_DUMMY60       0x60
#define O_DUMMY61	0x61
#define O_CAS           0x62	/* compare and swap */
#define O_DUMMY63	0x63
#define O_SLD           0x64	/* shift left double */
#define O_SLL           0x65	/* shift left logical */
#define O_SLA           0x66	/* shift left arithmetic 4 byte */
#define O_LDZ           0x67	/* leading zero count */
#define O_CMX           0x68	/* compare and select maximum/minimum 8 byte */
#define O_LFR           0x69	/* load flag register */
#define O_CPX           0x6A	/* compare 8 byte */
#define O_MPD           0x6B	/* multiply 4 byte (result 8 byte) */
#define O_FAQ           0x6C	/* floating add quadruple */
#define O_FMQ           0x6D	/* floating multiply quadruple */
#define O_MPX           0x6E	/* multiply 8 byte */
#define O_DIV           0x6F	/* divide unsigned */
#define O_DUMMY70	0x70
#define O_DUMMY71	0x71
#define O_DUMMY72	0x72
#define O_DUMMY73	0x73
#define O_SRD           0x74	/* shift right double */
#define O_SRL           0x75	/* shift right logical */
#define O_SRA           0x76	/* shift right arithmetic 4 byte */
#define O_SRAX          0x77	/* shift right arithmetic 8 byte */
#define O_CMS           0x78	/* compare and select maximum/minimum 4 byte */
#define O_NOP           0x79	/* no operation */
#define O_CPS           0x7A	/* compare 4 byte */
#define O_DVS           0x7B	/* divide 4 byte */
#define O_FSQ           0x7C	/* floating subtract quadruple */
#define O_FCQ           0x7D	/* floating compare quadruple */
#define O_FCP           0x7E	/* floating point compare */
#define O_DVX           0x7F	/* divide 8 byte */
#define O_PFCHV         0x80	/* prefetch vector */
#define O_VLD           0x81	/* vector load 8 byte */
#define O_VLDU          0x82	/* vector load upper */
#define O_VLDL          0x83	/* vector load lower */
#define O_ANDM          0x84	/* and vector mask */
#define O_ORM           0x85	/* or vector mask */
#define O_XORM          0x86	/* xor vector mask */
#define O_EQVM          0x87	/* equivalence vector mask */
#define O_VRAND         0x88	/* vector reduction and */
#define O_VRXOR         0x89	/* vector reduction xor */
#define O_VCMS          0x8A	/* vector compare and select Max/Min 4 byte */
#define O_VADX          0x8B	/* vector add 8 byte */
#define O_VBRD          0x8C	/* vector broadcast */
#define O_VCP           0x8D	/* vector compress */
#define O_LSV           0x8E	/* load scalar to vector */
#define O_VCVD          0x8F	/* vector convert to double */
#define O_DUMMY90	0x90
#define O_VST           0x91	/* vector store */
#define O_VSTU          0x92	/* vector store upper */
#define O_VSTL          0x93	/* vector store lower */
#define O_NNDM          0x94	/* negate and vector mask */
#define O_NEGM          0x95	/* nagete vector mask */
#define O_DUMMY96	0x96
#define O_DUMMY97	0x97
#define O_VROR          0x98	/* vector reduction or */
#define O_VSEQ          0x99	/* vector sequential number */
#define O_VCMX          0x9A	/* vector compare and select Max/Min 8 byte */
#define O_VSBX          0x9B	/* vector subtract 8 byte */
#define O_VMV           0x9C	/* vector move */
#define O_VEX           0x9D	/* vector expand */
#define O_LVS           0x9E	/* load vector to scalar */
#define O_VCVS          0x9F	/* vector convert to single */
#define O_DUMMYA0	0xA0
#define O_VGT           0xA1	/* vector gather */
#define O_VGTU          0xA2	/* vector gather upper */
#define O_VGTL          0xA3	/* vector gather lower */
#define O_PCVM          0xA4	/* population count of vector mask */
#define O_LZVM          0xA5	/* leading zero of vector mask */
#define O_TOVM          0xA6	/* trailing one of vector mask */
#define O_SVM           0xA7	/* save vector mask */
#define O_VFIXX         0xA8	/* vector convert to 8 byte */
#define O_DUMMYA9	0xA9
#define O_VSUMX         0xAA	/* vector sum 8 byte */
#define O_VMAXX         0xAB	/* vector Max/Min 8 byte */
#define O_VPCNT         0xAC	/* vector population count */
#define O_VFMAX         0xAD	/* vector floating point Max/Min */
#define O_DUMMYAE	0xAE
#define O_LVIX          0xAF	/* load vector data index */
#define O_DUMMYB0	0xB0
#define O_VSC           0xB1	/* vector scatter */
#define O_VSCU          0xB2	/* vector scatter upper */
#define O_VSCL          0xB3	/* vector scatter lower */
#define O_VFMK          0xB4	/* vector form mask 8 byte */
#define O_VFMS          0xB5	/* vector form mask 4 byte */
#define O_VFMF          0xB6	/* vector form mask floating point */
#define O_LVM           0xB7	/* load vector mask */
#define O_VFLTX         0xB8	/* vector convert from 8 byte */
#define O_VCMP          0xB9	/* vector compare unsigned */
#define O_VCPX          0xBA	/* vector compare 8 byte */
#define O_VMAXS         0xBB	/* vector Max/Min 4 byte */
#define O_VSHF          0xBC
#define O_VFCM          0xBD	/* vector floating compare and select Max/Min */
#define O_DUMMYBE	0xBE
#define O_LVL           0xBF	/* load vector length */
#define O_DUMMYC0	0xC0
#define O_VLD2D		0xC1	/* vector load 2D */
#define O_VLDU2D	0xC2	/* vector load upper 2D */
#define O_VLDL2D	0xC3	/* vector load lower 2D */
#define O_VAND          0xC4	/* vector logical and */
#define O_VOR           0xC5	/* vector logical or */
#define O_VXOR          0xC6	/* vector logical xor */
#define O_VEQV          0xC7	/* vector logical equivalence */
#define O_VADD          0xC8	/* vector add unsigned */
#define O_VMPY          0xC9	/* vector multiply unsigned */
#define O_VADS          0xCA	/* vector add 4 byte */
#define O_VMPS          0xCB	/* vector multiply 4 byte */
#define O_VFAD          0xCC	/* vector floating point add */
#define O_VFMP          0xCD	/* vector floating point multiply */
#define O_VFIA          0xCE	/* vector floating point iteration add */
#define O_VFIM          0xCF	/* vector floating point iteration multiply */
#define O_DUMMYD0	0xD0
#define O_VST2D		0xD1	/* vector store 2D */
#define O_VSTU2D	0xD2	/* vector store upper 2D */
#define O_VSTL2D	0xD3	/* vector store lower 2D */
#define O_VSLAX         0xD4	/* vector shift left arithmetic 8 byte */
#define O_VSRAX         0xD5	/* vector shift right arithmetic 8 byte */
#define O_VMRG          0xD6	/* vector merge */
#define O_VSFA          0xD7	/* vector shift left and add */
#define O_VSUB          0xD8	/* vector subtract unsigned */
#define O_VMPD          0xD9	/* vector multiply 4 byte (result 8 byte) */
#define O_VSBS          0xDA	/* vector subtract 4 byte */
#define O_VMPX          0xDB	/* vector multiply 8 byte */
#define O_VFSB          0xDC	/* vector floating point subtract */
#define O_VFDV          0xDD	/* vector floating point divide */
#define O_VFIS          0xDE	/* vector floating point iteration subtract */
#define O_DUMMYDF	0xDF
#define O_DUMMYE0       0xE0
#define O_VRCP		0xE1	/* vector floating point reciprocal */
#define O_VFMAD         0xE2	/* vector floating point multiply and add */
#define O_VFNMAD        0xE3	/* vector floating negative multiply and add */
#define O_VSLD          0xE4	/* vector shift left double */
#define O_VSLL          0xE5	/* vector shift left logical */
#define O_VSLA          0xE6	/* vector shift left arithmetic 4 byte */
#define O_VLDZ          0xE7	/* vector leading zero count */
#define O_VFIX          0xE8	/* vector convert to 4 byte */
#define O_VDIV          0xE9	/* vector divide unsigned */
#define O_VSUMS         0xEA	/* vector sum 4 byte */
#define O_VDVS          0xEB	/* vector divide 4 byte */
#define O_VFSUM         0xEC	/* vector floating point sum */
#define O_VSQRT         0xED	/* vector floating point square root */
#define O_VFIAM         0xEE	/* vector floating iteration add and multiply */
#define O_VFIMA         0xEF	/* vector floating iteration multiply and add */
#define O_DUMMYF0       0xF0
#define O_VRSQRT	0xF1	/* vector floating reciprocal square root */
#define O_VFMSB         0xF2	/* vector floating multiply and subtract */
#define O_VFNMSB        0xF3	/* vector FP negative multiply and subtract */
#define O_VSRD          0xF4	/* vector shift right double */
#define O_VSRL          0xF5	/* vector shift right logical */
#define O_VSRA          0xF6	/* vector shift right arithmetic 4 byte */
#define O_VBRV          0xF7	/* vector bit reverse */
#define O_VFLT          0xF8	/* vector convert from 4 byte */
#define O_DUMMYF9	0xF9
#define O_VCPS          0xFA	/* vector compare 4 byte */
#define O_VDVX          0xFB	/* vector divide 8 byte */
#define O_VFCP          0xFC	/* vector floating point compare */
#define O_DUMMYFD	0xFD
#define O_VFISM         0xFE	/* vector FP iteration subtract and multiply */
#define O_VFIMS         0xFF	/* vector FP iteration multiply and subtract */

/*
 * Instruction format
 */
#define F_RR	0x01
#define F_RW	0x02
#define F_RV	0x04
#define F_RM	0x08
#define F_CF	0x10
#define F_RRM	0x20
#define F_RVM	0x40

/*
 * Operands format
 */
#define FM_XYZWM 0x000	/* X, Y, Z, W, M */
#define FM_ASX	0x100	/* ASX */
#define FM_AS	0x200	/* AS */
#define FM_DXY_Z 0x300	/* X(Y), Z */
#define FM_DX_ZY 0x400	/* X, Z(Y) */
#define FM_DXZ_Y 0x500	/* (X, Z), Y */
#define FM_ZX	0x600	/* Z, Y */
#define FM_XZY	0x700	/* X, Z, Y */
#define FM_XYZM 0x800	/* X, Y, Z, M */
#define FM_XZYM 0x900	/* X, Z, Y, M */
#define FM_X_DYZ_WM 0xa00	/* X, (Z, Y), W, M */
#define FM_XZYWM 0xb00	/* X, Z, Y, W, M */
#define FM_XWYZM 0xc00	/* X, W, Y, Z, M */
#define FM_SPREG 0xd00	/* special reg implicit in opcode */

/* VE opcode arguments (operands) format */
#define VE_OA_FMT(x)	((x) & 0xf00)

/*
 * Field type.
 */

/* what type of data is in the field? */
#define TREG	0x0100	/* field contains register */
#define TCONDF	0x0200	/* field contains condition flags */
#define TDISPL	0x0400	/* field contains displacement */
#define TLITER	0x0800	/* field is a literal value */
#define TVDVC	0x1000	/* vector, vector data, and both */
#define TVDMC	0x2000	/* vector mask */
#define TSOFT	0x4000	/* software controlled field */
#define TOPT	0x8000	/* if set, param is optional */

/* What type of register is in the field? */
#define TREG_MASK	(TREG|0x00F0)	/* mask for selecting register types */
#define TSREG		(TREG|0x0010)	/* Scalar register */
#define TVREG		(TREG|0x0020)	/* Vector register */
#define TVMREG		(TREG|0x0040)	/* Vector Mask register */
#define TVIXREG		(TREG|0x0080)	/* Vector Index register */

/* What type of literal is in the field? */
#define TLIT_MASK	(TLITER|0x000F)	/* mask for selecting literal types */
#define TLZERO		(TLITER|0x0001)	/* literal value is zero */
#define TLIS63		(TLITER|0x0002)	/* signed int between -64..63 */
#define TLM0M1		(TLITER|0x0004)	/* 64bit (m)0, (m)1, m=0..63 */
#define TLI127		(TLITER|0x0008)	/* int between 0..127 */

/*
 * Instruction flags
 */
#define FL_MASK	 0x00FF
#define FL_SHFT  0
#define CX_ON	 0x0001
# define VO_ON	 CX_ON
#define CX2_ON	 0x0002
# define VC_ON	 CX2_ON
#define CS_ON	 0x0004
#define CT_ON    CS_ON
#define CS2_ON   0x0008
#define CM_ON    CS2_ON
#define CW_ON	 0x0010
#define CW2_ON	 0x0020

#define DS_MASK  0x3000
#define DS_SHFT  12
#define DS_BYTE  0x0000
#define DS_HALF  0x1000
#define DS_WORD  0x2000
#define DS_LONG  0x3000

#define FENCE_C  0x4000	/* for disassemble */

#define CF_MASK  0x0F00
#define CF_SHFT  8
#define CF_AF    0x0000
#define CF_GT    0x0100
#define CF_LT    0x0200
#define CF_NE    0x0300
#define CF_EQ    0x0400
#define CF_GE    0x0500
#define CF_LE    0x0600
#define CF_NUM   0x0700
#define CF_NAN   0x0800
#define CF_GTNAN 0x0900
#define CF_LTNAN 0x0A00
#define CF_NENAN 0x0B00
#define CF_EQNAN 0x0C00
#define CF_GENAN 0x0D00
#define CF_LENAN 0x0E00
#define CF_AT    0x0F00

#define BP_MASK  0x30000
#define BP_SHFT	 16
#define BP_NP    0x00000
#define BP_PNT   0x20000
#define BP_PT    0x30000

#define RD_MASK  0xF00000
#define RD_SHFT  20
#define RD_PSW	 0x000000
#define RD_RZ    0x800000
#define RD_RP    0x900000
#define RD_RM    0xA00000
#define RD_RN    0xB00000
#define RD_RA    0xC00000

/* Special registers */
#define REG_INFO  17    /* Info area register */
#define REG_PLT 16	/* Procedure Likage Table pointer */
#define REG_GOT 15	/* Global Offset Table pointer */
#define REG_TP  14	/* Thread pointer (descriptor) */
#define REG_OUTER 12    /* Outer register */
#define REG_SP	11	/* Stack pointer */
#define REG_LR	10	/* Link register */
#define REG_FP	9	/* Frame pointer */
#define REG_SL	8	/* Stack limit */

#endif /* !__OPCODES_VE_H__ */

