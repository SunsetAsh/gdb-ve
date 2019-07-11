/* Common target dependent code for GDB on ARM systems.
   Copyright (C) 2002-2016 Free Software Foundation, Inc.

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

#ifndef VE_TDEP_H
#define VE_TDEP_H

/* Instruction size */
#define	VE_INSN_SIZE	8

/* Forward declarations.  */
struct gdbarch;
struct regset;
struct address_space;

#include "arch/ve.h"

/* Say how long Vector Mask registers are.  Used for documentation
   purposes and code readability.  These are fixed at 64 * 4 bits.  */
#define VM_REGISTER_SIZE        32

/* Say how long Vector registers are.  Used for documentation
   purposes and code readability.  These are fixed at 64 * 256 bits.  */
#define VEC_REGISTER_SIZE       2048

/* Number of machine registers.  The only define actually required 
   is gdbarch_num_regs.  The other definitions are used for documentation
   purposes and code readability.  */
/* For 26 bit ARM code, a fake copy of the PC is placed in register 25 (PS)
   (and called PS for processor status) so the status bits can be cleared
   from the PC (register 15).  For 32 bit ARM code, a copy of CPSR is placed
   in PS.  */
#define NUM_FREGS	8	/* Number of floating point registers.  */
#define NUM_SREGS	2	/* Number of status registers.  */
#define NUM_GREGS	18	/* Number of general purpose scalar registers %s45 to%s63.  */



/* Type of floating-point code in use by inferior.  There are really 3 models
   that are traditionally supported (plus the endianness issue), but gcc can
   only generate 2 of those.  The third is APCS_FLOAT, where arguments to
   functions are passed in floating-point registers.  

   In addition to the traditional models, VFP adds two more. 

   If you update this enum, don't forget to update fp_model_strings in 
   ve-tdep.c.  */

enum ve_float_model
{
  VE_FLOAT_AUTO,	/* Automatic detection.  Do not set in tdep.  */
  VE_FLOAT_LAST		/* Keep at end.  */
};

/* ABI used by the inferior.  */
enum ve_abi_kind
{
  VE_ABI_AUTO,
  VE_ABI_VER0,	/* The intial ABI document 
		System V Application Binary Interface */
  VE_ABI_LAST
};

/* Convention for returning structures.  */

enum struct_return
{
  pcc_struct_return,		/* Return "short" structures in memory.  */
  reg_struct_return		/* Return "short" structures in registers.  */
};

/* Target-dependent structure in gdbarch.  */
struct gdbarch_tdep
{
  /* The ABI for this architecture.  It should never be set to
     VE_ABI_AUTO.  */
  enum ve_abi_kind ve_abi;

  enum ve_float_model fp_model; /* Floating point calling conventions.  */

  int have_vec_registers;	/* Does the target report the Vector registers?  */
  CORE_ADDR lowest_pc;		/* Lowest address at which instructions 
				   will appear.  */

  const gdb_byte *ve_breakpoint;	/* Breakpoint pattern for an VE insn.  */
  int ve_breakpoint_size;	/* And its size.  */

  int jb_pc;			/* Offset to PC value in jump buffer.
				   If this is negative, longjmp support
				   will be disabled.  */
  size_t jb_elt_size;		/* And the size of each entry in the buf.  */

  /* Convention for returning structures.  */
  enum struct_return struct_return;

  /* Cached core file helpers.  */
  struct regset *gregset, *fpregset, *vfpregset;

  /* ISA-specific data types.  */
  struct type *ve_vm_type;
  struct type *ve_vec_type;

  /* Return the expected next PC if FRAME is stopped at a syscall
     instruction.  */
  CORE_ADDR (*syscall_next_pc) (struct frame_info *frame);

   /* Parse swi insn args, sycall record.  */
  int (*ve_swi_record) (struct regcache *regcache);
};

/* The maximum number of modified instructions generated for one single-stepped
   instruction, including the breakpoint (usually at the end of the instruction
   sequence) and any scratch words, etc.  */
#define DISPLACED_MODIFIED_INSNS	8

CORE_ADDR ve_skip_stub (struct frame_info *, CORE_ADDR);

extern pid_t ve_gdb_waitpid(pid_t , int *, int );
extern char *ve_exec_file;

/* ve_exec launcher path */
#define VE_EXEC_PATH BINDIR "/ve_exec"

/* traceme option */
#define	VE_OPT_TRACEME	"--traceme"

#endif /* ve-tdep.h */
