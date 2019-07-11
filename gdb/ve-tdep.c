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

#include "defs.h"

#include <ctype.h>		/* XXX for isupper ().  */

#include "frame.h"
#include "inferior.h"
#include "infrun.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "dis-asm.h"		/* For register styles.  */
#include "regcache.h"
#include "reggroups.h"
#include "doublest.h"
#include "value.h"
#include "arch-utils.h"
#include "osabi.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "trad-frame.h"
#include "objfiles.h"
#include "dwarf2-frame.h"
#include "gdbtypes.h"
#include "prologue-value.h"
#include "remote.h"
#include "target-descriptions.h"
#include "user-regs.h"
#include "observer.h"

#include "arch/ve.h"
#include "ve-tdep.h"

#include "elf-bfd.h"
#include "coff/internal.h"
#include "elf/ve.h"

#include "vec.h"

#include "record.h"
#include "record-full.h"

#include "features/ve.c"

/* for ve_gdb_waitpid() */
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "inf-ptrace.h"
#include "ve-ptrace.h"
#include "nat/linux-nat.h"

static int ve_debug;

char *ve_exec_file = VE_EXEC_PATH;

/* Macros for setting and testing a bit in a minimal symbol that marks
   it as Thumb function.  The MSB of the minimal symbol's "info" field
   is used for this purpose.

   MSYMBOL_SET_SPECIAL	Actually sets the "special" bit.
   MSYMBOL_IS_SPECIAL   Tests the "special" bit in a minimal symbol.  */

#define MSYMBOL_SET_SPECIAL(msym)				\
	MSYMBOL_TARGET_FLAG_1 (msym) = 1

#define MSYMBOL_IS_SPECIAL(msym)				\
	MSYMBOL_TARGET_FLAG_1 (msym)

/* Per-objfile data used for mapping symbols.  */
static const struct objfile_data *ve_objfile_data_key;

struct ve_mapping_symbol
{
  bfd_vma value;
  char type;
};
typedef struct ve_mapping_symbol ve_mapping_symbol_s;
DEF_VEC_O(ve_mapping_symbol_s);

struct ve_per_objfile
{
  VEC(ve_mapping_symbol_s) **section_maps;
};

/* A variable that can be configured by the user.  */
static enum ve_float_model ve_fp_model = VE_FLOAT_AUTO;

/* A variable that can be configured by the user.  */
static enum ve_abi_kind ve_abi_global = VE_ABI_AUTO;

/* The standard register names, and all the valid aliases for them.  Note
   that `fp', `sp' and `pc' are not added in this alias list, because they
   have been added as builtin user registers in
   std-regs.c:_initialize_frame_reg.  */
static const struct
{
  const char *name;
  int regnum;
} ve_register_aliases[] = {
  /* Basic register numbers.  */
  { "s8", 37 },
  { "s9", 38 },
  { "s10", 39 },
  { "s11", 40 },
  { "s14", 43 },
  { "s15", 44 },
  { "s16", 45 },
  /* Synonyms (argument and variable registers).  */
  { "a1", 29 },
  { "a2", 30 },
  { "a3", 31 },
  { "a4", 32 },
  { "a5", 33 },
  { "a6", 34 },
  { "a7", 35 },
  { "a8", 36 },
  /* Special names.  */
  { "ip", 19 },
  { "pc", 19 },
  /* Names used by Compiler  */
};

static const char *const ve_register_names[] =
{"usrcc", "pmc0", "pmc1", "pmc2",
 "pmc3", "pmc4", "pmc5", "pmc6",
 "pmc7", "pmc8", "pmc9", "pmc10",
 "pmc11", "pmc12", "pmc13", "pmc14",
 "pmc15", "psw", "exs", "ic",
 "ice", "vixr", "vl", "sar",
 "pmmr", "pmcr0", "pmcr1", "pmcr2",
 "pmcr3", "s0",  "s1",  "s2",
 "s3", "s4",  "s5",  "s6",
 "s7", "sl",  "fp",  "lr",
 "sp", "s12", "s13", "tp",
 "got", "plt", "s17", "s18",
 "s19", "s20", "s21", "s22",
 "s23", "s24", "s25", "s26",
 "s27", "s28", "s29", "s30",
 "s31", "s32", "s33", "s34",
 "s35", "s36", "s37", "s38",
 "s39", "s40", "s41", "s42",
 "s43", "s44", "s45", "s46",
 "s47", "s48", "s49", "s50",
 "s51", "s52", "s53", "s54",
 "s55", "s56", "s57", "s58",
 "s59", "s60", "s61", "s62",
 "s63", "vm0", "vm1", "vm2",
 "vm3", "vm4", "vm5", "vm6",
 "vm7", "vm8", "vm9", "vm10",
 "vm11", "vm12", "vm13", "vm14",
 "vm15", "v0", "v1", "v2",
 "v3", "v4", "v5", "v6",
 "v7", "v8", "v9", "v10",
 "v11", "v12", "v13", "v14",
 "v15", "v16", "v17", "v18",
 "v19", "v20", "v21", "v22",
 "v23", "v24", "v25", "v26",
 "v27", "v28", "v29", "v30",
 "v31", "v32", "v33", "v34",
 "v35", "v36", "v37", "v38",
 "v39", "v40", "v41", "v42",
 "v43", "v44", "v45", "v46",
 "v47", "v48", "v49", "v50",
 "v51", "v52", "v53", "v54",
 "v55", "v56", "v57", "v58",
 "v59", "v60", "v61", "v62",
 "v63" };

struct ve_prologue_cache
{
  /* The stack pointer at the time this frame was created; i.e. the
     caller's stack pointer when this function was called.  It is used
     to identify this frame.  */
  CORE_ADDR prev_sp;

  /* The frame base for this frame is just prev_sp - frame size.
     FRAMESIZE is the distance from the frame pointer to the
     initial stack pointer.  */

  int framesize;

  /* The register used to hold the frame pointer for this frame.  */
  int framereg;

  /* Saved register offsets.  */
  struct trad_frame_saved_reg *saved_regs;
};

static CORE_ADDR ve_analyze_prologue (struct gdbarch *gdbarch,
				       CORE_ADDR prologue_start,
				       CORE_ADDR prologue_end,
				       struct ve_prologue_cache *cache);

/* Architecture version for displaced stepping.  This effects the behaviour of
   certain instructions, and really should not be hard-wired.  */

#define DISPLACED_STEPPING_ARCH_VERSION		5
#define	EXTENDED_STATUS_SHIFT			16

static int
build_extended_status(int status,int sicode)
{
  int ext = 0;

  switch(sicode)
    {
    case (SIGTRAP | PTRACE_EVENT_FORK << 8) :
      ext = PTRACE_EVENT_FORK << EXTENDED_STATUS_SHIFT;
      break;
    case (SIGTRAP | PTRACE_EVENT_VFORK << 8) :
      ext = PTRACE_EVENT_VFORK << EXTENDED_STATUS_SHIFT;
      break;
    case (SIGTRAP | PTRACE_EVENT_CLONE << 8) :
      ext = PTRACE_EVENT_CLONE << EXTENDED_STATUS_SHIFT;
      break;
    case (SIGTRAP | PTRACE_EVENT_EXIT << 8) :
      ext = PTRACE_EVENT_EXIT << EXTENDED_STATUS_SHIFT;
      break;
    /* SYSCALL_SIGTRAP == SIGTRAP | 0x80 */
    case (SIGTRAP | 0x80) :
      return SYSCALL_SIGTRAP << 8 | 0x7f;
    default:	/* do nothing */
      break;
    }

  return status | ext;
}

pid_t
ve_gdb_waitpid(pid_t pid, int *statusp, int flags)
{
  int ret;
  long pret;
  siginfo_t siginfo;

  if (ve_debug)
    printf_unfiltered(_("ve_gdb_waitpid(%d, 0x%x)\n"), pid, flags);

  do
    {
      ret = waitpid(pid, statusp, flags);
    }
  while (ret == -1 && errno == EINTR);

  if (ve_debug) 
    {
      printf_unfiltered(_("ve_gdb_waitpid(%d, 0x%x): status(0x%x), %d\n"),
      pid, flags, (ret > 0 && statusp != NULL) ? *statusp : -1, ret);
      if (ret == -1)
	printf_unfiltered(_("ve_gdb_waitpid(%d, 0x%x): error(%d) %s\n"),
	pid, flags, errno,strerror(errno));
    }

  if (statusp == NULL || !WIFSTOPPED(*statusp) || ret <= 0)
    return ret;

  /* Below is the special code for VE */

  /* stop VE process */
  pret = ptrace_func(PTRACE_STOP_VE,ret,0,0);	/* ret == pid */
  if (ve_debug)
    printf_unfiltered(_("ve_gdb_waitpid(%d, 0x%x): (STOP_VE, %d) return=%ld\n"), 
    pid, flags, ret, pret);
  if (pret == -1)
    return ret;
  if (WSTOPSIG(*statusp) != SIGTRAP)
    return ret;

  /* This would fetch the event information from 
   * from siginfo.si_code and place into the appropriate
   * bits(for event occurred) of statusp
   * check si_code;
   * si_code == (SIGTRAP | PTRACE_EVENT_foo << 8)
   */
  pret = ptrace_func(PTRACE_GETSIGINFO, ret, NULL, &siginfo);
  if (ve_debug)
    printf_unfiltered(_("ve_gdb_waitpid(%d, 0x%x): (GETSIGINFO, %d) si_code(%x),return=%ld\n"),
    pid, flags, ret, siginfo.si_code, pret);
  if (pret == -1)
    return ret;
  *statusp = build_extended_status(*statusp,siginfo.si_code);
  if (ve_debug) 
    printf_unfiltered(_("ve_gdb_waitpid(%d, 0x%x): => status(%x), %d\n"),
    pid, flags, (ret > 0 && statusp != NULL) ? *statusp : -1, ret);
  return ret;
}
  
/* Remove useless bits from addresses in a running program.  */
static CORE_ADDR
ve_addr_bits_remove (struct gdbarch *gdbarch, CORE_ADDR val)
{
  /* There are none in VE */
  return val;
}

/* Advance the PC across any function entry prologue instructions to
   reach some "real" code.  */

static CORE_ADDR
ve_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  CORE_ADDR func_addr, limit_pc;

  if (ve_debug)
    fprintf_unfiltered (gdb_stdlog, "fu: %s: start (pc 0x%lx)\n",
			__func__, pc);

  /* See if we can determine the end of the prologue via the symbol table.
     If so, then return either PC, or the PC after the prologue, whichever
     is greater.  */
  if (find_pc_partial_function (pc, NULL, &func_addr, NULL))
    {
      CORE_ADDR post_prologue_pc
	= skip_prologue_using_sal (gdbarch, func_addr);
      struct compunit_symtab *cust = find_pc_compunit_symtab (func_addr);

      if (ve_debug)
	fprintf_unfiltered (gdb_stdlog, "fu: %s: prologue using sal (post pc 0x%lx)\n",
			    __func__, post_prologue_pc);

      /* "ncc" does not match startswith (COMPUNIT_PRODUCER (cust), "clang ") */
      if (post_prologue_pc)
        return post_prologue_pc;
    }

  /* Can't determine prologue from the symbol table, need to examine
     instructions.  */

  /* Find an upper limit on the function prologue using the debug
     information.  If the debug information could not be used to provide
     that bound, then use an arbitrary large number as the upper bound.  */
  /* Like ve_scan_prologue, stop no later than pc + 64.  */
  limit_pc = skip_prologue_using_sal (gdbarch, pc);
  if (limit_pc == 0)
    limit_pc = pc + 280;          /* Magic.  */

  if (ve_debug)
    fprintf_unfiltered (gdb_stdlog, "fu: %s: skip (pc 0x%lx, limit 0x%lx)\n",
			__func__, pc, limit_pc);
  return ve_analyze_prologue (gdbarch, pc, limit_pc, NULL);
}


/* Analyze an VE mode prologue starting at PROLOGUE_START and
   continuing no further than PROLOGUE_END.  If CACHE is non-NULL,
   fill it in.  Return the first address not recognized as a prologue
   instruction.

   We recognize all the instructions typically found in VE prologues,
   plus hveless instructions which can be skipped (either for analysis
   purposes, or a more restrictive set that can be skipped when finding
   the end of the prologue).  */

static CORE_ADDR
ve_analyze_prologue (struct gdbarch *gdbarch,
		      CORE_ADDR prologue_start, CORE_ADDR prologue_end,
		      struct ve_prologue_cache *cache)
{
  enum bfd_endian byte_order_for_code = gdbarch_byte_order_for_code (gdbarch);
  int regno;
  CORE_ADDR offset, current_pc;
  pv_t regs[VE_VM0_REGNUM];
  struct pv_area *stack;
  struct cleanup *back_to;
  CORE_ADDR unrecognized_pc = 0;

  if (ve_debug)
    fprintf_unfiltered (gdb_stdlog, "fu: %s: start (start 0x%lx, "
			"end 0x%lx, cache 0x%p)\n",
			__func__, prologue_start, prologue_end, cache);

  /* Search the prologue looking for instructions that calls grow 
   * system call , set up the frame pointer, adjust the stack pointer
   * , and save registers.

     Be careful, however, and if it doesn't look like a prologue,
     don't try to scan it.  If, for instance, a frameless function
     begins with stmfd sp!, then we will tell ourselves there is
     a frame, which will confuse stack traceback, as well as "finish" 
     and other operations that rely on a knowledge of the stack
     traceback.  */

  for (regno = 0; regno < VE_VM0_REGNUM; regno++)
    regs[regno] = pv_register (regno, 0);
  stack = make_pv_area (VE_SP_REGNUM, gdbarch_addr_bit (gdbarch));
  back_to = make_cleanup_free_pv_area (stack);

  for (current_pc = prologue_start;
       current_pc < prologue_end;
       current_pc += VE_INSN_SIZE)
    {
      pv_t addr;
      uint64_t insn
	= read_memory_unsigned_integer (current_pc, VE_INSN_SIZE,
					byte_order_for_code);

      if ((bits (insn, 32, 63) & 0xff00ffff) == 0x1100008b)
							/* st Rd, #n(,%sp) */
	{
	  addr = pv_add_constant (regs[VE_SP_REGNUM], (insn & 0xffffffff));
	  if (pv_area_store_would_trash (stack, addr))
	    break;
	  pv_area_store (stack, addr, 8,
			 regs[VE_S0_REGNUM + bits (insn, 48, 54)]);
	  continue;
	}
      else if ((bits (insn, 32, 63) & 0xff00ffff) == 0x11000089)
							/* st Rd, #n(,%fp) */
	continue;
      else if (insn == 0x4509008b00000000)		/* or %fp, 0, %sp */
	{
	  regs[VE_FP_REGNUM] = regs[VE_SP_REGNUM];
	  continue;
	}
      else if (insn == 0x453e008000000000)		/* or %s62, 0, %s0 */
	{
	  regs[VE_S0_REGNUM + 62] = regs[VE_S0_REGNUM];
	  continue;
	}
      else if (insn == 0x450000be00000000)		/* or %s0, 0, %s62 */
	{
	  regs[VE_S0_REGNUM] = regs[VE_S0_REGNUM + 62];
	  if (ve_debug)
	    fprintf_unfiltered (gdb_stdlog, "fu: %s: reach 0x%lx "
				"<or %%s0, 0, %%s62>\n", __func__, current_pc);
	  unrecognized_pc = current_pc + VE_INSN_SIZE;
	  break;
	}
      else if (bits (insn, 32, 63) == 0x060b0089)
			/* lea %sp, -<needed stack size for func>(,%fp) */
	{
	  uint32_t stack_size = (uint32_t)bits (insn, 0, 31);

	  regs[VE_SP_REGNUM] = pv_add_constant (regs[VE_FP_REGNUM], stack_size);
	  continue;
	}
#if 1  /* for new instruction */
      else if (bits (insn, 32, 63) == 0x060d0000)	/* lea %s13,0x0(0,0) */
	{
	  long d = (long)((int)bits (insn, 0, 31));
	  regs[VE_S0_REGNUM + 13] = pv_constant (d);
	  continue;
	}
      else if (bits (insn, 32, 63) == 0x440d8d60)	/* and %s13,%s13,(32)0 */
	{
	  pv_t mask = pv_constant(0x00000000ffffffff);

	  regs[VE_S0_REGNUM + 13] = pv_logical_and(regs[VE_S0_REGNUM + 13],mask);
	  continue;
	}
      else if (bits (insn, 32, 63) == 0x068b898d)	/* lea %s11,0x0(%s9,%s13) */
	{
	  long d = (long)((int)bits (insn, 0, 31));
	  regs[VE_SP_REGNUM] = pv_add (regs[VE_FP_REGNUM], regs[VE_S0_REGNUM + 13]);
	  regs[VE_SP_REGNUM] = pv_add_constant (regs[VE_SP_REGNUM], (d << 32));
	  continue;
	}
#endif
      else if (bits (insn, 32, 63) == 0x063f0000)
							/* lea %s63, 0x13b */
	{
	  regs[VE_S0_REGNUM + 63] = pv_constant (bits (insn, 0, 31));
	  continue;
	}
      else if (bits (insn, 32, 63) == 0x18358b88)
						/* brge.l.t %sp,%sl,.L1.EoP */
	{
	  if (ve_debug)
	    fprintf_unfiltered (gdb_stdlog, "fu: %s: <brge.l.t ...> "
				"(%%s%d %ld, %%s%d %ld, D 0x%lx)\n", __func__,
				(int)bits (insn, 40, 46),
				(long)regs[VE_S0_REGNUM + bits (insn, 40, 46)].k,
				(int)bits (insn, 32, 38),
				(long)regs[VE_S0_REGNUM + bits (insn, 32, 38)].k,
				bits (insn, 0, 31));
	  if ((long)regs[VE_S0_REGNUM + bits (insn, 40, 46)].k
	      >= (long)regs[VE_S0_REGNUM + bits (insn, 32, 38)].k)
	    {
	      unrecognized_pc = current_pc + bits (insn, 0, 31);
	      break;
	    }
	  else
	    continue;
	}
      else if (insn == 0x013d008e00000018)	/* ld %s61, 0x18 (,%tp) */
	continue;
      else if (insn == 0x313f03bd00000000)	/* shm.l %s63, 0x0(%s61) */
	continue;
      else if (insn == 0x310803bd00000008)	/* shm.l %sl, 0x8(%s61) */
	continue;
      else if (insn == 0x310b03bd00000010)	/* shm.l %sp, 0x10(%s61) */
	continue;
      else if (insn == 0x3f00000000000000)	/* monc */
	continue;
      else
	{
	  /* The optimizer might shove anything into the prologue, if
	     we build up cache (cache != NULL) from scanning prologue,
	     we just skip what we don't recognize and scan further to
	     make cache as complete as possible.  However, if we skip
	     prologue, we'll stop immediately on unrecognized
	     instruction.  */
	  unrecognized_pc = current_pc;
	  if (cache != NULL)
	    continue;
	  else
	    break;
	}
    }

  if (unrecognized_pc == 0)
    unrecognized_pc = current_pc;

  if (cache)
    {
      int framereg, framesize;

      /* The frame size is just the distance from the frame register
	 to the original stack pointer.  */
      if (pv_is_register (regs[VE_FP_REGNUM], VE_SP_REGNUM))
	{
	  /* Frame pointer is fp.  */
	  framereg = VE_FP_REGNUM;
	  framesize = -regs[VE_FP_REGNUM].k;
	}
      else
	{
	  /* Try the stack pointer... this is a bit desperate.  */
	  framereg = VE_SP_REGNUM;
	  framesize = -regs[VE_SP_REGNUM].k;
	}

      cache->framereg = framereg;
      cache->framesize = framesize;

      if (ve_debug)
	fprintf_unfiltered (gdb_stdlog, "fu: %s: in cache (framereg %d, "
			    "framesize %d)\n", __func__, framereg, framesize);

      for (regno = 0; regno < VE_VM0_REGNUM; regno++)
	if (pv_area_find_reg (stack, gdbarch, regno, &offset))
	  cache->saved_regs[regno].addr = offset;
    }

  if (ve_debug)
    fprintf_unfiltered (gdb_stdlog, "Prologue scan stopped at %s\n",
			paddress (gdbarch, unrecognized_pc));

  do_cleanups (back_to);
  return unrecognized_pc;
}

static void
ve_scan_prologue (struct frame_info *this_frame,
		   struct ve_prologue_cache *cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR prologue_start, prologue_end;
  CORE_ADDR prev_pc = get_frame_pc (this_frame);
  CORE_ADDR block_addr = get_frame_address_in_block (this_frame);

  if (ve_debug)
    fprintf_unfiltered (gdb_stdlog, "fu: %s: start (cache 0x%p)\n",
			__func__, cache);

  /* Assume there is no frame until proven otherwise.  */
  cache->framereg = VE_SP_REGNUM;
  cache->framesize = 0;

  /* Find the function prologue.  If we can't find the function in
     the symbol table, peek in the stack frame to find the PC.  */
  if (find_pc_partial_function (block_addr, NULL, &prologue_start,
				&prologue_end))
    {
      /* One way to find the end of the prologue (which works well
         for unoptimized code) is to do the following:

	    struct symtab_and_line sal = find_pc_line (prologue_start, 0);

	    if (sal.line == 0)
	      prologue_end = prev_pc;
	    else if (sal.end < prologue_end)
	      prologue_end = sal.end;

	 This mechanism is very accurate so long as the optimizer
	 doesn't move any instructions from the function body into the
	 prologue.  If this happens, sal.end will be the last
	 instruction in the first hunk of prologue code just before
	 the first instruction that the scheduler has moved from
	 the body to the prologue.

	 In order to make sure that we scan all of the prologue
	 instructions, we use a slightly less accurate mechanism which
	 may scan more than necessary.  To help compensate for this
	 lack of accuracy, the prologue scanning loop below contains
	 several clauses which'll cause the loop to terminate early if
	 an implausible prologue instruction is encountered.

	 The expression

	      prologue_start + 64

	 is a suitable endpoint since it accounts for the largest
	 possible prologue plus up to five instructions inserted by
	 the scheduler.  */

      if (ve_debug)
	fprintf_unfiltered (gdb_stdlog, "fu: %s: find func (start 0x%lx, "
			    "end 0x%lx)\n",
			    __func__, prologue_start, prologue_end);
      if (prologue_end > prologue_start + 280)
	{
	  prologue_end = prologue_start + 280;	/* See above.  */
	}
    }
  else
    {
      /* We have no symbol information.  Our only option is to assume this
	 function has a standard stack frame and the normal frame register.
	 Then, we can find the value of our frame pointer on entrance to
	 the callee (or at the present moment if this is the innermost frame).
	 The value stored there should be the address of the stmfd + 8.  */
      CORE_ADDR frame_loc;
      LONGEST return_value;

      frame_loc = get_frame_register_unsigned (this_frame, VE_FP_REGNUM);
      if (!safe_read_memory_integer (frame_loc, 8, byte_order, &return_value))
        return;
      else
        {
          prologue_start = gdbarch_addr_bits_remove
			     (gdbarch, return_value) - 8;
          prologue_end = prologue_start + 280;	/* See above.  */
        }
      if (ve_debug)
	fprintf_unfiltered (gdb_stdlog, "fu: %s: not find func (start 0x%lx, "
			    "end 0x%lx)\n",
			    __func__, prologue_start, prologue_end);
    }

  if (prev_pc < prologue_end)
    prologue_end = prev_pc;

  ve_analyze_prologue (gdbarch, prologue_start, prologue_end, cache);
}

static struct ve_prologue_cache *
ve_make_prologue_cache (struct frame_info *this_frame)
{
  int reg;
  struct ve_prologue_cache *cache;
  CORE_ADDR unwound_fp;

  if (ve_debug)
    fprintf_unfiltered (gdb_stdlog, "fu: %s: start (frame 0x%p)\n",
			__func__, this_frame);
  cache = FRAME_OBSTACK_ZALLOC (struct ve_prologue_cache);
  cache->saved_regs = trad_frame_alloc_saved_regs (this_frame);

  ve_scan_prologue (this_frame, cache);

  unwound_fp = get_frame_register_unsigned (this_frame, cache->framereg);
  if (ve_debug)
    fprintf_unfiltered (gdb_stdlog, "fu: %s: get frame register "
			"(unwound_fp 0x%lx)\n",
			__func__, unwound_fp);
  if (unwound_fp == 0)
    return cache;

  cache->prev_sp = unwound_fp + cache->framesize;

  /* Calculate actual addresses of saved registers using offsets
     determined by ve_scan_prologue.  */
  for (reg = 0; reg < gdbarch_num_regs (get_frame_arch (this_frame)); reg++)
    if (trad_frame_addr_p (cache->saved_regs, reg))
      cache->saved_regs[reg].addr += cache->prev_sp;

  return cache;
}

/* Our frame ID for a normal frame is the current function's starting PC
   and the caller's SP when we were called.  */

static void
ve_prologue_this_id (struct frame_info *this_frame,
		      void **this_cache,
		      struct frame_id *this_id)
{
  struct ve_prologue_cache *cache;
  struct frame_id id;
  CORE_ADDR pc, func;

  if (*this_cache == NULL)
    *this_cache = ve_make_prologue_cache (this_frame);
  cache = *this_cache;

  /* This is meant to halt the backtrace at "_start".  */
  pc = get_frame_pc (this_frame);
  if (pc <= gdbarch_tdep (get_frame_arch (this_frame))->lowest_pc)
    return;

  /* If we've hit a wall, stop.  */
  if (cache->prev_sp == 0)
    return;

  /* Use function start address as part of the frame ID.  If we cannot
     identify the start address (due to missing symbol information),
     fall back to just using the current PC.  */
  func = get_frame_func (this_frame);
  if (!func)
    func = pc;

  id = frame_id_build (cache->prev_sp, func);
  *this_id = id;
}

static struct value *
ve_prologue_prev_register (struct frame_info *this_frame,
			    void **this_cache,
			    int prev_regnum)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct ve_prologue_cache *cache;

  if (*this_cache == NULL)
    *this_cache = ve_make_prologue_cache (this_frame);
  cache = (struct ve_prologue_cache *) *this_cache;

  /* If we are asked to unwind the PC, then we need to return the LR
     instead.  The prologue may save PC, but it will point into this
     frame's prologue, not the next frame's resume location.  Also
     strip the saved T bit.  A valid LR may have the low bit set, but
     a valid PC never does.  */
  if (prev_regnum == VE_PC_REGNUM)
    {
      CORE_ADDR lr;

      lr = frame_unwind_register_unsigned (this_frame, VE_LR_REGNUM);
      return frame_unwind_got_constant (this_frame, prev_regnum,
					ve_addr_bits_remove (gdbarch, lr));
    }

  /* SP is generally not saved to the stack, but this frame is
     identified by the next frame's stack pointer at the time of the call.
     The value was already reconstructed into PREV_SP.  */
  if (prev_regnum == VE_SP_REGNUM)
    return frame_unwind_got_constant (this_frame, prev_regnum, cache->prev_sp);

  /* other registers */
  return trad_frame_get_prev_register (this_frame, cache->saved_regs,
				       prev_regnum);
}

struct frame_unwind ve_prologue_unwind = {
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  ve_prologue_this_id,
  ve_prologue_prev_register,
  NULL,
  default_frame_sniffer
};

static struct ve_prologue_cache *
ve_make_stub_cache (struct frame_info *this_frame)
{
  struct ve_prologue_cache *cache;

  cache = FRAME_OBSTACK_ZALLOC (struct ve_prologue_cache);
  cache->saved_regs = trad_frame_alloc_saved_regs (this_frame);

  cache->prev_sp = get_frame_register_unsigned (this_frame, VE_SP_REGNUM);

  return cache;
}

/* Our frame ID for a stub frame is the current SP and LR.  */

static void
ve_stub_this_id (struct frame_info *this_frame,
		  void **this_cache,
		  struct frame_id *this_id)
{
  struct ve_prologue_cache *cache;
  struct frame_id id;
  CORE_ADDR pc, func;

  if (*this_cache == NULL)
    *this_cache = ve_make_stub_cache (this_frame);
  cache = *this_cache;

  /* pc is below "__start" */
  pc = get_frame_pc(this_frame);
  if (pc <= gdbarch_tdep (get_frame_arch (this_frame))->lowest_pc)
    return;

  func = get_frame_func (this_frame);
  if (!func)
    func = pc;

  id = frame_id_build (cache->prev_sp, func);
  *this_id = id;
}

static int
ve_stub_unwind_sniffer (const struct frame_unwind *self,
			 struct frame_info *this_frame,
			 void **this_prologue_cache)
{
  CORE_ADDR addr_in_block, pc;
  gdb_byte dummy[4];

  addr_in_block = get_frame_address_in_block (this_frame);
  pc = get_frame_pc (this_frame);
  if (in_plt_section (addr_in_block)
      /* We also use the stub winder if the target memory is unreadable
	 to avoid having the prologue unwinder trying to read it.  */
      || target_read_memory (pc, dummy, 4) != 0)
    return 1;

  return 0;
}

struct frame_unwind ve_stub_unwind = {
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  ve_stub_this_id,
  ve_prologue_prev_register,
  NULL,
  ve_stub_unwind_sniffer
};

static CORE_ADDR
ve_normal_frame_base (struct frame_info *this_frame, void **this_cache)
{
  struct ve_prologue_cache *cache;

  if (*this_cache == NULL)
    *this_cache = ve_make_prologue_cache (this_frame);
  cache = *this_cache;

  return cache->prev_sp - cache->framesize;
}

struct frame_base ve_normal_base = {
  &ve_prologue_unwind,
  ve_normal_frame_base,
  ve_normal_frame_base,
  ve_normal_frame_base
};

/* Assuming THIS_FRAME is a dummy, return the frame ID of that
   dummy frame.  The frame ID's base needs to match the TOS value
   saved by save_dummy_frame_tos() and returned from
   ve_push_dummy_call, and the PC needs to match the dummy frame's
   breakpoint.  */

static struct frame_id
ve_dummy_id (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  return frame_id_build (get_frame_register_unsigned (this_frame,
						      VE_SP_REGNUM),
			 get_frame_pc (this_frame));
}

/* Given THIS_FRAME, find the previous frame's resume PC (which will
   be used to construct the previous frame's ID, after looking up the
   containing function).  */

static CORE_ADDR
ve_unwind_pc (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  CORE_ADDR pc;
  pc = frame_unwind_register_unsigned (this_frame, VE_PC_REGNUM);
  return ve_addr_bits_remove (gdbarch, pc);
}

static CORE_ADDR
ve_unwind_sp (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  return frame_unwind_register_unsigned (this_frame, VE_SP_REGNUM);
}

static struct value *
ve_dwarf2_prev_register (struct frame_info *this_frame, void **this_cache,
			  int regnum)
{
  struct gdbarch * gdbarch = get_frame_arch (this_frame);
  CORE_ADDR lr, cpsr;

  switch (regnum)
    {
    case VE_PC_REGNUM:
      /* The PC is normally copied from the return column, which
	 describes saves of LR.  However, that version may have an
	 extra bit set to indicate Thumb state.  The bit is not
	 part of the PC.  */
      lr = frame_unwind_register_unsigned (this_frame, VE_LR_REGNUM);
      return frame_unwind_got_constant (this_frame, regnum,
					ve_addr_bits_remove (gdbarch, lr));

    case VE_PS_REGNUM:
      /* Reconstruct the T bit; see ve_prologue_prev_register for details.  */
      cpsr = get_frame_register_unsigned (this_frame, regnum);
      return frame_unwind_got_constant (this_frame, regnum, cpsr);

    default:
      internal_error (__FILE__, __LINE__,
		      _("Unexpected register %d"), regnum);
    }
}

static void
ve_dwarf2_frame_init_reg (struct gdbarch *gdbarch, int regnum,
			   struct dwarf2_frame_state_reg *reg,
			   struct frame_info *this_frame)
{
  switch (regnum)
    {
    case VE_PC_REGNUM:
    case VE_PS_REGNUM:
      reg->how = DWARF2_FRAME_REG_FN;
      reg->loc.fn = ve_dwarf2_prev_register;
      break;
    case VE_SP_REGNUM:
      reg->how = DWARF2_FRAME_REG_CFA;
      break;
    }
}

/* prologue opcodes + function return */
#define	PR_OPCODE_NUM	(sizeof(prologues)/sizeof(prologues[0]))
#define	PR_OPCODE_RET	(prologues[5])
unsigned long prologues[] = {
	0x0000000089000b45,	/* or %s11,0,%s9 */
	0x180000008b000f01,	/* ld %s15,0x18(0,%s11) */
	0x200000008b001001,	/* ld %s16,0x20(0,%s11) */
	0x080000008b000a01,	/* ld %s10,0x8(0x%s11) */
	0x000000008b000901,	/* ld %s9,0x0(0,%s11) */
	0x000000008a000f19	/* b.l 0x0(,%s10) */
};

static int
ve_in_function_epilogue_p (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  enum bfd_endian byte_order_for_code = gdbarch_byte_order_for_code (gdbarch);
  unsigned long insn;
  int found_return, i;
  CORE_ADDR func_start, func_end, addr;

  if (!find_pc_partial_function (pc, NULL, &func_start, &func_end))
    return 0;

  addr = pc;
  found_return = 0;
  for (i = 0;i < PR_OPCODE_NUM;i++) 
    {
      addr += VE_INSN_SIZE;
      insn = read_memory_unsigned_integer (addr, VE_INSN_SIZE, byte_order_for_code);
      if (insn == PR_OPCODE_RET)
        {
          found_return = 1;
          break;
        }
    }

  if (!found_return)
    return 0;
      
  addr -= VE_INSN_SIZE * (PR_OPCODE_NUM-1);
  for(i = 0;i < PR_OPCODE_NUM-1;i++)
    {
      insn = read_memory_unsigned_integer (addr, VE_INSN_SIZE, byte_order_for_code);
      if (insn != prologues[i])
        return 0;
      addr += VE_INSN_SIZE;
    }

  return 1;
}

/* When arguments must be pushed onto the stack, they go on in reverse
   order.  The code below implements a FILO (stack) to do this.  */

struct stack_item
{
  int len;
  struct stack_item *prev;
  void *data;
};

static struct stack_item *
push_stack_item (struct stack_item *prev, const void *contents, int len)
{
  struct stack_item *si;
  si = xmalloc (sizeof (struct stack_item));
  si->data = xmalloc (len);
  si->len = len;
  si->prev = prev;
  memcpy (si->data, contents, len);
  return si;
}

static struct stack_item *
pop_stack_item (struct stack_item *si)
{
  struct stack_item *dead = si;
  si = si->prev;
  xfree (dead->data);
  xfree (dead);
  return si;
}


/* Return the alignment (in bytes) of the given type.  */

static int
ve_type_align (struct type *t)
{
  int n;
  int align;
  int falign;

  t = check_typedef (t);
  switch (TYPE_CODE (t))
    {
    default:
      /* Should never happen.  */
      internal_error (__FILE__, __LINE__, _("unknown type alignment"));
      return 8;

    case TYPE_CODE_PTR:
    case TYPE_CODE_ENUM:
    case TYPE_CODE_INT:
    case TYPE_CODE_FLT:
    case TYPE_CODE_SET:
    case TYPE_CODE_RANGE:
    case TYPE_CODE_REF:
    case TYPE_CODE_CHAR:
    case TYPE_CODE_BOOL:
      return TYPE_LENGTH (t);

    case TYPE_CODE_ARRAY:
      if (TYPE_VECTOR (t))
	return TYPE_LENGTH (t);
      else
	return ve_type_align (TYPE_TARGET_TYPE (t));
    case TYPE_CODE_COMPLEX:
      /* TODO: What about vector types?  */
      return ve_type_align (TYPE_TARGET_TYPE (t));

    case TYPE_CODE_STRUCT:
    case TYPE_CODE_UNION:
      align = 1;
      for (n = 0; n < TYPE_NFIELDS (t); n++)
	{
	  falign = ve_type_align (TYPE_FIELD_TYPE (t, n));
	  if (falign > align)
	    align = falign;
	}
      return align;
    }
}

/* Floating-point size */
#define VE_FLOAT_SIZE		4
#define VE_DOUBLE_SIZE		8
#define VE_LONG_DOUBLE_SIZE	16

static CORE_ADDR
ve_push_dummy_call (struct gdbarch *gdbarch, struct value *function,
		     struct regcache *regcache, CORE_ADDR bp_addr, int nargs,
		     struct value **args, CORE_ADDR sp, int struct_return,
		     CORE_ADDR struct_addr)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  int argnum;
  int argreg;
  int nstack;
  struct stack_item *si = NULL;
  struct type *ftype;
  struct stack_item *ref_si = NULL;
  int rsa_len = 0xb0;
  gdb_byte rsa_buf[rsa_len];

  /* Determine the type of this function and whether the VFP ABI
     applies.  */
  ftype = check_typedef (value_type (function));
  if (TYPE_CODE (ftype) == TYPE_CODE_PTR)
    ftype = check_typedef (TYPE_TARGET_TYPE (ftype));

  /* Set the return address.  For the VE, the return breakpoint is
     always at BP_ADDR.  */
  regcache_cooked_write_unsigned (regcache, VE_LR_REGNUM, bp_addr);

  /* Walk through the list of args and determine how large a temporary
     stack is required.  Need to take care here as structs may be
     passed on the stack, and we have to push them.  */
  argreg = VE_ARG0_REGNUM;
  nstack = 0;

  /* The struct_return pointer occupies the first parameter
     passing register.  */
  if (struct_return)
    {
      gdb_byte buf[INT_REGISTER_SIZE];

      if (ve_debug)
	fprintf_unfiltered (gdb_stdlog, "struct return in %s = %s\n",
			    gdbarch_register_name (gdbarch, argreg),
			    paddress (gdbarch, struct_addr));
      regcache_cooked_write_unsigned (regcache, argreg, struct_addr);
      argreg++;

      memset (buf, 0, sizeof (buf));
      store_unsigned_integer (buf, INT_REGISTER_SIZE, byte_order, struct_addr);

      /* Push the arguments onto the stack.  */
      if (ve_debug)
	fprintf_unfiltered (gdb_stdlog, "struct return in @ sp + %d\n",
			    nstack);
      si = push_stack_item (si, buf, INT_REGISTER_SIZE);
      nstack += INT_REGISTER_SIZE;
    }

  for (argnum = 0; argnum < nargs; argnum++)
    {
      int len;
      struct type *arg_type;
      const bfd_byte *val;
      int align;
      int total_len;

      arg_type = check_typedef (value_type (args[argnum]));
      len = TYPE_LENGTH (arg_type);
      total_len = len;
      val = value_contents (args[argnum]);

      align = ve_type_align (arg_type);
      /* Round alignment up to a whole number of words.  */
      align = (align + INT_REGISTER_SIZE - 1) & ~(INT_REGISTER_SIZE - 1);

      /* Push stack padding for doubleword alignment.  */
      if (nstack & (align - 1))
	{
	  si = push_stack_item (si, val, INT_REGISTER_SIZE);
	  nstack += INT_REGISTER_SIZE;
	}
      
      /* Doubleword aligned quantities must go in even register pairs.  */
      if (argreg <= VE_LAST_ARG_REGNUM
	  && align > INT_REGISTER_SIZE
	  && !(argreg & 1))
	argreg++;

      /* Copy the argument to general registers or the stack in
	 register-sized pieces.  Large arguments are split between
	 registers and stack.  */
      while (len > 0)
	{
	  gdb_byte buf[INT_REGISTER_SIZE];
	  int partial_len = len < INT_REGISTER_SIZE ? len : INT_REGISTER_SIZE;
	  CORE_ADDR regval
	    = extract_unsigned_integer (val, partial_len, byte_order);

	  if (TYPE_CODE (arg_type) == TYPE_CODE_STRUCT
	      || TYPE_CODE (arg_type) == TYPE_CODE_UNION
	      || TYPE_CODE (arg_type) == TYPE_CODE_ARRAY)
	    {
	      sp -= len;
	      write_memory (sp, val, len);
	      regval = sp;
	      len = INT_REGISTER_SIZE;
	      partial_len = INT_REGISTER_SIZE;
	    }

	  if (TYPE_CODE_FLT == TYPE_CODE (arg_type)
	      && total_len == VE_FLOAT_SIZE)
	    {
	      CORE_ADDR tmp = regval;
	      regval = ((tmp << (total_len * 8)) | (tmp >> (total_len * 8)));
	      len = INT_REGISTER_SIZE;
	      partial_len = INT_REGISTER_SIZE;
	    }

	  if (argreg <= VE_LAST_ARG_REGNUM)
	    {
	      /* The argument is being passed in a general purpose
		 register.  */
	      if (byte_order == BFD_ENDIAN_BIG)
		regval <<= (INT_REGISTER_SIZE - partial_len) * 8;
	      if (ve_debug)
		fprintf_unfiltered (gdb_stdlog, "arg %d in %s = 0x%s\n",
				    argnum,
				    gdbarch_register_name
				      (gdbarch, argreg),
				    phex (regval, INT_REGISTER_SIZE));
	      regcache_cooked_write_unsigned (regcache, argreg, regval);
	      argreg++;
	    }

	  memset (buf, 0, sizeof (buf));
	  store_unsigned_integer (buf, partial_len, byte_order, regval);

	  /* Push the arguments onto the stack.  */
	  if (ve_debug)
	    fprintf_unfiltered (gdb_stdlog, "arg %d @ sp + %d\n",
				argnum, nstack);
	  si = push_stack_item (si, buf, INT_REGISTER_SIZE);
	  nstack += INT_REGISTER_SIZE;

	  len -= partial_len;
	  val += partial_len;
	}
    }

  while (si)
    {
      sp -= si->len;
      write_memory (sp, si->data, si->len);
      si = pop_stack_item (si);
    }

  /* needed stack size for RSA, return address and frame pointer of
     callee. The default size is 176(0xb0) bytes. */
  sp -= rsa_len;
  memset (rsa_buf, 0, rsa_len);
  write_memory (sp, rsa_buf, rsa_len);

  /* Finally, update the SP register.  */
  regcache_cooked_write_unsigned (regcache, VE_SP_REGNUM, sp);

  return sp;
}


/* Always align the frame to an 8-byte boundary.  This is required on
   some platforms and hveless on the rest.  */

static CORE_ADDR
ve_frame_align (struct gdbarch *gdbarch, CORE_ADDR sp)
{
  /* Align the stack to eight bytes.  */
  return sp & ~ (CORE_ADDR) 7;
}

/* Construct the vector mask type of the VE architecture. */
static struct type *
ve_vm_type (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (!tdep->ve_vm_type)
    {
      const struct builtin_type *bt = builtin_type (gdbarch);

      /* The type we're building is this:  */
      struct type *t;

      t = arch_composite_type (gdbarch,
			       "__gdb_builtin_type_vec4i", TYPE_CODE_UNION);
      append_composite_type_field (t, "v4_uint64",
				   init_vector_type (bt->builtin_uint64, 4));

      TYPE_VECTOR (t) = 1;
      TYPE_NAME (t) = "builtin_type_vec4i";
      tdep->ve_vm_type = t;
    }

  return tdep->ve_vm_type;
}

/* Construct the vector(floating point) type of the VE architecture. */
static struct type *
ve_vec_type (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (!tdep->ve_vec_type)
    {
      const struct builtin_type *bt = builtin_type (gdbarch);

      /* The type we're building is this:  */
      struct type *t;

      t = arch_composite_type (gdbarch,
			       "__gdb_builtin_type_vec256d", TYPE_CODE_UNION);
      append_composite_type_field (t, "v256_double",
				   init_vector_type (bt->builtin_double, 256));

      TYPE_VECTOR (t) = 1;
      TYPE_NAME (t) = "builtin_type_vec256d";
      tdep->ve_vec_type = t;
    }

  return tdep->ve_vec_type;
}

/* Return the GDB type object for the "standard" data type of data in
   register N.  */

static struct type *
ve_register_type (struct gdbarch *gdbarch, int regnum)
{
  if (regnum >= VE_VM0_REGNUM && regnum < VE_V0_REGNUM)
    return ve_vm_type (gdbarch);

  if (regnum >= VE_V0_REGNUM && regnum < VE_NUM_REGS)
    return ve_vec_type (gdbarch);

  if (regnum == VE_SP_REGNUM || regnum == VE_FP_REGNUM)
    return builtin_type (gdbarch)->builtin_data_ptr;
  else if (regnum == VE_PC_REGNUM)
    return builtin_type (gdbarch)->builtin_func_ptr;
  else if (regnum >= ARRAY_SIZE (ve_register_names))
    /* These registers are only supported on targets which supply
       an XML description.  */
    return builtin_type (gdbarch)->builtin_int0;
  else
    return builtin_type (gdbarch)->builtin_uint64;
}

/* Map a DWARF register REGNUM onto the appropriate GDB register
   number.  */

static int
ve_dwarf_reg_to_regnum (struct gdbarch *gdbarch, int reg)
{
  /* Scalar registers.  */
  if (reg >= 0 && reg <= 63)
    return VE_S0_REGNUM + reg;

  /* Vector registers.  */
  if (reg >= 64 && reg <= 127)
    return VE_V0_REGNUM + reg - 64;

  /* Vector Mask registers.  */
  if (reg >= 128 && reg <= 143)
    return VE_VM0_REGNUM + reg - 128;

  return -1;
}

#include "bfd-in2.h"
#include "libcoff.h"

static int
gdb_print_insn_ve (bfd_vma memaddr, disassemble_info *info)
{
  struct gdbarch *gdbarch = info->application_data;

  info->symbols = NULL;

  return print_insn_ve (memaddr, info);
}

/* The following define instruction sequences that will cause VE
   cpu's to take an undefined instruction trap.  These are used to
   signal a breakpoint to GDB.
   
   The newer VEv4T cpu's are capable of operating in VE or Thumb
   modes.  A different instruction is required for each mode.  The VE
   cpu's can also be big or little endian.  Thus four different
   instructions are needed to support all cases.
   
   Note: VEv4 defines several new instructions that will take the
   undefined instruction trap.  VE7TDMI is nominally VEv4T, but does
   not in fact add the new instructions.  The new undefined
   instructions in VEv4 are all instructions that had no defined
   behaviour in earlier chips.  There is no guarantee that they will
   raise an exception, but may be treated as NOP's.  In practice, it
   may only safe to rely on instructions matching:
   
   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1 
   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
   C C C C 0 1 1 x x x x x x x x x x x x x x x x x x x x 1 x x x x
   
   Even this may only true if the condition predicate is true.  The
   following use a condition predicate of ALWAYS so it is always TRUE.
   
   There are other ways of forcing a breakpoint.  GNU/Linux, RISC iX,
   and NetBSD all use a software interrupt rather than an undefined
   instruction to force a trap.  This can be handled by by the
   abi-specific code during establishment of the gdbarch vector.  */

/* MONC TRAP */
#define VE_LE_BREAKPOINT {0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x3f}
#define VE_BE_BREAKPOINT {0x3f,0x80,0x00,0x00,0x00,0x00,0x00,0x00}

static const gdb_byte ve_default_ve_le_breakpoint[] = VE_LE_BREAKPOINT;
static const gdb_byte ve_default_ve_be_breakpoint[] = VE_BE_BREAKPOINT;

/* Determine the type and size of breakpoint to insert at PCPTR.  Uses
   the program counter value to determine whether a 16-bit or 32-bit
   breakpoint should be used.  It returns a pointer to a string of
   bytes that encode a breakpoint instruction, stores the length of
   the string to *lenptr, and adjusts the program counter (if
   necessary) to point to the actual memory location where the
   breakpoint should be inserted.  */

static const unsigned char *
ve_breakpoint_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr, int *lenptr)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  *lenptr = tdep->ve_breakpoint_size;

  return tdep->ve_breakpoint;
}

static void
ve_remote_breakpoint_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr,
			       int *kindptr)
{
  ve_breakpoint_from_pc (gdbarch, pcptr, kindptr);
}

/* Extract from an array REGBUF containing the (raw) register state a
   function return value of type TYPE, and copy that, in virtual
   format, into VALBUF.  */

static void
ve_extract_return_value (struct type *type, struct regcache *regs,
			  gdb_byte *valbuf)
{
  struct gdbarch *gdbarch = get_regcache_arch (regs);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  if (TYPE_CODE_FLT == TYPE_CODE (type))
    {
      switch (gdbarch_tdep (gdbarch)->fp_model)
	{
	case VE_FLOAT_AUTO:
	  {
	    int len = TYPE_LENGTH (type);
	    int regno = VE_A1_REGNUM;
	    ULONGEST tmp;

	    regcache_cooked_read_unsigned (regs, regno, &tmp);
	    switch (len)
	      {
	      case VE_FLOAT_SIZE:
		store_unsigned_integer (valbuf, len, byte_order,
					(tmp >> (len * 8)));
		break;
	      case VE_LONG_DOUBLE_SIZE:
		store_unsigned_integer (valbuf, len, byte_order, tmp);
		regno++;
		len -= INT_REGISTER_SIZE;
		valbuf += INT_REGISTER_SIZE;
		regcache_cooked_read_unsigned (regs, regno, &tmp);
	      case VE_DOUBLE_SIZE:
		store_unsigned_integer (valbuf, len, byte_order, tmp);
	      }
	  }
	  break;

	default:
	  internal_error (__FILE__, __LINE__,
			  _("ve_extract_return_value: "
			    "Floating point model not supported"));
	  break;
	}
    }
  else if (TYPE_CODE (type) == TYPE_CODE_INT
	   || TYPE_CODE (type) == TYPE_CODE_CHAR
	   || TYPE_CODE (type) == TYPE_CODE_BOOL
	   || TYPE_CODE (type) == TYPE_CODE_PTR
	   || TYPE_CODE (type) == TYPE_CODE_REF
	   || TYPE_CODE (type) == TYPE_CODE_ENUM)
    {
      /* If the type is a plain integer, then the access is
	 straight-forward.  Otherwise we have to play around a bit
	 more.  */
      int len = TYPE_LENGTH (type);
      int regno = VE_A1_REGNUM;
      ULONGEST tmp;

      while (len > 0)
	{
	  /* By using store_unsigned_integer we avoid having to do
	     anything special for small big-endian values.  */
	  regcache_cooked_read_unsigned (regs, regno++, &tmp);
	  store_unsigned_integer (valbuf, 
				  (len > INT_REGISTER_SIZE
				   ? INT_REGISTER_SIZE : len),
				  byte_order, tmp);
	  len -= INT_REGISTER_SIZE;
	  valbuf += INT_REGISTER_SIZE;
	}
    }
  else
    {
      /* For a structure or union the behaviour is as if the value had
         been stored to word-aligned memory and then loaded into 
         registers with 32-bit load instruction(s).  */
      int len = TYPE_LENGTH (type);
      int regno = VE_A1_REGNUM;
      bfd_byte tmpbuf[INT_REGISTER_SIZE];

      while (len > 0)
	{
	  regcache_cooked_read (regs, regno++, tmpbuf);
	  memcpy (valbuf, tmpbuf,
		  len > INT_REGISTER_SIZE ? INT_REGISTER_SIZE : len);
	  len -= INT_REGISTER_SIZE;
	  valbuf += INT_REGISTER_SIZE;
	}
    }
}


/* Write into appropriate registers a function return value of type
   TYPE, given in virtual format.  */

static void
ve_store_return_value (struct type *type, struct regcache *regs,
			const gdb_byte *valbuf)
{
  struct gdbarch *gdbarch = get_regcache_arch (regs);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  if (TYPE_CODE (type) == TYPE_CODE_FLT)
    {
      switch (gdbarch_tdep (gdbarch)->fp_model)
	{
	case VE_FLOAT_AUTO:
	  {
	    int len = TYPE_LENGTH (type);
	    int regno = VE_A1_REGNUM;

	    if (len <= VE_FLOAT_SIZE)
	      {
		bfd_byte tmpbuf[INT_REGISTER_SIZE];
		ULONGEST val = unpack_long (type, valbuf);

		store_unsigned_integer (tmpbuf, INT_REGISTER_SIZE, byte_order,
					(val << (len * 8)));
		regcache_cooked_write (regs, regno, tmpbuf);
	      }
	    else
	      {
		while (len > 0)
		  {
		    regcache_cooked_write (regs, regno++, valbuf);
		    len -= INT_REGISTER_SIZE;
		    valbuf += INT_REGISTER_SIZE;
		  }
	      }
	  }
	  break;

	default:
	  internal_error (__FILE__, __LINE__,
			  _("ve_store_return_value: Floating "
			    "point model not supported"));
	  break;
	}
    }
  else if (TYPE_CODE (type) == TYPE_CODE_INT
	   || TYPE_CODE (type) == TYPE_CODE_CHAR
	   || TYPE_CODE (type) == TYPE_CODE_BOOL
	   || TYPE_CODE (type) == TYPE_CODE_PTR
	   || TYPE_CODE (type) == TYPE_CODE_REF
	   || TYPE_CODE (type) == TYPE_CODE_ENUM)
    {
      if (TYPE_LENGTH (type) <= 4)
	{
	  /* Values of one word or less are zero/sign-extended and
	     returned in r0.  */
	  bfd_byte tmpbuf[INT_REGISTER_SIZE];
	  LONGEST val = unpack_long (type, valbuf);

	  store_signed_integer (tmpbuf, INT_REGISTER_SIZE, byte_order, val);
	  regcache_cooked_write (regs, VE_A1_REGNUM, tmpbuf);
	}
      else
	{
	  /* Integral values greater than one word are stored in consecutive
	     registers starting with r0.  This will always be a multiple of
	     the regiser size.  */
	  int len = TYPE_LENGTH (type);
	  int regno = VE_A1_REGNUM;

	  while (len > 0)
	    {
	      regcache_cooked_write (regs, regno++, valbuf);
	      len -= INT_REGISTER_SIZE;
	      valbuf += INT_REGISTER_SIZE;
	    }
	}
    }
  else
    {
      /* For a structure or union the behaviour is as if the value had
         been stored to word-aligned memory and then loaded into 
         registers with 32-bit load instruction(s).  */
      int len = TYPE_LENGTH (type);
      int regno = VE_A1_REGNUM;
      bfd_byte tmpbuf[INT_REGISTER_SIZE];

      while (len > 0)
	{
	  memcpy (tmpbuf, valbuf,
		  len > INT_REGISTER_SIZE ? INT_REGISTER_SIZE : len);
	  regcache_cooked_write (regs, regno++, tmpbuf);
	  len -= INT_REGISTER_SIZE;
	  valbuf += INT_REGISTER_SIZE;
	}
    }
}


/* Handle function return values.  */

static enum return_value_convention
ve_return_value (struct gdbarch *gdbarch, struct value *function,
		  struct type *valtype, struct regcache *regcache,
		  gdb_byte *readbuf, const gdb_byte *writebuf)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  struct type *func_type = function ? value_type (function) : NULL;

  if (TYPE_CODE (valtype) == TYPE_CODE_STRUCT
      || TYPE_CODE (valtype) == TYPE_CODE_UNION
      || TYPE_CODE (valtype) == TYPE_CODE_ARRAY)
    {
      if (tdep->struct_return == pcc_struct_return)
	return RETURN_VALUE_STRUCT_CONVENTION;
    }

  if (writebuf)
    ve_store_return_value (valtype, regcache, writebuf);

  if (readbuf)
    ve_extract_return_value (valtype, regcache, readbuf);

  return RETURN_VALUE_REGISTER_CONVENTION;
}


static int
ve_get_longjmp_target (struct frame_info *frame, CORE_ADDR *pc)
{
  struct gdbarch *gdbarch = get_frame_arch (frame);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR jb_addr;
  gdb_byte buf[INT_REGISTER_SIZE];
  
  jb_addr = get_frame_register_unsigned (frame, VE_A1_REGNUM);

  if (target_read_memory (jb_addr + tdep->jb_pc * tdep->jb_elt_size, buf,
			  INT_REGISTER_SIZE))
    return 0;

  *pc = extract_unsigned_integer (buf, INT_REGISTER_SIZE, byte_order);
  return 1;
}

/* Recognize GCC and GNU ld's trampolines.  If we are in a trampoline,
   return the target PC.  Otherwise return 0.  */

CORE_ADDR
ve_skip_stub (struct frame_info *frame, CORE_ADDR pc)
{
  return find_solib_trampoline_target (frame, pc);
}


/* Return the VE register name corresponding to register I.  */
static const char *
ve_register_name (struct gdbarch *gdbarch, int i)
{
  if (i >= ARRAY_SIZE (ve_register_names))
    /* These registers are only supported on targets which supply
       an XML description.  */
    return "";

  return ve_register_names[i];
}

static void
ve_write_pc (struct regcache *regcache, CORE_ADDR pc)
{
  /* Clear upper 16 bits and lower 3 bits */
  pc <<= 16;
  pc >>= (16+3);
  pc <<= 3;
  regcache_cooked_write_unsigned (regcache, VE_PC_REGNUM, pc);
}

static struct value *
value_of_ve_user_reg (struct frame_info *frame, const void *baton)
{
  const int *reg_p = (const int *) baton;
  return value_of_register (*reg_p, frame);
}

static int
ve_register_reggroup_p (struct gdbarch *gdbarch, int regnum,
			  struct reggroup *group)
{
    return default_register_reggroup_p (gdbarch, regnum, group);
}


/* Initialize the current architecture based on INFO.  If possible,
   re-use an architecture from ARCHES, which is a list of
   architectures already created during this debugging session.

   Called e.g. at program startup, when reading a core file, and when
   reading a binary file.  */

static struct gdbarch *
ve_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  struct gdbarch_tdep *tdep;
  struct gdbarch *gdbarch;
  struct gdbarch_list *best_arch;
  enum ve_abi_kind ve_abi = ve_abi_global;
  enum ve_float_model fp_model = ve_fp_model;
  struct tdesc_arch_data *tdesc_data = NULL;
  int i;
  const struct target_desc *tdesc = info.target_desc;

  /* If we have an object to base this architecture on, try to determine
     its ABI.  */

  if (ve_abi == VE_ABI_AUTO && info.abfd != NULL)
    {
      switch (bfd_get_flavour (info.abfd))
	{
	default:
	  /* Leave it as "auto".  */
	  break;
	}
    }

  /* Check any target description for validity.  */
  if (tdesc_has_registers (tdesc))
    {
      /* For most registers we require GDB's default names; but also allow
	 the numeric names for sp / lr / pc, as a convenience.  */
      static const char *const ve_sp_names[] = { "s11", "sp", NULL };
      static const char *const ve_lr_names[] = { "s10", "lr", NULL };
      static const char *const ve_pc_names[] = { "ic", "pc", NULL };

      const struct tdesc_feature *feature;
      int valid_p;

      feature = tdesc_find_feature (tdesc,
				    "org.gnu.gdb.ve.core");
      if (feature == NULL)
	return NULL;

      tdesc_data = tdesc_data_alloc ();

      valid_p = 1;
      for (i = 0; i < VE_NUM_REGS; i++)
	valid_p &= tdesc_numbered_register (feature, tdesc_data, i,
					    ve_register_names[i]);
      valid_p &= tdesc_numbered_register_choices (feature, tdesc_data,
						  VE_SP_REGNUM,
						  ve_sp_names);
      valid_p &= tdesc_numbered_register_choices (feature, tdesc_data,
						  VE_LR_REGNUM,
						  ve_lr_names);
      valid_p &= tdesc_numbered_register_choices (feature, tdesc_data,
						  VE_PC_REGNUM,
						  ve_pc_names);

      if (!valid_p)
	{
	  tdesc_data_cleanup (tdesc_data);
	  return NULL;
	}

    }


  /* If there is already a candidate, use it.  */
  for (best_arch = gdbarch_list_lookup_by_info (arches, &info);
       best_arch != NULL;
       best_arch = gdbarch_list_lookup_by_info (best_arch->next, &info))
    {
      if (ve_abi != VE_ABI_AUTO
	  && ve_abi != gdbarch_tdep (best_arch->gdbarch)->ve_abi)
	continue;

      /* Found a match.  */
      break;
    }

  if (best_arch != NULL)
    {
      if (tdesc_data != NULL)
	tdesc_data_cleanup (tdesc_data);
      return best_arch->gdbarch;
    }

  tdep = XCNEW (struct gdbarch_tdep);
  gdbarch = gdbarch_alloc (&info, tdep);

  /* Record additional information about the architecture we are defining.
     These are gdbarch discriminators, like the OSABI.  */
  tdep->ve_abi = ve_abi;
  tdep->fp_model = fp_model;

  /* Breakpoints.  */
  switch (info.byte_order_for_code)
    {
    case BFD_ENDIAN_BIG:
      tdep->ve_breakpoint = ve_default_ve_be_breakpoint;
      tdep->ve_breakpoint_size = VE_INSN_SIZE;

      break;

    case BFD_ENDIAN_LITTLE:
      tdep->ve_breakpoint = ve_default_ve_le_breakpoint;
      tdep->ve_breakpoint_size = VE_INSN_SIZE;

      break;

    default:
      internal_error (__FILE__, __LINE__,
		      _("ve_gdbarch_init: bad byte order for float format"));
    }

  /* On VE targets char defaults to unsigned.  */
  set_gdbarch_char_signed (gdbarch, 0);
  set_gdbarch_ptr_bit (gdbarch, 8 * TARGET_CHAR_BIT);
  set_gdbarch_short_bit (gdbarch, 2 * TARGET_CHAR_BIT);
  set_gdbarch_int_bit (gdbarch, 4 * TARGET_CHAR_BIT);
  set_gdbarch_long_bit (gdbarch, 8 * TARGET_CHAR_BIT);
  set_gdbarch_long_long_bit (gdbarch, 8 * TARGET_CHAR_BIT);
  set_gdbarch_float_bit (gdbarch, 4 * TARGET_CHAR_BIT);
  set_gdbarch_double_bit (gdbarch, 8 * TARGET_CHAR_BIT);
  set_gdbarch_long_double_bit (gdbarch, 16 * TARGET_CHAR_BIT);

  /* Note: for displaced stepping, this includes the breakpoint, and one word
     of additional scratch space.  This setting isn't used for anything beside
     displaced stepping at present.  */
  set_gdbarch_max_insn_length (gdbarch, 4 * DISPLACED_MODIFIED_INSNS);

  /* This should be low enough for everything.  */
  tdep->lowest_pc = 0x20;
  tdep->jb_pc = -1;	/* Longjump support not enabled by default.  */

  /* The default, for both APCS and AAPCS, is to return small
     structures in registers.  */
  tdep->struct_return = pcc_struct_return;

  set_gdbarch_push_dummy_call (gdbarch, ve_push_dummy_call);
  set_gdbarch_frame_align (gdbarch, ve_frame_align);

  set_gdbarch_write_pc (gdbarch, ve_write_pc);

  /* Frame handling.  */
  set_gdbarch_dummy_id (gdbarch, ve_dummy_id);
  set_gdbarch_unwind_pc (gdbarch, ve_unwind_pc);
  set_gdbarch_unwind_sp (gdbarch, ve_unwind_sp);

  frame_base_set_default (gdbarch, &ve_normal_base);

  /* Address manipulation.  */
  set_gdbarch_addr_bits_remove (gdbarch, ve_addr_bits_remove);

  /* Advance PC across function entry code.  */
  set_gdbarch_skip_prologue (gdbarch, ve_skip_prologue);

  /* Detect whether PC is in function epilogue.  */
  set_gdbarch_stack_frame_destroyed_p (gdbarch, ve_in_function_epilogue_p);

  /* Skip trampolines.  */
  set_gdbarch_skip_trampoline_code (gdbarch, ve_skip_stub);

  /* The stack grows downward.  */
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan);

  /* Breakpoint manipulation.  */
  set_gdbarch_breakpoint_from_pc (gdbarch, ve_breakpoint_from_pc);
  set_gdbarch_remote_breakpoint_from_pc (gdbarch,
					 ve_remote_breakpoint_from_pc);
  set_gdbarch_decr_pc_after_break (gdbarch, 8);

  /* Information about registers, etc.  */
  set_gdbarch_sp_regnum (gdbarch, VE_SP_REGNUM);
  set_gdbarch_pc_regnum (gdbarch, VE_PC_REGNUM);
  set_gdbarch_num_regs (gdbarch, VE_NUM_REGS);
  set_gdbarch_register_type (gdbarch, ve_register_type);
  set_gdbarch_register_reggroup_p (gdbarch, ve_register_reggroup_p);

   /* Internal <-> external register number maps.  */
  set_gdbarch_dwarf2_reg_to_regnum (gdbarch, ve_dwarf_reg_to_regnum);

  set_gdbarch_register_name (gdbarch, ve_register_name);

  /* Returning results.  */
  set_gdbarch_return_value (gdbarch, ve_return_value);

  /* Disassembly.  */
  set_gdbarch_print_insn (gdbarch, gdb_print_insn_ve);

  /* Virtual tables.  */
  set_gdbarch_vbit_in_delta (gdbarch, 1);

  /* Hook in the ABI-specific overrides, if they have been registered.  */
  gdbarch_init_osabi (info, gdbarch);

  dwarf2_frame_set_init_reg (gdbarch, ve_dwarf2_frame_init_reg);

  frame_unwind_append_unwinder (gdbarch, &ve_stub_unwind);
  dwarf2_append_unwinders (gdbarch);
  frame_unwind_append_unwinder (gdbarch, &ve_prologue_unwind);

  /* Now we have tuned the configuration, set a few final things,
     based on what the OS ABI has told us.  */

  /* If the ABI is not otherwise marked, assume the old VER 0 draft copy .  EABI
     binaries are always marked.  */
  if (tdep->ve_abi == VE_ABI_AUTO)
    tdep->ve_abi = VE_ABI_VER0;

  /* Watchpoints are not steppable.  */
  set_gdbarch_have_nonsteppable_watchpoint (gdbarch, 1);

  /* We default to generic VE */
  if (tdep->fp_model != VE_FLOAT_AUTO)
    tdep->fp_model = VE_FLOAT_AUTO;

  if (tdep->jb_pc >= 0)
    set_gdbarch_get_longjmp_target (gdbarch, ve_get_longjmp_target);

  /* Floating point sizes and format.  */
  set_gdbarch_float_format (gdbarch, floatformats_ieee_single);
    {
      set_gdbarch_double_format (gdbarch, floatformats_ieee_double);
      set_gdbarch_long_double_format (gdbarch, floatformats_ieee_double);
    }

  if (tdesc_data)
    {
      set_tdesc_pseudo_register_name (gdbarch, ve_register_name);

      tdesc_use_registers (gdbarch, tdesc, tdesc_data);

      /* Override tdesc_register_type to adjust the types of VFP
	 registers for NEON.  */
      set_gdbarch_register_type (gdbarch, ve_register_type);
    }

  /* Add standard register aliases.  We add aliases even for those
     nanes which are used by the current architecture - it's simpler,
     and does no hve, since nothing ever lists user registers.  */
  for (i = 0; i < ARRAY_SIZE (ve_register_aliases); i++)
    user_reg_add (gdbarch, ve_register_aliases[i].name,
		  value_of_ve_user_reg, &ve_register_aliases[i].regnum);

  return gdbarch;
}


static void
ve_dump_tdep (struct gdbarch *gdbarch, struct ui_file *file)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep == NULL)
    return;

  fprintf_unfiltered (file, _("ve_dump_tdep: Lowest pc = 0x%lx"),
		      (unsigned long) tdep->lowest_pc);
}

extern initialize_file_ftype _initialize_ve_tdep; /* -Wmissing-prototypes */

void
_initialize_ve_tdep (void)
{
  static char *helptext;
  char regdesc[1024], *rdptr = regdesc;
  size_t rest = sizeof (regdesc);

  gdbarch_register (bfd_arch_ve, ve_gdbarch_init, ve_dump_tdep);

  /* Initialize the standard target descriptions.  */
  initialize_tdesc_ve ();

  /* Debugging flag.  */
  add_setshow_boolean_cmd ("ve", class_maintenance, &ve_debug,
			   _("Set VE debugging."),
			   _("Show VE debugging."),
			   _("When on, ve-specific debugging is enabled."),
			   NULL,
			   NULL, /* FIXME: i18n: "VE debugging is %s.  */
			   &setdebuglist, &showdebuglist);
}
