/* GNU/Linux on ARM target support.

   Copyright (C) 1999-2016 Free Software Foundation, Inc.

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
#include "target.h"
#include "value.h"
#include "gdbtypes.h"
#include "floatformat.h"
#include "gdbcore.h"
#include "frame.h"
#include "regcache.h"
#include "doublest.h"
#include "solib-svr4.h"
#include "osabi.h"
#include "regset.h"
#include "trad-frame.h"
#include "tramp-frame.h"
#include "breakpoint.h"
#include "auxv.h"
#include "xml-syscall.h"

#include "arch/ve.h"
#include "ve-tdep.h"
#include "ve-linux-tdep.h"
#include "linux-tdep.h"
#include "glibc-tdep.h"
#include "arch-utils.h"
#include "inferior.h"
#include "infrun.h"
#include "gdbthread.h"
#include "symfile.h"

#include "record-full.h"
#include "linux-record.h"

#include "cli/cli-utils.h"
#include "stap-probe.h"
#include "parser-defs.h"
#include "user-regs.h"
#include <ctype.h>
#include "elf/common.h"
#include <signal.h>
#include "solib-svr4.h"

/* Offset from top to 'SR' ,which are scalar registers, at 
 * core_user_reg_t
 */
#define	VE_SIGFRAME_OFFSET	 		512
#define	VE_SIGFRAME_UCONTEXT_OFFSET		(sizeof(uint64_t)*5 \
						 + sizeof(char)*256 \
						 + sizeof(siginfo_t))
#define	VE_UCONTEXT_CORE_USER_REG_OFFSET	(sizeof(unsigned long) \
						 + sizeof(void *) \
						 + sizeof(stack_t))
#define	VE_CORE_USER_REG_IC_OFFSET		0x1010
#define	VE_CORE_USER_REG_S0_OFFSET		0x1400
#define	VE_REG_OFFSET	(VE_SIGFRAME_OFFSET \
			 + VE_SIGFRAME_UCONTEXT_OFFSET \
			 + VE_UCONTEXT_CORE_USER_REG_OFFSET)
#define	VE_IC_OFFSET	(VE_REG_OFFSET + VE_CORE_USER_REG_IC_OFFSET)
#define	VE_SR_OFFSET	(VE_REG_OFFSET + VE_CORE_USER_REG_S0_OFFSET)

/* See following;
 * setup_ve_frame() in veos/psm/task_signal.c
 * struct ve_ucontext and struct sigframe in veos/psm/task_signal.h
 * core_user_reg_t in ve_hw.h 
 */
static void
ve_linux_sigreturn_init (const struct tramp_frame *self,
			  struct frame_info *this_frame,
			  struct trad_frame_cache *this_cache,
			  CORE_ADDR func)
{
  int i;
  CORE_ADDR sp = get_frame_register_unsigned (this_frame, VE_SP_REGNUM);
  CORE_ADDR base = sp + VE_SR_OFFSET;

  /* set scalar registers including LR, SP and FP. */
  for (i = 0; i < 64; i++)
    trad_frame_set_reg_addr (this_cache, VE_S0_REGNUM + i,
			     base + i * INT_REGISTER_SIZE);

  trad_frame_set_reg_addr (this_cache, VE_IC_REGNUM, sp + VE_IC_OFFSET);

  /* Save a frame ID.  */
  trad_frame_set_id (this_cache, frame_id_build (sp, func));
}

static struct tramp_frame ve_linux_sigreturn_tramp_frame = {
  SIGTRAMP_FRAME,
  INT_REGISTER_SIZE,
  {
    { 0x462eaeae00000000, -1 },
    { 0x012e008e00000018, -1 },
    { 0x45000f0000000000, -1 },
    { 0x310003ae00000000, -1 },
    { 0x3f00000000000000, -1 },
    { TRAMP_SENTINEL_INSN }
  },
  ve_linux_sigreturn_init
};

/* Core file and register set support.  */

void
ve_linux_supply_gregset (const struct regset *regset,
			 struct regcache *regcache,
			 int regnum, const void *gregs_buf, size_t len)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  const gdb_byte *gregs = (const gdb_byte *) gregs_buf;
  int regno;

  for (regno = 0; regno < VE_PS_REGNUM; regno++)
    if (regnum == -1 || regnum == regno)
      regcache_raw_supply (regcache, regno,
			   gregs + INT_REGISTER_SIZE * regno);

  for (regno = VE_PS_REGNUM; regno < VE_S0_REGNUM; regno++)
    if (regnum == -1 || regnum == regno)
      regcache_raw_supply (regcache, regno,
			   gregs + VEGP_PSW_OFFSET
			   + INT_REGISTER_SIZE * (regno - VE_PS_REGNUM));

  for (regno = VE_S0_REGNUM; regno < VE_VM0_REGNUM; regno++)
    if (regnum == -1 || regnum == regno)
      regcache_raw_supply (regcache, regno,
			   gregs + VEGP_SCALAR_OFFSET
			   + INT_REGISTER_SIZE * (regno - VE_S0_REGNUM));
}

void
ve_linux_collect_gregset (const struct regset *regset,
			  const struct regcache *regcache,
			  int regnum, void *gregs_buf, size_t len)
{
  gdb_byte *gregs = (gdb_byte *) gregs_buf;
  int regno;

  for (regno = 0; regno < VE_PS_REGNUM; regno++)
    if (regnum == -1 || regnum == regno)
      regcache_raw_collect (regcache, regno,
			    gregs + INT_REGISTER_SIZE * regno);

  for (regno = VE_PS_REGNUM; regno < VE_S0_REGNUM; regno++)
    if (regnum == -1 || regnum == regno)
      regcache_raw_collect (regcache, regno,
			    gregs + VEGP_PSW_OFFSET
			    + INT_REGISTER_SIZE * (regno - VE_PS_REGNUM));

  for (regno = VE_S0_REGNUM; regno < VE_VM0_REGNUM; regno++)
    if (regnum == -1 || regnum == regno)
      regcache_raw_collect (regcache, regno,
			    gregs + VEGP_SCALAR_OFFSET
			    + INT_REGISTER_SIZE * (regno - VE_S0_REGNUM));
}

/* Support for register format used by the NWFPE FPA emulator.  */

#define typeNone		0x00
#define typeSingle		0x01
#define typeDouble		0x02
#define typeExtended		0x03

void
supply_nwfpe_register (struct regcache *regcache, int regno,
		       const gdb_byte *regs)
{
  const gdb_byte *reg_data;

  if (regno >= VE_VM0_REGNUM && regno < VE_V0_REGNUM)
    reg_data = regs + VEFP_VMASK_OFFSET
	       + (regno - VE_VM0_REGNUM) * VM_REGISTER_SIZE;
  else
    reg_data = regs + VEFP_VECTOR_OFFSET
	       + (regno - VE_V0_REGNUM) * VEC_REGISTER_SIZE;

  regcache_raw_supply (regcache, regno, reg_data);
}

void
collect_nwfpe_register (const struct regcache *regcache, int regno,
			gdb_byte *regs)
{
  gdb_byte *reg_data;

  if (regno >= VE_VM0_REGNUM && regno < VE_V0_REGNUM)
    reg_data = regs + VEFP_VMASK_OFFSET
	       + (regno - VE_VM0_REGNUM) * VM_REGISTER_SIZE;
  else
    reg_data = regs + VEFP_VECTOR_OFFSET
	       + (regno - VE_V0_REGNUM) * VEC_REGISTER_SIZE;

  regcache_raw_collect (regcache, regno, reg_data);
}

void
ve_linux_supply_nwfpe (const struct regset *regset,
		       struct regcache *regcache,
		       int regnum, const void *regs_buf, size_t len)
{
  const gdb_byte *regs = (const gdb_byte *) regs_buf;
  int regno;

  for (regno = VE_VM0_REGNUM; regno <= VE_V63_REGNUM; regno++)
    if (regnum == -1 || regnum == regno)
      supply_nwfpe_register (regcache, regno, regs);
}

void
ve_linux_collect_nwfpe (const struct regset *regset,
			const struct regcache *regcache,
			int regnum, void *regs_buf, size_t len)
{
  gdb_byte *regs = (gdb_byte *) regs_buf;
  int regno;

  for (regno = VE_VM0_REGNUM; regno <= VE_V63_REGNUM; regno++)
    if (regnum == -1 || regnum == regno)
      collect_nwfpe_register (regcache, regno, regs);
}

static const struct regset ve_linux_gregset =
  {
    NULL, ve_linux_supply_gregset, ve_linux_collect_gregset
  };

static const struct regset ve_linux_fpregset =
  {
    NULL, ve_linux_supply_nwfpe, ve_linux_collect_nwfpe
  };

/* Iterate over core file register note sections.  */

static void
ve_linux_iterate_over_regset_sections (struct gdbarch *gdbarch,
				       iterate_over_regset_sections_cb *cb,
				       void *cb_data,
				       const struct regcache *regcache)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  cb (".reg", VE_LINUX_SIZEOF_GREGSET, &ve_linux_gregset, NULL, cb_data);

  cb (".reg2", VE_LINUX_SIZEOF_NWFPE, &ve_linux_fpregset,
      "FPA floating-point", cb_data);
}

/* At a ptrace syscall-stop, return the syscall number.  This either
   comes from the SWI instruction (OABI) or from r7 (EABI).

   When the function fails, it should return -1.  */

static LONGEST
ve_linux_get_syscall_number (struct gdbarch *gdbarch,
			      ptid_t ptid)
{
  struct regcache *regs = get_thread_regcache (ptid);
  ULONGEST svc_number = -1;

  if (regs != NULL)
    {
      regcache_cooked_read_unsigned (regs, VE_S0_REGNUM, &svc_number);
    }

  return svc_number;
}

static void
ve_linux_init_abi (struct gdbarch_info info,
		   struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  linux_init_abi (info, gdbarch);

  tdep->lowest_pc = 0x8000;

  set_solib_svr4_fetch_link_map_offsets (gdbarch,
					svr4_lp64_fetch_link_map_offsets);

  /* Enable TLS supports. */
  set_gdbarch_fetch_tls_load_module_address (gdbarch,
					svr4_fetch_objfile_link_map);

  tramp_frame_prepend_unwinder (gdbarch,
				&ve_linux_sigreturn_tramp_frame);
  /* Core file support.  */
  set_gdbarch_iterate_over_regset_sections
    (gdbarch, ve_linux_iterate_over_regset_sections);

  /* `catch syscall' */
  set_xml_syscall_file_name (gdbarch, "syscalls/ve-linux.xml");
  set_gdbarch_get_syscall_number (gdbarch, ve_linux_get_syscall_number);
}

/* Provide a prototype to silence -Wmissing-prototypes.  */
extern initialize_file_ftype _initialize_ve_linux_tdep;

void
_initialize_ve_linux_tdep (void)
{
  gdbarch_register_osabi (bfd_arch_ve, 0, GDB_OSABI_LINUX,
			  ve_linux_init_abi);
}
