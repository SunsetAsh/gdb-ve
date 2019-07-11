/* GNU/Linux on ARM native support.
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
#include "inferior.h"
#include "regcache.h"
#include "linux-nat.h"

#include "ve-tdep.h"
#include "ve-linux-tdep.h"

#include <elf/common.h>
#include "nat/gdb_ptrace.h"

/* Prototypes for supply_gregset etc.  */
#include "gregset.h"

/* Prototypes for ptrace_func.  */
#include "ve-ptrace.h"

/* ve_proc_pid_to_exec_file() */
#include "nat/ve-linux-procfs.h"

/* Get the whole floating point state of the process and store it
   into regcache.  */

static void
fetch_fpregs (struct regcache *regcache)
{
  int ret, regno, tid;
  gdb_byte fp[VE_LINUX_SIZEOF_NWFPE];

  /* Get the thread id for the ptrace call.  */
  tid = ptid_get_lwp (inferior_ptid);

  /* Read the floating point state.  */
  if (have_ptrace_getregset == TRIBOOL_TRUE)
    {
      struct iovec iov;

      iov.iov_base = &fp;
      iov.iov_len = VE_LINUX_SIZEOF_NWFPE;

      ret = ptrace_func (PTRACE_GETREGSET, tid, NT_FPREGSET, &iov);
    }
  else
    ret = ptrace_func (PT_GETFPREGS, tid, 0, fp);

  if (ret < 0)
    perror_with_name (_("Unable to fetch the floating point registers."));

  /* Fetch the vector mask registers.  */
  for (regno = VE_VM0_REGNUM; regno <= VE_VM15_REGNUM; regno++)
    supply_nwfpe_register (regcache, regno, fp);

  /* Fetch the vector registers.  */
  for (regno = VE_V0_REGNUM; regno <= VE_V63_REGNUM; regno++)
    supply_nwfpe_register (regcache, regno, fp);
}

/* Save the whole floating point state of the process using
   the contents from regcache.  */

static void
store_fpregs (const struct regcache *regcache)
{
  int ret, regno, tid;
  gdb_byte fp[VE_LINUX_SIZEOF_NWFPE];

  /* Get the thread id for the ptrace call.  */
  tid = ptid_get_lwp (inferior_ptid);

  /* Read the floating point state.  */
  if (have_ptrace_getregset == TRIBOOL_TRUE)
    {
      ve_elf_fpregset_t fpregs;
      struct iovec iov;

      iov.iov_base = &fpregs;
      iov.iov_len = sizeof (fpregs);

      ret = ptrace_func (PTRACE_GETREGSET, tid, NT_FPREGSET, &iov);
    }
  else
    ret = ptrace_func (PT_GETFPREGS, tid, 0, fp);

  if (ret < 0)
    perror_with_name (_("Unable to fetch the floating point registers."));

  /* Store the vector mask registers.  */
  for (regno = VE_VM0_REGNUM; regno <= VE_VM15_REGNUM; regno++)
    if (REG_VALID == regcache_register_status (regcache, regno))
      collect_nwfpe_register (regcache, regno, fp);

  /* Store the vector registers.  */
  for (regno = VE_V0_REGNUM; regno <= VE_V63_REGNUM; regno++)
    if (REG_VALID == regcache_register_status (regcache, regno))
      collect_nwfpe_register (regcache, regno, fp);

  if (have_ptrace_getregset == TRIBOOL_TRUE)
    {
      struct iovec iov;

      iov.iov_base = &fp;
      iov.iov_len = VE_LINUX_SIZEOF_NWFPE;

      ret = ptrace_func (PTRACE_SETREGSET, tid, NT_FPREGSET, &iov);
    }
  else
    ret = ptrace_func (PTRACE_SETFPREGS, tid, 0, fp);

  if (ret < 0)
    perror_with_name (_("Unable to store floating point registers."));
}

/* Fetch all general registers of the process and store into
   regcache.  */

static void
fetch_regs (struct regcache *regcache)
{
  int ret, regno, tid;
  ve_elf_gregset_t regs;
  gdb_byte *reg_data = (gdb_byte *) &regs;

  /* Get the thread id for the ptrace call.  */
  tid = ptid_get_lwp (inferior_ptid);

  if (have_ptrace_getregset == TRIBOOL_TRUE)
    {
      struct iovec iov;

      iov.iov_base = &regs;
      iov.iov_len = sizeof (regs);

      ret = ptrace_func (PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov);
    }
  else
    ret = ptrace_func (PTRACE_GETREGS, tid, 0, &regs);

  if (ret < 0)
    perror_with_name (_("Unable to fetch general registers."));

  for (regno = 0; regno < VE_PS_REGNUM; regno++)
    regcache_raw_supply (regcache, regno,
			 reg_data + INT_REGISTER_SIZE * regno);

  for (regno = VE_PS_REGNUM; regno < VE_S0_REGNUM; regno++)
    regcache_raw_supply (regcache, regno,
			 reg_data + VEGP_PSW_OFFSET
			 + INT_REGISTER_SIZE * (regno - VE_PS_REGNUM));

  for (regno = VE_S0_REGNUM; regno < VE_VM0_REGNUM; regno++)
    regcache_raw_supply (regcache, regno,
			 reg_data + VEGP_SCALAR_OFFSET
			 + INT_REGISTER_SIZE * (regno - VE_S0_REGNUM));
}

static void
store_regs (const struct regcache *regcache)
{
  int ret, regno, tid;
  ve_elf_gregset_t regs;
  gdb_byte *reg_data = (gdb_byte *) &regs;

  /* Get the thread id for the ptrace call.  */
  tid = ptid_get_lwp (inferior_ptid);

  /* Fetch the general registers.  */
  if (have_ptrace_getregset == TRIBOOL_TRUE)
    {
      struct iovec iov;

      iov.iov_base = &regs;
      iov.iov_len = sizeof (regs);

      ret = ptrace_func (PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov);
    }
  else
    ret = ptrace_func (PTRACE_GETREGS, tid, 0, &regs);

  if (ret < 0)
    perror_with_name (_("Unable to fetch general registers."));

  for (regno = 0; regno < VE_PS_REGNUM; regno++)
    regcache_raw_collect (regcache, regno,
			  reg_data + INT_REGISTER_SIZE * regno);

  for (regno = VE_PS_REGNUM; regno < VE_S0_REGNUM; regno++)
    regcache_raw_collect (regcache, regno,
			  reg_data + VEGP_PSW_OFFSET
			  + INT_REGISTER_SIZE * (regno - VE_PS_REGNUM));

  for (regno = VE_S0_REGNUM; regno < VE_VM0_REGNUM; regno++)
    regcache_raw_collect (regcache, regno,
			  reg_data + VEGP_SCALAR_OFFSET
			  + INT_REGISTER_SIZE * (regno - VE_S0_REGNUM));

  if (have_ptrace_getregset == TRIBOOL_TRUE)
    {
      struct iovec iov;

      iov.iov_base = &regs;
      iov.iov_len = sizeof (regs);

      ret = ptrace_func (PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov);
    }
  else
    ret = ptrace_func (PTRACE_SETREGS, tid, 0, &regs);

  if (ret < 0)
    perror_with_name (_("Unable to store general registers."));
}

/* Fetch registers from the child process.  Fetch all registers if
   regno == -1, otherwise fetch all general registers or all floating
   point registers depending upon the value of regno.  */

static void
ve_linux_fetch_inferior_registers (struct target_ops *ops,
				   struct regcache *regcache, int regno)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (-1 == regno)
    {
      fetch_regs (regcache);
      fetch_fpregs (regcache);
    }
  else 
    {
      if (regno < VE_VM0_REGNUM || regno == VE_PS_REGNUM)
	fetch_regs (regcache);
      else if (regno >= VE_VM0_REGNUM && regno <= VE_V63_REGNUM)
	fetch_fpregs (regcache);
    }
}

/* Store registers back into the inferior.  Store all registers if
   regno == -1, otherwise store all general registers or all floating
   point registers depending upon the value of regno.  */

static void
ve_linux_store_inferior_registers (struct target_ops *ops,
				   struct regcache *regcache, int regno)
{
  if (-1 == regno)
    {
      store_regs (regcache);
      store_fpregs (regcache);
    }
  else
    {
      if (regno < VE_VM0_REGNUM || regno == VE_PS_REGNUM)
	store_regs (regcache);
      else if ((regno >= VE_VM0_REGNUM) && (regno <= VE_V63_REGNUM))
	store_fpregs (regcache);
    }
}

/* Wrapper functions for the standard regset handling, used by
   thread debugging.  */

void
fill_gregset (const struct regcache *regcache,	
	      gdb_gregset_t *gregsetp, int regno)
{
  ve_linux_collect_gregset (NULL, regcache, regno, gregsetp, 0);
}

void
supply_gregset (struct regcache *regcache, const gdb_gregset_t *gregsetp)
{
  ve_linux_supply_gregset (NULL, regcache, -1, gregsetp, 0);
}

void
fill_fpregset (const struct regcache *regcache,
	       gdb_fpregset_t *fpregsetp, int regno)
{
  ve_linux_collect_nwfpe (NULL, regcache, regno, fpregsetp, 0);
}

/* Fill GDB's register array with the floating-point register values
   in *fpregsetp.  */

void
supply_fpregset (struct regcache *regcache, const gdb_fpregset_t *fpregsetp)
{
  ve_linux_supply_nwfpe (NULL, regcache, -1, fpregsetp, 0);
}

static const struct target_desc *
ve_linux_read_description (struct target_ops *ops)
{
  CORE_ADDR arm_hwcap = 0;

  if (have_ptrace_getregset == TRIBOOL_UNKNOWN)
    {
      ve_elf_gregset_t gpregs;
      struct iovec iov;
      int tid = ptid_get_lwp (inferior_ptid);

      iov.iov_base = &gpregs;
      iov.iov_len = sizeof (gpregs);

      /* Check if PTRACE_GETREGSET works.  */
      if (ptrace_func (PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov) < 0)
	have_ptrace_getregset = TRIBOOL_FALSE;
      else
	have_ptrace_getregset = TRIBOOL_TRUE;
    }

  return ops->beneath->to_read_description (ops->beneath);
}

/* Information describing the hardware breakpoint capabilities.  */
struct ve_linux_hwbp_cap
{
  gdb_byte arch;
  gdb_byte max_wp_length;
  gdb_byte wp_count;
  gdb_byte bp_count;
};

/* Since we cannot dynamically allocate subfields of ve_linux_process_info,
 *    assume a maximum number of supported break-/watchpoints.  */
#define MAX_BPTS 16
#define MAX_WPTS 16

/* Type describing an ARM Hardware Breakpoint Control register value.  */
typedef unsigned int ve_hwbp_control_t;

/* Structure used to keep track of hardware break-/watch-points.  */
struct ve_linux_hw_breakpoint
{
  /* Address to break on, or being watched.  */
  unsigned int address;
  /* Control register for break-/watch- point.  */
  ve_hwbp_control_t control;
};


/* Structure containing arrays of per process hardware break-/watchpoints
   for caching address and control information.

   The Linux ptrace interface to hardware break-/watch-points presents the 
   values in a vector centred around 0 (which is used fo generic information).
   Positive indicies refer to breakpoint addresses/control registers, negative
   indices to watchpoint addresses/control registers.

   The Linux vector is indexed as follows:
      -((i << 1) + 2): Control register for watchpoint i.
      -((i << 1) + 1): Address register for watchpoint i.
                    0: Information register.
       ((i << 1) + 1): Address register for breakpoint i.
       ((i << 1) + 2): Control register for breakpoint i.

   This structure is used as a per-thread cache of the state stored by the 
   kernel, so that we don't need to keep calling into the kernel to find a 
   free breakpoint.

   We treat break-/watch-points with their enable bit clear as being deleted.
   */
struct ve_linux_debug_reg_state
{
  /* Hardware breakpoints for this process.  */
  struct ve_linux_hw_breakpoint bpts[MAX_BPTS];
  /* Hardware watchpoints for this process.  */
  struct ve_linux_hw_breakpoint wpts[MAX_WPTS];
};

/* Per-process arch-specific data we want to keep.  */
struct ve_linux_process_info
{
  /* Linked list.  */
  struct ve_linux_process_info *next;
  /* The process identifier.  */
  pid_t pid;
  /* Hardware break-/watchpoints state information.  */
  struct ve_linux_debug_reg_state state;

};

/* Per-thread arch-specific data we want to keep.  */
struct arch_lwp_info
{
  /* Non-zero if our copy differs from what's recorded in the thread.  */
  char bpts_changed[MAX_BPTS];
  char wpts_changed[MAX_WPTS];
};

static struct ve_linux_process_info *ve_linux_process_list = NULL;

/* Find process data for process PID.  */

static struct ve_linux_process_info *
ve_linux_find_process_pid (pid_t pid)
{
  struct ve_linux_process_info *proc;

  for (proc = ve_linux_process_list; proc; proc = proc->next)
    if (proc->pid == pid)
      return proc;

  return NULL;
}

/* Add process data for process PID.  Returns newly allocated info
   object.  */

static struct ve_linux_process_info *
ve_linux_add_process (pid_t pid)
{
  struct ve_linux_process_info *proc;

  proc = XCNEW (struct ve_linux_process_info);
  proc->pid = pid;

  proc->next = ve_linux_process_list;
  ve_linux_process_list = proc;

  return proc;
}

/* Get data specific info for process PID, creating it if necessary.
   Never returns NULL.  */

static struct ve_linux_process_info *
ve_linux_process_info_get (pid_t pid)
{
  struct ve_linux_process_info *proc;

  proc = ve_linux_find_process_pid (pid);
  if (proc == NULL)
    proc = ve_linux_add_process (pid);

  return proc;
}

/* Called whenever GDB is no longer debugging process PID.  It deletes
   data structures that keep track of debug register state.  */

static void
ve_linux_forget_process (pid_t pid)
{
  struct ve_linux_process_info *proc, **proc_link;

  proc = ve_linux_process_list;
  proc_link = &ve_linux_process_list;

  while (proc != NULL)
    {
      if (proc->pid == pid)
    {
      *proc_link = proc->next;

      xfree (proc);
      return;
    }

      proc_link = &proc->next;
      proc = *proc_link;
    }
}

/* Get hardware break-/watchpoint state for process PID.  */

static struct ve_linux_debug_reg_state *
ve_linux_get_debug_reg_state (pid_t pid)
{
  return &ve_linux_process_info_get (pid)->state;
}

/* Handle thread creation.  We need to copy the breakpoints and watchpoints
   in the parent thread to the child thread.  */
static void
ve_linux_new_thread (struct lwp_info *lp)
{
  int i;
  struct arch_lwp_info *info = XCNEW (struct arch_lwp_info);

  /* Mark that all the hardware breakpoint/watchpoint register pairs
     for this thread need to be initialized.  */

  for (i = 0; i < MAX_BPTS; i++)
    {
      info->bpts_changed[i] = 1;
      info->wpts_changed[i] = 1;
    }

  lp->arch_private = info;
}

/* Called when resuming a thread.
   The hardware debug registers are updated when there is any change.  */

static void
ve_linux_prepare_to_resume (struct lwp_info *lwp)
{
  struct ve_linux_hw_breakpoint *bpts, *wpts;
  struct arch_lwp_info *ve_lwp_info = lwp->arch_private;

  bpts = ve_linux_get_debug_reg_state (ptid_get_pid (lwp->ptid))->bpts;
  wpts = ve_linux_get_debug_reg_state (ptid_get_pid (lwp->ptid))->wpts;

  /* NULL means this is the main thread still going through the shell,
     or, no watchpoint has been set yet.  In that case, there's
     nothing to do.  */
  if (ve_lwp_info == NULL)
    return;

}

/* linux_nat_new_fork hook.  */

static void
ve_linux_new_fork (struct lwp_info *parent, pid_t child_pid)
{
  pid_t parent_pid;
  struct ve_linux_debug_reg_state *parent_state;
  struct ve_linux_debug_reg_state *child_state;

  /* NULL means no watchpoint has ever been set in the parent.  In
     that case, there's nothing to do.  */
  if (parent->arch_private == NULL)
    return;

  /* GDB core assumes the child inherits the watchpoints/hw
     breakpoints of the parent, and will remove them all from the
     forked off process.  Copy the debug registers mirrors into the
     new process so that all breakpoints and watchpoints can be
     removed together.  */

  parent_pid = ptid_get_pid (parent->ptid);
  parent_state = ve_linux_get_debug_reg_state (parent_pid);
  child_state = ve_linux_get_debug_reg_state (child_pid);
  *child_state = *parent_state;
}

long (*ptrace_func) (enum __ptrace_request, ...);
extern long ve_ptrace (enum __ptrace_request, ...);

/*
 * switch ptrace function(ptrace -> ve_ptrace)
 * set ptrace_func to ve_ptrace if ptrace for VE is completed
 *  because ptrace_func is used as ptrace(2),
 */
static long
ve_gdb_ptrace(enum __ptrace_request request, pid_t pid,
	void *addr, void *data)
{
  long ret;

  ret = ve_ptrace(request, pid, addr, data);
  if (ret == -1) {
    if (errno == ESRCH) {
      ptrace(PT_CONTINUE, pid, 0, 0);
    }
  }

  return ret;
}

static void
setup_ptrace(void)
{
	ptrace_func = ve_gdb_ptrace;
}

char * ve_child_pid_to_exec_file (struct target_ops *, int );

char *
ve_linux_child_pid_to_exec_file (struct target_ops *self, int pid)
{
  return ve_linux_proc_pid_to_exec_file (pid);
}

void _initialize_ve_linux_nat(void);

void
_initialize_ve_linux_nat(void)
{
	struct target_ops *t;

	setup_ptrace();

  /* Fill in the generic GNU/Linux methods.  */
  t = linux_target ();

  /* Add our register access methods.  */
  t->to_fetch_registers = ve_linux_fetch_inferior_registers;
  t->to_store_registers = ve_linux_store_inferior_registers;
  /* to get a path of VE program from /proc */
  t->to_pid_to_exec_file = ve_linux_child_pid_to_exec_file;

  /* Add our hardware breakpoint and watchpoint implementation.  */
  /* unnecessary */

  t->to_read_description = ve_linux_read_description;

  /* Register the target.  */
  linux_nat_add_target (t);

  /* Handle thread creation and exit.  */
  linux_nat_set_new_thread (t, ve_linux_new_thread);
  linux_nat_set_prepare_to_resume (t, ve_linux_prepare_to_resume);
  /* unnecessary */

  /* Handle process creation and exit.  */
  linux_nat_set_new_fork (t, ve_linux_new_fork);
  linux_nat_set_forget_process (t, ve_linux_forget_process);
  /* unnecessary */
}
