/* GNU/Linux on ARM target support, prototypes.

   Copyright (C) 2006-2016 Free Software Foundation, Inc.

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

#ifndef	VE_LINUX_TDEP_H
#define	VE_LINUX_TDEP_H

struct regset;
struct regcache;

#define VE_LINUX_SIZEOF_GREGSET (sizeof (ve_elf_gregset_t))
#define VE_LINUX_SIZEOF_NWFPE (sizeof (ve_elf_fpregset_t))

/* The index to access CSPR in user_regs defined in GLIBC.  */
#define VE_CPSR_GREGNUM 16


#define VEGP_PSW_OFFSET		(0x1000)
#define VEGP_SCALAR_OFFSET	(0x1400)
#define VEFP_VMASK_OFFSET	(0x1800)
#define VEFP_VECTOR_OFFSET	(0x40000)

void ve_linux_supply_gregset (const struct regset *regset,
			      struct regcache *regcache,
			      int regnum, const void *gregs_buf, size_t len);
void ve_linux_collect_gregset (const struct regset *regset,
			       const struct regcache *regcache,
			       int regnum, void *gregs_buf, size_t len);

void supply_nwfpe_register (struct regcache *regcache, int regno,
			    const gdb_byte *regs);
void collect_nwfpe_register (const struct regcache *regcache, int regno,
			     gdb_byte *regs);

void ve_linux_supply_nwfpe (const struct regset *regset,
			    struct regcache *regcache,
			    int regnum, const void *regs_buf, size_t len);
void ve_linux_collect_nwfpe (const struct regset *regset,
			     const struct regcache *regcache,
			     int regnum, void *regs_buf, size_t len);

#endif
