/* Low level child interface to ptrace.

   Copyright (C) 2004-2016 Free Software Foundation, Inc.

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
/*
 * @file ve-ptrace.h
 * @brief VE PTrace function and definitions
 *
 * @internal
 * @author PTRACE
 */

#ifndef VE_PTRACE_H
#define VE_PTRACE_H

#define	PTRACE_STOP_VE	25
/*
 * ptrace function
 */
extern long (*ptrace_func) (enum __ptrace_request, ...);

#endif
