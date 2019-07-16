/* This testcase is part of GDB, the GNU debugger.

   Copyright 2009-2017 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   Test that GDB doesn't lose an event for a thread it didn't know
   about, until an event is reported for it.  */

#define _GNU_SOURCE
#include <sched.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <features.h>
#ifdef VEOS
#include <sys/mman.h>
#endif

#ifdef __UCLIBC__
#if !(defined(__UCLIBC_HAS_MMU__) || defined(__ARCH_HAS_MMU__))
#define HAS_NOMMU
#endif
#endif

#define STACK_SIZE 0x1000

static int
tkill (int lwpid, int signo)
{
  return syscall (__NR_tkill, lwpid, signo);
}

static pid_t
gettid (void)
{
  return syscall (__NR_gettid);
}

static int
fn (void *unused)
{
  tkill (gettid (), SIGUSR1);
  return 0;
}

int
main (int argc, char **argv)
{
  unsigned char *stack;
  int new_pid;
#ifdef VEOS
  unsigned char *tls;
  unsigned long tid;
  unsigned long ctid;
#endif

  stack = malloc (STACK_SIZE);
#ifdef VEOS
  tls = mmap(NULL, 2 * 1024 * 1024, PROT_READ | PROT_WRITE,
	     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif

  assert (stack != NULL);

#ifdef VEOS
#define CLONE_FLAGS (CLONE_VM |CLONE_FS | CLONE_FILES | CLONE_SIGHAND  \
                     | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS      \
                     | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID       \
                     | CLONE_DETACHED)
#endif

#ifndef VEOS
  new_pid = clone (fn, stack + STACK_SIZE, CLONE_FILES
#if defined(__UCLIBC__) && defined(HAS_NOMMU)
		   | CLONE_VM
#endif /* defined(__UCLIBC__) && defined(HAS_NOMMU) */
		   , NULL, NULL, NULL, NULL);
  // Wait for the child process to finish, to ensure that SIGUSR1 is caught
  // before the parent dies.
  int new_pid_status = 0;
  int expect_duplicate_pid = waitpid (new_pid, &new_pid_status, __WCLONE);
  assert (expect_duplicate_pid  == new_pid);
  assert (new_pid > 0);
#else
  new_pid = clone (fn, stack + STACK_SIZE, CLONE_FLAGS
                  , NULL, &tid, tls, &ctid, NULL);
  assert (new_pid > 0);
sleep (10);
#endif

  return 0;
}
