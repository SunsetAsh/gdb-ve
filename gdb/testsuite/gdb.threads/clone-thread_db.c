/* This testcase is part of GDB, the GNU debugger.

   Copyright 2015-2017 Free Software Foundation, Inc.

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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#ifdef VEOS
#include <sys/mman.h>
#endif
#define STACK_SIZE 0x1000

int clone_pid;

static int
clone_fn (void *unused)
{
  return 0;
}

void *
thread_fn (void *arg)
{
  unsigned char *stack;
  int res;
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
#define CLONE_FLAGS (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND  \
                     | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS      \
                     | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID       \
                     | CLONE_DETACHED)
#endif


#ifdef __ia64__
  clone_pid = __clone2 (clone_fn, stack, STACK_SIZE, CLONE_VM, NULL);
#else
#ifndef VEOS
  clone_pid = clone (clone_fn, stack + STACK_SIZE, CLONE_VM, NULL);
#else
  clone_pid = clone (clone_fn, stack + STACK_SIZE, CLONE_FLAGS, NULL,
 		     &tid, tls, &ctid, NULL);
#endif
#endif

  assert (clone_pid > 0);
  /* Wait for child.  */
  sleep (10);
//  res = waitpid (clone_pid, NULL, __WCLONE);
//  assert (res != -1);

  return NULL;
}

int
main (int argc, char **argv)
{
  pthread_t child;

  alarm (300);

  pthread_create (&child, NULL, thread_fn, NULL);
  pthread_join (child, NULL);

  return 0;
}
