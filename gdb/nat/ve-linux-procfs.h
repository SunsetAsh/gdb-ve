#ifndef	VE_LINUX_PROCFS_H
#define	VE_LINUX_PROCFS_H
/* Return the full absolute name of the executable file that was run
 *    to create the process PID.  The returned value persists until this
 *       function is next called.  */

extern char *ve_linux_proc_pid_to_exec_file (int pid);
#endif	/* VE_LINUX_PROCFS_H */
