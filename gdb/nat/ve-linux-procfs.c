#include	"common-defs.h"
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<nat/ve-linux-procfs.h>

#define		TBUF_SIZE	256

char * ve_cmdpath_data(char *, size_t *);
char * ve_cmdpath_cmdline(pid_t );
/*
 * alloc memory and read file data to it
 *
 * return: size of file data
 * 	NULL: error
 *
 * Note: A returned value,which is allocated, has to be freed
 * 	if it is not NULL.
 */
char *
ve_cmdpath_data(char *path, size_t *size)
{
	int fd;
	char *buf;
	char tbuf[TBUF_SIZE];
	size_t fsize, sum;
	ssize_t ret;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		warning (_("unable to open file %s\n"), path);
		return NULL;
	}

	fsize = 0;
	while ((ret = read(fd, tbuf, TBUF_SIZE)) != 0) {
		if (ret == -1) 
			goto err_close;
		fsize += ret;
	}

	buf = (char *)malloc(fsize);
	if (buf == NULL)
		goto err_close;

	if (lseek(fd, 0, SEEK_SET) == -1)
		goto err_free;

	sum = 0;
	while((ret = read(fd, buf + sum, fsize - sum)) != 0) {
		if (ret == -1)
			goto err_free;
		sum += ret;
	}
	if (sum != fsize) {
		warning (_("%s is changed\n"), path);
		goto err_free;
	}

	close(fd);

	*size = fsize;

	return buf;

err_free:
	free(buf);
err_close:
	close(fd);

	return NULL;
}

/*
 * get command name from pid
 *
 * return: command name
 *		NULL: error
 *
 * Note: A returned value from ve_cmdpath_data() has to be freed
 * 	if it is not NULL.
 * 	 A returned value from this has to be freed if it is not NULL.
 */
char *
ve_cmdpath_cmdline(pid_t pid)
{
	char path[PATH_MAX];
	char *data;
	size_t size;
	char *sep, *end, *cmd = NULL;

	snprintf(path, PATH_MAX, "/proc/%u/cmdline", pid);
	data = ve_cmdpath_data(path, &size);
	if (data == NULL) {
		return NULL;
	}

	sep = data;
	end = data + size;
	/* find '--' */
	/* -2: to avoid exceeding 'data' area */
	while ((sep = (char *)memchr(sep, '-', end - sep - 2)) != NULL) {
		if (sep[1] == '-') {
			if (sep[2] == '\0')
				break;
			sep++;
		}
		sep++;
	}
	if (sep == NULL) {
		warning (_("cmdline %s is invalid\n"), path);
		goto end;
	}

	/* command name => sep + 3 */
	cmd = strdup(&sep[3]);
	if (cmd == NULL) {
		warning (_("memory allocation error\n"));
		goto end;
	}

end:
	free(data);	

	return cmd;
}

/*
 * get full path of command from pid
 *
 * return: command path
 * 	NULL: error
 *
 * Note: A returned value from ve_cmdpath_cmdline() has to be freed
 * 	if it is not NULL.
 *	type of 'pid' is same as linux_proc_pid_to_exec_file().
 */
char *
ve_linux_proc_pid_to_exec_file(int pid)
{
	static char ve_path[PATH_MAX];
	char *cmd, *path;
	char buf[PATH_MAX], resolv[PATH_MAX];
	ssize_t len, left;

	if (pid == 0 || pid == 1) {
		warning (_("invalid pid %d\n"), pid);
		return NULL;
	}

	cmd = ve_cmdpath_cmdline(pid);
	if (cmd == NULL)
		return NULL;

	if (cmd[0] == '/') {			/* abolute path */
		strcpy(ve_path, cmd);
	} else {
		snprintf(buf, PATH_MAX, "/proc/%d/cwd", pid);
		len = readlink(buf, resolv, PATH_MAX - 1);
		if (len <= 0) {
			warning (_("invalid file %s\n"), buf);
			goto err;
		}
		resolv[len] = '\0';
		left = PATH_MAX - len - 1;
		strncat(resolv, "/", left);
		strncat(resolv, cmd, left - 1);
		if (realpath(resolv, ve_path) == NULL) {
			warning (_("invalid file %s\n"), resolv);
			goto err;
		}

	}

	free(cmd);
	return ve_path;

err:
	free(cmd);
	return NULL;
}
