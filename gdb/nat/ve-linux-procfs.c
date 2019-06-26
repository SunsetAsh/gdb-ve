#include	"common-defs.h"
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<nat/ve-linux-procfs.h>

#define		TBUF_SIZE	64

char * ve_cmdpath_data(char *, size_t *);
char * ve_cmdpath_cmdline(pid_t );
/*
 * alloc memory and read file data to it
 * return
 * 	!NULL: size of file data
 * 	NULL1: error
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
	if (fd == -1)
		return NULL;

	fsize = 0;
	while ((ret = read(fd, tbuf, TBUF_SIZE)) != 0) {
		if (ret == -1) 
			goto err_close;
		fsize += ret;
	}

	buf = malloc(fsize);
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
		errno = EINVAL;
		printf("%s is changed\n",path);
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

char *
ve_cmdpath_cmdline(pid_t pid)
{
	char path[PATH_MAX];
	char *data;
	size_t size;
	char *sep, *end, *cmd = NULL;

	snprintf(path, PATH_MAX, "/proc/%u/cmdline", pid);
	printf("cmdline:%s\n",path);
	data = ve_cmdpath_data(path, &size);
	if (data == NULL) {
		perror("get_vepath");
		return NULL;
	}
	printf("size=%lu\n",size);

	sep = data;
	end = data + size;
	/* find '--' */
	while ((sep = memchr(sep, '-', end - sep)) != NULL) {
		if (sep[1] == '-') {
			if (sep[2] == '\0')
				break;
			sep++;
		}
		sep++;
	}
	if (sep == NULL) {
		printf("cmdline is broken\n");
		goto end;
	}

	/* executed command => sep + 3 */
	cmd = strdup(&sep[3]);
	if (cmd == NULL)
		goto end;
	printf("cmd:\"%s\"\n",cmd);

end:
	free(data);	

	return cmd;
}

char *
ve_linux_proc_pid_to_exec_file(int pid)
{
	static char ve_path[PATH_MAX];
	char *cmd, *path;
	char buf[PATH_MAX], resolv[PATH_MAX];
	ssize_t len;

	if (pid == 0 || pid == 1) {
		errno = EINVAL;
		return NULL;
	}

	cmd = ve_cmdpath_cmdline(pid);
	if (cmd == NULL)
		return NULL;

	if (cmd[0] == '/') {			/* abolute path */
		strcpy(ve_path, cmd);
	} else {
		snprintf(buf, PATH_MAX, "/proc/%u/cwd", pid);
		len = readlink(buf, resolv, PATH_MAX - 1);
		if (len <= 0)
			goto err;
		resolv[len] = '\0';
		strcat(resolv, "/");
		strcat(resolv, cmd);
		if (realpath(resolv, ve_path) == NULL)
			goto err;

	}

	free(cmd);
	return ve_path;

err:
	free(cmd);
	return NULL;
}
