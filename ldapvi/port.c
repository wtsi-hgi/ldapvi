/* (c) 2003 David Lichteblau.  License: GNU GPL. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <ldap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"

#ifndef HAVE_MKDTEMP
char *
mkdtemp(char *template)
{
	int l = strlen(template);
	int i = l - 6;
	int fd;
	int n;

	if (i < 0) { errno = EINVAL; return 0; }

	fd = open("/dev/random", O_RDONLY);
	if (fd == -1) {
		fputs("Do you have /dev/random?\n", stderr);
		return 0;
	}
	while (i < l) {
		if ( (n = read(fd, template + i, l - i)) == -1) {
			close(fd);
			return 0;
		}
		while (n--) {
			unsigned char c = template[i];
			c &= 63;
			if (c < 10)		c += '0';
			else if (c < 38)	c += '?' - 10;
			else			c += 'a' - 38;
			template[i] = c;
			i++;
		}
	}
	close(fd);

	if (mkdir(template, 0700) == -1) return 0;
	return template;
}
#endif

#ifndef HAVE_ON_EXIT
static void (*onexitfunction)(int , void *) = 0;
static void *onexitarg;

static void
atexitfunction(void)
{
	onexitfunction(-1, onexitarg);
}

int
on_exit(void (*function)(int, void *), void *arg)
{
	if (onexitfunction) yourfault("on_exit called twice");
	onexitfunction = function;
	onexitarg = arg;
	return atexit(atexitfunction);
}
#endif
