/* (c) 2003 David Lichteblau.  License: GNU GPL. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <ldap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void
do_syserr(char *file, int line)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "error (%s line %d)", file, line);
	perror(buf);
	exit(1);
}

void
yourfault(char *str)
{
	fprintf(stderr, "%s\n", str);
	exit(1);
}

void
ldaperr(LDAP *ld, char *str)
{
	ldap_perror(ld, str);
	exit(1);
}
