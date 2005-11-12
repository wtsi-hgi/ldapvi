/* (c) 2003 David Lichteblau.  License: GNU GPL. */
#include <curses.h>
#include <term.h>
#include "common.h"

int
carray_cmp(GArray *a, GArray *b)
{
	int d = memcmp(a->data, b->data, MIN(a->len, b->len));
	if (d) return d;
	if (a->len < b->len)
		return -1;
	else if (a->len == b->len)
		return 0;
	else
		return 1;
}

int
carray_ptr_cmp(const void *aa, const void *bb)
{
	GArray *a = *((GArray **) aa);
	GArray *b = *((GArray **) bb);
	return carray_cmp(a ,b);
}

void
fdcp(int fdsrc, int fddst)
{
	int n;
	char buf[4096];
	
	do {
		if ( (n = read(fdsrc, buf, sizeof(buf))) == -1) syserr();
		if (write(fddst, buf, n) != n) syserr();
	} while (n);
}

void
cp(char *src, char *dst, off_t skip, int append)
{
	int fdsrc, fddst;
	int flags = append ? O_WRONLY | O_APPEND : O_CREAT | O_EXCL | O_WRONLY;
	
	if ( (fdsrc = open(src, O_RDONLY)) == -1) syserr();
	if (lseek(fdsrc, skip, SEEK_SET) == -1) syserr();
	if ( (fddst = open(dst, flags, 0600)) == -1) syserr();
	fdcp(fdsrc, fddst);
	if (close(fdsrc) == -1) syserr();
	if (close(fddst) == -1) syserr();
}

char
choose(char *prompt, char *charbag, char *help)
{
	struct termios term;
	int c;
	
	if (tcgetattr(0, &term) == -1) syserr();
	term.c_lflag &= ~ICANON;
        term.c_cc[VMIN] = 1;
        term.c_cc[VTIME] = 0;
	for (;;) {
		if (tcsetattr(0, TCSANOW, &term) == -1) syserr();
		printf("%s [%s] ", prompt, charbag);
		if (strchr(charbag, c = getchar()))
			break;
		printf("\nPlease enter one of [%s].", charbag);
		if (help) printf("  %s", help);
		putchar('\n');
	}
	term.c_lflag |= ICANON;
	if (tcsetattr(0, TCSANOW, &term) == -1) syserr();
	putchar('\n');
	return c;
}

void
edit(char *pathname)
{
	int childpid;
	int status;
	char *vi;

	vi = getenv("VISUAL");
	if (!vi) vi = getenv("EDITOR");
	if (!vi) vi = "vi";

	switch ( (childpid = fork())) {
	case -1:
		syserr();
	case 0:
		execlp(vi, vi, pathname, 0);
		syserr();
	}

	if (waitpid(childpid, &status, 0) == -1) syserr();
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		yourfault("editor died");
}

void
view(char *pathname)
{
	int childpid;
	int status;
	char *vi;
	char *cl;

	vi = getenv("PAGER");
	if (!vi) vi = "less";

	if ( cl = tigetstr("clear")) {
		fputs(cl, stdout);
		fflush(stdout);
	}
	
	switch ( (childpid = fork())) {
	case -1:
		syserr();
	case 0:
		execlp(vi, vi, pathname, 0);
		syserr();
	}

	if (waitpid(childpid, &status, 0) == -1) syserr();
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		puts("pager died");
}

GString *
getline(char *prompt)
{
	GString *result = g_string_sized_new(8);
	int c;

	fputs(prompt, stdout);
	for (;;) {
		if ( (c = getchar()) == EOF) syserr();
		if (c == '\n') break;
		g_string_append_c(result, c);
	}
	return result;
}

char *
get_password()
{
	GString *buf = 0;
	char *result;
	struct termios term;

	if (tcgetattr(0, &term) == -1) syserr();
	term.c_lflag &= ~ECHO;
	if (tcsetattr(0, TCSANOW, &term) == -1) syserr();
	buf = getline("Password: ");
	term.c_lflag |= ECHO;
	if (tcsetattr(0, TCSANOW, &term) == -1) syserr();
	putchar('\n');

	result = buf->str;
	g_string_free(buf, 0);
	return result;
}

char *
append(char *a, char *b)
{
	int k = strlen(a);
	char *result = xalloc(k + strlen(b) + 1);
	strcpy(result, a);
	strcpy(result + k, b);
	return result;
}

void *
xalloc(size_t size)
{
	void *result = malloc(size);
	if (!result) {
		write(2, "\nmalloc error\n", sizeof("\nmalloc error\n") - 1);
		_exit(2);
	}
	return result;
}

char *
xdup(char *str)
{
	char *result;

	if (!str)
		return str;
	if (!(result = strdup(str))) {
		write(2, "\nstrdup error\n", sizeof("\nstrdup error\n") - 1);
		_exit(2);
	}
	return result;
}
