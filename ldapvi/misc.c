/* Copyright (c) 2003,2004,2005 David Lichteblau
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <curses.h>
#include <term.h>
#include "common.h"
#include <readline/readline.h>
#include <readline/history.h>

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

static long
line_number(char *pathname, long pos)
{
	FILE *f;
	long line = 1;
	int c;
	
	if ( !(f = fopen(pathname, "r+"))) syserr();
	while (pos > 0) {
		switch ( c = getc_unlocked(f)) {
		case EOF:
			goto done;
		case '\n':
			if ( (c = getc_unlocked(f)) != EOF) {
				ungetc(c, f);
				line++;
			}
			/* fall through */
		default:
			pos--;
		}
	}
done:
	if (fclose(f) == EOF) syserr();
	return line;
}

void
edit(char *pathname, long line)
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
		if (line > 0) {
			char buf[20];
			snprintf(buf, 20, "+%ld", line);
			execlp(vi, vi, buf, pathname, 0);
		} else
			execlp(vi, vi, pathname, 0);
		syserr();
	}

	if (waitpid(childpid, &status, 0) == -1) syserr();
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		yourfault("editor died");
}

void
edit_pos(char *pathname, long pos)
{
	edit(pathname, pos > 0 ? line_number(pathname, pos) : -1);
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

char *
home_filename(char *name)
{
	char *home = getenv("HOME");
	int n;
	char *result;

	if (!home) {
		fputs("Warning: You don't have a $HOME.\n", stderr);
		return 0;
	}

	n = strlen(home);
	result = xalloc(n + 1 + strlen(name));
	strcpy(result, home);
	result[n] = '/';
	strcpy(result + n + 1, name);
	return result;
}


static char *
history_filename()
{
	return home_filename(".ldapvi_history");
}

void
read_ldapvi_history()
{
	char *filename = history_filename();
	using_history();
	if (!filename)
		return;
	if (read_history(filename) && errno != ENOENT)
		perror("Oops, couldn't read history");
	free(filename);
}

void
write_ldapvi_history()
{
	char *filename = history_filename();
	if (!filename)
		return;
	if (write_history(filename))
		perror("Oops, couldn't write history");
	free(filename);
}

GString *
getline(char *prompt)
{
	GString *result = g_string_sized_new(8);
	char *str = readline(prompt);
	if (str && *str) {
		add_history(str);
		g_string_append(result, str);
	}
	return result;
}

static GString *
trivial_getline(char *prompt)
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
	buf = trivial_getline("Password: ");
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

void
adjoin_str(GPtrArray *strs, char *str)
{
	int i;
	for (i = 0; i < strs->len; i++)
		if (!strcmp(str, g_ptr_array_index(strs, i)))
			return;
	g_ptr_array_add(strs, str);
}
