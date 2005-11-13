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
#define _XOPEN_SOURCE
#include <unistd.h>
#include "common.h"

#define fast_g_string_append_c(gstring, c)				\
	do {								\
		if ((gstring)->len + 1 >= (gstring)->allocated_len)	\
			g_string_append_c((gstring), (c));		\
		else {							\
			(gstring)->str[(gstring)->len++] = (c);		\
			(gstring)->str[(gstring)->len] = 0;		\
		}							\
	} while (0)

static int
read_lhs(FILE *s, GString *lhs)
{
	int c;

	for (;;) {
		switch ( c = getc_unlocked(s)) {
		case ' ':
			if (ferror(s)) syserr();
			return 0;
		case EOF:
			fputs("Error: Unexpected EOF.\n", stderr);
			return -1;
		case '\n':
			fputs("Error: Unexpected EOL.\n", stderr);
			return -1;
		case 0:
			fputs("Error: Null byte not allowed.\n", stderr);
			return -1;
		default:
			fast_g_string_append_c(lhs, c);
		}
	}
}

static int
read_backslashed(FILE *s, GString *data)
{
	int c;

	for (;;) {
		switch ( c = getc_unlocked(s)) {
		case '\n':
			if (ferror(s)) syserr();
			return 0;
		case EOF:
			goto error;
		case '\\':
			if ( (c = fgetc(s)) == EOF) goto error;
			/* fall through */
		default:
			fast_g_string_append_c(data, c);
		}
	}

error:
	fputs("Error: Unexpected EOF.\n", stderr);
	return -1;
}

static int
read_ldif_attrval(FILE *s, GString *data)
{
	int c;

	for (;;)
		switch ( c = getc_unlocked(s)) {
		case '\n':
			if ( (c = fgetc(s)) == ' ') /* folded line */ break;
			ungetc(c, s);
			if (ferror(s)) syserr();
			return 0;
		case EOF:
			fputs("Error: Unexpected EOF.\n", stderr);
			return -1;
		default:
			fast_g_string_append_c(data, c);
		}
}

static int
read_from_file(GString *data, char *name)
{
	int fd, n;
	if ( (fd = open(name, O_RDONLY)) == -1) {
		perror("open");
		return -1;
	}
	data->len = 0;
	n = 1024;
	do {
		int olen = data->len;
		g_string_set_size(data, data->len + n);
		if ( (n = read(fd, data->str + olen, n)) == -1) syserr();
		data->len = olen + n;
	} while (n > 0);
	if (close(fd) == -1) syserr();
	return 0;
}

static int
skip_comment(FILE *s)
{
	int c;

	for (;;)
		switch ( c = fgetc(s)) {
		case EOF:
			fputs("Error: Unexpected EOF.\n", stderr);
			return -1;
		case '\n':
			if ( (c = fgetc(s)) == ' ') /* folded line */ break;
			ungetc(c, s);
			if (ferror(s)) syserr();
			return 0;
		}
}

static char *saltbag
	= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890./";

static char *
docrypt(char *key)
{
	unsigned char salt[2];
	int fd = open("/dev/random", 2);
	if (fd == -1) {
		puts("Sorry, crypt not available: Cannot open /dev/random.");
		return 0;
	}
	if (read(fd, salt, 2) != 2) syserr();
	close(fd);
	salt[0] = saltbag[salt[0] & 63];
	salt[1] = saltbag[salt[1] & 63];
	return crypt(key, (char *) salt);
}

static char *
domd5(char *key)
{
	char *result;
	unsigned char salt[11];
	int i;
	int fd = open("/dev/random", 2);
	if (fd == -1) {
		puts("Sorry, MD5 not available: Cannot open /dev/random.");
		return 0;
	}
	salt[0] = '$';
	salt[1] = '1';
	salt[2] = '$';
	if (read(fd, salt + 3, 8) != 8) syserr();
	close(fd);
	for (i = 3; i < 11; i++)
		salt[i] = saltbag[salt[i] & 63];
	result = crypt(key, (char *) salt);
	if (!result || strlen(result) < 25) {
		puts("Sorry, MD5 not available: Are you using the glibc?");
		return 0;
	}
	return result;
}

static int
read_line(FILE *s, GString *name, GString *value)
{
	int c;
	char *encoding;

	g_string_truncate(name, 0);
	g_string_truncate(value, 0);
	
	/* skip comment lines */
	do {
		c = fgetc(s);
		switch (c) {
		case EOF:
			if (ferror(s)) syserr();
			return 0;
		case '\n':
			return 0;
		case '#':
			if (skip_comment(s) == -1) return -1;
			break;
		default:
			ungetc(c, s);
			c = -1;
		}
	} while (c != -1);

	if (read_lhs(s, name) == -1) return -1;
	if (!name->len) {
		fputs("Error: Space at beginning of line.\n", stderr);
		return -1;
	}
	if ( encoding = memchr(name->str, ':', name->len)) {
		encoding++;
		name->len = encoding - name->str - 1;
		name->str[name->len] = 0;
	}

	if (!encoding) {
		if (read_backslashed(s, value) == -1) return -1;
	} else if (!*encoding) {
		if (read_ldif_attrval(s, value) == -1) return -1;
	} else if (!strcmp(encoding, ":")) {
		unsigned char *ustr;
		int len;
		if (read_ldif_attrval(s, value) == -1) return -1;
		ustr = (unsigned char *) value->str;;
		if ( (len = read_base64(value->str, ustr, value->len)) == -1) {
			fputs("Error: Invalid Base64 string.\n", stderr);
			return -1;
		}
		value->len = len;
	} else if (!strcmp(encoding, "<")) {
		if (read_ldif_attrval(s, value) == -1) return -1;
		if (strncmp(value->str, "file://", 7)) {
			fputs("Error: Unknown URL scheme.\n", stderr);
			return -1;
		}
		if (read_from_file(value, value->str + 7) == -1)
			return -1;
	} else if (!strcasecmp(encoding, "crypt")) {
		char *hash;
		if (read_ldif_attrval(s, value) == -1) return -1;
		if ( !(hash = docrypt(value->str))) return -1;
		g_string_assign(value, "{CRYPT}");
		g_string_append(value, hash);
	} else if (!strcasecmp(encoding, "md5")) {
		char *hash;
		if (read_ldif_attrval(s, value) == -1) return -1;
		if ( !(hash = domd5(value->str))) return -1;
		g_string_assign(value, "{CRYPT}");
		g_string_append(value, hash);
	} else {
		char *ptr;
		int n = strtol(encoding, &ptr, 10);
		if (*ptr) {
			fputs("Error: Unknown value encoding.\n", stderr);
			return -1;
		}
		g_string_set_size(value, n);
		if (fread(value->str, 1, n, s) != n) syserr();
	}
	return 0;
}

int
read_entry(FILE *s, long offset, char **key, tentry **entry, long *pos)
{
	GString *name = g_string_new("");
	GString *value = g_string_new("");
	char **rdns = 0;
	tentry *result = 0;
	int rc = 0;

	if (offset != -1)
		if (fseek(s, offset, SEEK_SET) == -1) syserr();
	do {
		if (pos)
			if ( (*pos = ftell(s)) == -1) syserr();
		if (read_line(s, name, value) == -1) { rc = -1; goto cleanup; }
		if (feof(s)) goto cleanup;
	} while (!name->len);

	rdns = ldap_explode_dn(value->str, 0);
	if (!rdns) {
		fputs("Error: Invalid distinguished name string.\n", stderr);
		return -1;
	}

	if (key) *key = xdup(name->str);
	if (entry)
		result = entry_new(xdup(value->str));
	else
		goto cleanup;

	for (;;) {
		tattribute *attribute;
		
		if (read_line(s, name, value) == -1) { rc = -1; goto cleanup; }
		if (!name->len) break;
		attribute = entry_find_attribute(result, name->str, 1);
		attribute_append_value(attribute, value->str, value->len);
	}

cleanup:
	g_string_free(name, 1);
	g_string_free(value, 1);
	if (rdns) ldap_value_free(rdns);
	if (entry)
		*entry = result;
	return rc;
}
