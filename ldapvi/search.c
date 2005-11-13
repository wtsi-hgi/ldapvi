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
#include "common.h"

static void
print_entry_message(FILE *s, LDAP *ld, LDAPMessage *entry, int key)
{
	char *dn, *ad;
	BerElement *ber;

	fprintf(s, "\n%d ", key);
	fputs(dn = ldap_get_dn(ld, entry), s);
	ldap_memfree(dn);
	fputc('\n', s);

	for (ad = ldap_first_attribute(ld, entry, &ber);
	     ad;
	     ad = ldap_next_attribute(ld, entry, ber))
	{
		struct berval **values = ldap_get_values_len(ld, entry, ad);
		struct berval **ptr;

		if (!values) continue; /* weird server */
		for (ptr = values; *ptr; ptr++) {
			fputs(ad, s);
			print_attrval(s, (*ptr)->bv_val, (*ptr)->bv_len);
			fputc('\n', s);
		}
		ldap_memfree(ad);
		ldap_value_free_len(values);
	}
	ber_free(ber, 0);
	if (ferror(s)) syserr();
}

static int
get_ws_col(void)
{
        struct winsize ws;
        if (ioctl(1, TIOCGWINSZ, &ws) == -1) return 80;
	return ws.ws_col;
}

static void
update_progress(LDAP *ld, int n, LDAPMessage *entry)
{
	int cols = get_ws_col();
	static struct timeval tv;
	static int usec = 0;
	int i;

	if (gettimeofday(&tv, 0) == -1) syserr();
	if (!entry)
		usec = 0;
	else if (!usec)
		usec = tv.tv_usec;
	else {
		if (tv.tv_usec < usec) usec -= 1000000;
		if (tv.tv_usec - usec < 200000)
			return;
		usec = tv.tv_usec;
	}
	
	putchar('\r');
	for (i = 0; i < cols; i++) putchar(' ');

	printf((n == 1) ? "\r%7d entry read  " :"\r%7d entries read", n);
	if (entry) {
		char *dn = ldap_get_dn(ld, entry);
		if (strlen(dn) < cols - 28)
			printf("        %s", dn);
		ldap_memfree(dn);
	}
	fflush(stdout);
}

void
handle_result(LDAP *ld, LDAPMessage *result, int n, int noninteractive)
{
        int rc;
        int err;
        char *matcheddn;
        char *text;
	
        rc = ldap_parse_result(ld, result, &err, &matcheddn, &text, 0, 0, 0);
        if (rc) ldaperr(ld, "ldap_parse_result");

	if (err) {
		fprintf(stderr, "Search failed: %s\n", ldap_err2string(err));
		if (text && *text) fprintf(stderr, "\t%s\n", text);
		if ((err != LDAP_TIMELIMIT_EXCEEDED
		     && err != LDAP_SIZELIMIT_EXCEEDED
		     && err != LDAP_ADMINLIMIT_EXCEEDED)
		    || n == 0
		    || noninteractive)
		{
			exit(1);
		}
		if (choose("Continue anyway?", "yn", 0) != 'y')
			exit(0);
	}

	if (n == 0) {
		fputs("No search results.", stderr);
		if (!noninteractive)
			fputs("  (Maybe use --add instead?)", stderr);
		putc('\n', stderr);
		if (matcheddn && *matcheddn)
			fprintf(stderr, "(matched: %s)\n", matcheddn);
		exit(0);
	}

	if (matcheddn) ldap_memfree(matcheddn);
	if (text) ldap_memfree(text);
}

void
log_reference(LDAP *ld, LDAPMessage *reference, FILE *s)
{
        char **refs;
	char **ptr;

        if (ldap_parse_reference(ld, reference, &refs, 0, 0))
		ldaperr(ld, "ldap_parse_reference");
	fputc('\n', s);
	for (ptr = refs; *ptr; ptr++)
		fprintf(s, "# reference to: %s\n", *ptr);
	ldap_value_free(refs);
}

GArray *
search(FILE *s, LDAP *ld, char *base, int scope, char *filter, char **attrs,
       LDAPControl **ctrls, int progress, int noninteractive)
{
	int msgid;
	LDAPMessage *result, *entry;
	int n = 0;
	GArray *offsets = g_array_new(0, 0, sizeof(long));
	long offset;

	if (ldap_search_ext(ld, base, scope, filter, attrs, 0,
			    ctrls, 0, 0, 0, &msgid))
		ldaperr(ld, "ldap_search");

	while (n >= 0)
		switch (ldap_result(ld, msgid, 0, 0, &result)) {
		case -1:
		case 0:
			ldaperr(ld, "ldap_result");
		case LDAP_RES_SEARCH_ENTRY:
			entry = ldap_first_entry(ld, result);
			offset = ftell(s);
			if (offset == -1 && !noninteractive) syserr();
			g_array_append_val(offsets, offset);
			print_entry_message(s, ld, entry, n);
			n++;
			if (progress) update_progress(ld, n, entry);
			ldap_msgfree(entry);
			break;
		case LDAP_RES_SEARCH_REFERENCE:
			log_reference(ld, result, s);
			ldap_msgfree(result);
			break;
		case LDAP_RES_SEARCH_RESULT:
			update_progress(ld, n, 0);
			putchar('\n');
			handle_result(ld, result, n, noninteractive);
			n = -1;
			ldap_msgfree(result);
			break;
		default:
			abort();
		}

	return offsets;
}
