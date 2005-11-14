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

		if (!values) continue;
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
handle_result(LDAP *ld, LDAPMessage *result, int start, int n,
	      int progress, int noninteractive)
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
		if ((err != LDAP_NO_SUCH_OBJECT
		     && err != LDAP_TIMELIMIT_EXCEEDED
		     && err != LDAP_SIZELIMIT_EXCEEDED
		     && err != LDAP_ADMINLIMIT_EXCEEDED)
		    || noninteractive)
		{
			exit(1);
		}
		if (n > start /* otherwise there is only point in continuing
			       * if other searches find results, and we check
			       * that later */
		    && choose("Continue anyway?", "yn", 0) != 'y')
			exit(0);
	}

	if (n == start && progress) {
		fputs("No search results", stderr);
		if (matcheddn && *matcheddn)
			fprintf(stderr, " (matched: %s)", matcheddn);
		fputs(".\n", stderr);
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

static void
search_subtree(FILE *s, LDAP *ld, GArray *offsets, char *base,
	       cmdline *cmdline, LDAPControl **ctrls, int notty)
{
	int msgid;
	LDAPMessage *result, *entry;
	int start = offsets->len;
	int n = start;
	long offset;

	if (ldap_search_ext(
		    ld, base,
		    cmdline->scope, cmdline->filter, cmdline->attrs,
		    0, ctrls, 0, 0, 0, &msgid))
		ldaperr(ld, "ldap_search");

	while (n >= 0)
		switch (ldap_result(ld, msgid, 0, 0, &result)) {
		case -1:
		case 0:
			ldaperr(ld, "ldap_result");
		case LDAP_RES_SEARCH_ENTRY:
			entry = ldap_first_entry(ld, result);
			offset = ftell(s);
			if (offset == -1 && !notty) syserr();
			g_array_append_val(offsets, offset);
			print_entry_message(s, ld, entry, n);
			n++;
			if (cmdline->progress && !notty)
				update_progress(ld, n, entry);
			ldap_msgfree(entry);
			break;
		case LDAP_RES_SEARCH_REFERENCE:
			log_reference(ld, result, s);
			ldap_msgfree(result);
			break;
		case LDAP_RES_SEARCH_RESULT:
			if (!notty) {
				update_progress(ld, n, 0);
				putchar('\n');
			}
			handle_result(ld, result, start, n, cmdline->progress,
				      notty);
			n = -1;
			ldap_msgfree(result);
			break;
		default:
			abort();
		}
}

GArray *
search(FILE *s, LDAP *ld, cmdline *cmdline, LDAPControl **ctrls, int notty)
{
	GArray *offsets = g_array_new(0, 0, sizeof(long));
	GPtrArray *basedns = cmdline->basedns;
	int i;

	if (basedns->len == 0)
		search_subtree(s, ld, offsets, 0, cmdline, ctrls, notty);
	else
		for (i = 0; i < basedns->len; i++) {
			char *base = g_ptr_array_index(basedns, i);
			if (cmdline->progress && (basedns->len > 1))
				fprintf(stderr, "Searching in: %s\n", base);
			search_subtree(
				s, ld, offsets, base, cmdline, ctrls, notty);
		}

	if (!offsets->len) {
		if (!cmdline->progress) /* if not printed already... */
			fputs("No search results.  ", stderr);
		fputs("(Maybe use --add instead?)\n", stderr);
		exit(0);
	}

	return offsets;
}

static LDAPMessage *
get_entry(LDAP *ld, char *dn, LDAPMessage **result)
{
	LDAPMessage *entry;
	char *attrs[3] = {"+", "*", 0};

	if (ldap_search_s(ld, dn, LDAP_SCOPE_BASE, 0, attrs, 0, result))
		ldaperr(ld, "ldap_search");
	if ( !(entry = ldap_first_entry(ld, *result)))
		ldaperr(ld, "ldap_first_entry");
	return entry;
}

void
discover_naming_contexts(LDAP *ld, GPtrArray *basedns)
{
	LDAPMessage *result, *entry;
	char **values;

	entry = get_entry(ld, "", &result);
	values = ldap_get_values(ld, entry, "namingContexts");
	if (values) {
		char **ptr = values;
		for (ptr = values; *ptr; ptr++)
			g_ptr_array_add(basedns, xdup(*ptr));
		ldap_value_free(values);
	}
	ldap_msgfree(result);
}

void
get_schema(LDAP *ld, GPtrArray *objectclasses, GPtrArray *attributetypes)
{
	LDAPMessage *result, *entry;
	char **values;
	char *subschema_dn;
	int code;
	const char *errp;

	entry = get_entry(ld, "", &result);
	values = ldap_get_values(ld, entry, "subschemaSubentry");
	if (!values) {
		ldap_msgfree(result);
		return;
	}
	subschema_dn = xdup(*values);
	ldap_value_free(values);
	ldap_msgfree(result);

	entry = get_entry(ld, subschema_dn, &result);
	free(subschema_dn);
	values = ldap_get_values(ld, entry, "objectClasses");
	if (values) {
		char **ptr = values;
		for (ptr = values; *ptr; ptr++) {
			struct ldap_objectclass *cls
				= ldap_str2objectclass(
					*ptr, &code, &errp, 0);
			if (!cls) yourfault(ldap_scherr2str(code));
			g_ptr_array_add(objectclasses, cls);
		}
		ldap_value_free(values);
	}
	values = ldap_get_values(ld, entry, "attributeTypes");
	if (values) {
		char **ptr = values;
		for (ptr = values; *ptr; ptr++) {
			struct ldap_attributetype *at
				= ldap_str2attributetype(
					*ptr, &code, &errp, 0);
			if (!at) yourfault(ldap_scherr2str(code));
			g_ptr_array_add(attributetypes, at);
		}
		ldap_value_free(values);
	}
	ldap_msgfree(result);
}
