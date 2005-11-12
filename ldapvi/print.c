/* (c) 2003 David Lichteblau.  License: GNU GPL. */
#include "common.h"

void
write_backslashed(FILE *s, char *ptr, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		if (ptr[i] == '\n') fputc('\\', s);
		fputc(ptr[i], s);
	}
	if (ferror(s)) syserr();
}

int
readable_string_p(char *str, int n)
{
	int i;
	/* XXX we could do something more fancy here.  Checking for UTF-8
	 * might make sense, so that you can use a UTF-8 capable editor
	 * in the presence of binary data. */
	for (i = 0; i < n; i++) {
		char c = str[i];
		if (c < 32 && c != '\n' && c != '\t')
			return 0;
	}
	return 1;
}

void
print_attrval(FILE *s, char *str, int len)
{
	if (!readable_string_p(str, len)) {
		fputs(":: ", s);
		print_base64((unsigned char *) str, len, s);
	} else if (!safe_string_p(str, len)) {
		fputc(' ', s);
		write_backslashed(s, str, len);
	} else {
		fputs(": ", s);
		fwrite(str, 1, len, s);
	}
}

static void
print_attribute(FILE *s, tattribute *attribute)
{
	GPtrArray *values = attribute_values(attribute);
	int j;
	
	for (j = 0; j < values->len; j++) {
		GArray *av = g_ptr_array_index(values, j);
		fputs(attribute_ad(attribute), s);
		print_attrval(s, av->data, av->len);
		fputc('\n', s);
	}
	if (ferror(s)) syserr();
}

void
print_entry_object(FILE *s, tentry *entry, char *key)
{
	GPtrArray *attributes = entry_attributes(entry);
	int i;

	fputc('\n', s);
	fputs(key ? key : "entry", s);
	fputc(' ', s);
	fputs(entry_dn(entry), s);
	fputc('\n', s);
	if (ferror(s)) syserr();

	for (i = 0; i < attributes->len; i++) {
		tattribute *attribute = g_ptr_array_index(attributes, i);
		print_attribute(s, attribute);
	}
}

int
safe_string_p(char *str, int n)
{
	int safe = 1;
	char c;
	int i;

	if (n == 0) return 1;
		
	c = str[0];
	safe = (c != ' ') && (c != ':') && (c != '<');
	
	for (i = 0; i < n; i++) {
		c = str[i];
		if ((c == '\0') || (c == '\r') || (c == '\n'))
			safe = 0;
	}
	return safe;
}

static void
print_ldif_ldapmod(FILE *s, LDAPMod *mod)
{
	struct berval **values = mod->mod_bvalues;
	for (; *values; values++) {
		struct berval *value = *values;
		fputs(mod->mod_type, s);
		if (safe_string_p(value->bv_val, value->bv_len)) {
			fputs(": ", s);
			fwrite(value->bv_val, value->bv_len, 1, s);
		} else {
			fputs(":: ", s);
			print_base64((unsigned char *) value->bv_val,
				     value->bv_len,
				     s);
		}
		fputs("\n", s);
	}
	if (ferror(s)) syserr();
}

void
print_ldif_modify(FILE *s, char *dn, LDAPMod **mods)
{
	fputs("\ndn: ", s);
	fputs(dn, s);
	fputs("\nchangetype: modify\n", s);

	for (; *mods; mods++) {
		LDAPMod *mod = *mods;

		switch (mod->mod_op & ~LDAP_MOD_BVALUES) {
		case LDAP_MOD_ADD: fputs("add: ", s); break;
		case LDAP_MOD_DELETE: fputs("delete: ", s); break;
		case LDAP_MOD_REPLACE: fputs("replace: ", s); break;
		default: abort();
		}
		fputs(mod->mod_type, s);
		fputc('\n', s);

		print_ldif_ldapmod(s, mod);
		fputs("-\n", s);
	}
	if (ferror(s)) syserr();
}

void
print_ldif_add(FILE *s, char *dn, LDAPMod **mods)
{
	fputs("\ndn: ", s);
	fputs(dn, s);
	fputs("\nchangetype: add\n", s);

	for (; *mods; mods++)
		print_ldif_ldapmod(s, *mods);
	if (ferror(s)) syserr();
}

void
print_ldif_rename(FILE *s, char *olddn, char *newdn, int deleteoldrdn)
{
	char **newrdns = ldap_explode_dn(newdn, 0);
	char **ptr = newrdns;
	
	fputs("\ndn: ", s);
	fputs(olddn, s);
	fputs("\nchangetype: modrdn\nnewrdn: ", s);
	fputs(*ptr, s);
	fprintf(s, "\ndeleteoldrdn: %d\nnewsuperior: ", !!deleteoldrdn);
	ptr++;
	if (*ptr)
		fputs(*ptr, s);
	ptr++;
	for (; *ptr; ptr++) {
		fputc(',', s);
		fputs(*ptr, s);
	}
	fputc('\n', s);
	if (ferror(s)) syserr();
	ldap_value_free(newrdns);
}

void
print_ldif_delete(FILE *s, char *dn)
{
	fputs("\ndn: ", s);
	fputs(dn, s);
	fputs("\nchangetype: delete\n", s);
	if (ferror(s)) syserr();
}
