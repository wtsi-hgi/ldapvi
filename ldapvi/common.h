/* Copyright (c) 2003,2004,2005,2006 David Lichteblau
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <ldap.h>
#include <ldap_schema.h>
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
#include <ctype.h>

#define MANUAL_SYNTAX_URL					\
"http://www.lichteblau.com/ldapvi/manual/manual.xml#syntax"
#define RFC_2849_URL				\
"http://www.rfc-editor.org/rfc/rfc2849.txt"
#define MANUAL_LDIF_URL							\
"http://www.lichteblau.com/ldapvi/manual/manual.xml#syntax-ldif"

/*
 * error.c
 */
#define syserr() do_syserr(__FILE__, __LINE__)

void do_syserr(char *file, int line);
void yourfault(char *str);
void ldaperr(LDAP *ld, char *str);

/*
 * arguments.c
 */
enum ldapvi_mode {
	ldapvi_mode_edit, ldapvi_mode_in, ldapvi_mode_out,
	ldapvi_mode_delete, ldapvi_mode_rename, ldapvi_mode_modrdn
};
typedef struct cmdline {
	char *server;
	GPtrArray *basedns;
	int scope;
	char *filter;
	char **attrs;
	char *user;
	char *password;
	int progress;
	int referrals;
	GPtrArray *classes;
	int ldapmodify_add;
	int managedsait;
	char *sortkeys;
	int starttls;
	int tls;
	int deref;
	int verbose;
	int noquestions;
	int noninteractive;
	int discover;
	int config;
	int ldif;
	int ldapvi;
	int mode;
	char **delete_dns;
	char *rename_old;
	char *rename_new;
	int rename_dor;
	char *in_file;
	int schema_comments;
} cmdline;

void init_cmdline(cmdline *cmdline);
void parse_arguments(
	int argc, const char **argv, cmdline *result, GPtrArray *ctrls);
void usage(int fd, int rc);

/*
 * data.c
 */
typedef struct named_array {
	char *name;
	GPtrArray *array;
} named_array;

typedef struct tentry {
	struct named_array e;
} tentry;
#define entry_dn(entry) ((entry)->e.name)
#define entry_attributes(entry) ((entry)->e.array)

typedef struct tattribute {
	struct named_array a;
} tattribute;
#define attribute_ad(attribute) ((attribute)->a.name)
#define attribute_values(attribute) ((attribute)->a.array)

tentry *entry_new(char *dn);
void entry_free(tentry *e);
int entry_cmp(tentry *e, tentry *f);

tattribute *attribute_new(char *ad);
void attribute_free(tattribute *a);
int attribute_cmp(tattribute *a, tattribute *b);

int named_array_ptr_cmp(const void *aa, const void *bb);

LDAPMod *attribute2mods(tattribute *attribute);
LDAPMod **entry2mods(tentry *entry);
tattribute *entry_find_attribute(tentry *entry, char *ad, int createp);
void attribute_append_value(tattribute *attribute, char *data, int n);
int attribute_find_value(tattribute *attribute, char *data, int n);
int attribute_remove_value(tattribute *a, char *data, int n);

struct berval *string2berval(GArray *s);
struct berval *gstring2berval(GString *s);
char *array2string(GArray *av);
void xfree_berval(struct berval *bv);

/*
 * parse.c
 */
typedef int (*parser_entry)(FILE *, long, char **, tentry **, long *);
typedef int (*parser_peek)(FILE *, long, char **, long *);
typedef int (*parser_skip)(FILE *, long, char **);
typedef int (*parser_rename)(FILE *, long, char **, char **, int *);
typedef int (*parser_delete)(FILE *, long, char **);
typedef int (*parser_modify)(FILE *, long, char **, LDAPMod ***);

typedef struct tparser {
	parser_entry entry;

	parser_peek peek;
	parser_skip skip;

	parser_rename rename;
	parser_delete delete;
	parser_modify modify;
} tparser;

extern tparser ldif_parser;
extern tparser ldapvi_parser;

int peek_entry(FILE *s, long offset, char **key, long *pos);
int read_entry(FILE *s, long offset, char **key, tentry **entry, long *pos);
int read_rename(FILE *s, long offset, char **dn1, char **dn2, int *);
int read_modify(FILE *s, long offset, char **dn, LDAPMod ***mods);
int read_delete(FILE *s, long offset, char **dn);
int skip_entry(FILE *s, long offset, char **key);
int read_profile(FILE *s, tentry **entry);

/*
 * diff.c
 */
typedef int (*handler_change)(int, char *, char *, LDAPMod **, void *);
typedef int (*handler_rename)(int, char *, tentry *, void *);
typedef int (*handler_add)(int, char *, LDAPMod **, void *);
typedef int (*handler_delete)(int, char *, void *);
typedef int (*handler_rename0)(int, char *, char *, int, void *);

typedef struct thandler {
	handler_change change;
	handler_rename rename;
	handler_add add;
	handler_delete delete;
	handler_rename0 rename0;
} thandler;

int compare_streams(
	tparser *parser,
	thandler *handler,
	void *userdata,
	GArray *offsets,
	FILE *clean,
	FILE *data,
	long *error_position,
	long *syntax_error_position);

enum frob_rdn_mode {
	FROB_RDN_CHECK, FROB_RDN_REMOVE, FROB_RDN_ADD, FROB_RDN_CHECK_NONE
};
int frob_rdn(tentry *entry, char *dn, int mode);
int process_immediate(tparser *, thandler *, void *, FILE *, long, char *);


/*
 * misc.c
 */
int carray_cmp(GArray *a, GArray *b);
int carray_ptr_cmp(const void *aa, const void *bb);
void cp(char *src, char *dst, off_t skip, int append);
void fcopy(FILE *src, FILE *dst);
char choose(char *prompt, char *charbag, char *help);
void edit_pos(char *pathname, long pos);
void edit(char *pathname, long line);
void view(char *pathname);
char *home_filename(char *name);
void read_ldapvi_history(void);
void write_ldapvi_history(void);
GString *getline(char *prompt);
char *get_password();
char *append(char *a, char *b);
void *xalloc(size_t size);
char *xdup(char *str);
int adjoin_str(GPtrArray *, char *);
int adjoin_ptr(GPtrArray *, void *);

/*
 * schema.c
 */
typedef struct tschema {
	GHashTable *classes;
	GHashTable *types;
} tschema;

typedef struct tentroid {
	tschema *schema;
	GPtrArray *classes;
	GPtrArray *must;
	GPtrArray *may;
	LDAPObjectClass *structural;
	GString *comment;
	GString *error;
} tentroid;

char *objectclass_name(LDAPObjectClass *);
char *attributetype_name(LDAPAttributeType *);

tschema *schema_new(LDAP *ld);
void schema_free(tschema *schema);
LDAPObjectClass *schema_get_objectclass(tschema *, char *);
LDAPAttributeType *schema_get_attributetype(tschema *, char *);

tentroid *entroid_new(tschema *);
void entroid_reset(tentroid *);
void entroid_free(tentroid *);
LDAPObjectClass *entroid_get_objectclass(tentroid *, char *);
LDAPAttributeType *entroid_get_attributetype(tentroid *, char *);
LDAPObjectClass *entroid_request_class(tentroid *, char *);
void entroid_remove_ad(tentroid *, char *);
int compute_entroid(tentroid *);

/*
 * print.c
 */
typedef enum t_print_binary_mode {
	PRINT_ASCII, PRINT_UTF8, PRINT_JUNK
} t_print_binary_mode;
extern t_print_binary_mode print_binary_mode;

void print_entry_object(FILE *s, tentry *entry, char *key);
void print_ldapvi_modify(FILE *s, char *dn, LDAPMod **mods);
void print_ldapvi_rename(FILE *s, char *olddn, char *newdn, int deleteoldrdn);
void print_ldapvi_add(FILE *s, char *dn, LDAPMod **mods);
void print_ldapvi_delete(FILE *s, char *dn);
void print_ldapvi_modrdn(FILE *s, char *olddn, char *newrdn, int deleteoldrdn);
void print_entry_message(FILE *, LDAP *, LDAPMessage *, int key, tentroid *);
void print_ldif_modify(FILE *s, char *dn, LDAPMod **mods);
void print_ldif_rename(FILE *s, char *olddn, char *newdn, int deleteoldrdn);
void print_ldif_add(FILE *s, char *dn, LDAPMod **mods);
void print_ldif_delete(FILE *s, char *dn);
void print_ldif_modrdn(FILE *s, char *olddn, char *newrdn, int deleteoldrdn);
void print_ldif_message(FILE *, LDAP *, LDAPMessage *, int key, tentroid *);

/*
 * search.c
 */
void discover_naming_contexts(LDAP *ld, GPtrArray *basedns);
GArray *search(
	FILE *s, LDAP *ld, cmdline *cmdline, LDAPControl **ctrls, int notty,
	int ldif);
LDAPMessage *get_entry(LDAP *ld, char *dn, LDAPMessage **result);

/*
 * port.c
 */
typedef void (*on_exit_function)(int, void *);
int g_string_append_sha(GString *string, char *key);
int g_string_append_ssha(GString *string, char *key);
int g_string_append_md5(GString *string, char *key);
int g_string_append_smd5(GString *string, char *key);

/*
 * base64.c
 */
void print_base64(unsigned char const *src, size_t srclength, FILE *s);
void g_string_append_base64(
	GString *string, unsigned char const *src, size_t srclength);
int read_base64(char const *src, unsigned char *target, size_t targsize);
