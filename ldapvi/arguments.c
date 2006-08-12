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
#include <popt.h>
#include "common.h"
#include "version.h" 

#define USAGE								   \
"Usage: ldapvi [OPTION]... [FILTER] [AD]...\n"				   \
"       ldapvi --diff FILE1 FILE2\n"					   \
"Quickstart:\n"                                                            \
"       ldapvi --discover --host HOSTNAME\n"                               \
"Perform an LDAP search and update results using a text editor.\n"	   \
"\n"									   \
"Connection options:\n"							   \
"  -h, --host URL         Server.\n"					   \
"  -D, --user USER        Search filter or DN: User to bind as.     [1]\n" \
"  -w, --password SECRET  USER's password.\n"				   \
"\n"									   \
"Search parameters:\n"							   \
"  -b, --base DN          Search base.\n"				   \
"  -s, --scope SCOPE      Search scope.  One of base|one|sub.\n"	   \
"  -S, --sort KEYS        Sort control (critical).\n"			   \
"\n"									   \
"Miscellaneous options:\n"						   \
"  -A, --add              Don't search, start with empty file.  See -o.\n" \
"  -o, --class OBJCLASS   Class to add.  Can be repeated.  Implies -A.\n"  \
"  -a, --deref            never|searching|finding|always\n"		   \
"  -d, --discover         Auto-detect naming contexts.              [2]\n" \
"  -c, --config           Print parameters in ldap.conf syntax.\n"         \
"      --encoding [ASCII|UTF-8|binary]\n"                                  \
"                         The encoding to allow.  Default is UTF-8.\n"     \
"  -M, --managedsait      manageDsaIT control (critical).\n"		   \
"  -Z, --starttls         Require startTLS.\n"				   \
"      --tls [never|allow|try|strict]  Level of TLS strictess.\n"          \
"  -R, --read DN          Same as -b DN -s base '(objectclass=*)' + *\n"   \
"  -q, --quiet            Disable progress output.\n"			   \
"  -v, --verbose          Note every update.\n"				   \
"  -!, --noquestions      Don't ask for confirmation.\n"		   \
"  -H, --help             This help.\n"					   \
"\n"									   \
"Environment variables: VISUAL, EDITOR, PAGER.\n"			   \
"\n"									   \
"[1] User names can be specified as distinguished names:\n"		   \
"      uid=foo,ou=bar,dc=acme,dc=com\n"					   \
"    or search filters:\n"						   \
"      (uid=foo)\n"							   \
"    Note the use of parenthesis, which can be omitted from search\n"	   \
"    filters usually but are required here.  For this searching bind to\n" \
"    work, your client library must be configured with appropriate\n"	   \
"    default search parameters.\n"					   \
"\n"									   \
"[2] Repeat the search for each naming context found and present the\n"    \
"    concatenation of all search results.  Conflicts with --base.\n"	   \
"    With --config, show a BASE configuration line for each context.\n"    \
"\n"									   \
"A special (offline) option is --diff, which compares two files\n"	   \
"and writes any changes to standard output in LDIF format.\n"		   \
"\n"									   \
"Report bugs to \"ldapvi@lists.askja.de\"."

#define OPTION_TLS 1000
#define OPTION_ENCODING 1001

static struct poptOption options[] = {
	{"host",	'h', POPT_ARG_STRING, 0, 'h', 0, 0},
	{"scope",	's', POPT_ARG_STRING, 0, 's', 0, 0},
	{"base",	'b', POPT_ARG_STRING, 0, 'b', 0, 0},
	{"user",	'D', POPT_ARG_STRING, 0, 'D', 0, 0},
	{"password",	'w', POPT_ARG_STRING, 0, 'w', 0, 0},
	{"chase",	'C', POPT_ARG_STRING, 0, 'C', 0, 0},
	{"deref",	'a', POPT_ARG_STRING, 0, 'a', 0, 0},
	{"sort",	'S', POPT_ARG_STRING, 0, 'S', 0, 0},
	{"class",	'o', POPT_ARG_STRING, 0, 'o', 0, 0},
	{"root",	'R', POPT_ARG_STRING, 0, 'R', 0, 0},
	{"tls",		  0, POPT_ARG_STRING, 0, OPTION_TLS, 0, 0},
	{"encoding",	  0, POPT_ARG_STRING, 0, OPTION_ENCODING, 0, 0},
	{"profile",	'p', POPT_ARG_STRING, 0, 'p', 0, 0},
	{"add",		'A', 0, 0, 'A', 0, 0},
	{"config",	'c', 0, 0, 'c', 0, 0},
	{"discover",	'd', 0, 0, 'd', 0, 0},
	{"quiet",	'q', 0, 0, 'q', 0, 0},
	{"verbose",	'v', 0, 0, 'v', 0, 0},
	{"managedsait",	'M', 0, 0, 'M', 0, 0},
	{"starttls",	'Z', 0, 0, 'Z', 0, 0},
	{"help",	'H', 0, 0, 'H', 0, 0},
	{"version",	'V', 0, 0, 'V', 0, 0},
	{"noquestions", '!', 0, 0, '!', 0, 0},
	{0, 0, 0, 0, 0}
};


void
usage(int fd, int rc)
{
	if (fd != -1) dup2(fd, 1);
	puts(USAGE);
	if (rc != -1) exit(rc);
}

static void
parse_argument(int c, char *arg, cmdline *result, GPtrArray *ctrls)
{
	LDAPControl *control;

	switch (c) {
	case 'H':
		usage(-1, 0);
	case 'h':
		result->server = arg;
		break;
	case 's':
		if (!strcmp(arg, "base"))
			result->scope = LDAP_SCOPE_BASE;
		else if (!strcmp(arg, "one"))
			result->scope = LDAP_SCOPE_ONELEVEL;
		else if (!strcmp(arg, "sub"))
			result->scope = LDAP_SCOPE_SUBTREE;
		else {
			fprintf(stderr, "invalid scope: %s\n", arg);
			usage(2, 1);
		}
		break;
	case 'b':
		g_ptr_array_add(result->basedns, arg);
		break;
	case 'D':
		result->user = arg;
		break;
	case 'w':
		result->password = arg;
		break;
	case 'd':
		result->discover = 1;
		break;
	case 'c':
		result->config = 1;
		break;
	case 'q':
		result->progress = 0;
		break;
	case 'A':
		if (!result->add)
			result->add = g_ptr_array_new();
		break;
	case 'o':
		if (!result->add)
			result->add = g_ptr_array_new();
		adjoin_str(result->add, arg);
		break;
	case 'C':
		if (!strcasecmp(arg, "yes"))
			result->referrals = 1;
		else if (!strcasecmp(arg, "no"))
			result->referrals = 0;
		else {
			fprintf(stderr, "--chase invalid%s\n", arg);
			usage(2, 1);
		}
		break;
	case 'M':
		result->managedsait = 1;
		control = malloc(sizeof(LDAPControl));
		control->ldctl_oid = LDAP_CONTROL_MANAGEDSAIT;
		control->ldctl_value.bv_len = 0;
		control->ldctl_value.bv_val = 0;
		control->ldctl_iscritical = 1;
		g_ptr_array_add(ctrls, control);
		break;
	case 'V':
		puts("ldapvi " VERSION);
		exit(0);
	case 'S':
		result->sortkeys = arg;
		break;
	case 'Z':
		result->starttls = 1;
		break;
	case OPTION_TLS:
		if (!strcmp(arg, "never"))
			result->tls = LDAP_OPT_X_TLS_NEVER;
		else if (!strcmp(arg, "allow"))
			result->tls = LDAP_OPT_X_TLS_ALLOW;
		else if (!strcmp(arg, "try"))
			result->tls = LDAP_OPT_X_TLS_TRY;
		else if (!strcmp(arg, "strict"))
			result->tls = LDAP_OPT_X_TLS_HARD;
		else {
			fprintf(stderr, "invalid tls level: %s\n",
				arg);
			usage(2, 1);
		}
		break;
	case OPTION_ENCODING:
		if (!strcasecmp(arg, "ASCII"))
			print_binary_mode = PRINT_ASCII;
		else if (!strcasecmp(arg, "binary"))
			print_binary_mode = PRINT_JUNK;
		else if (!strcasecmp(arg, "UTF-8")
			 || !strcasecmp(arg, "UTF_8")
			 || !strcasecmp(arg, "UTF8"))
			print_binary_mode = PRINT_UTF8;
		else {
			fprintf(stderr, "invalid encoding: %s\n", arg);
			usage(2, 1);
		}
		break;
	case 'R':
		g_ptr_array_add(result->basedns, arg);
		result->scope = LDAP_SCOPE_BASE;
		result->filter = "(objectclass=*)";
		{
			static char *attrs[3] = {"+", "*", 0};
			result->attrs = attrs;
		}
		break;
	case 'a':
		if (!strcasecmp(arg, "never"))
			result->deref = LDAP_DEREF_NEVER;
		else if (!strcasecmp(arg, "searching"))
			result->deref = LDAP_DEREF_SEARCHING;
		else if (!strcasecmp(arg, "finding"))
			result->deref = LDAP_DEREF_FINDING;
		else if (!strcasecmp(arg, "always"))
			result->deref = LDAP_DEREF_ALWAYS;
		else {
			fprintf(stderr, "--deref invalid%s\n", arg);
			usage(2, 1);
		}
		break;
	case 'v':
		result->verbose = 1;
		break;
	case '!':
		result->noquestions = 1;
		break;
	default:
		abort();
	}
}

static void
parse_profile_line(tattribute *attribute, cmdline *result, GPtrArray *ctrls)
{
	char *name = attribute_ad(attribute);
	GPtrArray *values = attribute_values(attribute);
	int i;
	struct poptOption *o = 0;

	for (i = 0; options[i].longName; i++)
		if (!strcmp(name, options[i].longName)) {
			o = &options[i];
			break;
		}
	if (!o) {
		fprintf(stderr, "Error: unknown configuration option: '%s'\n",
			name);
		exit(1);
	}

	for (i = 0; i < values->len; i++) {
		char *value = array2string(g_ptr_array_index(values, i));
		if (o->argInfo == 0)
			if (!strcmp(value, "no"))
				continue;
			else if (strcmp(value, "yes")) {
				fprintf(stderr,
					"invalid value '%s' to configuration"
					" option '%s', expected 'yes' or"
					" 'no'.\n",
					value,
					name);
				exit(1);
			}
		parse_argument(o->val, value, result, ctrls);
	}
}

static void
parse_configuration(char *profile_name, cmdline *result, GPtrArray *ctrls)
{
	struct stat st;
	char *profile_requested = profile_name;
	char *filename = home_filename(".ldapvirc");
	FILE *s;
	tentry *p;
	tentry *profile_found = 0;
	int duplicate = 0;

	if (!profile_name)
		profile_name = "default";

	if (!filename || stat(filename, &st)) {
		filename = "/etc/ldapvi.conf";
		if (stat(filename, &st))
			filename = 0;
	}
	if (!filename) {
		if (profile_requested) {
			fputs("Error: ldapvi configuration file not found.\n",
			      stderr);
			exit(1);
		}
		return;
	}

	if ( !(s = fopen(filename, "r"))) syserr();
	for (;;) {
		p = 0;
		if (read_profile(s, &p)) {
			fputs("Error in configuration file, giving up.\n",
			      stderr);
			exit(1);
		}
		if (!p)
			break;
		if (strcmp(entry_dn(p), profile_name)) 
			entry_free(p);
		else if (profile_found)
			duplicate = 1;
		else
			profile_found = p;
	}
	if (duplicate) {
		fprintf(stderr,
			"Error: Duplicate configuration profile '%s'.\n",
			profile_name);
		exit(1);
	}
	if (profile_found) {
		GPtrArray *attributes = entry_attributes(profile_found);
		int i;
		for (i = 0; i < attributes->len; i++) {
			tattribute *a = g_ptr_array_index(attributes, i);
			parse_profile_line(a, result, ctrls);
		}
		entry_free(profile_found);
		if (setenv("LDAPNOINIT", "thanks", 1)) syserr();
	} else if (profile_requested) {
		fprintf(stderr,
			"Error: Configuration profile not found: '%s'.\n",
			profile_name);
		exit(1);
	}
	if (fclose(s) == EOF) syserr();
}

void
parse_arguments(int argc, const char **argv, cmdline *result, GPtrArray *ctrls)
{
	int c;
	poptContext ctx;
	char *profile = 0;

	ctx = poptGetContext(
		0, argc, argv, options, POPT_CONTEXT_POSIXMEHARDER);

	while ( (c = poptGetNextOpt(ctx)) > 0) {
		char *arg = (char *) poptGetOptArg(ctx);
		if (c != 'p') continue;
		if (profile) {
			fputs("Multiple profile options given.\n", stderr);
			usage(2, 1);
		}
		profile = arg;
	}
	parse_configuration(profile, result, ctrls);

	poptResetContext(ctx);
	while ( (c = poptGetNextOpt(ctx)) > 0) {
		char *arg = (char *) poptGetOptArg(ctx);
		if (c != 'p')
			parse_argument(c, arg, result, ctrls);
	}
	if (c != -1) {
		fprintf(stderr, "%s: %s\n",
			poptBadOption(ctx, POPT_BADOPTION_NOALIAS),
			poptStrerror(c));
		usage(2, 1);
	}
	if (!result->filter)
		result->filter = (char *) poptGetArg(ctx);
	if (!result->attrs)
		result->attrs = (char **) poptGetArgs(ctx);
	/* don't free! */
/* 	poptFreeContext(ctx); */
}
