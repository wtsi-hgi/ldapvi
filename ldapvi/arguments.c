/* (c) 2003 David Lichteblau.  License: GNU GPL. */
#include <popt.h>
#include "common.h"
#include "version.h" 

#define USAGE								    \
"Usage: ldapvi [OPTION]... [FILTER] [AD]...\n"				    \
"       ldapvi --diff FILE1 FILE2\n"					    \
"Perform an LDAP search and update results using a text editor.\n"	    \
"\n"									    \
"Connection options:\n"							    \
"  -h, --host URL         Server.\n"					    \
"  -D, --user USER        Search filter or DN: User to bind as.     [1]\n"  \
"  -w, --password SECRET  USER's password.\n"				    \
"\n"									    \
"Search parameters:\n"							    \
"  -b, --base DN          Search base.\n"				    \
"  -s, --scope SCOPE      Search scope.  One of base|one|sub.\n"	    \
"  -S, --sort KEYS        Sort control (critical).\n"			    \
"\n"									    \
"Miscellaneous options:\n"						    \
"  -A, --add              Don't search, start with empty file.\n"	    \
"  -a, --deref            never|searching|finding|always\n"		    \
"  -M, --managedsait      manageDsaIT control (critical).\n"		    \
"  -Z, --starttls         Require startTLS.\n"				    \
"  -q, --quiet            Disable progress output.\n"			    \
"  -v, --verbose          Note every update.\n"				    \
"  -!, --noquestions      Don't ask for confirmation.\n"		    \
"  -H, --help             This help.\n"					    \
"\n"									    \
"Environment variables: VISUAL, EDITOR, PAGER.\n"			    \
"\n"									    \
"[1] User names can be specified as distinguished names:\n"		    \
"      uid=foo,ou=bar,dc=acme,dc=com\n"					    \
"    or search filters:\n"						    \
"      (uid=foo)\n"							    \
"    Note the use of parenthesis, which can be omitted from search\n"	    \
"    filters usually but are required here.  For this searching bind to\n"  \
"    work, your client library must be configured with appropriate\n"	    \
"    default search parameters.\n"					    \
"\n"									    \
"A special (offline) option is --diff, which compares two files\n"	    \
"and writes any changes to standard output in LDIF format.\n"		    \
"\n"									    \
"Report bugs to \"david@lichteblau.com\"."

static struct poptOption options[] = {
	{"host",	'h', POPT_ARG_STRING, 0, 'h', 0, 0},
	{"scope",	's', POPT_ARG_STRING, 0, 's', 0, 0},
	{"base",	'b', POPT_ARG_STRING, 0, 'b', 0, 0},
	{"user",	'D', POPT_ARG_STRING, 0, 'D', 0, 0},
	{"password",	'w', POPT_ARG_STRING, 0, 'w', 0, 0},
	{"chase",	'C', POPT_ARG_STRING, 0, 'C', 0, 0},
	{"deref",	'a', POPT_ARG_STRING, 0, 'a', 0, 0},
	{"sort",	'S', POPT_ARG_STRING, 0, 'S', 0, 0},
	{"discover",	'd', 0, 0, 'd', 0, 0},
	{"quiet",	'q', 0, 0, 'q', 0, 0},
	{"verbose",	'v', 0, 0, 'v', 0, 0},
	{"add",		'A', 0, 0, 'A', 0, 0},
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

void
parse_arguments(int argc, const char **argv, cmdline *result, GPtrArray *ctrls)
{
	int c;
	poptContext ctx;
	LDAPControl *control;

	ctx = poptGetContext(
		0, argc, argv, options, POPT_CONTEXT_POSIXMEHARDER);
	while ( (c = poptGetNextOpt(ctx)) > 0) {
		char *arg = (char *) poptGetOptArg(ctx);
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
			result->base = arg;
			break;
		case 'D':
			result->user = arg;
			break;
		case 'w':
			result->password = arg;
			break;
		case 'q':
			result->progress = 0;
			break;
		case 'A':
			result->add = 1;
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
	if (c != -1) {
		fprintf(stderr, "%s: %s\n",
			poptBadOption(ctx, POPT_BADOPTION_NOALIAS),
			poptStrerror(c));
		usage(2, 1);
	}
	result->filter = (char *) poptGetArg(ctx);
	result->attrs = (char **) poptGetArgs(ctx);
	/* don't free! */
/* 	poptFreeContext(ctx); */
}
