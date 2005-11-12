/* (c) 2003 David Lichteblau.  License: GNU GPL. */
#include <popt.h>
#include "common.h"
#include "version.h" 

static struct poptOption options[] = {
	{"host",	'h', POPT_ARG_STRING, 0, 'h', 0, 0},
	{"scope",	's', POPT_ARG_STRING, 0, 's', 0, 0},
	{"base",	'b', POPT_ARG_STRING, 0, 'b', 0, 0},
	{"user",	'D', POPT_ARG_STRING, 0, 'D', 0, 0},
	{"password",	'w', POPT_ARG_STRING, 0, 'w', 0, 0},
	{"chase",	'C', POPT_ARG_STRING, 0, 'C', 0, 0},
	{"deref",	'a', POPT_ARG_STRING, 0, 'a', 0, 0},
	{"sort",	'S', POPT_ARG_STRING, 0, 'S', 0, 0},
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
	puts("Usage: ldapvi [OPTION]... [FILTER] [AD]...\n"
	     "       ldapvi --diff FILE1 FILE2\n"
	     "Perform an LDAP search and update results using a text editor.\n"
	     "\n"
	     "Connection options:\n"
	     "  -h, --host URL         Server.\n"
	     "  -D, --user USER        Search filter or DN: User to bind as.\n"
	     "  -w, --password SECRET  USER's password.\n"
	     "\n"
	     "Search parameters:\n"
	     "  -b, --base DN          Search base.\n"
	     "  -s, --scope SCOPE      Search scope.  One of base|one|sub.\n"
	     "  -S, --sort KEYS        Sort control (critical).\n"
	     "\n"
	     "Miscellaneous options:\n"
	     "  -A, --add              Don't search, start with empty file.\n"
	     "  -a, --deref            never|searching|finding|always\n"
	     "  -M, --managedsait      manageDsaIT control (critical).\n"
	     "  -Z, --starttls         Require startTLS.\n"
	     "  -q, --quiet            Disable progress output.\n"
	     "  -v, --verbose          Note every update.\n"
	     "  -!, --noquestions      Don't ask for confirmation.\n"
	     "  -H, --help             This help.\n"
	     "\n"
	     "Environment variables: VISUAL, EDITOR, PAGER.\n"
	     "\n"
	     "User names can be specified as distinguished names:\n"
	     "  uid=foo,ou=bar,dc=acme,dc=com\n"
	     "or search filters:\n"
	     "  (uid=foo)\n"
	     "\n"
	     "Note the parenthesis, which can be omitted from search filters\n"
	     "usually, but are required here.  For this searching bind to\n"
	     "work your client library must be configured with appropriate\n"
	     "default search parameters.\n"
	     "\n"
	     "A special (offline) option is --diff, which compares two files\n"
	     "and writes any changes to standard output in LDIF format.\n"
	     "\n"
	     "Report bugs to \"david@lichteblau.com\".");
	if (rc != -1) exit(rc);
}

void
parse_arguments(int argc, const char **argv,
		char **server, char **base, int *scope, char **filter,
		char ***attrs, char **user, char **password, int *progress,
		int *referrals, int *add, GPtrArray *ctrls, int *managedsait,
		char **sortkeys, int *starttls, int *deref, int *verbose,
		int *noquestions)
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
			*server = arg;
			break;
		case 's':
			if (!strcmp(arg, "base"))
				*scope = LDAP_SCOPE_BASE;
			else if (!strcmp(arg, "one"))
				*scope = LDAP_SCOPE_ONELEVEL;
			else if (!strcmp(arg, "sub"))
				*scope = LDAP_SCOPE_SUBTREE;
			else {
				fprintf(stderr, "invalid scope: %s\n", arg);
				usage(2, 1);
			}
			break;
		case 'b':
			*base = arg;
			break;
		case 'D':
			*user = arg;
			break;
		case 'w':
			*password = arg;
			break;
		case 'q':
			*progress = 0;
			break;
		case 'A':
			*add = 1;
			break;
		case 'C':
			if (!strcasecmp(arg, "yes"))
				*referrals = 1;
			else if (!strcasecmp(arg, "no"))
				*referrals = 0;
			else {
				fprintf(stderr, "--chase invalid%s\n", arg);
				usage(2, 1);
			}
			break;
		case 'M':
			*managedsait = 1;
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
			*sortkeys = arg;
			break;
		case 'Z':
			*starttls = 1;
			break;
		case 'a':
			if (!strcasecmp(arg, "never"))
				*deref = LDAP_DEREF_NEVER;
			else if (!strcasecmp(arg, "searching"))
				*deref = LDAP_DEREF_SEARCHING;
			else if (!strcasecmp(arg, "finding"))
				*deref = LDAP_DEREF_FINDING;
			else if (!strcasecmp(arg, "always"))
				*deref = LDAP_DEREF_ALWAYS;
			else {
				fprintf(stderr, "--deref invalid%s\n", arg);
				usage(2, 1);
			}
			break;
		case 'v':
			*verbose = 1;
			break;
		case '!':
			*noquestions = 1;
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
	*filter = (char *) poptGetArg(ctx);
	*attrs = (char **) poptGetArgs(ctx);
	/* don't free! */
/* 	poptFreeContext(ctx); */
}
