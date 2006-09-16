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
#include <curses.h>
#include <signal.h>
#include <term.h>
#include "common.h"

static int
compare(tparser *p, thandler *handler, void *userdata, GArray *offsets, 
	char *cleanname, char *dataname, long *error_position)
{
	FILE *clean, *data;
	int rc;
	long pos;

	if ( !(clean = fopen(cleanname, "r+"))) syserr();
	if ( !(data = fopen(dataname, "r"))) syserr();
	rc = compare_streams(p, handler, userdata, offsets, clean, data, &pos,
			     error_position);
	if (fclose(clean) == EOF) syserr();
	if (fclose(data) == EOF) syserr();

	if (rc == -2) {
		/* an error has happened */
		int n;

		/* remove already-processed entries from the data file */
		char *tmpname = append(dataname, ".tmp");
		cp(dataname, tmpname, pos, 0);
		rename(tmpname, dataname);
		free(tmpname);

		/* flag already-processed entries in the offset table */
		for (n = 0; n < offsets->len; n++)
			if (g_array_index(offsets, long, n) < 0)
				g_array_index(offsets, long, n) = -1;
	}
	return rc;
}

static void
cleanup(int rc, char *pathname)
{
	DIR *dir;
	struct dirent *entry;
	GString *str = g_string_new(pathname);
	int len;
	struct termios term;

	/*
	 * delete temporary directory
	 */
	g_string_append(str, "/");
	len = str->len;

	if ( !(dir = opendir(pathname))) syserr();
	while ( (entry = readdir(dir)))
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")){
			g_string_truncate(str, len);
			g_string_append(str, entry->d_name);
			if (unlink(str->str) == -1) syserr();
		}
	if (closedir(dir) == -1) syserr();
	if (rmdir(pathname) == -1) syserr();
	g_string_free(str, 1);

	/*
	 * reset terminal
	 */
	if (tcgetattr(0, &term) == -1)
		/* oh, running without a terminal */
		return;
	term.c_lflag |= ICANON;
	term.c_lflag |= ECHO;
	if (tcsetattr(0, TCSANOW, &term) == -1) syserr();
}

static void
cleanup_signal(int n)
{
	fprintf(stderr, "\nCaught signal %d, exiting...\n", n);
	exit(2);
}

static int
moddn(LDAP *ld, char *old, char *new, int dor, LDAPControl **ctrls)
{
	int rc;
	char **newrdns = ldap_explode_dn(new, 0);
	char **ptr = newrdns;
	char *newrdn = *ptr++; /* non-null (checked in validate_rename) */
	GString *newsup = g_string_sized_new(strlen(new));
	if (*ptr) g_string_append(newsup, *ptr++);
	for (; *ptr; ptr++) {
		g_string_append_c(newsup, ',');
		g_string_append(newsup, *ptr);
	}
	rc = ldap_rename_s(ld, old, newrdn, newsup->str, dor, ctrls, 0);
	g_string_free(newsup, 1);
	ldap_value_free(newrdns);
	return rc;
}

struct ldapmodify_context {
	LDAP *ld;
	LDAPControl **controls;
	int verbose;
	int noquestions;
};

static int
ldapmodify_change(char *labeldn, char *dn, LDAPMod **mods, void *userdata)
{
	struct ldapmodify_context *ctx = userdata;
	LDAP *ld = ctx->ld;
	LDAPControl **ctrls = ctx->controls;
	int verbose = ctx->verbose;
	
	if (verbose) printf("(modify) %s\n", labeldn);
	if (ldap_modify_ext_s(ld, dn, mods, ctrls, 0)) {
		ldap_perror(ld, "ldap_modify");
		return -1;
	}
	return 0;
}

static int
ldapmodify_rename(char *dn1, tentry *modified, void *userdata)
{
	struct ldapmodify_context *ctx = userdata;
	LDAP *ld = ctx->ld;
	LDAPControl **ctrls = ctx->controls;
	int verbose = ctx->verbose;
	
	char *dn2 = entry_dn(modified);
	int deleteoldrdn = frob_rdn(modified, dn1, FROB_RDN_CHECK) == -1;
	if (verbose) printf("(rename) %s to %s\n", dn1, dn2);
	if (moddn(ld, dn1, dn2, deleteoldrdn, ctrls)) {
		ldap_perror(ld, "ldap_rename");
		return -1;
	}
	return 0;
}

static int
ldapmodify_add(char *dn, LDAPMod **mods, void *userdata)
{
	struct ldapmodify_context *ctx = userdata;
	LDAP *ld = ctx->ld;
	LDAPControl **ctrls = ctx->controls;
	int verbose = ctx->verbose;
	
	if (verbose) printf("(add) %s\n", dn);
	if (ldap_add_ext_s(ld, dn, mods, ctrls, 0)) {
		ldap_perror(ld, "ldap_add");
		return -1;
	}
	return 0;
}

static int
ldapmodify_delete(char *dn, void *userdata)
{
	struct ldapmodify_context *ctx = userdata;
	LDAP *ld = ctx->ld;
	LDAPControl **ctrls = ctx->controls;
	int verbose = ctx->verbose;
	
	if (verbose) printf("(delete) %s\n", dn);
	switch (ldap_delete_ext_s(ld, dn, ctrls, 0)) {
	case 0:
		break;
	case LDAP_NOT_ALLOWED_ON_NONLEAF:
		if (!ctx->noquestions)
			return -2;
		/* else fall through */
	default:
		ldap_perror(ld, "ldap_delete");
		return -1;
	}
	return 0;
}

static int
ldapmodify_rename0(char *dn1, char *dn2, int deleteoldrdn, void *userdata)
{
	struct ldapmodify_context *ctx = userdata;
	LDAP *ld = ctx->ld;
	LDAPControl **ctrls = ctx->controls;
	int verbose = ctx->verbose;

	if (verbose) printf("(rename) %s to %s\n", dn1, dn2);
	if (moddn(ld, dn1, dn2, deleteoldrdn, ctrls)) {
		ldap_perror(ld, "ldap_rename");
		return -1;
	}
	return 0;
}

static int
ldif_change(char *labeldn, char *dn, LDAPMod **mods, void *userdata)
{
	FILE *s = userdata;
	print_ldif_modify(s, dn, mods);
	return 0;
}

static int
ldif_rename(char *olddn, tentry *modified, void *userdata)
{
	FILE *s = userdata;
	int deleteoldrdn = frob_rdn(modified, olddn, FROB_RDN_CHECK) == -1;
	print_ldif_rename(
		s, olddn, entry_dn(modified),
		deleteoldrdn);
	return 0;
}

static int
ldif_add(char *dn, LDAPMod **mods, void *userdata)
{
	FILE *s = userdata;
	print_ldif_add(s, dn, mods);
	return 0;
}

static int
ldif_delete(char *dn, void *userdata)
{
	FILE *s = userdata;
	print_ldif_delete(s, dn);
	return 0;
}

static int
ldif_rename0(char *dn1, char *dn2, int deleteoldrdn, void *userdata)
{
	FILE *s = userdata;
	print_ldif_rename(s, dn1, dn2, deleteoldrdn);
	return 0;
}

static thandler ldif_handler = {
	ldif_change,
	ldif_rename,
	ldif_add,
	ldif_delete,
	ldif_rename0
};

static int
vdif_change(char *labeldn, char *dn, LDAPMod **mods, void *userdata)
{
	FILE *s = userdata;
	print_ldapvi_modify(s, dn, mods);
	return 0;
}

static int
vdif_rename(char *olddn, tentry *modified, void *userdata)
{
	FILE *s = userdata;
	int deleteoldrdn = frob_rdn(modified, olddn, FROB_RDN_CHECK) == -1;
	print_ldapvi_rename(s, olddn, entry_dn(modified), deleteoldrdn);
	return 0;
}

static int
vdif_add(char *dn, LDAPMod **mods, void *userdata)
{
	FILE *s = userdata;
	print_ldapvi_add(s, dn, mods);
	return 0;
}

static int
vdif_delete(char *dn, void *userdata)
{
	FILE *s = userdata;
	print_ldapvi_delete(s, dn);
	return 0;
}

static int
vdif_rename0(char *dn1, char *dn2, int deleteoldrdn, void *userdata)
{
	FILE *s = userdata;
	print_ldapvi_rename(s, dn1, dn2, deleteoldrdn);
	return 0;
}

struct statistics {
	int nmodify, nadd, ndelete, nrename;
};

static int
statistics_change(char *labeldn, char *dn, LDAPMod **mods, void *userdata)
{
	struct statistics *st = userdata;
	st->nmodify++;
	return 0;
}

static int
statistics_rename(char *olddn, tentry *modified, void *userdata)
{
	struct statistics *st = userdata;
	st->nrename++;
	return 0;
}

static int
statistics_add(char *dn, LDAPMod **mods, void *userdata)
{
	struct statistics *st = userdata;
	st->nadd++;
	return 0;
}

static int
statistics_delete(char *dn, void *userdata)
{
	struct statistics *st = userdata;
	st->ndelete++;
	return 0;
}

static int
statistics_rename0(char *dn1, char *dn2, int deleteoldrdn, void *userdata)
{
	struct statistics *st = userdata;
	st->nrename++;
	return 0;
}

struct rebind_data {
	char *user;
	char *password;
	LDAPURLDesc *seen;
};

static char *login(
	LDAP *ld, char *user, char *password, int register_callback);

static int
rebind_callback(
	LDAP *ld, const char *url, ber_tag_t request, int msgid, void *args)
{
	struct rebind_data *rebind_data = args;
	char *user = rebind_data->user;
	char *password = rebind_data->password;
	LDAPURLDesc *urld;
	
	printf("Received referral to %s.\n", url);

	if (ldap_url_parse(url, &urld)) {
		puts("Error: Cannot parse URL.");
		return -1;
	}
	if (rebind_data->seen
	    && !strcmp(rebind_data->seen->lud_scheme, urld->lud_scheme)
	    && !strcmp(rebind_data->seen->lud_host, urld->lud_host)
	    && rebind_data->seen->lud_port == urld->lud_port)
		/* confirmed already */
		return 0;

	printf("You are not logged in to %s://%s:%d yet.\n"
	       "Type '!' or 'y' to do so.\n",
	       urld->lud_scheme, urld->lud_host, urld->lud_port);
	for (;;) {
		switch (choose("Rebind?", "y!nqQ?", "(Type '?' for help.)")) {
		case 'y':
			user = password = 0;
			/* fall through */
		case '!':
			if (login(ld, user, password, 0)) {
				if (rebind_data->seen)
					ldap_free_urldesc(rebind_data->seen);
				rebind_data->seen = urld;
				return 0;
			}
			break;
		case 'n':
			ldap_free_urldesc(urld);
			return 0;
		case 'q':
			ldap_free_urldesc(urld);
			return -1;
		case 'Q':
			exit(0);
		case '?':
			puts("Commands:\n"
			     "  y -- ask for user name and rebind\n"
			     "  ! -- rebind using cached credentials\n"
			     "  n -- don't login, just continue\n"
			     "  q -- give up\n"
			     "  Q -- give up and exit ldapvi\n"
			     "  ? -- this help");
			break;
		}
	}
}

static char *
find_user(LDAP *ld, char *filter)
{
	char *dn = 0;
	LDAPMessage *result = 0;
	LDAPMessage *entry = 0;

	if (ldap_bind_s(ld, 0, 0, LDAP_AUTH_SIMPLE)) {
		ldap_perror(ld, "ldap_bind");
		goto cleanup;
	}
	if (ldap_search_s(ld, 0, LDAP_SCOPE_SUBTREE, filter, 0, 0, &result)) {
		ldap_perror(ld, "ldap_search");
		goto cleanup;
	}
	if ( !(entry = ldap_first_entry(ld, result))) {
		puts("User not found.");
		goto cleanup;
	}
	if (ldap_next_entry(ld, result)) {
		puts("More than one entry matched user filter.");
		goto cleanup;
	}
	dn = ldap_get_dn(ld, entry);

cleanup:
	if (result) ldap_msgfree(result);
	return dn;
}

static int
rebind(LDAP *ld, char *user, char *password, int register_callback, char **dn)
{
	int free_password = 0;
	int rc = -1;
	struct rebind_data *rebind_data = xalloc(sizeof(struct rebind_data));
	
	if (user && !password) {
		password = get_password();
		free_password = 1;
	}
	if (user && user[0] == '(') 
		/* user is a search filter, not a name */
		if ( !(user = find_user(ld, user)))
			goto cleanup;
	if (ldap_bind_s(ld, user, password, LDAP_AUTH_SIMPLE)) {
		ldap_perror(ld, "ldap_bind");
		goto cleanup;
	}
	rc = 0;
	if (dn) *dn = user;

	if (register_callback) {
		rebind_data->user = user;
		rebind_data->password = xdup(password);
		rebind_data->seen = 0;
		if (ldap_set_rebind_proc(ld, rebind_callback, rebind_data))
			ldaperr(ld, "ldap_set_rebind_proc");
	}

cleanup:
	if (free_password)
		free(password);
	return rc;
}

static LDAP *
do_connect(char *server, char *user, char *password,
	   int referrals, int starttls, int tls, int deref)
{
	LDAP *ld = 0;
	int rc = 0;
	int drei = 3;
	
	if (server && !strstr(server, "://")) {
		char *url = xalloc(strlen(server) + sizeof("ldap://"));
		strcpy(url, "ldap://");
		strcpy(url + 7, server);
		server = url;
	}
	if (ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, (void *) &tls))
		ldaperr(ld, "ldap_set_option(LDAP_OPT_X_TLS)");
	if ( rc = ldap_initialize(&ld, server)) {
		fprintf(stderr, "ldap_initialize: %s\n", ldap_err2string(rc));
		exit(1);
	}
	if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &drei))
		ldaperr(ld, "ldap_set_option(LDAP_OPT_PROTOCOL_VERSION)");
	if (starttls)
		if (ldap_start_tls_s(ld, 0, 0))
			ldaperr(ld, "ldap_start_tls_s");
	if (rebind(ld, user, password, 1, 0) == -1) {
		ldap_unbind_s(ld);
		return 0;
	}
	if (ldap_set_option(ld, LDAP_OPT_REFERRALS,
                            referrals ? LDAP_OPT_ON : LDAP_OPT_OFF))
		ldaperr(ld, "ldap_set_option(LDAP_OPT_REFERRALS)");
	if (ldap_set_option(ld, LDAP_OPT_DEREF, (void *) &deref))
		ldaperr(ld, "ldap_set_option(LDAP_OPT_DEREF)");

	return ld;
}

static char *
login(LDAP *ld, char *user, char *password, int register_callback)
{
	char *dn;
	if (!user) user = getline("Filter or DN: ")->str;
	if (rebind(ld, user, password, register_callback, &dn) == 0)
		printf("OK, bound as %s.\n", dn);
	else
		user = 0;
	return user;
}

static int
save_ldif(tparser *parser, GArray *offsets, char *clean, char *data,
	  char *server, char *user, int managedsait)
{
	int fd;
	FILE *s;

	GString *name = g_string_sized_new(300);
	g_string_append(name, ",ldapvi-");
	if (gethostname(name->str + name->len, 300 - name->len) == -1)
		syserr();
	name->len = strlen(name->str);
	g_string_sprintfa(name, "-%d.ldif", getpid());

	if ( (fd = open(name->str, O_WRONLY | O_CREAT | O_EXCL, 0600)) == -1) {
		int error = errno;
		fprintf(stderr, "Cannot save %s: ", name->str);
		errno = error;
		perror(0);
		g_string_free(name, 1);
		return 1;
	}
	if ( !(s = fdopen(fd, "w"))) syserr();

	fputs("version: 1\n", s);
	fputs("# apply these changes using ldapmodify(1) like this:\n", s);
	fputs("# ldapmodify", s);
	if (managedsait)
		fputs(" -MM", s);
	if (server) {
		fputs(" -h ", s);
		fputs(server, s);
	}
	if (user) {
		fputs(" -D ", s);
		fputs(user, s);
	}
	fputs(" -f ", s);
	fputs(name->str, s);
	fputs("\n", s);

	compare(parser, &ldif_handler, s, offsets, clean, data, 0);
	if (fclose(s) == EOF) syserr();

	printf("Your changes have been saved to %s.\n", name->str);
	return 0;
}

static void
view_ldif(tparser *parser, char *dir, GArray *offsets, char *clean, char *data)
{
	FILE *s;
	char *name = append(dir, "/ldif");
	if ( !(s = fopen(name, "w"))) syserr();
	fputs("version: 1\n", s);
	compare(parser, &ldif_handler, s, offsets, clean, data, 0);
	if (fclose(s) == EOF) syserr();
	view(name);
	free(name);
}

static void
view_vdif(tparser *parser, char *dir, GArray *offsets, char *clean, char *data)
{
	FILE *s;
	static thandler vdif_handler = {
		vdif_change,
		vdif_rename,
		vdif_add,
		vdif_delete,
		vdif_rename0
	};
	char *name = append(dir, "/vdif");

	if ( !(s = fopen(name, "w"))) syserr();
	fputs("version: ldapvi\n", s);
	compare(parser, &vdif_handler, s, offsets, clean, data, 0);
	if (fclose(s) == EOF) syserr();
	view(name);
	free(name);
}

static void
setcolor(int fg)
{
	char *bold = tigetstr("bold");
	char *setaf = tigetstr("setaf");
	if (setaf) putp(tparm(setaf, fg));
	if (bold) putp(bold);
}

static void
print_counter(int color, char *label, int value)
{
	char *sgr0 = tigetstr("sgr0");

	if (value) setcolor(color);
	printf("%s: %d", label, value);
	if (sgr0) putp(sgr0);
}

/* collect statistics.  This comparison step is important
 * for catching syntax errors before real processing starts.
 */
static int
analyze_changes(tparser *p, GArray *offsets, char *clean, char *data)
{
	struct statistics st;
	static thandler statistics_handler = {
		statistics_change,
		statistics_rename,
		statistics_add,
		statistics_delete,
		statistics_rename0
	};
	int rc;
	long pos;

retry:
	memset(&st, 0, sizeof(st));
	rc = compare(p, &statistics_handler, &st, offsets, clean, data, &pos);

	/* Success? */
	if (rc == 0) {
		if (!(st.nadd + st.ndelete + st.nmodify + st.nrename)) {
			puts("No changes.");
			return 0;
		}
		print_counter(COLOR_GREEN, "add", st.nadd);
		fputs(", ", stdout);
		print_counter(COLOR_BLUE, "rename", st.nrename);
		fputs(", ", stdout);
		print_counter(COLOR_YELLOW, "modify", st.nmodify);
		fputs(", ", stdout);
		print_counter(COLOR_RED, "delete", st.ndelete);
		putchar('\n');
		return 1;
	}

	/* Syntax error */
	for (;;) {
		switch (choose("What now?", "eQ?", "(Type '?' for help.)")) {
		case 'e':
			edit_pos(data, pos);
			goto retry;
		case 'Q':
			exit(0);
		case '?':
			puts("Commands:\n"
			     "  Q -- discard changes and quit\n"
			     "  e -- open editor again\n"
			     "  ? -- this help");
			break;
		}
	}
}

static void
commit(tparser *p, LDAP *ld, GArray *offsets, char *clean, char *data,
       LDAPControl **ctrls, int verbose, int noquestions)
{
	struct ldapmodify_context ctx;
	static thandler ldapmodify_handler = {
		ldapmodify_change,
		ldapmodify_rename,
		ldapmodify_add,
		ldapmodify_delete,
		ldapmodify_rename0
	};
	ctx.ld = ld;
	ctx.controls = ctrls;
	ctx.verbose = verbose;
	ctx.noquestions = noquestions;
	
	switch (compare(p, &ldapmodify_handler, &ctx, offsets, clean, data, 0))
	{
	case 0:
		puts("Done.");
		exit(0);
	case -1:
		yourfault("unexpected syntax error!");
	case -2:
		/* user error */
		break;
	default:
		abort();
	}
}

static int
getty(int fd)
{
	if (close(fd) == -1)
		syserr();
	if (open("/dev/tty", O_RDWR) != fd)
		return -1;
	return 0;
}

static int
fixup_streams(FILE **source, FILE **target)
{
	int rc = 0;

	/* find a terminal and restore fds 0, 1 to a sensible value for
	 * reading the password.  Save the original streams for later use.*/

	if (!isatty(0)) {
		/* user has redirected stdout */
		int in = dup(fileno(stdout));
		if (in == -1) syserr();
		*source = fdopen(in, "r");
		if (getty(0) == -1) rc = -1;
	}
	if (!isatty(1)) {
		/* user has redirected stdout */
		int out = dup(fileno(stdout));
		if (out == -1) syserr();
		*target = fdopen(out, "w");
		if (getty(1) == -1) rc = -1;
	}
	return rc;
}

static int
ndecimalp(char *str)
{
	char *ptr;
	strtol(str, &ptr, 10);
	return !*ptr;
}

void
skip(tparser *p, char *dataname, GArray *offsets)
{
	long pos;
	char *key;
	char *tmpname = append(dataname, ".tmp");
	FILE *s;

	if ( !(s = fopen(dataname, "r"))) syserr();
	p->skip(s, 0, &key);
	if ( (pos = ftell(s)) == -1) syserr();
	if (fclose(s) == EOF) syserr();

	if (key) {
		/* remove from datafile */
		cp(dataname, tmpname, pos, 0);
		rename(tmpname, dataname);
		free(tmpname);

		if (ndecimalp(key))
			g_array_index(offsets, long, atoi(key)) = -1;
		free(key);
	} else {
                /* Im Normalfall wollen wir einen Eintrag in data
                 * ueberspringen.  Wenn aber in data nichts mehr steht,
                 * sind wir ueber die eigentlichen Aenderungen schon
                 * hinweg und es handelt sich um eine Loeschung.  In
                 * diesem Fall muessen wir nur das Offset aus der
                 * Tabelle entfernen. */
                int n;
                for (n = 0; n < offsets->len; n++)
                        if (g_array_index(offsets, long, n) >= 0) {
                                g_array_remove_index(offsets, n);
				break;
			}
	}
}

static void
append_sort_control(LDAP *ld, GPtrArray *ctrls, char *keystring)
{
	LDAPControl *ctrl;
	LDAPSortKey **keylist;

	if (ldap_create_sort_keylist(&keylist, keystring))
		ldaperr(ld, "ldap_create_sort_keylist");
	if (ldap_create_sort_control(ld, keylist, 1, &ctrl))
		ldaperr(ld, "ldap_create_sort_keylist");
	g_ptr_array_add(ctrls, ctrl);
}

static GArray *
read_offsets(tparser *p, char *file)
{
	GArray *offsets = g_array_new(0, 0, sizeof(long));
	FILE *s;
	
	if ( !(s = fopen(file, "r"))) syserr();
	for (;;) {
		long offset;
		char *key, *ptr;
		int n;
		tentry *entry;

		key = 0;
		if (p->entry(s, -1, &key, &entry, &offset) == -1) exit(1);
		if (!key) break;

		n = strtol(key, &ptr, 10);
		if (*ptr) {
			fprintf(stderr, "Error: Invalid key: `%s'.\n", key);
			exit(1);
		}
		if (n != offsets->len) {
			fprintf(stderr, "Error: Unexpected key: `%s'.\n", key);
			exit(1);
		}
		free(key);
		entry_free(entry);
		g_array_append_val(offsets, offset);
	}
	if (fclose(s) == -1) syserr();

	return offsets;
}

static void
offline_diff(tparser *p, char *a, char *b)
{
	GArray *offsets = read_offsets(p, a);
	compare(p, &ldif_handler, stdout, offsets, a, b, 0);
	g_array_free(offsets, 1);
}

void
write_config(LDAP *ld, FILE *f, cmdline *cmdline)
{
	char *user = cmdline->user;
	char *server = cmdline->server;
	int limit;

	if (!f) f = stdout;
	fputs("# ldap.conf(5)\n", f);
	fputs("# edit this as needed and paste into ~/.ldaprc\n", f);

	/* URI/HOST */
	fputc('\n', f);
	fputs("# server name\n", f);
	fputs("# (for parameterless operation, make sure to include at"
	      " least this line)\n",
	      f);
	if (!server) 
		ldap_get_option(ld, LDAP_OPT_URI, &server);
	if (!server) 
		ldap_get_option(ld, LDAP_OPT_HOST_NAME, &server);
	if (server)
		if (strstr(server, "://"))
			fprintf(f, "URI %s\n", server);
		else
			fprintf(f, "HOST %s\n", server);

	/* BASE */
	fputc('\n', f);
	fputs("# default search base\n", f);
	if (cmdline->basedns->len) {
		GPtrArray *basedns = cmdline->basedns;
		int i;
		if (basedns->len > 1)
			fputs("### multiple namingcontexts found (uncomment"
			      " one of these lines):\n",
			      f);
		for (i = 0; i < basedns->len; i++) {
			if (basedns->len > 1) fputc('#', f);
			fprintf(f, "BASE %s\n", g_ptr_array_index(basedns, i));
		}
	} else {
		if (!cmdline->discover)
			fputs("### no search base specified, retry with"
			      " --discover?\n",
			      f);
		fputs("#BASE <dn>\n", f);
	}
	
	/* BINDDN */
	fputc('\n', f);
	fputs("# user to bind as\n", f);
	if (user && user[0] == '(')
		user = find_user(ld, user);
	if (user)
		fprintf(f, "BINDDN %s\n", user);
	else
		fputs("#BINDDN <dn>\n", f);
	
	/* search options */
	fputc('\n', f);
	fputs("# search parameters (uncomment as needed)\n", f);
	switch (cmdline->deref) {
	case LDAP_DEREF_NEVER:
		fputs("#DEREF never\n", f);
		break;
	case LDAP_DEREF_SEARCHING:
		fputs("#DEREF searcing\n", f);
		break;
	case LDAP_DEREF_FINDING:
		fputs("#DEREF finding\n", f);
		break;
	case LDAP_DEREF_ALWAYS:
		fputs("#DEREF always\n", f);
		break;
	}
	ldap_get_option(ld, LDAP_OPT_SIZELIMIT, &limit);
	fprintf(f, "#SIZELIMIT %d\n", limit);
	ldap_get_option(ld, LDAP_OPT_TIMELIMIT, &limit);
	fprintf(f, "#TIMELIMIT %d\n", limit);
}

static struct ldap_objectclass *
get_objectclass(GPtrArray *classes, char *name)
{
	int i;
	char **ptr;
	for (i = 0; i < classes->len; i++) {
		struct ldap_objectclass *cls = g_ptr_array_index(classes, i);
		if (!strcmp(cls->oc_oid, name))
			return cls;
		for (ptr = cls->oc_names; ptr && *ptr; ptr++)
			if (!strcasecmp(*ptr, name))
				return cls;
	}
	fprintf(stderr, "Error: Object class not found: %s\n", name);
	exit(1);
}

static struct ldap_attributetype *
get_attributetype(GPtrArray *types, char *name)
{
	int i;
	char **ptr;
	for (i = 0; i < types->len; i++) {
		struct ldap_attributetype *cls = g_ptr_array_index(types, i);
		if (!strcmp(cls->at_oid, name))
			return cls;
		for (ptr = cls->at_names; ptr && *ptr; ptr++)
			if (!strcasecmp(*ptr, name))
				return cls;
	}
	fprintf(stderr, "Error: Attribute type not found: %s\n", name);
	exit(1);
}

static char *
class_name(struct ldap_objectclass *cls)
{
	char **names = cls->oc_names;
	if (names && *names)
		return *names;
	return cls->oc_oid;
}

static char *
type_name(struct ldap_attributetype *at)
{
	char **names = at->at_names;
	if (names && *names)
		return *names;
	return at->at_oid;
}

static void
add_changerecord(FILE *s, cmdline *cmdline)
{
	switch (cmdline->mode) {
	case ldapvi_mode_delete: {
		char **ptr;
		for (ptr = cmdline->delete_dns; *ptr; ptr++)
			if (cmdline->ldif)
				print_ldif_delete(s, *ptr);
			else
				print_ldapvi_delete(s, *ptr);
		break;
	}
	case ldapvi_mode_rename:
		if (cmdline->ldif)
			print_ldif_rename(s,
					  cmdline->rename_old,
					  cmdline->rename_new,
					  cmdline->rename_dor);
		else
			print_ldapvi_rename(s,
					    cmdline->rename_old,
					    cmdline->rename_new,
					    cmdline->rename_dor);
		break;
	case ldapvi_mode_modrdn:
		if (cmdline->ldif)
			print_ldif_modrdn(s,
					  cmdline->rename_old,
					  cmdline->rename_new,
					  cmdline->rename_dor);
		else
			print_ldapvi_modrdn(s,
					    cmdline->rename_old,
					    cmdline->rename_new,
					    cmdline->rename_dor);
		break;
	default:
		abort();
	}
}

static void
add_template(LDAP *ld,  FILE *s, GPtrArray *wanted, char *base)
{
	int i, j;
	GPtrArray *classes = g_ptr_array_new();
	GPtrArray *types = g_ptr_array_new();
	GPtrArray *must = g_ptr_array_new();
	GPtrArray *may = g_ptr_array_new();
	char **ptr;
	struct ldap_objectclass *cls;
	struct ldap_attributetype *at;
	struct ldap_objectclass *structural = 0;
	
	get_schema(ld, classes, types);
	fputc('\n', s);

	/* normalize "wanted" to oids */
	for (i = 0; i < wanted->len; i++) {
		char *name = g_ptr_array_index(wanted, i);
		cls = get_objectclass(classes, name);
		g_ptr_array_index(wanted, i) = cls->oc_oid;
		if (cls->oc_kind == LDAP_SCHEMA_ABSTRACT)
			fprintf(s, "### NOTE: objectclass is abstract: %s\n",
				name);
	}
	/* add all superclasses */
	for (i = 0; i < wanted->len; i++) {
		cls = get_objectclass(classes, g_ptr_array_index(wanted, i));
		for (ptr = cls->oc_sup_oids; ptr && *ptr; ptr++)
			adjoin_str(wanted, *ptr);
		if (cls->oc_kind == LDAP_SCHEMA_STRUCTURAL)
			if (structural)
				fprintf(s,
					"### WARNING: extra structural object class: %s\n",
					class_name(cls));
			else {
				fprintf(s,
					"# structural object class: %s\n",
					class_name(cls));
				structural = cls;
			}
		for (ptr = cls->oc_at_oids_must; ptr && *ptr; ptr++) {
			at = get_attributetype(types, *ptr);
			g_ptr_array_remove(may, at);
			for (j = 0; j < must->len; j++)
				if (at == g_ptr_array_index(must, j))
					break;
			if (j >= must->len) g_ptr_array_add(must, at);
		}
		for (ptr = cls->oc_at_oids_may; ptr && *ptr; ptr++) {
			at = get_attributetype(types, *ptr);
			for (j = 0; j < must->len; j++)
				if (at == g_ptr_array_index(must, j))
					break;
			if (j >= must->len) g_ptr_array_add(may, at);
		}
	}
	if (!structural)
		fputs("### WARNING: no structural object class specified!\n",
		      s);

	fprintf(s, "add %s\n", base ? base : "<DN>");
	for (i = 0; i < wanted->len; i++) {
		cls = get_objectclass(classes, g_ptr_array_index(wanted, i));
		fprintf(s, "objectClass: %s\n", class_name(cls));
	}
	for (i = 0; i < must->len; i++) {
		at = g_ptr_array_index(must, i);
		if (strcmp(at->at_oid, "2.5.4.0"))
			fprintf(s, "%s: \n", type_name(at));
	}
	for (i = 0; i < may->len; i++) {
		at = g_ptr_array_index(may, i);
		if (strcmp(at->at_oid, "2.5.4.0"))
			fprintf(s, "#%s: \n", type_name(at));
	}
}

int
main(int argc, const char **argv)
{
	LDAP *ld;
	cmdline cmdline;
	GPtrArray *ctrls = g_ptr_array_new();
	static char dir[] = "/tmp/ldapvi-XXXXXX";
	char *clean;
	char *data;
	GArray *offsets;
	int changed;
	FILE *s;
	FILE *source_stream = 0;
	FILE *target_stream = 0;
	tparser *parser;
	int nlines;

	cmdline.server = 0;
	cmdline.basedns = g_ptr_array_new();
	cmdline.scope = LDAP_SCOPE_SUBTREE;
	cmdline.filter = 0;
	cmdline.attrs = 0;
	cmdline.user = 0;
	cmdline.password = 0;
	cmdline.progress = 1;
	cmdline.referrals = 1;
	cmdline.add = 0;
	cmdline.managedsait = 0;
	cmdline.sortkeys = 0;
	cmdline.starttls = 0;
	cmdline.tls = LDAP_OPT_X_TLS_TRY;
	cmdline.deref = LDAP_DEREF_NEVER;
	cmdline.verbose = 0;
	cmdline.noquestions = 0;
	cmdline.noninteractive = 0;
	cmdline.discover = 0;
	cmdline.config = 0;
	cmdline.ldif = 0;
	cmdline.ldapvi = 0;
	cmdline.mode = ldapvi_mode_edit;
	cmdline.rename_dor = 0;

	if (argc >= 2 && !strcmp(argv[1], "--diff")) {
		if (argc != 4) {
			fputs("wrong number of arguments to --diff\n", stderr);
			usage(2, 1);
		}
		offline_diff(&ldapvi_parser,
			     (char *) argv[2],
			     (char *) argv[3]);
		exit(0);
	}

	parse_arguments(argc, argv, &cmdline, ctrls);
	if (fixup_streams(&source_stream, &target_stream) == -1)
		cmdline.noninteractive = 1;
	if (cmdline.noninteractive) {
		cmdline.noquestions = 1;
		cmdline.progress = 0;
	}
	if (cmdline.ldif)
		parser = &ldif_parser;
	else
		parser = &ldapvi_parser;
	read_ldapvi_history();

	ld = do_connect(cmdline.server,
			cmdline.user,
			cmdline.password,
			cmdline.referrals,
			cmdline.starttls,
			cmdline.tls,
			cmdline.deref);
	if (!ld) exit(1);
	setupterm(0, 1, 0);

	if (cmdline.sortkeys)
		append_sort_control(ld, ctrls, cmdline.sortkeys);
	g_ptr_array_add(ctrls, 0);

	if (cmdline.discover) {
		if (cmdline.basedns->len > 0)
			yourfault("Conflicting options given:"
				  " --base and --discover.");
		discover_naming_contexts(ld, cmdline.basedns);
	}

	if (cmdline.config) {
		write_config(ld, target_stream, &cmdline);
		exit(0);
	}

	if (cmdline.mode == ldapvi_mode_out
	    || (cmdline.mode == ldapvi_mode_edit && target_stream))
	{
		if (cmdline.add)
			yourfault("Cannot --add entries noninteractively.");
		if (!target_stream)
			target_stream = stdout;
		search(target_stream, ld, &cmdline, (void *) ctrls->pdata, 1,
		       cmdline.mode == ldapvi_mode_out
		       ? !cmdline.ldapvi
		       : cmdline.ldif);
		exit(0);
	}

	mkdtemp(dir);
	on_exit((on_exit_function) cleanup, dir);
	signal(SIGTERM, cleanup_signal);
	signal(SIGINT, cleanup_signal);
	signal(SIGPIPE, SIG_IGN);
	clean = append(dir, "/clean");
	data = append(dir, "/data");

	if ( !(s = fopen(data, "w"))) syserr();
	nlines = 1;
	if (print_binary_mode == PRINT_UTF8 && !cmdline.ldif) {
		fputs("# -*- coding: utf-8 -*- vim:encoding=utf-8:\n", s);
		nlines++;
	}
	if (cmdline.ldif) {
		fputs("# http://www.rfc-editor.org/rfc/rfc2849.txt\n"
		      "# http://www.lichteblau.com/ldapvi/manual/manual.xml#syntax-ldif\n",
		      s);
		nlines += 2;
	} else  {
		fputs("# http://www.lichteblau.com/ldapvi/manual/manual.xml#syntax\n",
		      s);
		nlines++;
	}
	if (cmdline.add || cmdline.mode != ldapvi_mode_edit) {
		if (!cmdline.add)
			add_changerecord(s, &cmdline);
		else if (cmdline.add->len) {
			char *base = 0;
			if (cmdline.basedns->len > 0)
				base = g_ptr_array_index(cmdline.basedns, 0);
			add_template(ld, s, cmdline.add, base);
		} else
			fputc('\n', s);
		if (fclose(s) == EOF) syserr();
		cp("/dev/null", clean, 0, 0);
		offsets = g_array_new(0, 0, sizeof(long));
	} else {
		offsets = search(s, ld, &cmdline, (void *) ctrls->pdata, 0,
				 cmdline.ldif);
		if (fclose(s) == EOF) syserr();
		cp(data, clean, 0, 0);
	}
	if (!cmdline.noninteractive)
		edit(data, nlines);
	else if (cmdline.mode == ldapvi_mode_edit)
		yourfault("Cannot edit entries noninteractively.");

	if (cmdline.noquestions) {
		if (!analyze_changes(parser, offsets, clean, data)) return 0;
		commit(parser, ld, offsets, clean, data, (void *) ctrls->pdata,
		       cmdline.verbose, 1);
		return 1;
	}

	changed = 1;
	for (;;) {
		if (changed)
			if (!analyze_changes(parser, offsets, clean, data))
				return 0;
		changed = 0;
		switch (choose("Action?", "yqQvVebrs?", "(Type '?' for help.)")) {
		case 'y':
			commit(parser, ld, offsets, clean, data,
			       (void *) ctrls->pdata, cmdline.verbose, 0);
			changed = 1;
			break; /* reached only on user error */
		case 'q':
			if (save_ldif(parser,
				      offsets, clean, data,
				      cmdline.server,
				      cmdline.user,
				      cmdline.managedsait))
				break;
			write_ldapvi_history();
			return 0;
		case 'Q':
			write_ldapvi_history();
			return 0;
		case 'v':
			view_ldif(parser, dir, offsets, clean, data);
			break;
		case 'V':
			view_vdif(parser, dir, offsets, clean, data);
			break;
		case 'e':
			edit(data, 0);
			changed = 1;
			break;
		case 'b':
			cmdline.user = login(ld, 0, 0, 1);
			changed = 1; /* print stats again */
			break;
		case 'r':
			ldap_unbind_s(ld);
			ld = do_connect(
				cmdline.server,
				cmdline.user,
				cmdline.password,
				cmdline.referrals,
				cmdline.starttls,
				cmdline.tls,
				cmdline.deref);
			printf("Connected to %s.\n", cmdline.server);
			changed = 1; /* print stats again */
			break;
		case 's':
			skip(parser, data, offsets);
			changed = 1;
			break;
		case '?':
			puts("Commands:\n"
			     "  y -- commit changes\n"
			     "  q -- save changes as LDIF and quit\n"
			     "  Q -- discard changes and quit\n"
			     "  v -- view changes as LDIF change records\n"
			     "  V -- view changes as ldapvi change records\n"
			     "  e -- open editor again\n"
			     "  b -- ask for user name and rebind\n"
			     "  r -- reconnect to server\n"
			     "  s -- skip one entry\n"
			     "  ? -- this help");
			break;
		}
	}
}
