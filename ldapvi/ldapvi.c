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
#include <signal.h>
#include <term.h>
#include "common.h"

static int
compare(int (*handler)(tentry *, tentry *, LDAPMod **, void *),
	void *userdata,
	GArray *offsets, char *cleanname, char *dataname)
{
	FILE *clean, *data;
	int rc;
	long pos;

	if ( !(clean = fopen(cleanname, "r+"))) syserr();
	if ( !(data = fopen(dataname, "r"))) syserr();
	rc = compare_streams(handler, userdata, offsets, clean, data, &pos);
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
	if (tcgetattr(0, &term) == -1) syserr();
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
};

static int
ldapmodify_handler(tentry *clean, tentry *modified, LDAPMod **mods,
		   void *userdata)
{
	struct ldapmodify_context *ctx = userdata;
	LDAP *ld = ctx->ld;
	LDAPControl **ctrls = ctx->controls;
	int verbose = ctx->verbose;
	
	if (clean && modified) {
		char *dn1 = entry_dn(clean);
		char *dn2 = entry_dn(modified);
		if (mods) {
			if (verbose) printf("(modify) %s\n", dn1);
			if (ldap_modify_ext_s(ld, dn2, mods, ctrls, 0)) {
				ldap_perror(ld, "ldap_modify");
				return -1;
			}
		} else {
			int deleteoldrdn =
				frob_rdn(modified, dn1, FROB_RDN_CHECK) == -1;
			if (verbose) printf("(rename) %s to %s\n", dn1, dn2);
			if (moddn(ld, dn1, dn2, deleteoldrdn, ctrls)) {
				ldap_perror(ld, "ldap_rename");
				return -1;
			}
		}
	} else if (modified) {
		if (verbose) printf("(add) %s\n", entry_dn(modified));
		if (ldap_add_ext_s(ld, entry_dn(modified), mods, ctrls, 0)) {
			ldap_perror(ld, "ldap_add");
			return -1;
		}
	} else if (clean) {
		if (verbose) printf("(delete) %s\n", entry_dn(clean));
		switch (ldap_delete_ext_s(ld, entry_dn(clean), ctrls, 0)) {
		case 0:
			break;
		case LDAP_NOT_ALLOWED_ON_NONLEAF:
			return -2;
		default:
			ldap_perror(ld, "ldap_delete");
			return -1;
		}
	} else
		abort();
	return 0;
}

static int
ldif_handler(tentry *clean, tentry *modified, LDAPMod **mods, void *userdata)
{
	FILE *s = userdata;
	if (clean && modified) {
		if (mods)
			print_ldif_modify(s, entry_dn(modified), mods);
		else {
			char *dn1 = entry_dn(clean);
			int deleteoldrdn =
				frob_rdn(modified, dn1, FROB_RDN_CHECK) == -1;
			print_ldif_rename(
				s, entry_dn(clean), entry_dn(modified),
				deleteoldrdn);
		}
	} else if (modified)
		print_ldif_add(s, entry_dn(modified), mods);
	else if (clean)
		print_ldif_delete(s, entry_dn(clean));
	else
		abort();
	return 0;
}

struct statistics {
	int nmodify, nadd, ndelete, nrename;
};

static int
statistics_handler(tentry *clean, tentry *modified, LDAPMod **mods,
		   void *userdata)
{
	struct statistics *st = userdata;

	if (clean && modified) {
		if (mods)
			st->nmodify++;
		else
			st->nrename++;
	} else if (modified)
		st->nadd++;
	else if (clean)
		st->ndelete++;
	else
		abort();
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
	   int referrals, int starttls, int deref)
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
save_ldif(GArray *offsets, char *clean, char *data,
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

	compare(ldif_handler, s, offsets, clean, data);
	if (fclose(s) == EOF) syserr();

	printf("Your changes have been saved to %s.\n", name->str);
	return 0;
}

static void
view_ldif(char *dir, GArray *offsets, char *clean, char *data)
{
	FILE *s;
	char *name = append(dir, "/ldif");
	if ( !(s = fopen(name, "w"))) syserr();
	fputs("version: 1\n", s);
	compare(ldif_handler, s, offsets, clean, data);
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
analyze_changes(GArray *offsets, char *clean, char *data)
{
	struct statistics st;
	int rc;

retry:
	memset(&st, 0, sizeof(st));
	rc = compare(statistics_handler, &st, offsets, clean, data);

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
			edit(data);
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
commit(LDAP *ld, GArray *offsets, char *clean, char *data, LDAPControl **ctrls,
       int verbose)
{
	struct ldapmodify_context ctx;
	ctx.ld = ld;
	ctx.controls = ctrls;
	ctx.verbose = verbose;
	
	switch (compare(ldapmodify_handler, &ctx, offsets, clean, data)) {
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

FILE *
fixup_streams()
{
	FILE *target_stream = 0;
	
	if (!isatty(0)) yourfault("Error: Standard input is not a terminal.");
	if (!isatty(1)) {
		/* clever user has redirected stdout */

		/* record current stdout */
		int out = dup(fileno(stdout));
		if (out == -1) syserr();
		target_stream = fdopen(out, "w");
		if (close(1) == -1) syserr();

		/* find a terminal and restore fd 1 to a sensible value
		 * for reading the password */
		if ( (out = open("/dev/tty", O_RDWR)) != 1)
			yourfault("Error: Sorry, cannot find a terminal.");
	}
	return target_stream;
}

void
skip(char *dataname, GArray *offsets)
{
	long pos;
	char *key;
	char *tmpname = append(dataname, ".tmp");

	/* find file position right after entry */
	tentry *entry;
	FILE *s = fopen(dataname, "r");
	if (!s) syserr();
	read_entry(s, 0, &key, &entry, 0);
        if (!entry) {
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
                if (fclose(s) == EOF) syserr();
                return;
        }
	entry_free(entry);
	if ( (pos = ftell(s)) == -1) syserr();
	if (fclose(s) == EOF) syserr();

	/* remove from datafile */
	cp(dataname, tmpname, pos, 0);
	rename(tmpname, dataname);
	free(tmpname);

	/* remove entry from offsets table */
	if (strcmp(key, "add"))
		g_array_index(offsets, long, atoi(key)) = -1;
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
read_offsets(char *file)
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
		if (read_entry(s, -1, &key, &entry, &offset) == -1) exit(1);
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
offline_diff(char *a, char *b)
{
	GArray *offsets = read_offsets(a);
	compare(ldif_handler, stdout, offsets, a, b);
	g_array_free(offsets, 1);
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
	FILE *target_stream;

	cmdline.server = 0;
	cmdline.base = 0;
	cmdline.scope = LDAP_SCOPE_SUBTREE;
	cmdline.filter = "(objectclass=*)";
	cmdline.attrs = 0;
	cmdline.user = 0;
	cmdline.password = 0;
	cmdline.progress = 1;
	cmdline.referrals = 1;
	cmdline.add = 0;
	cmdline.managedsait = 0;
	cmdline.sortkeys = 0;
	cmdline.starttls = 0;
	cmdline.deref = LDAP_DEREF_NEVER;
	cmdline.verbose = 0;
	cmdline.noquestions = 0;

	if (argc >= 2 && !strcmp(argv[1], "--diff")) {
		if (argc != 4) {
			fputs("wrong number of arguments to --diff\n", stderr);
			usage(2, 1);
		}
		offline_diff((char *) argv[2], (char *) argv[3]);
		exit(0);
	}

	parse_arguments(argc, argv, &cmdline, ctrls);
	target_stream = fixup_streams();

	ld = do_connect(cmdline.server,
			cmdline.user,
			cmdline.password,
			cmdline.referrals,
			cmdline.starttls,
			cmdline.deref);
	if (!ld) exit(1);
	setupterm(0, 1, 0);

	if (cmdline.sortkeys)
		append_sort_control(ld, ctrls, cmdline.sortkeys);
	g_ptr_array_add(ctrls, 0);
	if (target_stream) {
		if (cmdline.add)
			yourfault("Cannot --add entries noninteractively.");
		search(target_stream,
		       ld,
		       cmdline.base,
		       cmdline.scope,
		       cmdline.filter,
		       cmdline.attrs,
		       (void *) ctrls->pdata,
		       cmdline.progress,
		       1);
		exit(0);
	}

	mkdtemp(dir);
	on_exit((on_exit_function) cleanup, dir);
	signal(SIGTERM, cleanup_signal);
	signal(SIGINT, cleanup_signal);
	signal(SIGPIPE, SIG_IGN);
	clean = append(dir, "/clean");
	data = append(dir, "/data");
	
	if ( !(s = fopen(clean, "w"))) syserr();
	fputs("# ldapvi(1)\n", s);
	if (cmdline.add)
		offsets = g_array_new(0, 0, sizeof(long));
	else
		offsets = search(s,
				 ld,
				 cmdline.base,
				 cmdline.scope,
				 cmdline.filter,
				 cmdline.attrs,
				 (void *) ctrls->pdata,
				 cmdline.progress,
				 cmdline.noquestions);
	if (fclose(s) == EOF) syserr();
	cp(clean, data, 0, 0);
	edit(data);

	if (cmdline.noquestions) {
		if (!analyze_changes(offsets, clean, data)) return 0;
		commit(ld, offsets, clean, data, (void *) ctrls->pdata,
		       cmdline.verbose);
		return 1;
	}

	changed = 1;
	for (;;) {
		if (changed)
			if (!analyze_changes(offsets, clean, data)) return 0;
		changed = 0;
		switch (choose("Action?", "yqQvebrs?", "(Type '?' for help.)")) {
		case 'y':
			commit(ld, offsets, clean, data, (void *) ctrls->pdata,
			       cmdline.verbose);
			changed = 1;
			break; /* reached only on user error */
		case 'q':
			if (save_ldif(offsets, clean, data,
				      cmdline.server,
				      cmdline.user,
				      cmdline.managedsait))
				break;
			return 0;
		case 'Q':
			return 0;
		case 'v':
			view_ldif(dir, offsets, clean, data);
			break;
		case 'e':
			edit(data);
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
				cmdline.deref);
			printf("Connected to %s.\n", cmdline.server);
			changed = 1; /* print stats again */
			break;
		case 's':
			skip(data, offsets);
			changed = 1;
			break;
		case '?':
			puts("Commands:\n"
			     "  y -- commit changes\n"
			     "  q -- save changes as LDIF and quit\n"
			     "  Q -- discard changes and quit\n"
			     "  v -- view changes as LDIF\n"
			     "  e -- open editor again\n"
			     "  b -- ask for user name and rebind\n"
			     "  r -- reconnect to server\n"
			     "  s -- skip one entry\n"
			     "  ? -- this help");
			break;
		}
	}
}
