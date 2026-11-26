# Kerberos

KLLDAP runs a Kerberos KDC inside the `lldap` process, on its own threads, and
keeps it in step with the user database. Nothing Kerberos-specific has to be
configured for the common case: the realm comes from the base DN, the database
is created on first start, and principals follow the users.

## Realm

The realm is the base DN's `dc` components, joined and uppercased: `dc=example,dc=com`
gives realm `EXAMPLE.COM` and domain `example.com`. `kerberos_options.realm`
(`LLDAP_KERBEROS_OPTIONS__REALM`) overrides the realm. Principals are `<user id>@REALM`.

## Bootstrap

There is no `kerberos_manager`, and no separate `krb5kdc` or `kadmind` process.
When `kerberos_options.enabled` is true, the server opens the realm itself:

1. creates `data_dir` (default `krb5kdc`) at mode 0700 and opens or
   creates the database (`principal`) and the stash (`.k5.<REALM>`). The master
   key is random and lives only in the stash. A directory that already exists
   with a looser mode is tightened to 0700 when this process owns it; otherwise
   the server warns and continues,
2. writes `admin/admin@REALM` to `admin_keytab` (default `kadm5.keytab`) at
   mode 0600, owned by the service user, on every boot,
3. writes the client `krb5.conf` to `client_config` (default `krb5.conf`),
4. binds the KDC on UDP and TCP at `kdc_host`:`kdc_port` (default `0.0.0.0:1088`) and
   kadmin at `kadmin_host`:`kadmin_port` (default `127.0.0.1:1749`), then serves them on the threads
   `krb5-kdc` and `krb5-kadmind`.

`/data/kerberos_config.toml` is gone. The realm settings are `[kerberos_options]`.

Keep `/data/kadm5.keytab` out of any backup that is not secured as tightly as
the machine itself. It is rewritten at every boot, and it is the admin
credential for the realm.

**If either Kerberos thread dies, the process exits non-zero. Without a restart
policy, the container stays down.**

### When the realm cannot open

If Kerberos is enabled and the realm does not
open at startup (for example, the KDC port is taken, or the realm's database or
directory cannot be read), the server starts without the realm instead of
exiting. So it does when the realm opens but reconciling its principals or its
start pass fails: the server then still holds the realm (no other server takes
it over until this one stops), and its KDC and kadmin do not serve.
`kerberos_options.on_realm_failure`
(`LLDAP_KERBEROS_OPTIONS__ON_REALM_FAILURE`) says what such a server goes on
serving: `directory-only`, the default, or `admin-only`. Any other value
refuses the start.

**The default changed in 0.8.2. Until 0.8.1 a server whose realm did not open
listened on loopback only and let in only members of `lldap_admin`. From 0.8.2
it serves the directory to every user, as configured, with Kerberos closed.**
To keep the old behaviour, set `on_realm_failure = "admin-only"` before the
first 0.8.2 start. See
[Upgrading from KLLDAP 0.8.1](install.md#upgrading-from-klldap-081).

Neither state is entered by a running server. A server that loses its realm
while it runs exits, as before, and so does one that finds the realm lost
before its KDC starts; the restart then comes up as described here.

#### directory-only

The server holds the realm's row in the database, so no other server opens
the realm beside it, and it serves the directory with Kerberos closed:

- LDAP, LDAPS and the web interface listen as configured. The KDC and kadmin
  do not answer.
- Every user binds and signs in. Every policy is judged as always.
- A change that touches no principal is made as usual: creating, changing and
  deleting a user without `kerberosSync`, that user's password, groups,
  memberships, OUs, policies, the schema, unlock and re-enable, two-factor
  enrolment.
- A change that needs a principal is refused, and nothing is written or
  queued: a password change of a user with `kerberosSync` at every door,
  creating a user with `kerberosSync`, and turning `kerberosSync` on or off.
  The answer is LDAP result 52 (unavailable), HTTP 503, or a GraphQL error,
  with one text: "Kerberos KDC unavailable: `<class>`; the change will be
  possible when this server's realm opens", where `<class>` is the kind of
  cause (see [Health](#health)), for example "Kerberos KDC unavailable: the
  realm's records did not open; the change will be possible when this
  server's realm opens". It names no file and no count. The refusal's log row
  keeps the full cause. The Keycloak keytab export is refused too, and answers
  the admin with the cause.
- Deleting a user with `kerberosSync` needs a confirmation, because its
  principal cannot go with it. An LDAP Delete of such a user is refused, and so
  is a GraphQL `deleteUser` without `confirmUserId`: the text above, then "or
  delete the user now and leave its Kerberos principal until then: confirm the
  delete on the web page, or give deleteUser a confirmUserId equal to userId".
  `deleteUser(userId: "bob", confirmUserId: "bob")` deletes the user and
  answers, in `warnings`, "the user's Kerberos principal stays until this
  server's realm opens, which removes it before the KDC serves". The users
  page asks for the name of each such user in turn. The two names compare as
  user ids do, in any case. A confirmation that names another user, or one
  for a user who has no `kerberosSync` now (it was re-created or changed after
  the page read it), is refused and deletes nothing. Outside directory-only
  `confirmUserId` changes nothing but the check that it names the user.
- A confirmed delete marks the principal in the table `kerberos_delete_marks`
  (its name and the time), in the delete's own transaction, and writes one
  `kerberos_sync` row. At the realm's next opening the start pass removes each
  marked principal before the KDC serves, whatever user of that name exists
  by then, and clears its mark in the same commit; a user of that name with
  `kerberosSync` gets a new principal at its next password change. Until its
  mark is cleared the KDC refuses the name, at AS and TGS alike.
- A change of a synced user's `lldap_disabled` membership commits, and the
  principal's status is left for the realm's next opening (see
  [Principals](#principals)).
- `/health` answers 200 and names the state. `lldap healthcheck` passes, and
  `lldap healthcheck --kerberos` fails (see [Health](#health)).
- The log says so once at start: "The Kerberos realm `<REALM>` is closed and
  this server is directory-only (`<cause>`): the directory is served to
  everyone, …". One `kerberos_sync` failure row says `directory-only:
  <cause>`.
- The web interface shows admins a notice with the state and the cause, and
  the Kerberos sync switch is locked: a user is created without sync, and a
  synced user's other attributes are still saved.

A server configured `directory-only` stays `admin-only` in three cases, and
logs "kerberos_options.on_realm_failure is directory-only, but this server
stays admin-only: …" with the reason:

- The realm's lockout file is missing, unreadable or not a lockout file (see
  [The realm in the database](#the-realm-in-the-database)).
- The database holds no Kerberos realm yet: the realm has never opened on it.
  That is a first start that fails before the realm is written, an upgrade
  from 0.7.2 without its dump, or an empty or wrong database beside an old
  stash.
- The server cannot learn that it holds the realm's row: another server holds
  it, or the database did not answer. A server beside another holder then
  exits, as below.

#### admin-only

- LDAP, LDAPS and the web interface listen on loopback only (`127.0.0.1`, or
  `::1` when the configured host is IPv6). The KDC and kadmin do not listen.
- Only members of `lldap_admin` can sign in. Another user with the right
  password is refused with LDAP result 52 (unavailable) or HTTP 503; a wrong
  password is still invalid credentials (49, 401). Other users' existing
  sessions are refused too.
- Directory changes are refused, with the cause, except a change of
  `lldap_disabled` membership: it commits, and the principal's status is left
  for the realm's next opening (see [Principals](#principals)). Password
  changes are refused with "try again" (LDAP 52, HTTP 503), with or without
  `kerberosSync`, until the realm is repaired or Kerberos is disabled in the
  configuration.
- `/health` answers 503 and names the state, and `lldap healthcheck` prints
  that and fails.
- In a container, loopback is the container's own, so reach the server with
  `docker exec klldap /app/lldap healthcheck --config-file
  /data/lldap_config.toml`.

In both states the log names the cause: `the Kerberos realm <REALM> did not
open: …`, or `reconciling the principals of the Kerberos realm <REALM>
failed: …`, or `the start pass of the Kerberos realm <REALM> failed: …`. The
forced reset's warning and `kerberos_sync` row name the same step.

Fix the cause and restart. At startup the server tries the realm again and, if
it opens, serves normally. Nothing in the product repairs the realm.

#### Health

`/health` answers one JSON object in every state: `{"kerberos": "<state>",
"cause": "<text>"}`, without `cause` where there is none. The cause there is
fit for an open endpoint: it names no file and no count. The full cause is in
the server log, and admins read it in the web interface's notice and in
`kerberosInfo.cause`.

| State | Status | `cause` |
|---|---|---|
| `disabled` (Kerberos disabled in the configuration) | 200 | none |
| `ready` | 200 | none |
| `directory-only` | 200 | the kind of cause, below |
| `admin-only` | 503 | the same |
| `unsettled` (the answer to the last Kerberos write is lost, see [Principals](#principals)) | 503 | "the answer to this server's last Kerberos write was lost and is not yet settled" |
| `lost` (the realm was lost; the server is about to exit) | 503 | "the Kerberos realm was lost; the server log has the cause" |

The kind of cause of a realm that did not open, which `/health` and the
refusals in directory-only name:

| `cause` | The step that failed |
|---|---|
| "the Kerberos data directory cannot be used" | `data_dir` could not be created or read |
| "the realm's records did not open" | the realm's rows, the stash, the lockout file, the 0.7.2 import, the key roll, the admin keytab or `krb5.conf`; any other failure of the open |
| "the start pass failed" | reconciling the principals, or the start pass |
| "the KDC did not start" | a KDC or kadmin port, the kadmin ACL, or the KDC and kadmind themselves |
| "the database's durability setting is unsafe" | SQLite's `synchronous` is not `EXTRA`, or it could not be read |
| "this database holds no Kerberos realm yet" | a server that stays admin-only on a database the realm has never opened on |

`lldap healthcheck` asks LDAP, LDAPS when enabled, and `/health`:

- Without a flag it passes when the directory answers and `/health` answers
  200: for `disabled`, `ready` and `directory-only`. For a `ready` realm it
  also wants the KDC port to accept a connection and the admin keytab to
  exist, as before. For a 503 it prints "503 Service Unavailable: Kerberos is
  `<state>`: `<cause>`" and fails. **So the plain command, and the image's
  HEALTHCHECK, no longer say that the realm serves: a directory-only server is
  healthy.**
- `lldap healthcheck --kerberos` also fails unless the state is `ready`:
  "Healthcheck failed: --kerberos passes only a ready Kerberos realm, and this
  server's is `<state>`". It takes the server's word over HTTP. Use it where a
  monitor must know that Kerberos serves. It fails a server with Kerberos
  disabled too. A flag of this name was removed in 0.8.0; it is back with this
  meaning.

### The forced admin password reset

`force_ldap_user_pass_reset` is the way back in, as in LLDAP: it resets the
admin (`ldap_user_dn`) to `ldap_user_pass` at startup, once with `true` (the
server then stops and asks to be started without it) or at every start with
`"always"`. That password must be at least 8 characters long (characters, not
bytes), with no NUL character (U+0000), or the server refuses to start; so must
the first start's admin password. The admin's `password-min-length` does not
apply to it; the start warns once when that minimum is higher
([policies.md](policies.md#password-length)). With Kerberos enabled the reset
waits until the realm has opened and runs before the KDC, kadmind, LDAP and
HTTP answer anything; for an admin with `kerberosSync` it sets the Kerberos
keys in the same transaction and logs "Reset the password and the Kerberos
keys of `<admin>` from the configuration". When Kerberos cannot take part
(disabled in the configuration, the realm does not open, reconcile or the start pass fails, or the reset with
the realm fails), the reset runs without the realm: the directory password is
the configured one, an admin with `kerberosSync` has the sync turned off in the
same transaction, with one `kerberos_sync` row, and a warning at start says so.
The server then starts, with the realm if it is usable and without it if not
(see [When the realm cannot open](#when-the-realm-cannot-open)).
When the reset with the realm failed and the realm is usable, the start pass
runs again before the KDC serves, so the admin's old Kerberos password gets no
ticket from this server at any moment. Otherwise the holder's status pass
removes the principal left behind within a minute, or the next start with
Kerberos does. Only a configured password that breaks
the rules above refuses the start. A server that finds another one holding the
realm still runs the reset this way first, then exits, as such a server does.

Run a forced reset as you run an upgrade: with every other server that uses
the database stopped. The reset, like the first start's admin password, is
written while the server starts, before it takes requests, and nothing orders
it against another server's changes.

`enabled` defaults to true, and the image no longer sets it. The server
answers LDAP and HTTP only once the realm serves or the start has gone on
without it, so no request meets a realm that is still starting. For a ready
realm the container's healthcheck (`lldap healthcheck`) also requires the KDC
port to accept connections and the admin keytab to exist; see
[Health](#health) for what it says of a realm that did not open. Set `enabled`
to false to run without a realm: no principals are synced.

`admin/admin@REALM *` is always granted. `kadmin_acl` is optional extra
ACL text, read at boot.

## Principals

- `kerberosSync` (attribute `kerberossync`, alias `kerberos_sync`) is a per-user
  switch that admins set. While it is on, every password set — web UI,
  `setUserPassword`, LDAP Modify `userPassword`, `ldappasswd`, LDAP ADD with
  `userPassword` — creates or updates the principal. A password must be valid
  UTF-8 on every door. New principals require preauthentication
  (`REQUIRES_PRE_AUTH`). Turning the switch off deletes the principal, and
  deleting the user deletes it too, each in one transaction (see below).
  Deleting a user without `kerberosSync` touches no principal.
- Through `setUserPassword`, LDAP Modify `userPassword`, `ldappasswd` and LDAP
  ADD, a synced user's directory record, Kerberos keys and `password_change`
  log row are written in one database transaction, so a stop at any point
  leaves both old or both new. Kerberos checks the password before anything is
  written: a refusal is LDAP 53 (unwillingToPerform) or a GraphQL error, and a
  realm that did not open is 52 (unavailable), LDAP ADD included. A change that waits more
  than 10 s for another one is refused with 51 (busy) and writes nothing. If
  the database's answer to the commit is lost, KLLDAP reads the realm's
  generation back, and the read waits for the commit to finish. The change is
  reported done if it landed, with a warning in the server log, and failed if
  it did not. It is reported as "the result is unknown: try the new password"
  (LDAP 80) if the read does not finish within 5 s; the KDC then reloads the
  realm from the database, and that reload first waits up to 5 s for the commit
  to end. Until the reload or the next heartbeat settles it, the server still
  holds the realm, and only what writes a password or both stores waits: every
  password change, turning `kerberosSync` on or off, creating or deleting a
  user with `kerberosSync`, and a change of such a user's `lldap_disabled`
  membership answer "try again" with one failure row, and `/health` answers
  503 with the state `unsettled`. Every user still binds and signs in, searches go on,
  and other directory changes are made as usual. If the commit landed after
  all, this server stops serving the realm and exits; the next start loads it.
  It is unknown too if another server moved the generation meanwhile; this
  server then stops serving the realm and exits. An
  LDAP ADD with a password creates the entry, its record and its principal
  together, or nothing. The web pages and `lldap_set_password` take the same
  one transaction (see below).
- A deleted user's ticket requests are refused for every kind of request,
  delegation and user-to-user included. Renewals and service tickets keep their
  answer (code 18, `CLIENT_NOT_FOUND`); the refusal rows are described in
  [logging.md](logging.md). A request whose subject's entry could not be read
  is refused too (code 18, no text; the row says `the principal could not be
  read`): MIT goes on with such a request. So is a request for a name whose
  delete mark the start pass has read and not cleared (code 18, the row says
  `the user was deleted while the realm was closed`).
- Users in `lldap_disabled` have their principal disabled (`DISALLOW_ALL_TIX`).
  Leaving the group re-enables it. With the realm ready, the membership of a
  user with `kerberosSync`, its log row and the principal's status are written
  in one database transaction: all of them, or none and one failure row, and
  the admin tries again. Every such change on the holder waits for the realm's
  other writes and reads the user's `kerberosSync` again first, so a switch
  turned on meanwhile is followed in the same transaction. A change of that
  membership is never refused because
  Kerberos is disabled or the realm did not open: with Kerberos disabled in
  the configuration, or the server directory-only or admin-only, the
  membership changes alone and a `kerberos_sync` row says the principal's
  status is left for the start pass or for the realm's next opening.
  Whenever the realm opens, every principal the directory made (marked) for a
  user with `kerberosSync` takes its status from `lldap_disabled`, one
  `kerberos_sync` row for each principal changed ("disabled as the realm
  opened" or "enabled as the realm opened"). The statuses are written 100 to a
  transaction, each with its rows, so a pass that fails part-way keeps the
  rows of every status it changed. A start does this, and its start
  pass, before the KDC and kadmind answer anything: their ports are bound
  when the realm opens, and a request that arrives meanwhile waits and is
  answered from the new state. A reload after a failed write does it right
  after the reload. The server that holds the realm also does it every 60
  seconds, with one read of the group's members with `kerberosSync`: only a
  status that differs is written, one row each ("disabled by the holder's
  status pass" or "enabled by the holder's status pass"), and a pass that
  fails is tried again at the next. That pass also removes a marked principal
  whose user is gone or no longer has `kerberosSync`, as the start pass does,
  one row each ("removed by the holder's status pass: user gone" or "…: no
  sync"), in the same transaction, so the old Kerberos password of such a user
  stops working within a minute. A change left for the start pass on another
  server so reaches the holder within a minute. A `kerberosSync`
  user's password change also sets the principal's status from the group, in
  the same transaction as the keys: it reads the membership once it holds the
  write lock, so a user disabled while the change waits gets a disabled
  principal.
- Deleting a user with `kerberosSync`, and turning the switch off, change the
  directory and the principal in one database transaction: both change, or
  neither, and one `user_delete` or `user_update` log row covers both. On a
  server whose realm did not open both are refused, except that a
  directory-only server deletes such a user once the delete is confirmed and
  leaves the principal to the realm's next opening (see
  [directory-only](#directory-only)).
  A change that finds the switch other than it read it writes
  nothing and answers "the user's Kerberos sync changed; try again"; so does a
  password change that finds the switch turned off when it commits, and a
  password change of a user without sync that finds it turned on: such a
  change waits for the realm's other writes, reads the switch again, and only
  then writes the directory alone. A user whose
  principal name is an alias of another principal is deleted alone: the alias
  stays, and a `kerberos_sync` row says so.
- With Kerberos disabled in the configuration (`kerberos_options.enabled =
  false`) no realm runs, and that is its own state, not an offline KDC:
  - turning the switch off and deleting a user change the directory alone. A
    principal, if there is one, is left as it is, and a `kerberos_sync` row
    says so; the start pass removes it at the next start with Kerberos enabled,
    and a server that holds the realm meanwhile removes it at its next status
    pass, within a minute, with one `kerberos_sync` row;
  - adding a user to `lldap_disabled` or removing one changes the directory
    alone, with a `kerberos_sync` row; the next start with Kerberos enabled
    sets the principal's status before the KDC serves, and a holder's status
    pass sets it within a minute;
  - turning the switch on is refused, and so is creating a user with it on
    ("Kerberos is disabled; create the user without Kerberos sync"), at
    `createUser` and LDAP ADD;
  - a password change of a user with the switch on is refused, with "enable
    Kerberos, or turn the user's Kerberos sync off first" (LDAP 53, 400 at the
    web pages and the tool, a GraphQL error);
  - so an installation that gives Kerberos up turns the switch off for its
    users and carries on as LLDAP.
- Turning the switch on, and creating a user with it on, write the attribute
  in one transaction with what they do to the principal of the user's name.
  With no such principal, nothing more: the next password change creates it.
  A principal not made by the directory (made with kadmin, or one the start
  disabled) is adopted: it keeps its fields, but its keys are replaced with
  random ones and the old keys dropped, and it is marked and disabled, with one
  `kerberos_sync` row, so no password the directory never saw works on it.
  The exception is its Kerberos password policy: adoption clears it, and the
  password expiry date it set with it, in the same transaction, with a second
  `kerberos_sync` row that names the policy. Every rule that policy carried
  goes with it: its minimum length, password history, character classes,
  minimum password life, allowed key types and its lockout threshold. For a
  directory user the OU policy item `password-min-length` is the rule
  ([policies.md](policies.md#password-length)). The principal's own expiry
  date (kadmin `-expire`) and its other fields stay, and so does the policy
  itself, for the principals the directory does not own. The key history
  stays too; with no policy, nothing reads it.
  So is a principal the directory made, when the switch goes from off to on:
  one left behind by a sync turned off or a forced reset keeps no old key.
  Turning the switch on when it is already on changes nothing.
  An adopted principal is enabled by the next password change through the
  directory, right after a kadmin `cpw`, when the realm next opens, or at the
  holder's next status pass (within a minute), unless the user is in
  `lldap_disabled`; its random keys take no password. The
  `cpw` sets both forms, then a short change of its own sets the status from
  `lldap_disabled`. Until that change lands the principal stays disabled, and
  if it fails it stays disabled and one `kerberos_sync` failure row says so.
  Adoption does not revoke tickets already issued to the principal: they run
  out with their lifetime.
  An LDAP ADD with the switch on and a password sets both forms and marks the
  principal, whoever made it. When an LDAP ADD that carries a password takes
  over such a principal, that one password must also satisfy the principal's
  old Kerberos policy (whose minimum counts bytes); the policy is cleared with
  that change. To avoid it, create the user without a password, or clear the
  policy with kadmin (`modprinc -clearpolicy`), first.
  The start pass clears the policy of every principal the directory owns that
  still has one, such as those adopted before 0.8.1, before the KDC serves:
  one `kerberos_sync` row each, and a start that finds none writes nothing. A
  clear that cannot be written is a warning in the server log; the start goes
  on, and the next start tries again. Turning the switch on for a user id
  that Kerberos refuses (ASCII letters, digits, `.`, `_` and `-`, starting with
  a letter or a digit, and not `krbtgt`, `kadmin`, `kiprop` or `wellknown`) is
  refused with that rule, at `createUser` and `updateUser` alike. Both also
  refuse it for a user whose principal name is an alias of another principal.
- A password shorter than the user's minimum (`password-min-length`, 8 unless
  the user's OU sets more; [policies.md](policies.md#password-length)) is
  refused wherever the server sees it, for every user: `setUserPassword` (a
  GraphQL error: HTTP 200 with the error), `ldappasswd`, LDAP Modify
  `userPassword` and LDAP ADD with `userPassword` (53, unwillingToPerform; an
  ADD is judged by the OU its DN names), with "the password must be at least N
  characters", N being that minimum. A password with a NUL character (U+0000)
  is refused at the same doors with "the password must not contain a NUL
  character (U+0000)". A minimum that cannot be read refuses the change with
  "the password policy could not be read; try again". An LDAP ADD refused this
  way makes nothing, and each refusal writes one failure row. kadmin `cpw`
  answers `PASS_Q_TOOSHORT` under the minimum, and `PASS_Q_GENERIC` for a NUL
  or a minimum that cannot be read.
- The read-only, admin-visible `krbPrincipalName` attribute shows the principal
  recorded for the user.
- The web pages (change password, the e-mail reset, create user) and
  `lldap_set_password` set a password in one request pair,
  `/auth/opaque/register/start` and `/finish`:
  - For a user with `kerberosSync`, the start answer carries
    `kerberos_envelope_key`, the server's RSA public key. The client seals the
    new password to it with RSA-OAEP-SHA-256 and the OAEP label
    `klldap-kerberos-envelope-v2:<user id>:<server_data>` (the user id in lower
    case; `server_data` as the start answered it), and sends it as
    `kerberos_password_envelope` in the finish. The server opens it with the
    label of the user the registration is for and of the start the finish
    carries, so an envelope sealed for another user or for another start does
    not open (400, "the Kerberos password envelope did not open"). It then
    registers the password
    itself, ignoring the client's OPAQUE upload, and changes the directory
    record and the Kerberos keys in one transaction, as above. A password
    shorter than the user's minimum, or with a NUL character, is refused (400),
    and nothing is written. With Kerberos disabled, the start refuses a user with
    `kerberosSync` (400, naming both ways on) and gives no key; with the realm
    closed or its last write unsettled it answers 503. The finish refuses the
    same before it opens the envelope. Each refusal writes one `password_change` failure row.
  - A finish of a synced user without an envelope is refused (400, "reload the
    page and retry"): a page cached from an older version sends none.
  - A finish is taken once, within two minutes of its start, and only with the
    token its start was made with, for every user. A finish with no valid
    token is refused as the start is (401). A finish with another token, a
    second finish for one start, and a finish whose start another server
    process answered are refused (401, "this registration cannot be finished;
    start again"); a later one is refused with "the registration took too
    long; start again". Each of these writes one `password_change` failure
    row. A page whose token was refreshed between its two requests is told to
    start again. The server keeps a finished start's id and expiry, nothing
    else, in the table `used_registration_starts` for a few minutes.
  - Every start answer carries `password_min_length`, the user's minimum, and
    the pages and the tool refuse a shorter password before the finish
    ([scripting.md](scripting.md)).
  - For any other user, the start answer has no key and the finish is LLDAP's.
    A finish that carries an envelope anyway is refused (400) and nothing is
    written; the envelope is not opened. The server never sees such a user's
    password from the web pages or the tool.
  - The key is 3072 bits, made anew at every start in the background; the log
    line "Made the 3072-bit RSA key in `<ms>` ms" gives the time, and a start
    that comes before it is ready waits for it. The `kerberosInfo` query
    returns the same key, `enabled`, false when the configuration disables
    Kerberos, `state`, the realm's state as `/health` names it, for every
    signed-in user, and `cause`, the full cause, for admins only. The pages
    lock the Kerberos switch unless the state is `ready` or `disabled`. The
    create-user page reads it: with Kerberos disabled it shows no
    Kerberos switch and sends no `kerberosSync` (if the page cannot read it, it
    shows the switch, and the server refuses a create with sync); otherwise the
    switch starts on. RSA-OAEP with SHA-256 seals at most 318 bytes, so the
    pages and the tool refuse a longer password of a synced user before the
    finish, and nothing is written; the create-user page refuses it before it
    creates the user. LDAP and `setUserPassword` have no such bound.

kadmin listens on the container's loopback. The image sets
`KRB5_CONFIG=/data/krb5.conf`, so `docker exec` does not pass it:

```sh
docker exec klldap \
  kadmin -k -t /data/kadm5.keytab -p admin/admin -q listprincs
docker exec klldap \
  kadmin -k -t /data/kadm5.keytab -p admin/admin -q "getprinc bob"
```

On a host, skip `docker exec` and set `KRB5_CONFIG=krb5.conf`, the file in
the unit's working directory.

`getprinc` shows attributes such as `REQUIRES_PRE_AUTH` and `DISALLOW_ALL_TIX`.

## kadmin and directory users

KLLDAP marks the principal of each user with `kerberosSync` as its own (see
[Principals](#principals)). `getprinc` does not show the mark. kadmin reads
such a principal as any other: `getprinc`, `listprincs` and `getstrs` work.
KLLDAP answers each write to it:

| kadmin command | What happens | kadmin reports |
|---|---|---|
| `cpw` | Carried out by KLLDAP. The keys and the directory password change in one transaction; then the principal's status follows `lldap_disabled` (an adopted principal is enabled). | success |
| `cpw` with fewer characters than the user's `password-min-length` (8 by default) | Refused. Characters are counted, not bytes. The minimum is read when kadmind prepares the change, waiting at most 2 seconds, and the commit holds the password to that same number. The `access_denied` row names `PASS_Q_TOOSHORT`. | `Password is too short` |
| `cpw` while the user's minimum cannot be read | Refused, with nothing written. The minimum is read only when kadmind prepares the change, never under its lock; it can be tried again. The `access_denied` row says `PASS_Q_GENERIC: the password policy could not be read`. | `Unspecified password quality failure` |
| `cpw` with a password that is not valid UTF-8, or with a NUL character | Refused | `Unspecified password quality failure` |
| `cpw` kadmind could not prepare | Refused, before anything is derived or written; it can be tried again. A `cpw` that meets another change to the same principal at the same instant is not refused: it is written, from the change prepared once. The `access_denied` row says `PASS_Q_GENERIC: the change could not be prepared`. | `Unspecified password quality failure` |
| `cpw -e <types>` | Refused, with nothing derived or written, whatever the password: a directory user's key types are the realm's `supported_enctypes` and nothing else. MIT would store the types the client names. The `access_denied` row names `BAD_KEYSALTS`. | `Invalid key/salt tuples` |
| a change that would leave a key of a type outside `supported_enctypes`, or a Kerberos policy name, on the principal | Refused when it is written. The row adds the cause: `BAD_KEYSALTS: a key type outside supported_enctypes`, or `PROTECT_PRINCIPAL: a Kerberos policy is named on the principal` (a policy name on a directory user's principal is cleared at the server's start). | `Invalid key/salt tuples`, or `Cannot change protected principal` |
| `cpw -keepold`, `cpw -randkey`, `ktadd` | Refused | `Cannot change protected principal` |
| `ktadd -norandkey` | Refused by kerber-rust itself: the keys are never read out. No log row is written. | ```Operation requires ``extract-keys'' privilege``` |
| `modprinc -unlock` alone | Carried out by KLLDAP as the directory's unlock, in the change's own transaction: the user's lock is cleared, stamped with the server's clock (the unlock time kadmin sends is not read). Only the failure count, the unlock time and the modification stamp change on the principal. The keys and the password stay. | success |
| `modprinc` with any other option | Refused | `Cannot change protected principal` |
| `setstr`, `delstr`, `purgekeys` | Refused. The one string KLLDAP writes there itself is `otp`, for a user who turned on the code at kinit ([A second factor and kinit](#a-second-factor-and-kinit)); `getstrs` shows it | `Cannot change protected principal` |
| `delprinc`, `renprinc` | Refused | `Cannot change protected principal` |
| `alias` onto the principal, or onto one of its aliases | Refused | `Cannot change protected principal` |
| `renprinc` of one of its aliases | Refused | `Cannot change protected principal` |
| `delprinc` of one of its aliases | Carried out. The principal stays. | success |
| `cpw` through one of its aliases | As `cpw` on the principal | as above |

A directory user's name is reserved for that user. The name in another case
counts as the same name:

| kadmin command | kadmin reports |
|---|---|
| `addprinc` with the name, when no principal has it | ```Operation requires ``add'' privilege``` |
| `renprinc` of another principal onto the name | ```Operation requires ``add'' privilege``` |
| `alias` with the name | ```Operation requires ``add'' privilege``` |
| `alias` onto the name, or onto an alias that leads to it | `Cannot change protected principal` |
| `renprinc` of an alias that leads to the name | `Cannot change protected principal` |

Each refusal writes one `access_denied` log row,
`kadmin <operation> on <principal> by <client>: <code>`, for example
`kadmin randkey on bob@EXAMPLE.COM by admin/admin@EXAMPLE.COM: PROTECT_PRINCIPAL`.
A write sent through an alias adds `(requested as <alias>)`. A `cpw` that is
carried out writes a `password_change` row,
`kadmin change_password by <client>`, with `(self-service)` when users change
their own. An unlock writes a `kerberos_sync` row, `kadmin unlock by <client>`,
and an `account_unlock` row. These rows have the
protocol `kadmin`, and the kadmin client is their actor. An admin's refusals
are each stored. A user's refusals on its own principal coalesce like other
refusals: past the first 8, into `access_denied_flood` rows (see
[logging.md](logging.md)). A principal that KLLDAP has not marked, such as
`HTTP/<host>`, takes kadmin commands as usual, within the name rules above.

Make these changes in the directory instead:

- **Password:** the web UI, `ldappasswd`, LDAP Modify `userPassword`, or
  GraphQL `setUserPassword`. The keys follow. kadmin `cpw` also works, as above.
- **Disable:** add the user to `lldap_disabled`. Leaving the group enables the
  principal again.
- **Delete:** turn `kerberosSync` off for the user, or delete the user.
- **Rename:** the principal's name is the user id, and it changes only with
  the user.
- **A principal for a directory user:** turn `kerberosSync` on for the user,
  then set the user's password.

## A second factor and kinit

A directory user who must give a second factor at the directory's doors (their resolved
`enable_mfa` is `always`, or `enabled` and they are enrolled, and they are not in
`lldap_mfa_disabled`; see [mfa.md](mfa.md#modes)) gets a ticket in one of two ways:

- **The code at kinit**, for a user who turned it on for themselves: two `kinit` commands,
  the password and then the code, both inside Kerberos. Nothing is installed on the client.
- **A window**, for every such user and every client: within `mfa_proof_window` (default 10
  minutes) after a sign-in at a directory door with the password and a code (an LDAP bind
  or `/auth/simple/login` with `password:code`, the web login with its code step, or the
  finish of an enrolment or of a replacement of the factor), kinit with the password alone
  gets a ticket. Nothing else opens the window: not the password alone, a token refresh, a
  ticket, or a code given at kinit. `mfa_proof_window = "0"` opens none
  ([Configuration](#configuration)).

Every other user's kinit is unchanged, and nothing is read for them.

### The code at kinit

A user with a factor turns it on for themselves: the switch on the second-factor line of
their own page, or `setCodeAtKinit(on: true)` on their own session. It is off by default.
An administrator reads it (`codeAtKinit`); nobody else sets it. Removing or resetting the
factor turns it off, so a new enrolment starts with it off; a replacement keeps it. Within
a minute (the realm's status pass) the user's principal carries the string `otp`, which
makes the KDC offer the code to an armored kinit of that user. With the stock MIT client:

```sh
kinit -l 5m -c FILE:/run/user/$UID/krb5-armor alice   # the password
kinit -T FILE:/run/user/$UID/krb5-armor alice         # Enter OTP Token Value: the code alone
kdestroy -c FILE:/run/user/$UID/krb5-armor
```

- **The first ticket is armor only.** For such a user a password kinit that asks a
  ticket-granting ticket of ten minutes or less by the KDC's clock (`-l 5m`) always gets a
  ticket of five minutes that renews no further, inside a window too. It gets no service ticket and no
  renewal: `kvno` and `kinit -R` are answered error 12 (`KDC policy rejects request`), window
  or not. Its `login` row is a failure, `totp code required (armor ticket; <mechanism>)`: it
  counts nothing toward the lockout, clears nothing and is no sign-in for `inactivity-days`.
  A kinit that asks for more than ten minutes, or for a service, is judged as in
  [The password at kinit](#the-password-at-kinit). The server refuses to start with a
  `ticket_lifetime` of ten minutes or less, so that no ticket of full life has that shape.
- **The second ticket** carries the authentication indicator `mfa`. Its renewals and service
  tickets need no window for its whole life. Its row is `ticket issued (OTP)`: the lockout
  count is cleared and the sign-in counts for `inactivity-days`. A code at kinit opens no
  window.
- **Only six digits are read.** Type the code alone at the prompt, never `password:code`. A
  value that is not exactly six ASCII digits is refused before anything else is read: it is
  not tested, not counted and not logged, and its memory is wiped. Its row says `no
  six-digit code (OTP)` and nothing of the value. A client that sends the password with the
  code has still sent the password to the KDC, inside FAST; the KDC never asks for it.
- **The code is the doors' code:** the same five attempts per 30-second step and the same
  used-once mark (`totp_steps`), on every server of the database. A code taken at kinit is
  refused at a door, and the reverse.
- **The armor must be the user's own ticket.** A ticket of another user, a host keytab's
  ticket (SSSD with `krb5_use_fast`), an anonymous ticket or one of another realm is
  refused, the code not looked at, and the row names the armor's client.
- **A change of the factor ends the code's tickets.** A ticket with `mfa` issued before the
  user's factor last changed (enrolled, replaced, removed or reset, by anyone) is refused at
  its next service ticket or renewal, error 12, with an `access_denied` row `policy:
  enable-mfa (factor changed since the code)`. A change in the same second as the ticket
  cannot be told apart. Another server learns of the change at its next read of the user (at
  most about 30 seconds).
- **Every refusal of the code looks the same to the client:** `kinit: Preauthentication
  failed`. The `login` row says why:

| Case | Row detail | Lockout |
|---|---|---|
| A wrong code | `invalid totp (OTP)` | one failure |
| A code used before, at kinit or at a door | `totp replayed (OTP)` | nothing |
| The step's five attempts spent | `totp attempts exceeded (OTP)` | nothing |
| The armor is not the user's own ticket | `armor is not the user's own ticket: <armor client> (OTP)` | nothing; the code is not looked at |
| Not six ASCII digits | `no six-digit code (OTP)` | nothing; the value is not read |
| No code asked of the user (`off`, exempt, no factor, the choice turned off) | `no second factor asked (OTP)` | nothing |
| The database did not answer within 2 seconds | `totp: unreadable (OTP)` | nothing |
| Past the KDC's 5 seconds, or its queue full | `pre-authentication not completed (OTP)` | nothing |

A locked user is refused as locked (error 18, a `locked out` row) before any code is looked
at.

### The password at kinit

For a user with a factor the KDC judges the second factor after the password; until 0.8.1 it
judged it before.

- A wrong password is `Password incorrect` (error 24), row `pre-authentication failed
  (<mechanism>)`, and it counts toward the lockout.
- The right password with no window and no short ask is error 12 (`KDC policy rejects
  request`), row `policy: enable-mfa (no fresh proof)`, counted nowhere. For a user who
  turned on the code at kinit its text says both ways: "second factor needed: get a short
  ticket with kinit -l 5m, then give your code with kinit -T, or sign in to the directory
  with your code, then run kinit again". For the others it says "second factor needed: sign
  in to the directory with your code (enrol there first if you have none), then run kinit
  again". kinit prints only the code's message, `KDC policy rejects request`, and its trace
  (`KRB5_TRACE`) only the code: the text travels in the KDC's answer, for a client that shows
  it.
- Inside a window the password alone gets a ticket, as before, for a user who takes the code
  at kinit too (whose short ask is still armor).
- A user who must give a factor and has none (`always`, not enrolled) is refused before the
  password, as before, with the second text.

So for a user with a factor an answer tells a right password from a wrong one, as it does
for every user without one, and a request with no password does not show whether the user
needs a factor. An armored request still shows the code offered to a user who turned on the
code at kinit. For a user who must enrol first, the refusal comes before the password check
and each one writes its `login` row.

### Tickets and windows

- **Tickets:** renewals, validations, service tickets and user-to-user of a ticket without
  `mfa` are judged by the time the ticket was issued, which must lie in a window, so they go
  on after the window ends; user-to-user is judged on the asking user's own ticket. A ticket
  issued before the requirement applied to the user (an enrolment, a policy change, the
  upgrade) is refused at its next renewal or service ticket, with the same code and text and
  an `access_denied` row. A postdated ticket is judged by the time it was issued like any
  other, and is refused once its window is no longer kept (the longer of the ticket and
  renewable lifetimes, plus an hour).
- **Services acting for users:** a service that asks a ticket for a user (S4U2Self,
  S4U2Proxy) is not asked: the user is not there to give a code. A request made with a
  directory user's own ticket is judged as the ticket's renewals are.
- **The window is a stated limit:** inside it, the password alone gets a ticket.
- **The address:** with `mfa_proof_same_address = true` the kinit must come from the address
  the code was given from, the one on that sign-in's log row. An IPv4 address seen over IPv6
  (`::ffff:192.0.2.7`) counts as the IPv4 address. A short ask from another address inside
  the window is still armor, and armor never passes without the code.
- **Clocks:** a window is stamped by the directory server's clock and judged by the KDC's. A
  proof stamped up to 60 seconds ahead of the KDC's clock still opens its window, and nothing
  is allowed at its end. Keep the servers' clocks synchronised.
- **Servers:** the windows are kept in the database (`mfa_windows`), shared by every server.
  Another server learns of a proof at its next read of the policy cache (about every 30
  seconds), and at once after a refusal there reads that user again, factor, group and
  windows (at most once a second): the next kinit passes.
- **A proof belongs to its factor:** resetting or removing a user's factor ends their windows
  at once, and a replacement ends the old ones and opens its own. A password change leaves
  them.
- **Retention:** a window is kept for the longer of `ticket_lifetime` and `renew_lifetime` in
  force when it is pruned, and an hour more. Raising either later does not bring pruned
  windows back.
- **Failures:** a proof that cannot be stored leaves the sign-in standing, and its row says
  `proof not stored`. While the second factor's settings cannot be read, a user known to need
  a proof is refused, and every other user gets today's kinit.

### Stated limits of the code at kinit

- **The armor's age:** any unexpired ticket of the user works as armor, so the password proof
  behind a code may be as old as `ticket_lifetime` (24 hours by default), not five minutes.
- **S4U2Self and requests with a second ticket:** the KDC hands the policy no indicators for
  an S4U2Self request, so a ticket with `mfa` gets an S4U2Self ticket only inside a window; and
  a request that carries a second ticket (user-to-user, S4U2Proxy) is judged by the window and
  the asking ticket's shape, not by an `mfa` mark.
- **Clients not tested:** only MIT's `kinit` in the image runs the two commands in the gate.
  Windows, Heimdal, macOS, Java (Keycloak's Kerberos password login among them), pam_krb5 and
  SSSD's own login are not tested; for them the window is the way. SSSD with
  `krb5_use_fast` armors with the host's keytab: for a user who turned on the code at kinit
  it may ask the code, which is then refused (not the user's own armor). Leave the code at
  kinit off for a user who signs in through such a client.
- **The offer:** the `otp` string follows the user's choice within the status pass (60
  seconds). It only switches the offer: the KDC trusts nothing from it and judges the factor,
  the value and the choice from memory each time. A user whose value later becomes `off`, or
  who becomes exempt, keeps the string until they turn the choice off, and an armored kinit
  then gets a code prompt that refuses (`no second factor asked`).

## Inactivity and kinit

Under an OU's `inactivity-days` ([policies.md](policies.md#inactivity)), a ticket issued by
kinit counts as a sign-in; a renewal or a service ticket does not, because the KDC reports no
success there. Give a client that only renews its tickets a limit longer than `renew_lifetime`.
A service's request for a user (S4U2Self, S4U2Proxy) never counts either, so a user who comes in
only through such a service is refused once the limit passes.
An inactive user is refused at kinit, at a renewal, at a service ticket, and when a service asks
a ticket for them (S4U2Self, S4U2Proxy), with code 18 and no text, before the password is
checked: kinit prints "Client's credentials have been revoked", as for any policy refusal,
and the `login` or `access_denied` row says `policy: inactivity-days (inactive)`. The refusal
comes before the password, so a request for a user's name shows whether some directory policy
refuses that user. Tickets already issued run out by themselves. The sign-in is written off the
KDC's thread within a quarter of a second; one that does not land is kept while this server runs
and written once the database answers (a restart loses it; at most 65,536 are kept).

## Ports and clients

The KDC listens on 1088 and is published as `88:1088` (tcp and udp).
kadmin listens on the container's loopback (`127.0.0.1:1749`). kadmin is not
published, and it is used with `docker exec`. Clients outside use port 88.
The image sets `KRB5_CONFIG=/data/krb5.conf`. kpasswd (`464`) is not published: passwords
are changed through KLLDAP, which updates the KDC.

The `krb5.conf` the server writes (`client_config`, default `/data/krb5.conf`)
is for tools inside the container, and it carries the inner port. With the
default `kdc_host` it names `127.0.0.1` as the KDC and `kadmin_host` as the
admin server. Remote clients write their own and use port 88. The
[SSSD guide](SSSD_LDAP_Kerberos_Setup_Guide.md) has complete client and browser
configurations.

## Keycloak

The Federation tab's **Export keytab** creates `HTTP/<hostname>@REALM` with a
fresh random key and writes `keycloak_options.keytab` (default
`keytab/keycloak-http.keytab`, the types in `supported_enctypes`).
Mount that directory read-only into Keycloak; **Push To Keycloak** creates a
realm with KLLDAP as an LDAP + Kerberos user-federation provider. See
[the SSSD guide, section 7](SSSD_LDAP_Kerberos_Setup_Guide.md#7-keycloak-integration--spnego-sso).

## Configuration

`[kerberos_options]` in `lldap_config.toml`, or `LLDAP_KERBEROS_OPTIONS__<NAME>`:

| Option | Default |
|---|---|
| `enabled` | `true` |
| `realm` | derived from the base DN |
| `ticket_lifetime` | `24h` |
| `renew_lifetime` | `7d` |
| `forwardable` | `true` |
| `client_case_fold` | `true` |
| `mfa_proof_window` | `10m` |
| `mfa_proof_same_address` | `false` |
| `supported_enctypes` | `aes256-cts-hmac-sha1-96` |
| `kdc_host` / `kdc_port` | `0.0.0.0` / `1088` |
| `kadmin_host` / `kadmin_port` | `127.0.0.1` / `1749` |
| `kadmin_acl` | none |
| `data_dir` | `krb5kdc` (mode 0700) |
| `admin_keytab` | `kadm5.keytab` (mode 0600) |
| `client_config` | `krb5.conf` |

`client_case_fold` (default `true`) matches a client principal without regard
to case, so `kinit Livebob` finds `livebob`, and the ticket carries the name
as typed unless the client asks for the canonical name. At start the server
warns once for each set of principals that differ only in case. With the
option off, names match exactly.

`data_dir`, `admin_keytab`, `client_config`, `kadmin_acl`,
`keycloak_options.keytab` and `keycloak_options.config_file` take the path
itself. Their `_FILE` forms, in the environment or the file, stop the start
and name the key.

`mfa_proof_window` takes a Kerberos duration or a bare number of seconds, as the lifetimes
below. `"0"` opens no window: a sign-in with the code at a directory door then opens nothing
at the KDC, and a window already kept admits nothing. A user who must give a second factor
then gets a ticket only with the code at kinit, which they turn on for themselves (see
[A second factor and kinit](#a-second-factor-and-kinit)). A negative is refused.

`ticket_lifetime` and `renew_lifetime` take a Kerberos duration (`24h`, `7d`,
`36000s`) or a bare number of seconds (`36000`), quoted or not, in the file or
the environment. Zero and a negative are refused: to the KDC a zero ticket life
means no limit. A `ticket_lifetime` of ten minutes or less is refused too: that is the armor
ticket of the code at kinit. `renew_lifetime` is also the KDC's longest renewable life. A
principal keeps the ticket life it was created with. At every start the server
brings krbtgt and the users to the configured lives. The Keycloak HTTP
principal, `admin/admin` and the kadmin services keep theirs, so a raised
`ticket_lifetime` does not reach them. A lowered one still caps them through
the realm's value.

The image sets `data_dir`, `admin_keytab` and `client_config`, and
`keycloak_options.keytab` (default `keytab/keycloak-http.keytab`) and
`keycloak_options.config_file` (default `keycloak_config.toml`), to
`/var/kerberos/krb5kdc`, `/data/kadm5.keytab`, `/data/krb5.conf`,
`/data/keytab/keycloak-http.keytab` and `/data/keycloak_config.toml`. Inside
the image that environment overrides the same keys in the config file.

`supported_enctypes` is the only control of a directory user's key types: kadmin's
`-e` is refused for such a principal (a deviation from MIT, above). `supported_enctypes` takes one type name per item. It accepts
`aes256-cts-hmac-sha1-96`, `aes128-cts-hmac-sha1-96`,
`aes256-cts-hmac-sha384-192` and `aes128-cts-hmac-sha256-128`. A family name
such as `aes` or `default`, a `+` or `-` prefix, or two names in one item is
refused at startup, naming the item. `des3-cbc-sha1`, `arcfour-hmac` and
their aliases are refused as deprecated
([RFC 8429 section 7](https://www.rfc-editor.org/rfc/rfc8429)). `camellia128-cts-cmac`,
`camellia256-cts-cmac` and the `camellia` family are refused because the
embedded KDC does not serve them. `des-cbc-crc` and `des-cbc-md5` are not
encryption types this KDC knows. `allow_rc4` and `allow_des3` stay off. See
[MIT's encryption types](https://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html)
and
[krb5.conf](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html).

When the first listed type changes, the next start gives `krbtgt/REALM`,
`kadmin/admin` and `kadmin/changepw` new keys in the listed types and keeps
the old ones, so tickets issued before the change still work. The old key
versions are removed once `ticket_lifetime` plus `renew_lifetime` has passed,
at a start or by the hourly cleanup. A roll that fails leaves the realm closed
with the cause, as any realm that does not open: the server is then
directory-only or admin-only. A user's own keys take the
new types at that user's next password change.

The old `LLDAP_KERB_*` variables are unknown. They warn at startup and are
ignored. So do `kdc_bind`, `kadmin_bind`, `kadmin_acl_file`,
`max_renewable_life` and `kerberos_options.keycloak_keytab`. Use the options
above. `keycloak_keytab` is `keycloak_options.keytab`.

## The realm in the database

The realm is rows in the directory database: `kerberos_realm`,
`kerberos_principals` and `kerberos_policies`. The master key is the file
`.k5.<REALM>` in `kerberos_options.data_dir` (default `krb5kdc`, and in the
image `/var/kerberos/krb5kdc`). **Back up the database and that file
together.** If the database holds the realm and the file is missing, the
realm does not open. The server comes up directory-only (or admin-only, as
configured), and the cause in its log says to restore the stash from the
backup taken with the database.
See [When the realm cannot open](#when-the-realm-cannot-open).

A first start also writes `.k5.<REALM>.bootstrap` beside the stash, and
removes it once the realm's first commit is confirmed. It exists only between
a first start and that commit, so an ordinary backup never holds it. If the
first commit does not answer, the next start finds the marker and retries
with the same stash, or opens the realm if the commit had landed. A marker
without its stash stops the start: restore the stash that belongs to it; only
for a realm that never started may the marker be removed.

On MySQL and MariaDB the columns `kerberos_principals.record`,
`kerberos_policies.record` and `kerberos_realm.state` are `LONGBLOB`.
Upstream's own migrations use a plain blob.

A change the server has acknowledged, such as a password set or a kadmin
write, is in the database before the answer goes out. An acknowledged change
survives a kill of the server on SQLite, PostgreSQL, MySQL and MariaDB, and a
power cut on SQLite and PostgreSQL. On SQLite the server runs
`synchronous = EXTRA`, and the realm does not
open with any other setting. On PostgreSQL this holds when the start-up log
has no `database durability` warning (the warning names `fsync`,
`full_page_writes` or `synchronous_commit`). On MySQL and MariaDB the server
logs the same warning when `innodb_flush_log_at_trx_commit` or `sync_binlog`
is unsafe; a power cut has not been tested on them.

A directory user's failed Kerberos sign-ins are counted in the directory's one table,
`login_lockouts`, with the other doors' failures ([policies.md](policies.md#lockout)):
one counter for LDAP bind, the web, `/auth/simple/login` and kinit. Under a threshold the KDC
waits at most 250 ms for a failure's write before it answers: a write that lands in that time
survives a kill, and one that takes longer is owed, tried again about a second later, and lost
if the server is killed first. After a wait that ran out, the KDC does not wait for the
following writes: those counts are owed too, until a count's write lands within 250 ms again.
The sign-in time an issued ticket records for `inactivity-days` follows the same rule on its
own. A locked user gets error 18 (`CLIENT_REVOKED`) before the KDC
looks at any password, and so does a renewal or a service ticket asked with a ticket issued
before the lock; kinit prints "Client's credentials have been revoked". That is not the
wrong-password answer (24), and anyone can ask for it without a password, so a lock is
visible. An S4U2Self for a locked user is refused the same way and never counts. A ticket
asked with the password alone clears the count only for a user who need not give a second
factor at the directory's doors. An unlock by the host tool or by another server is seen
within a moment of the next attempt: the one refused asks for the user's stored row, and the
next is answered by it.

The failed sign-in counts of the other principals are the file `lockout` in the same directory. A missing
file means the realm does not open. The server comes up admin-only, whatever
`on_realm_failure` says, and the cause says the lockout file is missing;
restore it, or create an empty one and sync it (`sync <file>`) to count failed logins from zero. A
file that cannot be read or written, or that is not a kerber-rust lockout
file, is the same case: restore it, or put an empty file in its place and
sync it. An empty file counts from zero. See
[When the realm cannot open](#when-the-realm-cannot-open). A count already
written survives a kill of the server process. A power cut may forget
lockout changes from the last few minutes, as MIT's does. The realm still
opens. The `lockout` file itself, once on disk, is not lost. After an admin
unlock, a failure in that same second can leave the count at 1 for one extra
failure, as MIT does.

While the database is down, an administrative write is refused at once. The
kadmin client reports "Unable to access Kerberos database". A kadmin read of
an existing principal is still answered. The server gives the realm up after
twenty seconds without the database. A step still in flight can make that
twenty-five, or thirty: when the answer to a commit or a heartbeat is lost and
read back, or when a heartbeat first waits out another request's five-second
step. A heartbeat that starts that late does not read a lost answer back; the
cause then says "the heartbeat started too late to confirm a lost answer". A
start that finds the realm left open waits out a thirty-five-second watch,
five seconds past that. A second server pointed at the same database beside a
live holder serves nothing: it answers no LDAP, HTTP or Kerberos request (it
does not answer "try again"), waits out the watch, then exits and names the
cause. That holds whether the holder serves its realm or is directory-only.
With `on_realm_failure` at its default it also holds whatever stops the
second server's own realm from opening: before it goes on directory-only a
server asks whether it holds the realm's row, and that question is answered
only when the watch has ended. A second server set to `admin-only` does not
ask: if its own realm fails before it reads the realm from the database (0.7.2
files without a dump, a data directory it cannot use, an unsafe SQLite
durability setting), it comes up admin-only on loopback at once, and exits
when the watch ends. A forced reset configured on it runs, without the realm, after the
watch and before the exit.

Every server on one database needs the same `kerberos_options.enabled`. A
server started with Kerberos disabled on a database whose realm is marked
open logs one warning at start that says so. Beside a holder, its
`lldap_disabled` changes, deletes and sync changes reach the realm's
principals through the holder's 60-second status pass. On a lone server the
warning is harmless: the last server with Kerberos stopped without closing the
realm; start once with Kerberos enabled, wait out the watch and stop cleanly
to close it.

Passwords are changed only by the server that holds the realm. With Kerberos
enabled, an admin-only server, or one that has just lost the realm,
refuses every password change, with or without `kerberosSync`, before it
derives, opens or writes anything. It answers "try again" (LDAP 52, HTTP 503,
a GraphQL error) and writes one `password_change` failure row; a load
balancer retries elsewhere. A directory-only server holds the realm's row: it
changes the password of a user without `kerberosSync`, and refuses that of a
user with it, without "try again". A server still watching beside a holder answers
nothing at all. The holder
answers the same while the answer to its last write is lost and not yet
settled. An admin-only server changes no password, and a directory-only one
none of a user with `kerberosSync`, until the realm is repaired or
Kerberos is disabled in the configuration. The forced reset of the admin is
the one exception: it runs at start whatever the realm does.

A server that gives the realm up exits non-zero and relies on its restart
policy. The restarted server finds the realm left open, waits out the
thirty-five-second watch, takes the realm over and serves again; until then
the KDC, LDAP and the web interface do not answer. Without a restart policy
it stays down.

At the first start, a lost answer to the realm's first commit is probed: the
server inserts the realm row's key in a transaction it rolls back, which waits
for a first commit still in flight. It probes for sixty seconds. With the
commit's own five-second step before that, then a one-second pause and up to
two more steps for the last probe and its read, the start can wait about
seventy-five seconds before the answer is reported unknown. The commit counts as landed only when the realm
row holds this server's own realm and realm record. A row that another server
created first is reported as "another server created the realm first"; the
realm does not open and the process exits non-zero.

To upgrade, stop every server that uses the database before the first start
of the new version.

## Upgrading from 0.7.2

0.7.2 kept the realm in MIT's db2 format, which 0.8.1 cannot read. 0.8.1 keeps
the realm in the directory database.

Docker only, any tag: the script decides from the image itself.
`scripts/upgrade-0.7.2-to-0.8.0.sh <container>` prints the plan
and changes nothing. `scripts/upgrade-0.7.2-to-0.8.0.sh --yes <container>`
stops 0.7.2, backs up both volumes, writes the dump with the image that
container runs, and prints the edits in the steps below. It does not pull,
and it does not start 0.8.1. The script prints the edits for a compose file
and for a `docker run` command. Start 0.8.1, then
`scripts/upgrade-0.7.2-to-0.8.0.sh --verify <container> <backup-dir>`.
Podman follows the steps below. Those steps are what the script does.

1. Stop 0.7.2. Copy both volumes, the data directory and the KDC directory,
   before the first 0.8.1 start. On MySQL or MariaDB, back up the database as
   well: schema changes are not transactional.

2. Write a dump of the 0.7.2 realm into the KDC directory with the 0.7.2 image
   the install runs, in a one-off container on the stopped install's volume:

   ```
   docker run --rm --entrypoint kdb5_util -v <kdc volume>:/var/kerberos/krb5kdc \
       aelieth/klldap:0.7.2 -r <REALM> dump /var/kerberos/krb5kdc/principal.dump
   ```

   An install set up from 0.7.2's example uses its own image name there
   (`aelieth/lldap-with-kerberos:<its tag>`).
   `docker exec <your 0.7.2 container> kdb5_util -r <REALM> dump
   /var/kerberos/krb5kdc/principal.dump` works only while the 0.7.2 container
   is running; a change made after the dump is not carried over.

3. In the 0.7.2 compose file, publish `88:1088` for tcp and udp instead of
   `88:88`, or the KDC is unreachable. Remove `749:749`: kadmin listens on
   `127.0.0.1:1749` inside the container and is not published.
   `LLDAP_KERB_REALM_NAME` is ignored; set `LLDAP_KERBEROS_OPTIONS__REALM` to
   that realm, including when 0.7.2's `realm_name` in `kerberos_config.toml`
   was not the name the base DN gives. `LLDAP_KEYCLOAK_ADMIN_PASS` is ignored;
   set `LLDAP_KEYCLOAK_OPTIONS__ADMIN_PASS`. Name the image `aelieth/klldap:0.8.1`
   to get 0.8.1. 0.8.1's images are not published to a registry: build that image
   first ([install.md](install.md)). `aelieth/klldap:latest` is still 0.7.2.
   A configuration that does not set `kerberos_options.enabled` now starts a
   realm; set `enabled = false` to stay without one. Start the image you built.

4. The start logs `Loaded N Kerberos principals from …` and `Migrated the MIT
   realm; its files are kept in …`. Then list the principals and take a ticket
   with the admin keytab:

   ```
   docker exec <container> \
     kadmin -k -t /data/kadm5.keytab -p admin/admin@<REALM> -q listprincs
   docker exec <container> \
     kinit -kt /data/kadm5.keytab admin/admin@<REALM>
   ```

   What carries over: the realm, the master key (the stash stays), every
   principal with its keys and attributes, and `admin/admin`, whose keytab is
   written again from its key. Each key keeps the bytes it had in MIT's dump,
   still encrypted in the master key, so a later dump of the database carries
   the same key bytes as MIT's. A dump the master key cannot open is refused,
   and nothing is moved. What does not carry over: grants in `kadm5.acl` beyond
   the admin line (name them in `kadmin_acl`), and MIT's logs.

   At each start, KLLDAP takes the principal of each user with `kerberosSync`
   as its own, and only KLLDAP changes it from then on. It clears that
   principal's Kerberos password policy, with one `kerberos_sync` row, so the
   user's `password-min-length` is the rule. (kadmin binds a policy named
   `default`, when the realm has one, to each principal it adds without
   `-policy` or `-clearpolicy`.) A principal of a
   directory user without `kerberosSync` is disabled, not deleted, and a
   `kerberos_sync` log row names it. To use it again, turn `kerberosSync` on
   for the user, then change the user's password: the password change is what
   brings kinit back. Or remove the principal with kadmin. A principal that
   names no directory user is left as it is.

5. Without a dump the realm does not open. The database holds no realm yet,
   so the server comes up admin-only, whatever `on_realm_failure` says; the
   cause in its log names the file to write, and nothing is moved. Write the
   dump (step 2) and start again. A dump for a realm other than
   `kerberos_options.realm`, or a dump without its stash, is refused the same
   way. A dump that names a principal which is only a user id, when that user
   does not exist, is refused. The cause names the principal, the database is
   not written, and the MIT files stay. Create the user it names, or remove
   the principal on 0.7.2 and dump again.

6. When the realm works, remove `mit-db2.bak/`. Until then it holds the MIT
   files (`principal`, `principal.kadm5`, `principal.ok`,
   `principal.kadm5.lock`, `kadm5.acl`, `kdc.conf` and the dump), mode 0700.
   Nothing is deleted before that. The dump holds every principal's key data,
   encrypted in the master key, so keep the backup as safe as the database.

## Losing a volume

- `data_dir` lost, directory database intact (the default path is `krb5kdc`,
  and in the image `/var/kerberos/krb5kdc`): the stash `.k5.<REALM>` and the
  `lockout` file are gone, and the realm rows are still in the database. The
  realm does not open. The server comes up directory-only (or admin-only, as
  configured), and the cause says the stash is missing. Restore that file
  from the backup taken with the database. With the stash back, a missing
  `lockout` file is its own cause, and the server is then admin-only: restore
  it, or create an empty one and sync it (`sync <file>`) to
  count failed logins from zero.
  A file that cannot be read or written, or that is not a kerber-rust lockout
  file, is the same case. See
  [When the realm cannot open](#when-the-realm-cannot-open).
- The database has no realm, and `mit-db2.bak/` is still in `data_dir` without
  the stash: the realm does not open. The server comes up admin-only (the
  database holds no realm), and the cause names the backup, so a lost database is not silently
  replaced by a new realm. Restore the database and the stash, or move
  `mit-db2.bak/` away to start a fresh realm.
- `/data` lost: the directory database and `server_key` are gone, and with them
  the realm rows. If the stash is still in `data_dir`, the realm does not
  open. The server comes up admin-only (the database holds no realm), and the
  cause says that stash belongs to a realm the database does not hold. Restore the database,
  or put the 0.7.2 dump back beside the stash to run the import again. With
  nothing to restore and no 0.7.2 dump, moving the stash and the `lockout`
  file away is the last resort: the next start creates a new realm. Existing
  users then have no principal until their password is next set, or an admin
  sets one for them, with `kerberosSync` on. The Keycloak keytab is exported
  again.
