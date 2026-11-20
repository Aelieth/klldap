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
directory cannot be read), the server starts in a degraded state instead of
exiting. So it does when the realm opens but reconciling its principals or its
start pass fails: the server then still holds the realm (no other server takes
it over until this one stops), and its KDC and kadmin do not serve. The same
happens to a realm found lost before its KDC starts; the server then exits, as
a server that loses the realm does. In the degraded state:

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
- `/health` answers 503 with the cause, and `lldap healthcheck` prints it and
  fails.
- The log names the cause: `the Kerberos realm <REALM> did not open: …`, or
  `reconciling the principals of the Kerberos realm <REALM> failed: …`, or
  `the start pass of the Kerberos realm <REALM> failed: …`. `/health` and the
  forced reset's warning and `kerberos_sync` row name the same step.

Fix the cause and restart. At startup the server tries the realm again and, if
it opens, serves normally. Nothing in the product repairs the realm. In a
container, loopback is the container's own, so reach the server with `docker
exec klldap /app/lldap healthcheck --config-file /data/lldap_config.toml`.

### The forced admin password reset

`force_ldap_user_pass_reset` is the way back in, as in LLDAP: it resets the
admin (`ldap_user_dn`) to `ldap_user_pass` at startup, once with `true` (the
server then stops and asks to be started without it) or at every start with
`"always"`. That password must be at least 8 characters, with no NUL character
(U+0000), or the server refuses to start; so must the first start's admin
password. With Kerberos enabled the reset waits until the realm has opened and
runs before the KDC, kadmind, LDAP and HTTP answer anything; for an admin with
`kerberosSync` it sets the Kerberos keys in the same transaction and logs
"Reset the password and the Kerberos keys of `<admin>` from the
configuration". When Kerberos cannot take part (disabled in the configuration,
the realm does not open, reconcile or the start pass fails, or the reset with
the realm fails), the reset runs without the realm: the directory password is
the configured one, an admin with `kerberosSync` has the sync turned off in the
same transaction, with one `kerberos_sync` row, and a warning at start says so.
The server then starts, with the realm if it is usable and degraded if not.
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

`enabled` defaults to true, and the image no longer sets it. The container's
healthcheck (`lldap healthcheck`) then also requires the KDC port to accept
connections and the admin keytab to exist, otherwise the container reports
unhealthy, and **directory writes (users, groups, passwords, attributes,
settings) are refused with "Kerberos KDC unavailable" until the KDC has
answered once after boot**, except `lldap_disabled` membership. Logins and
reads are never gated. Set `enabled` to false to run without a realm: writes
never wait and no principals are synced.

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
  written: a refusal is LDAP 53 (unwillingToPerform) or a GraphQL error, and an
  offline KDC is 52 (unavailable), LDAP ADD included. A change that waits more
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
  503 with the cause. Every user still binds and signs in, searches go on,
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
  [logging.md](logging.md).
- Users in `lldap_disabled` have their principal disabled (`DISALLOW_ALL_TIX`).
  Leaving the group re-enables it. With the realm ready, the membership of a
  user with `kerberosSync`, its log row and the principal's status are written
  in one database transaction: all of them, or none and one failure row, and
  the admin tries again. Every such change on the holder waits for the realm's
  other writes and reads the user's `kerberosSync` again first, so a switch
  turned on meanwhile is followed in the same transaction. A change of that
  membership is never refused because
  Kerberos is disabled or not ready: with Kerberos disabled in the
  configuration, or the realm not ready, the membership changes alone and a
  `kerberos_sync` row says the principal's status is left for the start pass.
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
  neither, and one `user_delete` or `user_update` log row covers both. With the
  KDC offline or starting they are refused, as every directory write is ("retry
  shortly"). A change that finds the switch other than it read it writes
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
  `kerberos_sync` row, so no password the directory never saw works on it
  (its key history, which only a password policy's reuse check reads, stays).
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
  principal, whoever made it. Turning the switch on for a user id
  that Kerberos refuses (ASCII letters, digits, `.`, `_` and `-`, starting with
  a letter or a digit, and not `krbtgt`, `kadmin`, `kiprop` or `wellknown`) is
  refused with that rule, at `createUser` and `updateUser` alike. Both also
  refuse it for a user whose principal name is an alias of another principal.
- A password shorter than 8 characters is refused wherever the server sees it,
  for every user: `setUserPassword` (a GraphQL error: HTTP 200 with the
  error), `ldappasswd`, LDAP Modify `userPassword` and LDAP ADD with
  `userPassword` (53, unwillingToPerform), with "the password must be at least
  8 characters". A password with a NUL character (U+0000) is refused at the
  same doors with "the password must not contain a NUL character (U+0000)".
  An LDAP ADD refused this way makes nothing, and each refusal writes one
  failure row. kadmin `cpw` answers `PASS_Q_TOOSHORT`, and `PASS_Q_GENERIC` for
  a NUL.
- The read-only, admin-visible `krbPrincipalName` attribute shows the principal
  recorded for the user.
- The web pages (change password, the e-mail reset, create user) and
  `lldap_set_password` set a password in one request pair,
  `/auth/opaque/register/start` and `/finish`:
  - For a user with `kerberosSync`, the start answer carries
    `kerberos_envelope_key`, the server's RSA public key. The client seals the
    new password to it with RSA-OAEP-SHA-256 and the OAEP label
    `klldap-kerberos-envelope-v1:<user id>` (the user id in lower case), and
    sends it as `kerberos_password_envelope` in the finish. The server opens it
    with the label of the user the registration is for, so an envelope sealed
    for another user does not open (400). It then registers the password
    itself, ignoring the client's OPAQUE upload, and changes the directory
    record and the Kerberos keys in one transaction, as above. A password
    shorter than 8 characters, or with a NUL character, is refused (400), and
    nothing is written. With Kerberos disabled, the start refuses a user with
    `kerberosSync` (400, naming both ways on) and gives no key; with the realm
    not ready it answers 503. The finish refuses the same before it opens the
    envelope. Each refusal writes one `password_change` failure row.
  - A finish of a synced user without an envelope is refused (400, "reload the
    page and retry"): a page cached from an older version sends none.
  - For any other user, the start answer has no key and the finish is LLDAP's.
    A finish that carries an envelope anyway is refused (400) and nothing is
    written; the envelope is not opened. The server never sees such a user's
    password from the web pages or the tool.
  - The key is 3072 bits, made anew at every start in the background; the log
    line "Made the 3072-bit RSA key in `<ms>` ms" gives the time, and a start
    that comes before it is ready waits for it. The `kerberosInfo` query
    returns the same key, and `enabled`, false when the configuration disables
    Kerberos. The create-user page reads it: with Kerberos disabled it shows no
    Kerberos switch and sends no `kerberosSync`; otherwise the switch starts on. RSA-OAEP with SHA-256 seals at most 318 bytes, so
    the pages and the tool refuse a longer password of a synced user before
    the finish, and nothing is written; the create-user page refuses it before
    it creates the user. LDAP and `setUserPassword` have no such bound.

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
| `cpw` with fewer than 8 characters | Refused. Characters are counted, not bytes. | `Password is too short` |
| `cpw` with a password that is not valid UTF-8, or with a NUL character | Refused | `Unspecified password quality failure` |
| `cpw -keepold`, `cpw -randkey`, `ktadd` | Refused | `Cannot change protected principal` |
| `ktadd -norandkey` | Refused by kerber-rust itself: the keys are never read out. No log row is written. | ```Operation requires ``extract-keys'' privilege``` |
| `modprinc -unlock` alone | Carried out by KLLDAP as the directory's unlock, in the change's own transaction: the user's lock is cleared, stamped with the server's clock (the unlock time kadmin sends is not read). Only the failure count, the unlock time and the modification stamp change on the principal. The keys and the password stay. | success |
| `modprinc` with any other option | Refused | `Cannot change protected principal` |
| `setstr`, `delstr`, `purgekeys` | Refused | `Cannot change protected principal` |
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
`lldap_mfa_disabled`; see [mfa.md](mfa.md#modes)) gets a ticket only within
`mfa_proof_window` (default 10 minutes) after signing in at a directory door with the
password and a code: an LDAP bind or `/auth/simple/login` with `password:code`, the web
login with its code step, or the finish of an enrolment or of a replacement of the factor.
Nothing else opens the window: not the password alone, a token refresh or a ticket. Every
other user's kinit is unchanged, and nothing is read for them.

```sh
ldapwhoami -x -H ldap://ldap.example.com:3890 -D uid=alice,ou=people,dc=example,dc=com -W
kinit alice
```

At the prompt, type the password, a colon and the current code.

- **The refusal:** without a fresh proof the KDC answers error 12 (KDC policy rejects
  request) with the text "second factor needed: sign in to the directory with your code
  (enrol there first if you have none), then run kinit again", before it looks at the
  password. It writes one `login` row, `policy: enable-mfa (no fresh proof)`, and counts
  nothing toward the lockout. A locked user is refused as locked first. kinit prints only
  the code's message, `KDC policy rejects request`, and its trace (`KRB5_TRACE`) only the
  code: the text travels in the KDC's answer, for a client that shows it, and the server's
  log row names the reason.
- **Tickets:** a ticket issued under a proof is an ordinary ticket. Its renewals,
  validations and service tickets are judged by the time it was issued, which must lie in
  a window, so they go on after the window ends. A ticket issued before the requirement
  applied to the user (an enrolment, a policy change, the upgrade) is refused at its next
  renewal or service ticket, with the same code and text and an `access_denied` row. A
  postdated ticket is judged by the time it was issued like any other, and is refused once
  its window is no longer kept (the longer of the ticket and renewable lifetimes, plus an
  hour).
- **Services acting for users** (S4U2Self, S4U2Proxy) are not asked: the user is not there
  to give a code.
- **The window is a stated limit:** inside it, the password alone gets a ticket.
- **What a request shows:** the refusal comes before the password check, so anyone who
  can send the KDC a request for a user's name can see, without the password, whether
  that user needs a second factor and whether they proved it within the window: such a
  user is answered error 12 outside a window. Each refusal writes its `login` row.
- **The address:** with `mfa_proof_same_address = true` the kinit must come from the
  address the code was given from, the one on that sign-in's log row. An IPv4 address
  seen over IPv6 (`::ffff:192.0.2.7`) counts as the IPv4 address.
- **Clocks:** a window is stamped by the directory server's clock and judged by the
  KDC's. A proof stamped up to 60 seconds ahead of the KDC's clock still opens its window,
  and nothing is allowed at its end. Keep the servers' clocks synchronised.
- **Servers:** the windows are kept in the database (`mfa_windows`), shared by every
  server. Another server learns of a proof at its next read of the policy cache (about every 30
  seconds), and at once after a refusal there reads that user again, factor, group and
  windows (at most once a second): the next kinit passes.
- **A proof belongs to its factor:** resetting or removing a user's factor ends their
  windows at once, and a replacement ends the old ones and opens its own. A password change
  leaves them.
- **Retention:** a window is kept for the longer of `ticket_lifetime` and `renew_lifetime`
  in force when it is pruned, and an hour more. Raising either later does not bring pruned
  windows back.
- **Failures:** a proof that cannot be stored leaves the sign-in standing, and its row says
  `proof not stored`. While the second factor's settings cannot be read, a user known to
  need a proof is refused, and every other user gets today's kinit.
- **Later:** a path that asks the code inside Kerberos itself, in one exchange, is planned.

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

`ticket_lifetime` and `renew_lifetime` take a Kerberos duration (`24h`, `7d`,
`36000s`) or a bare number of seconds (`36000`), quoted or not, in the file or
the environment. Zero and a negative are refused: to the KDC a zero ticket life
means no limit. `renew_lifetime` is also the KDC's longest renewable life. A
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

`supported_enctypes` takes one type name per item. It accepts
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
with the cause, as any realm that does not open. A user's own keys take the
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
realm does not open. The server comes up in the degraded state, and the
cause says to restore the stash from the backup taken with the database.
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
if the server is killed first. A locked user gets error 18 (`CLIENT_REVOKED`) before the KDC
looks at any password, and so does a renewal or a service ticket asked with a ticket issued
before the lock; kinit prints "Client's credentials have been revoked". That is not the
wrong-password answer (24), and anyone can ask for it without a password, so a lock is
visible. An S4U2Self for a locked user is refused the same way and never counts. A ticket
asked with the password alone clears the count only for a user who need not give a second
factor at the directory's doors. An unlock by the host tool or by another server is seen
within a moment of the next attempt: the one refused asks for the user's stored row, and the
next is answered by it.

The failed sign-in counts of the other principals are the file `lockout` in the same directory. A missing
file means the realm does not open. The server comes up in the degraded
state, and the cause says the lockout file is missing; restore it, or create
an empty one and sync it (`sync <file>`) to count failed logins from zero. A
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
cause. A forced reset configured on it runs, without the realm, after the
watch and before the exit.

Every server on one database has the same `kerberos_options.enabled`. A
server started with Kerberos disabled on a database whose realm is marked
open logs one warning at start that says so. Beside a holder, its
`lldap_disabled` changes, deletes and sync changes reach the realm's
principals through the holder's 60-second status pass. On a lone server the
warning is harmless: the last server with Kerberos stopped without closing the
realm; start once with Kerberos enabled, wait out the watch and stop cleanly
to close it.

Passwords are changed only by the server that holds the realm. With Kerberos
enabled, a server whose realm is degraded, or that has just lost the realm,
refuses every password change, with or without `kerberosSync`, before it
derives, opens or writes anything. It answers "try again" (LDAP 52, HTTP 503,
a GraphQL error) and writes one `password_change` failure row; a load
balancer retries elsewhere. A server still watching beside a holder answers
nothing at all. The holder
answers the same while the answer to its last write is lost and not yet
settled. A server
whose realm is degraded changes no password until the realm is repaired or
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
of the new version. 0.8.0 watches for thirty seconds and 0.8.1 for
thirty-five, so the two side by side have no slack.

## Upgrading from 0.7.2

0.7.2 kept the realm in MIT's db2 format, which 0.8.0 cannot read. 0.8.0 keeps
the realm in the directory database.

Docker only, any tag: the script decides from the image itself.
`scripts/upgrade-0.7.2-to-0.8.0.sh <container>` prints the plan
and changes nothing. `scripts/upgrade-0.7.2-to-0.8.0.sh --yes <container>`
stops 0.7.2, backs up both volumes, writes the dump with the image that
container runs, and prints the edits in the steps below. It does not pull,
and it does not start 0.8.0. The script prints the edits for a compose file
and for a `docker run` command. Start 0.8.0, then
`scripts/upgrade-0.7.2-to-0.8.0.sh --verify <container> <backup-dir>`.
Podman follows the steps below. Those steps are what the script does.

1. Stop 0.7.2. Copy both volumes, the data directory and the KDC directory,
   before the first 0.8.0 start. On MySQL or MariaDB, back up the database as
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
   set `LLDAP_KEYCLOAK_OPTIONS__ADMIN_PASS`. Name the image `aelieth/klldap:0.8.0`
   to get 0.8.0. `aelieth/klldap:latest` is still 0.7.2.
   A configuration that does not set `kerberos_options.enabled` now starts a
   realm; set `enabled = false` to stay without one. Pull that tag and start it.

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
   as its own, and only KLLDAP changes it from then on. A principal of a
   directory user without `kerberosSync` is disabled, not deleted, and a
   `kerberos_sync` log row names it. To use it again, turn `kerberosSync` on
   for the user, then change the user's password: the password change is what
   brings kinit back. Or remove the principal with kadmin. A principal that
   names no directory user is left as it is.

5. Without a dump the realm does not open. The server comes up in the degraded
   state, the cause names the file to write, and nothing is moved. Write the
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
  realm does not open. The server comes up in the degraded state, and the
  cause says the stash is missing. Restore that file from the backup taken
  with the database. With the stash back, a missing `lockout` file is its own
  cause: restore it, or create an empty one and sync it (`sync <file>`) to
  count failed logins from zero.
  A file that cannot be read or written, or that is not a kerber-rust lockout
  file, is the same case. See
  [When the realm cannot open](#when-the-realm-cannot-open).
- The database has no realm, and `mit-db2.bak/` is still in `data_dir` without
  the stash: the realm does not open. The server comes up in the degraded
  state, and the cause names the backup, so a lost database is not silently
  replaced by a new realm. Restore the database and the stash, or move
  `mit-db2.bak/` away to start a fresh realm.
- `/data` lost: the directory database and `server_key` are gone, and with them
  the realm rows. If the stash is still in `data_dir`, the realm does not
  open. The server comes up in the degraded state, and the cause says that
  stash belongs to a realm the database does not hold. Restore the database,
  or put the 0.7.2 dump back beside the stash to run the import again. With
  nothing to restore and no 0.7.2 dump, moving the stash and the `lockout`
  file away is the last resort: the next start creates a new realm. Existing
  users then have no principal until their password is next set, or an admin
  sets one for them, with `kerberosSync` on. The Keycloak keytab is exported
  again.
