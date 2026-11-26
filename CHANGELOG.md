# Changelog

## [0.8.2] - 2026-11-25

0.8.2 is a pre-release: the owner's code review of 0.8.1, and its fixes. It is not merged to `main`,
and its images are not published to a registry. Its KDC and kadmin are kerber-rust v1.2.4-rc.4, a
release candidate. Further testing and verification come before it is promoted.

### Added

- kinit can ask for the second factor itself, for a user who turns on "code at kinit" on their own
  page. `kinit -l 5m` with the password gives a five-minute ticket good only as armor. `kinit -T`
  with that ticket and the code alone gives the ticket, marked `mfa`, whose renewals and service
  tickets need no window. The code is the directory's code: five attempts a step, and used once
  across every door and the KDC. A value that is not six digits is refused unread and never logged.
- GraphQL `setCodeAtKinit(on)` turns the code at kinit on or off for the signed-in user alone, and
  `User.codeAtKinit` reads it, for the user and an administrator. It is off by default, removing or
  resetting the factor turns it off, and each change writes one row.
- `mfa_proof_window = "0"` turns the window off: a sign-in with the code at a directory door then
  opens nothing at the KDC.
- A ticket marked `mfa` is refused at its next renewal or service ticket once the user's factor has
  changed after it was issued.
- `lldap healthcheck --kerberos` fails unless the server says its realm is ready. A flag of this
  name was removed in 0.8.0; it is back with this meaning, so a compose file that overrides the
  healthcheck with it now fails unless the realm is ready. `kerberosInfo` gains `state`, and `cause`
  for admins. The web interface shows admins a notice while the realm is closed, and locks the
  Kerberos sync switch.
- On a directory-only server a user with Kerberos sync is deleted with a confirmation: GraphQL
  `deleteUser` takes `confirmUserId`, equal to `userId` in any case, and the users page asks for
  each such user's name in turn. The user is deleted, and in the same transaction its principal is
  marked in the new table `kerberos_delete_marks` (made at start, with no schema number) with one
  `kerberos_sync` row; the database deletes the principal with the user, and the answer's
  `warnings` say so. The realm's next opening clears the marks; a principal still marked there is
  removed before the KDC serves, and until then the KDC refuses the name. Without the confirmation,
  and at an LDAP Delete, the delete is refused. A
  confirmation that names another user, or one for a user who has no sync now, deletes nothing;
  outside directory-only `confirmUserId` changes nothing but that check.

### Removed

- `kerberosInfo.publicKeyDerBase64` is removed. A client takes the envelope key from a register
  start, or from a login start that asks for it, which binds it.

### Changed

- Upgrading from 0.8.1 ([install.md](docs/install.md#upgrading-from-klldap-081)): a server whose
  Kerberos realm does not open now serves the directory to everyone by default (next entry); a web
  sign-in in progress across the upgrade is refused once: sign in again; `lldap_set_password
  --admin-password` no longer takes `password:code`; `kerberosInfo.publicKeyDerBase64` is gone; and
  a `ticket_lifetime` of ten minutes or less refuses the start.
- **The default changed: a server whose Kerberos realm does not open at start now serves the
  directory to everyone.** Until 0.8.1 such a server listened on loopback only, admitted only
  members of `lldap_admin` and refused most changes. From 0.8.2 it serves LDAP, LDAPS and the web
  interface as configured, to every user, with every policy judged as always (`directory-only`).
  Kerberos is closed: the KDC and kadmin do not answer, and every change that needs a principal is
  refused with LDAP 52, HTTP 503 or a GraphQL error and the text `Kerberos KDC unavailable: <class>;
  the change will be possible when this server's realm opens`, where `<class>` is the kind of cause
  (below): a password change of a user with Kerberos sync, creating such a user, turning sync on or
  off, and deleting such a user without a confirmation. The Keycloak keytab export is refused too.
  Nothing is queued. To keep the old behaviour set `kerberos_options.on_realm_failure =
  "admin-only"` (`LLDAP_KERBEROS_OPTIONS__ON_REALM_FAILURE=admin-only`). A server stays admin-only
  whatever the key says when the realm's lockout file is missing, unreadable or not a lockout file,
  when the database has never held a realm, and when it cannot learn that it holds the realm. A
  running server that loses its realm still exits.
- `/health` answers a JSON object in every state, `{"kerberos": "<state>", "cause": "<text>"}`, with
  `cause` only where there is one: 200 for `disabled`, `ready` and `directory-only`, 503 for
  `admin-only`, `unsettled` and `lost`. The cause there names no file and no count; the full cause
  is in the server log and, for admins, in `kerberosInfo.cause`. Before, the body was empty or the
  bare cause.
- A realm that did not open names the kind of its cause in public, in `/health`, in the healthcheck
  and in the refusals in directory-only: "the Kerberos data directory cannot be used", "the realm's
  records did not open", "the start pass failed", "the KDC did not start", "the database's
  durability setting is unsafe" or "this database holds no Kerberos realm yet". The server log, the
  rows and `kerberosInfo.cause` keep the full cause ([kerberos.md](docs/kerberos.md#health)).
- `lldap healthcheck`, and so the image's HEALTHCHECK, passes a directory-only server: it no longer
  says that the realm serves. For a ready realm it checks the KDC port and the admin keytab as
  before.
- `/auth/logout` now acts only on a refresh token the server holds; any other token changes nothing.
- A password registration sent over HTTP (the pages, `lldap_set_password`) is finished once, within
  two minutes of its start, and only by the session that started it.
- For a user with Kerberos sync the envelope's label is now `klldap-kerberos-envelope-v2:<user
  id>:<server_data>`, with `server_data` as the register start answered it, so an envelope opens
  only for its own start; it was `klldap-kerberos-envelope-v1:<user id>`. A Rust client gets the
  whole finish from `lldap_auth::kerberos_envelope::finish_with_envelope`. The finish takes its
  start's id in the new table `used_registration_starts`, made at start with no schema number and
  left out of dumps.
- A web login's finish is taken once, within two minutes of its start; a second or late finish gets
  the wrong-password answer with its own `login` row and counts nothing. The new table
  `used_login_starts` is made at start with no schema number, and left out of dumps.
- A password-reset link's token lives five minutes like its cookie, is taken only by the password's
  register start and finish, and ends when the password is set (at once on that server, on others at
  their next start). GraphQL answers it `Invalid JWT` with an `access_denied` row.
- The web pages, and `lldap_set_password` given `--admin-password`, seal a synced user's new
  password only to the envelope key bound to their own sign-in: a login start may ask for the key
  (`"kerberos_envelope_key": true`), and the server binds it as the OPAQUE login's context. After a
  reload, or a server restart, the admin's change page and the create page ask for a new sign-in.
  The e-mail reset page and `lldap_set_password --token` take the key as answered: serve the web
  port over TLS.
- `lldap_set_password --admin-password` signs in by OPAQUE, not by `/auth/simple/login`: the admin's
  password no longer reaches the server. An admin with a second factor gives the password alone and
  is asked the code; `password:code` no longer works there.
- `lldap_set_password --admin-password` with a second factor: `password:code` no longer works; the
  code comes from the prompt or `LLDAP_ADMIN_TOTP_CODE`.
- KLLDAP's own copies of a password at `/auth/simple/login`, an LDAP simple bind (the decoded
  request's copy included), a bind's check of the password, the web pages and `lldap_set_password`
  are wiped when they are dropped. Not wiped: the HTTP body buffers and the JSON reader's copies,
  GraphQL's parsed variables (and the query text when a password is written in it), the LDAP
  library's decode copies and read buffer, the browser's fields, form model and JavaScript side, and
  the tool's arguments, environment, parser copies and HTTP body.
- The migration tool (`lldap_migration_tool`) holds the source directory's bind password from its
  prompt, and each password value a search of that directory returns, in types that wipe them when
  they are dropped; a user's debug output prints no password.
- For a user with a second factor the KDC checks the password before the second factor. A wrong
  password at kinit is now `Password incorrect` and counts toward the lockout. The right password
  without the code or a window is refused with error 12 after it; 0.8.1 refused before looking at
  the password. A user who must enrol first is still refused before the password.
- The server refuses to start with a `ticket_lifetime` of ten minutes or less.
- A directory user's own ticket in an S4U request is now judged for the second factor; user-to-user
  is judged on the asking user's ticket.
- While a user's `enable-mfa` value cannot be read, the web login refuses when the sign-in starts,
  answered as a name with no password file is, with its one `login` row `policy: unreadable` and
  nothing counted toward the lockout; before, it refused at the finish, after the password had
  verified.
- As in 0.8.1, a refusal by a policy item counts nothing toward the lockout, at every door; the
  lockout counts only wrong passwords and wrong codes. While the lockout counts, a right password,
  or a right code, that a policy item refuses at an LDAP bind or `/auth/simple/login` now writes the
  user's lockout row again as it stands, the way a wrong password's count is written, and changes no
  count and no lock.
- The groups `lldap_admin` and `lldap_disabled` are compared in any case, as LLDAP compares them: at
  the LDAP bind and `/auth/simple/login`, the web login, the reset request, an admin-only server's
  check for admins, the Kerberos status of a synced user's principal, the last-admin guards, LDAP's
  `loginDisabled`, GraphQL `isDisabled` and the web pages' switches. `lldap_mfa_disabled` is still
  compared by its exact name.
- A sign-in refused before any credential was proved (a wrong password or a locked, disabled or
  unknown account at a bind, a web login, a Kerberos sign-in, a token refresh with a token the
  server does not hold, a password reset) is stored one to one only for the first 8 of its flood
  window; past that the refusals are counted in a `started` and a `resolved` row of the new kind
  `sign_in_flood`. Each known user's first 8 refusals from one client address, of one kind over one
  protocol, are kept, for up to 16 users per address at a time; past that, and for names that are no
  user, the address's first 8. This replaces the 0.7.5 statement that wrong passwords against real
  accounts are always stored one to one; what stays per user is the `account_lock` row and the
  stored counts; `logActivity.failuresSinceLastSuccess` counts stored rows. Rows written after a
  credential was proved are stored every time. Flood windows are keyed by the client address
  `allowed-networks` judges, not by the socket peer. At most 512 windows of one `sign_in_flood` kind
  are open at once; one more is counted in a `... flood from many sources` pair, and an open window
  is no longer closed to make room.
- Every terminal line a request can cause before a credential is proved goes through the failure
  lines' limit of 64 per 10 seconds, or is printed at `debug`: the server's own warnings that a
  request can cause (a policy or lockout that could not be read, a mail that could not be sent, an
  LDAP connection's error, now a warning, not an error) and the `info` line of an LDAP write request
  share the limit, and an unknown LDAP control and a malformed DN are `debug`. An internal error is
  said once where it is answered, within the limit: at the LDAP bind, at an HTTP 500, and where an
  LDAP search or a GraphQL list of users cannot read its users. A log writer that cannot store says
  so once when that starts and once when it ends, with the number lost. The embedded KDC's own lines
  (`target: krb5_klog`) are `debug` below a warning and share the limit from a warning up
  ([logging.md](docs/logging.md#terminal-lines)).
- Events the log writer drops are stored as at most one `log_gap` row every 10 seconds: the first
  drops are written at once, later ones together once the 10 seconds are over, or when the writer
  stops.
- The reads at the sign-in and token doors, and the background reads and writes, are given up at a
  bound of 2 seconds (5 for the second factor's prune). The policy cache's fill reads the activity
  rows and the proof windows 500 at a time, and the lockout reads the rows the other servers wrote
  500 users at a time, each page within the bound; a lockout read given up leaves the server judging
  with the rows it read before until its next read. A wait for a connection of the main database
  pool gives up after 10 seconds (it was 30).
- A read or a write given up at its bound says so in one set of words, `the database did not answer
  in time`: in the server's warning, in an HTTP 500's body, and as the detail of the row a token's
  use or a reset token's finish writes. A token's use whose groups cannot be read is refused with an
  `access_denied` row in those words, or `groups: unreadable` for another failure, where the row
  said `Account disabled`; a token refresh answers that read 500. A reset finish whose token cannot
  be read answers 500 with a row in those words, or `reset token: unreadable`; a wrong or expired
  token keeps its 404.
- A bind that gets none of the server's four key-stretching slots within 2 seconds, or finds 32
  binds already waiting for one, is answered busy (LDAP result 51, HTTP 503) with one failed `bind`
  row, `server busy`, and counts as no failure. A bind whose key stretching began and did not
  complete answers an internal error, no longer a wrong password.
- A name read as no user is remembered as such for 5 seconds on the server that read it, and is
  asked only before a credential is proved: a bind for such a name is refused as `unknown user` at
  once. A user created on another server within those seconds of a sign-in attempt for its name is
  answered `unknown user` there until they pass.
- After one wait of 250 ms for a lockout count's write runs out, the KDC stops waiting: until a
  count's write lands within 250 ms again, it answers at once and each count it takes is owed and
  tried again about a second later. The sign-in time an issued ticket records for `inactivity-days`
  follows the same rule on its own.
- A user or a second-factor proof written while another write or a short hold had the policy cache's
  lock is now loaded for Kerberos by that holder, or by the filler alone within a quarter of a
  second, instead of waiting for a whole refill. A write of one user no longer copies the whole
  policy cache. A fill lists users 500 at a time, each chunk under its own bound, and no longer
  holds back writes: a user created or changed during a fill is known to the KDC at once.
- 0.8.1's entry on adopted principals is corrected: when sync is turned on, or a user is created
  with sync, for a name that already has a principal, the principal's keys are replaced and with
  them its password expiry is cleared whoever set it, its must-change flag is cleared and its
  Kerberos failure count is set to 0.
- KLLDAP's own policy, lockout, inactivity and log code now keeps time with jiff instead of chrono.
  Stored data and LDAP and GraphQL output are unchanged, with three exceptions at the far edge: a
  log filter time after 9999-12-30T22:00:00Z is refused with an error; a stored time outside the
  years -9999 to 9999 is read as the nearest representable instant; the logged reason for an
  unreadable `inactivity_recording_since` value is worded differently.
- On MySQL and MariaDB the bounded policy read chooses its statement time limit by which of
  `max_statement_time` and `max_execution_time` the server has, asked once, not by the text of
  `SELECT VERSION()`; a server with neither refuses the read.
- A renewal or service ticket asked for a subject whose entry could not be read is refused (Kerberos
  error 18, no text, one `access_denied` row, `the principal could not be read`); MIT goes on with
  such a request.
- kadmin `cpw -e <types>` on a directory user's principal is refused with `BAD_KEYSALTS` (kadmin
  prints `Invalid key/salt tuples`) before anything is derived or written: a directory user's key
  types are the realm's `supported_enctypes`. A change that would leave a key of a type outside
  `supported_enctypes`, or a Kerberos policy name, on such a principal is refused when it is written
  (`BAD_KEYSALTS`, `PROTECT_PRINCIPAL`). Principals that are not directory users keep MIT's
  behaviour.
- A kadmin `cpw` that meets another change to the same principal at the same instant is written,
  from the change prepared once, instead of being refused.
- The gate's upgrade phase from the 0.8.0 pre-release is dropped; the `lldap-cli` phase is
  rewritten; CI builds the kill-points image, checks each package alone, and fails on a call that
  asks jiff for a time zone.

### Fixed

- A Cancel, Close or confirm clicked while a confirmation dialog is still opening now closes it when
  the opening ends, instead of doing nothing until a second click.
- A new token whose row cannot be stored answers HTTP 500; before, the request panicked.
- GraphQL `removeUserFromGroup` on `lldap_admin` answers a failed read of the group or of its
  members as an error and changes nothing. `deleteOu` reads the OU's users and groups before any
  change, and a failed read refuses the delete.

### Dependencies

- kerber-rust v1.2.4-rc.4, a release candidate, replaces v1.2.3, at its tag: `krb5-kdc`,
  `krb5-admin`, `krb5-asn1`, `krb5-config`, `krb5-crypto`, `krb5-gss`, `krb5-log`, `krb5-protocol`,
  `krb5-types` and its `rasn` patch.
- `url` 2.5.9 (RUSTSEC-2026-0592), with `form_urlencoded` 1.2.3.
- RUSTSEC-2026-0594 (`cookie` 0.16, through actix-web 4) is ignored in `deny.toml`: it concerns only
  private (encrypted) cookies, whose jar is not compiled; the server sets plain cookies only.

## [0.8.1] - 2026-11-23

0.8.1 is a pre-release. The new policies and the front end have not yet had thorough testing. Further testing, verification and code review come before it is promoted.

### Security

- A first two-factor enrollment proves the password to the server. **API change for
  scripts:** `startMfaEnrollment` takes a new argument, `enrollmentProof`, and refuses a
  first enrollment without a valid one (*Password proof required*); a session alone is not
  enough. A script obtains the proof from a login that asks for it: `"enrollmentProof": true`
  in the body of `/auth/simple/login` or `/auth/opaque/login/finish` returns `enrollmentProof`
  in the answer, for a user with no factor yet. It is valid for five minutes and used once on
  every server that shares the database (its random id is kept in the new table
  `mfa_used_proofs` at least until a minute past its expiry). Replacing a factor still takes
  `currentCode` and ignores a proof.
- A second factor's attempts and used codes are kept in the database (the new table
  `totp_steps`, no code stored): a code is accepted once and five attempts per 30-second step
  are counted on every server that shares the database, and a restart keeps both. Servers on
  one database need synchronised clocks for codes.

### Added

- `enable_mfa` per OU: the policy item `enable-mfa` (`off`, `enabled`, `always`) sets the second
  factor for an OU's users, by the OU policies' inheritance, wherever `enable_mfa` is not set
  server-wide. One resolution path gives each user's value: the server-wide value if set, else
  the user's OU, else `off`. Every directory door follows it (LDAP bind and
  `/auth/simple/login` ask `password:code` or refuse a user without a factor under `always`;
  the web login asks the code, or admits only to enroll), and so do enrollment (refused as
  *MFA is disabled for this user*), one's own reset, token refresh and use, and the web app
  (the new self-only GraphQL field `User.mfaMode`). A Kerberos ticket on the password alone
  clears a lockout count only where the bind would ask no code. The doors read the value from
  the policy cache only while some OU sets it and nothing is set server-wide; every server reads
  the policies once every 30 seconds, one small read shared with the lockout, and while they
  are not read the directory's doors it concerns refuse (`policy: unreadable`, token refresh
  and use among them) and the read is tried again every second. A policy change applies at once
  on the server that made it and within 30 seconds on the others. Where `enable_mfa` is set
  server-wide, the policy page says that it overrides the OUs (`/settings` gives it as
  `mfa_server_wide`).
- `/auth/opaque/login/finish` takes an optional `"session": false`: the finish confirms the
  password (and a code sent with it), admits or refuses the user as any finish does, and
  makes no session: no token, no refresh token, no cookie. A verified one answers
  `{"verified": true}`, with `enrollmentProof` when one was asked for. Every row it writes
  says `no session` in its detail, whatever the outcome: its one row at the door, and the
  `account_lock` row when a wrong code it carries locks the user. Without the field a finish
  is unchanged. `/auth/simple/login` is unchanged.
- The account lockout is enforced: `lockout-threshold` and `lockout-duration-seconds` from the
  user's OU policy lock a user after that many wrong passwords in a row, at every door (LDAP
  bind, `/auth/simple/login`, the web login, kinit, renewals and service tickets, token refresh
  and use, S4U2Self). One counter per user, in the new table `login_lockouts` (made at start,
  removed with its user), serves them all; kinit's failures are counted there too. A wrong TOTP
  code counts once. A success clears the count; a Kerberos ticket on the password alone does so
  only for a user who need not give a second factor at the directory's doors. An administrator's
  unlock wins over every failure counted before it. A locked user's bind and simple login are
  answered as for a wrong password, at once; the web login's first step as for a name with no
  password; kinit, renewals and service tickets with error 18 before any password is looked at,
  which is not the wrong-password answer and which anyone can ask for. Nothing a locked user
  sends is counted. Counting starts, for all users and from zero, when the first OU policy
  with a threshold takes effect: that change clears every stored count and logged lock in its
  own transaction and starts a new counting period. From then on users with no threshold are
  counted too, so a threshold added to another OU, or a move under one, applies at once (or when
  a refill in progress ends) to the failures already counted; the lock is computed, so lowering
  or raising it applies at once.
- A web start counts at once at every door, beside the stored count, so unfinished starts lock
  as they come; a verified finish, with a session or without, removes its own start's count
  once and changes nothing else, a completed sign-in drops the user's earlier starts on that
  server, and a start no finish removes within 10 seconds joins the stored count, unless its
  id, or the id of a later start made on the same server whose sign-in completed, was stored
  by a finish on another server; with two servers a sign-in whose steps start and finish on
  either never counts against the user. At most 32 starts per user are held; one beyond
  joins the count at once.
- Unlocking: GraphQL `unlockUser(userId)` (admins), the host tool
  `lldap unlock --config-file <config> <user>`, and
  kadmin `modprinc -unlock` on a directory user's principal, which now clears the directory's
  lock at the server's clock. Each writes an `account_unlock` row; a lock writes one
  `account_lock` row, and each refusal a `locked out` row (refusals of the same kind from one
  peer coalesce in a flood, see `docs/logging.md`). An unlock by the host tool or by another
  server takes effect at the directory's doors within a second (a server looks at a held lock
  again at most once a second for each user), and for Kerberos within a moment of the next
  attempt.
- Under a threshold a count is written before the door answers; the door, and the KDC, wait at
  most 250 ms for it in all, and a slower write is owed and tried again. Other counts, and a
  web start's after its 10 seconds, are owed and written within about a second. A clean stop
  writes what is owed, so a sign-in in progress then counts once (the next sign-in clears it);
  a crash or a power cut can lose the last second or so of counts and the
  last 10 seconds of web starts. Each write carries the user's state as it stands, never an
  increment; it stores nothing for a user who is gone or replaced under the same name, or
  from an earlier counting period, and
  a write the database refuses is retried until it is taken (for up to 65,536 users; past that
  the oldest are let go). With several servers on one database each counts what it sees
  exactly, they agree within 30 seconds, and a guesser spread over N servers gets at most N
  times the threshold.
- With no threshold set in any OU, the lockout costs nothing at any door: no read, no write and
  no cache fill. The first threshold set loads what the doors need before it takes effect.
  Until a starting server has read the policies once, the doors refuse (`policy: unreadable`).
- When lockout count writes start failing, the server log says so once at WARN, with the cause;
  when they are stored again, once at INFO, with how many users' rows waited.
- `password-min-length` per OU: the policy item (8 to 128, default 8, by the OU policies'
  inheritance; no server-wide setting) sets the fewest characters, not bytes, of a new or
  changed password; a password already set is never judged. The server holds every password it
  sees to the user's minimum and refuses a shorter one with "the password must be at least N
  characters": `setUserPassword`, LDAP password modify and `userPassword` replace (53), LDAP Add
  with `userPassword` (53, by the OU its DN names), a synced user's web pages and
  `lldap_set_password` (400 at the finish), and kadmin `cpw` on a directory user's principal
  (`PASS_Q_TOOSHORT`). The register start answers the user's minimum in the new optional field
  `password_min_length`, and the pages and the tool refuse a shorter password before the
  finish (*Invalid password. Min length: N*), the only check for a user without sync; a client
  that ignores the field keeps checking 8. The pages and the tool also refuse a password with a
  NUL character, and `lldap_set_password --bypass-password-policy` skips the minimum length
  only, never the NUL check. A policy that cannot be read within 2 seconds, or a stored
  value that is not a whole number, refuses the change ("the password policy could not be
  read; try again"; kadmin `PASS_Q_GENERIC`). The configuration's admin password is still
  checked against 8 only, and the start warns once, naming the minimum and never the
  password's length, when the admin's minimum is higher or cannot be read.
- `login-hours` is enforced. An OU's value (entries `DAY[-DAY] HH:MM-HH:MM` separated by `;`,
  empty for always) is judged at every sign-in door: LDAP bind, `/auth/simple/login`, the web
  login, token refresh and use, kinit, renewals and service tickets. A range may wrap
  (`fri-mon`), `mon-mon` is Monday alone, and `24:00` may end a window. The moment of the
  attempt is read on the wall clock of `login_hours_timezone`; a window admits from its start up
  to its end, to the second, on the wall clock's weekday, and across a change of the clocks only
  the wall-clock times that happen count: a window inside the skipped hour admits at no moment,
  one over the repeated hour admits during both passes. At LDAP bind and `/auth/simple/login`
  it is judged after the password and answered as a wrong password is (LDAP 49,
  `/auth/simple/login` 401 with the same body); the web login judges it when the sign-in starts,
  and a refused user's sign-in fails as a wrong password's does. The KDC refuses before the password
  is checked, with error 18 and no text, so a request for a user's name shows whether some directory
  policy refuses that user. S4U2Self and S4U2Proxy are not judged by it. A refusal at a sign-in door
  is one row, `policy: login-hours (outside login hours)`; a stored value that does not parse
  refuses as `policy: unreadable`, with one server warning naming the policy. A web session is
  refused at every API request while the rule refuses and works again when it no longer does; an
  LDAP connection is judged at its bind only. Where no OU sets it, it costs nothing at any door.
  When a linked policy first sets it, the doors that judge it refuse every user (`policy:
  unreadable`, at the KDC `not loaded yet`) until the policy cache's fill for it succeeds.
- `login_hours_timezone` (default `UTC`; `LLDAP_LOGIN_HOURS_TIMEZONE`,
  `--login-hours-timezone`): the zone `login-hours` is read in, an IANA name read once at start
  from the system's zone files (the directory `TZDIR` names, else `/usr/share/zoneinfo`); `TZ`
  is never read. A name under `right/` or `posix/`, `localtime`, `posixrules`, an unknown name,
  or a file that is not a zone file refuses the start, naming it; the start's log line names the
  zone and its file. A host
  install needs tzdata, and a tzdata update takes effect at the next start. `/settings` gives
  the zone's name as `login_hours_timezone`.
- The host tool `lldap policy-unlink --config-file <config> '<ou>'` removes one OU's policy link
  (the root is `'(root)'` or `""`; quote the key in a shell, as `'people\labs'`), with one
  `policy_change` row, `policy cleared: <name> (lldap policy-unlink)`, in the same transaction; a
  running server sees it within 30 seconds. It is the way back in when an OU's policy refuses
  everyone who could change it: unlink the OU whose policy sets the item, which can be a parent of
  the user's OU or the root. Run the host tools (`lldap unlock`, `lldap reenable`,
  `lldap policy-unlink`) as the user the server runs as, with its configuration
  ([policies.md](docs/policies.md#getting-back-in-from-the-host)).
- The GraphQL `Success` type has the field `warnings: [String!]!`; a client that does not ask
  for it is unaffected.
- `inactivity-days` per OU is enforced: the policy item (0 to 3650, default 0, by the OU
  policies' inheritance) refuses a user with no successful sign-in for that many days, at every
  door (LDAP bind, `/auth/simple/login`, the web login, token refresh and use, kinit, renewals,
  service tickets, S4U2Self and S4U2Proxy). Nobody is exempt. A sign-in counts at the LDAP bind,
  `/auth/simple/login`, the web login's finish, a token refresh and a ticket issued by kinit; a
  renewal or a service ticket does not, so a client that only renews needs a limit longer than
  `renew_lifetime`. The idle time runs from the latest of the last sign-in, the user's creation,
  the moment the item last went from off to on (kept in `system_config`), and the last
  re-enable. Sign-ins are kept in the new table `user_activity` (made at start, removed with its
  user), at most one write an hour per user on each server, and only while some OU sets the
  item; a ticket's sign-in is written off the KDC's thread within 250 ms, or owed: kept while
  this server runs (at most 65,536) and written once the database answers. LDAP bind and
  `/auth/simple/login` refuse only after the password is right, and answer exactly as for a
  wrong password; the web login judges every policy item when the sign-in starts, and a refused
  user's sign-in fails as a wrong password's does; Kerberos answers error 18 with no text. The row
  says `policy: inactivity-days (inactive)`. A rule that cannot be read (a value that does not
  parse, with one warning in the server log, or `inactivity_recording_since` or `user_activity` that
  cannot be read as the server starts or the item is linked) refuses with `policy: unreadable` every
  sign-in it would judge; a user whose OU sets 0 or nothing signs in as usual. The server reads
  again about every second, every five seconds after ten failed tries, and `lldap policy-unlink`
  takes the rule off from the host.
- Re-enabling: GraphQL `reenableUser(userId)` (admins) and the host tool `lldap reenable
  --config-file <config> <user>` restart a user's inactivity count now (or when a refill in
  progress ends). Each writes one row of the new log kind `account_reenable`
  (`ACCOUNT_REENABLE` in GraphQL), detail `reenableUser` or `lldap reenable`, in its own
  transaction. A running server sees the host tool's re-enable within 30 seconds.
- `allowed-networks` per OU is enforced: the policy item (comma-separated CIDRs, empty = any, by
  the OU policies' inheritance) refuses a sign-in from outside the list at the LDAP bind,
  `/auth/simple/login`, the web login, token refresh and use, kinit, renewals and service tickets;
  a service's S4U2Self or S4U2Proxy request for the user is not judged by it. Host bits of an entry
  are ignored, an IPv4 address seen over IPv6 counts as IPv4, and a request with no address is
  refused under a non-empty list. LDAP and Kerberos judge their socket's peer, HTTP its TCP peer
  or, behind a listed proxy, the forwarded address. LDAP bind and `/auth/simple/login` refuse
  only after the password is right, and answer exactly as for a wrong password; the web login
  judges it when the sign-in starts, and a refused user's sign-in fails as a wrong password's
  does. Kerberos refuses before the password is checked, with
  error 18 and no text, so a request for a user's name shows whether some directory policy
  refuses that user. The row says `policy: allowed-networks (address not allowed)` and keeps
  `peer` and `forwarded_for` as they came; a value that cannot be read refuses with
  `policy: unreadable` and one warning in the server log. When a linked policy first sets a list,
  the doors that judge it refuse every user (`policy: unreadable`, at the KDC `not loaded yet`)
  until the policy cache's fill for it succeeds. Behind Docker's published ports the server may
  see one address, the bridge gateway, for every client, and a list then admits everyone or no
  one: check `clientAddress` (shown on the policies page) before you save a list
  ([allowed-networks.md](docs/allowed-networks.md#behind-dockers-published-ports)).
- `trusted_proxies` (`LLDAP_TRUSTED_PROXIES`, `--trusted-proxies`; empty by default): one string
  of comma-separated CIDRs naming the reverse proxies whose `X-Forwarded-For` the
  `allowed-networks` item believes, read from the right to the first address that is no listed
  proxy; an entry on the way that is not a bare address leaves the client's address unknown, which
  a non-empty list refuses, and a listed proxy that sends no header is itself the client. The
  `Forwarded` header is not read. A bad entry refuses the start, naming it.
- GraphQL `clientAddress`, for any signed-in user: the address the server judges for that request,
  after `trusted_proxies`, or null when it has none.
- `updatePolicy`, `setOuPolicy`, `setOuPolicyInheritance`, `clearOuPolicy` and `deletePolicy`
  return `warnings` (a new field of `Success`, empty for every other mutation): one warning when,
  after the write, the author's own `allowed-networks` list refuses the address the server sees the
  author as (`unknown` when it has none). The warning names the way back,
  `lldap policy-unlink --config-file <config> '<ou>'` with the OU whose policy sets that list. The
  write is never refused for it.
- The web app's policy and user pages. The policy editor shows the zone `login-hours` is judged in
  and the address the server sees the admin as (`unknown` when it has none). A save shows its
  `warnings` under the success line, and when the page's next request is then refused, one line
  says so and names `lldap policy-unlink` as the way back. The inactivity item reads "Inactivity
  limit (days)", and a limit of 0 reads `off`. On a user's page an admin sees "Locked until …" or
  "Inactive since …", with an Unlock or a Re-enable button only for that state, read from the new
  admin-only GraphQL field `User.signInState` (`locked`, `lockedUntil`, `inactive`,
  `inactiveSince`; answered under `user(userId)` only, null in a list of users and for every
  other asker, read-only admins included). When that read fails,
  both buttons show. The result line ("Unlocked …", "Re-enabled …") lasts until the next action.

### Removed

- The `syncKerberosPassword` mutation. A synced user's password now travels sealed inside
  `/auth/opaque/register/finish`. The `kerberosInfo` query stays.

### Changed

- Upgrading from the 0.8.0 pre-release: stop every server that uses the database before the
  first 0.8.1 start, and do not run the two side by side
  ([install.md](docs/install.md#upgrading-from-klldap-080)); at that start, policies stored with
  `require-mfa` are carried over as `enable-mfa` (`enrolled` becomes `enabled`) and enforced from
  then on, the start warns once with how many OUs set it to `enabled` or `always` with no
  server-wide `enable_mfa` over them, and 0.8.0's `enable_mfa` values `false` and `true` still
  read as `off` and `enabled`.
- **kinit needs a fresh proof under `enabled` and `always`.** A directory user who must
  give a second factor at the directory's doors gets a Kerberos ticket only within
  `kerberos_options.mfa_proof_window` (default 10 minutes) after a sign-in at a directory
  door with the password and a code (an LDAP bind or `/auth/simple/login` with
  `password:code`, the web login's code step, or an enrolment's or a replacement's
  finish). Otherwise kinit is refused with error 12 and a text that says what to do, one
  `login` row `policy: enable-mfa (no fresh proof)`, and nothing counted. Renewals and
  service tickets are judged by the time their ticket was issued: a ticket issued outside
  every window is refused at its next renewal or service ticket. Services
  acting for users (S4U2Self, S4U2Proxy) are not asked. The windows are kept in the new
  table `mfa_windows` (made at start), shared by every server, for the longer of the ticket
  and renewable lifetimes and an hour, and end with a reset or a replacement of the factor;
  `kerberos_options.mfa_proof_same_address` ties a kinit to the address the code was given
  from.
- `enable_mfa` takes `off`, `enabled` or `always`. A value written in the file, the environment
  or the command line is explicit and overrides every OU's `enable-mfa`, so **an explicit `false`
  now keeps every OU from turning the factor on**: remove the line to let the OUs decide. Left
  unset, it is `off` until an OU says otherwise.
- The policy item `require-mfa` (`off`, `enrolled`, `always`) is now `enable-mfa` (`off`,
  `enabled`, `always`). `createPolicy` and `updatePolicy` given `require-mfa` are refused with a
  message naming `enable-mfa`.
- `lldap_mfa_disabled` is created the first time a value is known to turn the factor on: at
  start for a server-wide `enabled` or `always`; otherwise by whichever server first reads an
  OU's `enable-mfa` above `off` (at start, at the policy change, or at its 30-second read),
  never while the policies are not read. It is protected only while a value can turn the
  factor on; an install that sets nothing stays plain LLDAP, with no such group.
- The web login asks for the code in a second step: the password alone first, then, when
  the account has a factor, a code field; a wrong code keeps that step open. The password
  field no longer takes `password:code` (that text fails as a wrong password, and the page
  says the code is asked next). LDAP binds and `/auth/simple/login` still take
  `password:code`.
- The enrollment, reset-two-factor and change-password pages confirm the password with a
  finish that makes no session, and each finishes every login it starts.
  The change-password page checks the current password as typed, once: it no longer splits
  off a trailing `:` and six digits as a code.
- kadmin's unlock writes its `kerberos_sync` row as `kadmin unlock by <client>`.
- A deleted user's Kerberos ticket requests are refused for every kind of request, delegation and
  user-to-user included; renewals and service tickets keep their answer (code 18,
  `CLIENT_NOT_FOUND`).
- The web pages (change password, the e-mail reset, create user) and `lldap_set_password` set
  a `kerberossync` user's password in one request: the register/start answer carries the
  sealing key (`kerberos_envelope_key`) only for such a user, the finish carries the password
  sealed with RSA-OAEP-SHA-256 under the label `klldap-kerberos-envelope-v1:<user id>`
  (`kerberos_password_envelope`), and the server registers it itself, changing the directory
  record and the Kerberos keys in one transaction. An envelope sealed for another user, or
  sent for a user without sync, is refused (400) and nothing is written. Every other user's
  register calls are LLDAP's, and their pages send no password to the server.
- A synced user's password from the web pages or `lldap_set_password` must be at least the
  user's minimum (8 by default) in characters (400). The pages and the tool check that minimum
  for every user, counting characters.
- The create-user page refuses a password longer than 318 bytes for a user with Kerberos sync
  before it creates the user.
- `lldap_set_password` prints the server's answer when a call fails.
- A password with a NUL character (U+0000) is refused at every door that checks its length:
  GraphQL, LDAP (53), the web finish (400), `lldap_set_password` (before it sends), kadmin
  `cpw` (`PASS_Q_GENERIC`), the forced reset and the first start's admin password (the
  start is refused). Each change refused at GraphQL, LDAP, the web finish or kadmin writes
  one failure row, the web finish's envelope refusals included.
- A `kerberossync` change, a delete and a synced user's password change check the switch in the
  transaction that writes; one that finds it changed writes nothing and answers "the user's
  Kerberos sync changed; try again". A password change of a user without sync waits for the
  realm's other writes, reads the switch again, and answers the same if it is on now.
- Kerberos disabled in the configuration is its own state: turning the switch off and deleting
  a user change the directory alone (a `kerberos_sync` row says a principal, if there is one, is
  left for the start pass, which removes it at the next start with Kerberos); turning it on,
  creating a user with it on ("Kerberos is disabled; create the user without Kerberos sync")
  and a synced user's password change ("enable Kerberos, or turn the user's Kerberos sync off
  first") are refused. With the realm not ready, every change that needs it answers "retry
  shortly", and the web finish refuses before it opens the envelope.
- The create-user page shows no Kerberos switch and sends no `kerberossync` when the server has
  Kerberos disabled (if the page cannot read that, it shows the switch, and the server refuses
  a create with sync; `kerberosInfo { enabled }`, new).
- An adopted principal keeps its fields except its Kerberos password policy, which is cleared
  (next entry); its keys are replaced with random ones, the old ones dropped, and it is marked
  and disabled. A create with the switch on adopts the principal of its name too; an LDAP ADD
  with a password sets both forms and marks it. Right after a kadmin `cpw`, a change of its own
  sets the principal's status from `lldap_disabled`: an adopted principal is enabled then,
  unless its user is in `lldap_disabled`. Deleting a user without sync touches no principal.
  Sync on at `createUser` is refused for a name that is an alias, as at `updateUser`.
- **For a directory user, the OU policy's `password-min-length` is the rule; a Kerberos password
  policy no longer applies on top.** An adoption (sync turned on, a create with sync, an LDAP
  ADD with a password, the start's mark) clears the principal's Kerberos policy in the same
  transaction, with one `kerberos_sync` row, `Kerberos password policy <policy> cleared from
  <principal>: the directory's password-min-length applies`; the password expiry that policy
  set goes with it. The start pass clears it once from every principal adopted before,
  one row each; a clear that cannot be written is a warning, and the next start tries again.
  The policies stay, and so do the bindings of principals the directory does not own. An LDAP
  ADD whose password adopts a bound principal is still judged once by that policy; create the
  user without a password, or `modprinc -clearpolicy` first.
- A change of `lldap_disabled` membership is never refused because Kerberos is disabled or not
  ready. With Kerberos disabled in the configuration, or the realm not ready, it changes the
  directory alone with a `kerberos_sync` row saying the principal's status is left for the start
  pass. Whenever the realm opens (each start, before the KDC serves, and a reload after a failed
  write), every marked principal of a user with sync takes its status from `lldap_disabled`,
  with one `kerberos_sync` row for each principal changed. With the realm ready, a user with
  sync has the membership, its log row and the principal's status written in one transaction:
  all of them, or none and one failure row. On the holder every such change waits for the
  realm's other writes and reads the user's sync again first.
- With Kerberos enabled, only the server that holds the realm changes a password, with or
  without sync: a degraded server, or one that lost the realm, answers "try again" (LDAP 52,
  HTTP 503, a GraphQL error) with one failure row, before it derives, opens or writes anything;
  a server still watching beside a holder answers nothing, and exits after the watch. The holder
  answers "try again" too while the answer to its last write is lost and not yet settled by the
  read-back, a reload or the next heartbeat; in that window it also answers "try again" to a sync
  change and to a synced user's create, delete and `lldap_disabled` change, while every user
  still binds and signs in and other directory changes go on. A plain change whose derive or
  store fails writes one failure row too. An LDAP ADD with a password for a user without sync
  answers the same (52) while the realm is not ready.
- `force_ldap_user_pass_reset` is upstream's break-glass again and runs whatever Kerberos does:
  with the realm open it waits for it, and sets a synced admin's keys in the same transaction;
  when Kerberos cannot take part (disabled, the realm does not open, reconcile or the start
  pass fails, or the reset with the realm fails), it resets the directory password and turns a
  synced admin's Kerberos sync off in the same transaction, with one `kerberos_sync` row and a
  warning at start, and the server starts, degraded if the realm is not usable. When the realm
  is usable the start pass runs again before the KDC serves, so the admin's old Kerberos
  password gets no ticket from it. A server that finds another one holding the realm runs it
  so, then exits. Only a configured password under 8 characters or with a NUL refuses the start.
- A failed reconcile or start pass leaves the server degraded and still holding the realm, and
  is named as such in the log, `/health`, the forced reset's warning and its row; "did not
  open" stays for a realm that did not open. A realm found lost before its KDC starts never
  serves.
- At a start the KDC and kadmind bind their ports when the realm opens, but answer only after
  the status pass, reconcile, the start pass and a forced reset: a request that arrives
  meanwhile waits, and is answered from the new state. A server that takes the realm over
  starts the same way.
- The server that holds the realm sets each marked principal's status from `lldap_disabled`
  every 60 seconds too, from one read of the group's members with sync; only differences are
  written, one `kerberos_sync` row each, in the transaction of its status, and a pass that fails
  is tried again at the next. It also removes a marked principal whose user is gone or no
  longer has sync, one row each, so its old password stops working within a minute. The start
  pass writes each chunk's rows in that chunk's transaction too.
- Turning sync from off to on adopts any principal of the user's name, one the directory made
  included: random keys, disabled until its status is set from `lldap_disabled` by the holder's
  next status pass (within a minute), the next password change, a kadmin `cpw` or the next
  opening of the realm; its random keys take no password. Turning it on when it is already on
  changes nothing.
- Every server on one database needs the same `kerberos_options.enabled`; a server started with
  Kerberos disabled beside a realm marked open logs one warning saying what that means, and that
  it is harmless on a lone server.
- The user details page shows the Kerberos switch, while the server has Kerberos disabled, only
  for a user whose sync is on, so that it can be turned off.

- A `kerberossync` user's password change through GraphQL `setUserPassword`, LDAP Modify
  `userPassword`, `ldappasswd` or LDAP ADD writes the directory record, the Kerberos keys and
  its one `password_change` row in one transaction; no `kerberos_sync` row is written for it.
  An LDAP ADD with a password makes the entry and its principal together or not at all, and
  answers 52 when the KDC is offline.
- That password change also sets the principal's status from `lldap_disabled`, read once the
  change holds the write lock: a disabled principal of an enabled user is enabled, and an enabled
  principal of a disabled user is disabled.
- KLLDAP's copies of the plaintext password of a GraphQL `setUserPassword`, an LDAP Modify
  `userPassword`, an `ldappasswd` and an LDAP ADD are wiped when the request ends. So are the
  decoded LDAP request's own copies, on every exit, a refusal included: the `userPassword`
  values of a Modify or an ADD, and the encoded value of an `ldappasswd`. The copies the LDAP
  library makes while it decodes a request, and the buffers the LDAP and HTTP libraries fill
  while reading one, are not wiped.
- Every item of the policy catalog is enforced, so the policies page no longer shows a notice
  that values are not enforced yet.
- A read-only admin can read policies, the item catalog, effective items and OU policy
  states. Every policy write stays admin-only.
- `clearOuPolicy` and `effectivePolicyItems` refuse an OU that is not registered
  (`Unknown OU`).
- The Kerberos realm's watch is thirty-five seconds (thirty in 0.8.0). A server that finds
  the realm left open watches it that long before it takes it over, and a holder gives the
  realm up within thirty seconds of the start of its last write that reached the database,
  then exits.
- A lost answer to the realm's first commit is probed: the server inserts the realm row's key
  in a transaction it rolls back, for sixty seconds (about seventy-five from the commit's
  start). The commit counts as landed only when the row holds this server's own realm and
  realm record; a row another server created first is answered "another server created the
  realm first", and this server stops.
- An empty password is refused at sign-in: an LDAP bind with a name and no password answers 53
  (unwillingToPerform), and the simple login answers as any failed sign-in; `lldap_set_password`
  and the pages refuse an empty password.
- A password-reset finish registers only the reset token's own user.
- The exempt group `lldap_mfa_disabled` is compared by its exact name at every door, in the
  policy cache and at its creation, on every database. A group whose name differs from it only
  by case exempts nobody, `lldap_mfa_disabled` is not made beside it, and every start warns that
  while it exists nobody is exempt. While protected, such a group takes one rename only: to
  exactly `lldap_mfa_disabled`, after which its members are exempt; that rename's `group_update`
  row says how many (`members exempt from MFA: <n>`).
- A service's S4U2Self and S4U2Proxy requests, at the AS and at the TGS, are judged at one door,
  shown as `kerberos S4U`; a refusal there names the asking service, `(S4U2Self by <service>)`
  or `(S4U2Proxy by <service>)`.
- When an OU policy turns the lockout on and its first read fails, the doors the lockout judges
  refuse until a read succeeds.
- After a right password, the OU policy items are judged before a second factor or an enrolment
  is asked for, at the LDAP bind and `/auth/simple/login`, and again with the code; the web login
  judges them when the sign-in starts. An attempt they refuse gets the wrong-password answer and
  its one refusal row, and is not counted toward the lockout.

### Fixed

- A read of a user's OU policy that has not answered within 2 seconds (a locked `ou_policies`
  or `policies` table, say) no longer waits for as long as the lock lasts while holding one of
  the server's database connections: a sign-in, token refresh or token use is refused as
  `policy: unreadable`, and the policy cache takes a user's change at its next read instead.
- The policies page no longer fails on its first render while its data loads.
- The password pages show the server's reason when setting a password fails.
- A kadmin password change that kadmind could not prepare is refused and can be retried,
  instead of being prepared while the KDC waits.
- The verbose HTTP log records the request path without its query string.

### Dependencies

- kerber-rust v1.2.3 replaces v1.2.2, at its tag: `krb5-kdc`, `krb5-admin`, `krb5-asn1`,
  `krb5-config`, `krb5-crypto`, `krb5-gss`, `krb5-log`, `krb5-protocol`, `krb5-types` and its
  `rasn` patch.
- jiff 1.0.1 is new, built with its `std` feature only: `login-hours` is judged with it in the
  `login_hours_timezone` zone. It adds five entries to `Cargo.lock`: jiff, jiff-core and
  jiff-static 1.0.1, portable-atomic 1.15.0 and portable-atomic-util 0.2.8. The x86_64 and
  aarch64 builds compile jiff and jiff-core only: jiff-static serves jiff features that are
  not turned on, and portable-atomic and portable-atomic-util serve only targets without
  pointer-sized atomics.
- actix-http 3.21.3 and lettre 0.11.24, for the RustSec advisories published for both in
  November 2026.

## [0.8.0] - 2026-11-15

0.8.0 is a pre-release. The new policies and the front end have not yet had thorough testing. Further testing, verification and code review come before it is promoted.

Next release. The KDC is kerber-rust inside the `lldap` process.
0.7.4, 0.7.5 and 0.7.6 were never released, and their work is in 0.8.0.
KLLDAP 0.8.0 is 64-bit only (x86_64 and arm64); there is no 32-bit or ARMv7 build. Release tarballs are x86_64 and aarch64; earlier releases' recipe also built ARMv7.

### License

- KLLDAP is GPL-3.0-only again, the license LLDAP uses; `cargo deny` gates third-party licenses.

### Dependencies

- kerber-rust v1.2.2 (`krb5-kdc`, `krb5-admin`, `krb5-config`, `krb5-types`, `krb5-crypto`,
  `krb5-log`, `krb5-protocol`) is a git dependency at its tag and is the KDC inside the
  server. Its `rasn` patch is carried in `[patch.crates-io]`, and `.cargo/config.toml` sets
  `--cfg p384_backend="fiat"` so P-384 uses p384's constant-time field.
- `lldap_mfa` moves to hmac 0.13 and sha1 0.11, kerber-rust's RustCrypto generation. sha2
  0.10, hmac 0.12 and digest 0.10 remain, pinned by `opaque-ke` 4, `rsa` 0.9, `jwt` 0.16 and
  `sqlx` 0.8; `sqlx` also keeps sha1 0.10 and md-5 0.10.
- The browser's Kerberos password envelope (RSA-OAEP, SHA-256) moves to `rsa` 0.10 in the server
  and the app, whose constant-time code fixes RUSTSEC-2023-0071 (the Marvin timing attack).
  The wire format is unchanged. `sqlx-mysql` keeps its own `rsa` 0.9, which only encrypts to
  a MySQL server's public key. The key is 3072 bits (rsa 0.10's default) and is made at start
  in the background; a password set through the web UI is bounded at 318 bytes by the
  envelope.
- actix-web is built without its `http2` feature and without `compress-brotli`,
  `compress-gzip` and `compress-zstd`. The web port was already HTTP/1.1 only, and
  nothing of ours sends a compressed request, so clients see no change. `h2` leaves
  the lock, and RUSTSEC-2026-0258 with it. A precompressed `.wasm.gz` response is
  unchanged: the handler sets that header itself.
- `actix-files` 0.7.4 replaces 0.6.10. The wasm handlers call `NamedFile::open`.
  RUSTSEC-2026-0443, the Windows short-name ignore, leaves with 0.6.

### Configuration

- `smtp_options.tls_root_cert_file` (`LLDAP_SMTP_OPTIONS__TLS_ROOT_CERT_FILE`) is an
  optional PEM of the CA certificate(s) that signed the SMTP server's certificate,
  added to the roots compiled into the server. A self-signed server certificate that
  is itself marked as a CA (what `openssl req -x509` makes by default) is refused as
  a server certificate, so sign the server's certificate with that CA. Unset, nothing
  changes. A missing, unreadable, or empty file refuses the start and names the
  setting. The `_FILE` form is refused: the key is the path itself.
- `ticket_lifetime` and `renew_lifetime` take a Kerberos duration (`24h`, `7d`,
  `36000s`) or a bare number of seconds (`36000`), quoted or not, in the file
  or the environment. Zero and a negative stay refused.
- New `[kerberos_options]` section (`LLDAP_KERBEROS_OPTIONS__*`): `enabled`, `realm`,
  `ticket_lifetime`, `renew_lifetime`, `forwardable`, `client_case_fold`,
  `supported_enctypes`, `kdc_host`, `kdc_port`, `kadmin_host`, `kadmin_port`,
  `kadmin_acl`, `data_dir`, `admin_keytab`, `client_config`. Durations are
  checked at startup and must be positive: to the KDC a zero `ticket_lifetime` means no
  limit, and a zero `renew_lifetime` means no renewal.
  `renew_lifetime` is also the KDC's longest renewable life.
- `kerberos_options.enabled` defaults to `true`: `lldap run` starts the realm unless it is
  set to `false`. The image no longer sets it.
- `kerberos_options.enabled` replaces `healthcheck_options.kerberos`
  (`LLDAP_HEALTHCHECK_OPTIONS__KERBEROS`) and the `healthcheck --kerberos` flag
  (`LLDAP_KERBEROS_HEALTHCHECK`), which are removed: it gates the Kerberos sync, makes
  directory writes wait for the KDC after boot, and adds the KDC to the healthcheck. A compose
  file that overrides the healthcheck with `--kerberos` must drop the flag.
- `LLDAP_KERB_REALM_NAME` is removed; use `kerberos_options.realm`. It now warns as unknown.
- Renamed during 0.8.0's development, to follow LLDAP's shape (`ldap_host`, `ldap_port`):

  | Old name | New name |
  |---|---|
  | `kerberos_options.kdc_bind` (`LLDAP_KERBEROS_OPTIONS__KDC_BIND`) | `kerberos_options.kdc_host` (`LLDAP_KERBEROS_OPTIONS__KDC_HOST`) |
  | `kerberos_options.kadmin_bind` (`LLDAP_KERBEROS_OPTIONS__KADMIN_BIND`) | `kerberos_options.kadmin_host` and `kerberos_options.kadmin_port` (`LLDAP_KERBEROS_OPTIONS__KADMIN_HOST`, `LLDAP_KERBEROS_OPTIONS__KADMIN_PORT`) |
  | `kerberos_options.kadmin_acl_file` (`LLDAP_KERBEROS_OPTIONS__KADMIN_ACL_FILE`) | `kerberos_options.kadmin_acl` (`LLDAP_KERBEROS_OPTIONS__KADMIN_ACL`) |
  | `kerberos_options.keycloak_keytab` (`LLDAP_KERBEROS_OPTIONS__KEYCLOAK_KEYTAB`) | `keycloak_options.keytab` (`LLDAP_KEYCLOAK_OPTIONS__KEYTAB`) |

  `kerberos_options.max_renewable_life` is removed; `renew_lifetime` takes its place. The old
  names warn and are ignored: an environment variable as "Unknown environment variable", a
  key in the configuration file's `[kerberos_options]` or `[keycloak_options]` as "Unknown
  key in the configuration file".
- `supported_enctypes` takes one type name per item: `["aes256-cts-hmac-sha1-96",
  "aes128-cts-hmac-sha1-96"]` in the file, `[aes256-cts-hmac-sha1-96, aes128-cts-hmac-sha1-96]`
  in the environment. A family name such as `aes` or `default`, a `+` or `-` prefix, or two
  names in one item is refused at startup, naming the item.
- The path keys take the path itself, never a file holding it:
  `LLDAP_KERBEROS_OPTIONS__{DATA_DIR,ADMIN_KEYTAB,CLIENT_CONFIG,KADMIN_ACL}_FILE`,
  `LLDAP_KEYCLOAK_OPTIONS__{KEYTAB,CONFIG_FILE}_FILE` and the same `_file` keys in the
  configuration file stop the start, naming the variable or key.
- `[keycloak_options]` holds `config_file` (default `keycloak_config.toml`,
  `LLDAP_KEYCLOAK_OPTIONS__CONFIG_FILE`; the image sets
  `/data/keycloak_config.toml`), `keytab` (default `keytab/keycloak-http.keytab`,
  `LLDAP_KEYCLOAK_OPTIONS__KEYTAB`; the image sets `/data/keytab/keycloak-http.keytab`)
  and `admin_pass` (no default,
  `LLDAP_KEYCLOAK_OPTIONS__ADMIN_PASS`, or `LLDAP_KEYCLOAK_OPTIONS__ADMIN_PASS_FILE`
  for a file; if both are set, the plain value wins). `LLDAP_KEYCLOAK_CONFIG` and
  `LLDAP_KEYCLOAK_ADMIN_PASS` now warn as unknown and are ignored. An operator who
  keeps the old admin password gets a realm push that fails with "admin password is
  not set".
- `keycloak_config.toml` is saved through a temp file, synced, and renamed
  over the target, so a power cut during a save cannot leave it empty or
  short. The save needs write permission on its directory and cannot
  replace a single-file bind mount.
- `config_file` stays exempt from the file provider, with `key_file` and
  `cert_file`. The exemption matches that name at any depth, so a
  missing `LLDAP_CONFIG_FILE` starts the server on defaults, the same as a missing
  `--config-file`.
- `LLDAP_KERB_ADMIN_KEYTAB` is `kerberos_options.admin_keytab` (default
  `kadm5.keytab`). `LLDAP_KERB_KDC_DIR` is `data_dir` (default `krb5kdc`).
  `LLDAP_KERB_KDC_PORT` is `kdc_port` (default `1088`), with
  `kdc_host` (default `0.0.0.0`), `kadmin_host` (default `127.0.0.1`) and
  `kadmin_port` (default `1749`).
  `LLDAP_KERB_KRB5_CONF` defaulted to `/etc/krb5.conf`. It and
  `LLDAP_KERB_KRB5_TEMPLATE` are `client_config` (default `krb5.conf`).
  `/etc/krb5.conf` is no longer written. The image sets these paths to
  `/var/kerberos/krb5kdc`, `/data/kadm5.keytab`, `/data/keytab/keycloak-http.keytab`
  and `/data/krb5.conf`, and tools inside the container need
  `KRB5_CONFIG=/data/krb5.conf`. `LLDAP_KERB_KEYCLOAK_KEYTAB` is `keycloak_options.keytab`
  (default `keytab/keycloak-http.keytab`). `LLDAP_KERB_KADM5_ACL` and
  `LLDAP_KERB_KADM5_ACL_TEMPLATE` are `kadmin_acl` (no default;
  `admin/admin@REALM *` is always granted). `LLDAP_KERB_CONFIG`,
  `LLDAP_KERB_CONFIG_TEMPLATE`, `LLDAP_KERB_KDC_CONF`, `LLDAP_KERB_KDC_TEMPLATE` and
  `/data/kerberos_config.toml` are gone. Every one of those old names warns as unknown
  and is ignored.

### Kerberos

- The KDC and kadmin run inside `lldap`. `kerberos_manager`, `krb5kdc` and `kadmind`
  are not started. The admin keytab is rewritten at every boot at mode 0600; keep
  `/data/kadm5.keytab` out of any backup that is not secured as tightly as the
  machine itself. `data_dir` is mode 0700.
- A data directory created at first start is synced, so a power cut right after
  cannot lose it.
- A 0.7.2 realm moves over on the first start from a `principal.dump` written with the
  0.7.2 image (`kdb5_util dump`, see docs/kerberos.md); its MIT files are kept in
  `mit-db2.bak/`. Without a dump, or with a dump for another realm or without its
  stash, the realm does not open and the cause says why. A database lost after a
  migration is reported, not replaced by a new realm.
- A Kerberos thread that dies stops the server with a non-zero exit. Without a
  restart policy the container stays down.
- kadmin is no longer reachable from outside the container. It listens on
  `127.0.0.1:1749` and is used with `docker exec`. The image sets
  `KRB5_CONFIG=/data/krb5.conf`.
- **The KDC listens on 1088. Publish it as `88:1088` (tcp and udp). A 0.7.2
  compose file that publishes `88:88` must change, or the KDC is unreachable.**
  kadmin is not published. Clients outside use port 88. Tools inside the
  container use the `krb5.conf` the server writes, which carries 1088.
- The image no longer installs `krb5-server` or ships `kerberos_manager`.
  `krb5-libs` and `krb5-workstation` stay.
- A root start repairs ownership and `gosu` runs the server as `UID`:`GID`
  (default 1000). `LLDAP_UID` and `LLDAP_GID` still work and win when set.
  No capability is passed to the server. `tini` is the init. `--user` on the
  standard image fails, because `gosu` cannot switch user without root. The
  rootless image starts as user `lldap` and does not change ownership.
- The rootless image is published under `aelieth/klldap:0.8.0-rootless`, for the same platforms as the default image.
- The entrypoint no longer waits or prints "LLDAP is ready!". `tini` is the
  container's first process and forwards `docker stop` to the server.
- The image no longer declares `749` in `EXPOSE`. It declares `1088`.
- `supported_enctypes` accepts `aes256-cts-hmac-sha1-96`, `aes128-cts-hmac-sha1-96`,
  `aes256-cts-hmac-sha384-192` and `aes128-cts-hmac-sha256-128`. `des3-cbc-sha1`, `arcfour-hmac` and
  their aliases are refused as deprecated (RFC 8429 section 7,
  https://www.rfc-editor.org/rfc/rfc8429). `camellia128-cts-cmac`,
  `camellia256-cts-cmac` and the `camellia` family are refused because the embedded
  KDC does not serve them; MIT does not mark Camellia deprecated
  (https://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html). `des-cbc-crc`
  and `des-cbc-md5` are not encryption types this KDC knows. The shipped
  default remains `aes256-cts-hmac-sha1-96`, and `allow_rc4` / `allow_des3` stay
  off (MIT's default,
  https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html).
- The `krb5.conf` the server writes and the Keycloak keytab follow `supported_enctypes`;
  the keytab holds one key per listed type.
- When the first type of `supported_enctypes` changes, the next start rolls the keys of
  `krbtgt/REALM`, `kadmin/admin` and `kadmin/changepw` to the listed types and keeps the old
  ones, so tickets issued before the change still work. The old key versions are purged once
  `ticket_lifetime` plus `renew_lifetime` has passed, at a start or by the hourly cleanup. A
  roll that fails leaves the realm closed with the cause, as for any realm that does not open.
- At every start, `krbtgt/REALM` and every synced principal take `ticket_lifetime` as their
  longest ticket life and `renew_lifetime` as their longest renewable life. A principal that
  already matches is not written.
- A ticket issued before a user was disabled or deleted stops at the next
  ticket-granting request.

### Database

- SQLite now runs with `synchronous = EXTRA` (it was FULL), so a change the server has
  acknowledged survives a power loss: in SQLite's rollback-journal mode, FULL can roll the
  last transaction back at the next start
  (https://www.sqlite.org/pragma.html#pragma_synchronous).
- With the realm enabled, the server reads PostgreSQL's `fsync`, `full_page_writes` and
  `synchronous_commit`, and MySQL's and MariaDB's `innodb_flush_log_at_trx_commit` and
  `sync_binlog`, at start, and logs a `database durability` warning for an unsafe one. On
  PostgreSQL with no warning, an acknowledged change survives a power loss too; MySQL and
  MariaDB are not power-cut tested.
- A power cut may forget lockout changes from the last few minutes, as MIT's does. The
  realm still opens.
- On MySQL and MariaDB schema changes are not transactional (the server commits at each DDL
  statement), so take a backup before the first 0.8.0 start; if a start is interrupted
  mid-migration the next start completes it.
- MySQL and MariaDB support is newly tested in 0.8.0: the migrations, the
  Kerberos tables, kerber-rust's conformance suite, a kill of the server after
  an acknowledged write, and two servers on one database, on MySQL 9.7 and
  MariaDB 12.3.
- On MySQL and MariaDB the new time columns are `datetime(6)`. A MySQL name
  equal to its canonical name ignoring case is kept.

### Fixed

- LDAP Modify and ADD refuse a `userPassword` that is not valid UTF-8, with
  `constraintViolation`. A refused ADD creates no user.
- GraphQL gives Kerberos the directory's user id, so `Alice` and `alice` name the same principal.
- A failed Kerberos password sync is an error. A disabled user is put back after that failure.
- `kerberos_options.client_case_fold` (default true) lets `kinit Alice` sign in as `alice`, as an
  LDAP bind does; service tickets for that client follow the same lookup. `false` keeps MIT's
  exact names.
- The healthcheck reaches the KDC at `kdc_host` (loopback when it is `0.0.0.0` or `::`), not at
  `healthcheck_options.ldap_host`.
- `LLDAP_RAW_LOG` no longer warns as an unknown environment variable.
- The Keycloak realm push and the suggested Keycloak URL use the configured
  base DN, also when it is set only in the configuration file.

### Security

- A failed password-reset email logs the reset token at debug, not info. The
  warning that the send failed, and the failed `password_reset_request` row, stay.
- GraphQL refuses a mutation sent by GET. Queries by GET still answer, so send
  mutations by POST.
- A password manager may call `setUserPassword` for a non-admin, the same rule as
  the LDAP password doors.

### Performance

- OPAQUE key stretching for a cleartext bind or a password set runs on the blocking
  pool, at most four at once. Four at once is about 200 MB.

## [0.7.6] unreleased

### Organizational-unit policies

- Named policies of items can be attached **one per OU**, including the domain root. Closest
  wins; an OU may block inheritance (the root cannot). The v1 catalog is six user-scope
  items (`require-mfa`, lockout threshold/duration, login hours, allowed networks,
  inactivity days), all marked not yet enforced — nothing is checked at login or bind.
  Admin GraphQL: `policies`, `policy`, `policyItemCatalog`, `effectivePolicyItems`,
  `ouPolicyStates`, and the create/update/delete/set/clear/inheritance mutations. Writes
  record `policy_change`. `/settings` exposes `domain` from the LDAP base DN (e.g.
  `example.com`). See `docs/policies.md`.
- Web app: **Policies** in the admin navbar (`bi-journal-check`) — a single workbench
  page: an OU tree with per-policy colored chips (solid = set here, dashed = inherited,
  stop icon = blocked) beside an inspector that attaches/swaps/clears the one policy
  per OU, toggles inheritance, edits policies in place with tick-to-set catalog rules,
  and always shows the server-resolved effective items. The former **All** label is the
  uppercase domain (`EXAMPLE.COM`); the filter value stays `All`.

## [0.7.5] unreleased

### Multi-factor authentication

- A TOTP second factor (RFC 6238: SHA-1, six digits, 30-second steps, one step of
  clock skew). `enable_mfa` (`LLDAP_ENABLE_MFA`, `--enable-mfa`): `false` (the default)
  changes nothing, `true` lets users enroll an authenticator, `"always"` requires every
  user to enroll; members of the group `lldap_mfa_disabled` are exempt. The group is
  created at startup while the mode is on, and only then is its name protected from renaming
  and deletion; with MFA off it is not created and is an ordinary group if it exists.
- Enrollment and reset over GraphQL: `startMfaEnrollment(currentCode)` returns the
  `otpauth://` URI, the base32 secret and a sealed state valid for five minutes,
  `finishMfaEnrollment(state, code)` proves possession, `resetOwnMfa(code)` and the
  administrative `resetUserMfa(userId)` (admins; password managers for non-admin users)
  clear the factor, and `User.mfaEnrolled` is visible to the user and to admins.
  Replacing an authenticator needs a code from the current one. Secrets are sealed with a
  key derived from the server key and never leave the database. A login, own-reset or
  replacement code is accepted once; five wrong codes per 30-second step lock that step
  (enrollment confirmation is not attempt-limited).
- Under `"always"` a session that has not enrolled yet can only read its own user and
  enroll; every other query or mutation is refused until enrollment completes.
- New log kinds `mfa_enroll` and `mfa_reset`.
- Enrolled users present the code at every door by appending it to the password
  (`yourpassword:123456`): the web login answers a password-only attempt with
  `{"mfaRequired": true}` and the client retries with `totp_code`, `/auth/simple/login` and
  LDAP simple bind split the suffix and say why only after the password verified (*TOTP
  code required: append ':' and the code*, *TOTP code already used*, *Too many TOTP
  attempts*). The check runs in the same login handler as the password, so the event log
  keeps one `bind` / `login` row per ceremony (details `totp`, `invalid totp`,
  `totp replayed`, `totp attempts exceeded`, `mfa enrollment required`). Under `"always"`
  unenrolled users are refused on LDAP and simple login and admitted flagged on the web
  login and the refresh.
- A password reset by e-mail clears the factor once the new password is committed,
  `--force-ldap-user-pass-reset=true` clears the admin's, and a changed private key
  accepted with `--force-update-private-key=true` clears every factor (the sealed secrets
  died with the old key). The migration tool refuses enrolled accounts by name. The gate
  runs with `enable_mfa = true` and exercises enrollment, both doors, replay and reset.
  Documented in `docs/mfa.md`.
- The web app: the login form splits `yourpassword:123456`, sends the code on the OPAQUE
  finish and shows a help panel when an enrolled account tries the password alone (it also
  understands the `mfaRequired` answer, which surfaced as *Could not parse response*
  before); the change-password page accepts either form for the current password;
  **Set up / Reconfigure two-factor** on your profile opens the enrollment page (QR code
  and secret, confirmation with `password:code`, a live code check, a five-minute expiry);
  **Reset two-factor** for oneself with `password:code` and, for administrators, on any
  user's page; `mfaEnrolled` shows as a status on the user page and as an MFA column in
  the user table; under `"always"` an unenrolled web session is held on the enrollment
  page. The Enabled / Disabled toggle has its own row above the buttons, the two-factor
  controls use the QR-code icon, and the icon font moves from bootstrap-icons 1.5.0 to
  1.13.1.

### Logging

- Security-relevant events are now recorded in the database (`logs` table, part of the
  v13 schema; databases already at v13 get the table at their next start): LDAP binds and
  web logins (success, wrong password, disabled account), token refresh, logout, password
  reset requests and completions, password changes on every path, user, group, membership,
  schema, system-config and POSIX changes, access denials on both protocols (unparseable
  JWTs are printed, not stored), Kerberos principal operations and keytab exports,
  Keycloak federation changes, and server start / admin bootstrap. Each row carries the
  actor (claimed identity for authentication events), the target, the protocol (`ldap`,
  `http`, `graphql`, `system`), the client address (plus `X-Forwarded-For` for HTTP), a
  short detail and the time. Control characters are stripped from those strings.
- Events never touch the database on the request path: they go through a bounded in-memory
  queue and are written in batches; if the queue overflows, a `log_gap` row records how
  many events were dropped.
- `[log_options]` (`LLDAP_LOG_OPTIONS__PERSIST`, `__RETENTION_DAYS`, `__MAX_ENTRIES`,
  `--log-*` flags): persistence on by default, 30 days and 50000 entries kept (`0` removes
  a limit); the hourly cleaner trims by age and size, the writer by size after bursts, and
  the trim also runs while `persist = false`. Retention deletes run in 1000-row chunks so
  SQLite's one connection can still serve a bind. Every event is also printed
  (`target: logs`; failures at warn, other events at info, successful binds/logins/refreshes
  at debug), so the terminal log gains them even with persistence off.
- Admins read the log over GraphQL: `logs(filter, limit, beforeId, afterId)` returns
  `LogEntry` rows newest first (`id` is the paging cursor, `afterId` pages forward oldest
  first so another service can tail the log; filters on actor, target, kinds, success,
  protocol, peer, a time window and group membership; 100 rows by default, 1000 at most).
  Documented in `docs/logging.md`.
- Two lookups count in the database instead of returning rows, for the account policies
  that come next: `logSummary(filter, groupBy: [ACTOR|TARGET|KIND|PROTOCOL|PEER|SUCCESS|
  DAY|HOUR], limit)` gives one bucket (count, first, last) per distinct combination, most
  frequent first; `logActivity(actor, kinds, since)` gives one account's last success, last
  failure and the failures since that success. Both ride new indexes on `kind`, `target` and
  `peer` (each with `timestamp`; existing databases get them at the next start). The same
  methods sit on `LogBackendHandler` for in-process code. `docs/logging.md` maps each
  planned policy (failed-login lockout, inactivity, password age, login hours, addresses,
  policy by group) to its lookup and its limits. On SQLite those lookups share the one
  pooled connection; pass `since`/`kinds` on `logSummary` and `memberOf` so a busy box
  does not walk the whole table.
- Repeated successful binds by the same actor, protocol and address are stored once per
  `bind_coalesce_seconds` (`LLDAP_LOG_OPTIONS__BIND_COALESCE_SECONDS`,
  `--log-bind-coalesce-seconds`, default 300, `0` stores every bind), so service accounts
  that bind every few seconds no longer push the security rows out of `max_entries`; failed
  binds and every other kind are always stored, the terminal lines are unchanged.
- Unknown-name bind failures now carry the detail `unknown user` (an account with no
  password set reads the same, deliberately; the client response does not change) and are
  coalesced by the writer: the first 8 per client address, protocol and 300 s window are
  stored one-to-one, the rest become one `bind_flood` row carrying the count and the
  distinct-name count — a unique-name spray that used to write thousands of rows a second
  (and evict real history from `max_entries`) now stores a handful. Wrong passwords against
  real accounts are always stored one-to-one, so per-user failure counts stay exact.
- On SQLite the log lookups (`logs`, `logSummary`, `logActivity`) read on a small read-only
  pool of their own instead of queueing on the single write connection: an unfiltered
  summary or a `memberOf` scan no longer stalls LDAP binds behind it (a stress run measured
  5-28 s bind waits and pool timeouts; they are gone). The writer also drains a full queue
  back-to-back instead of pausing 250 ms per batch, so bursts stop dropping events long
  before the queue limit.
- Terminal calm under floods: the per-attempt `Login attempt` and LDAP bind session lines
  moved to debug (the `logs`-target line is the terminal record — one warn per failure),
  auth-path span errors no longer print at error level per attempt, and failure lines are
  rate-limited to 64 per 10 s with a `suppressed N failure lines` summary; the limiter is
  terminal-only, the table keeps every stored row.
- Bind floods are now bracketed so an admin can trace began → ended even while the spray is
  suppressed: the writer emits a `bind_flood` `started` row the moment a source is flagged
  (visible in GraphQL at once, not only after a window rolls or a restart) and a paired
  `resolved` row — with the total binds, distinct-name count and duration — when the source
  goes quiet (~20 s) or on shutdown. Each source is one incident; a later burst is a new one.
  A writer tick also flushes the terminal `suppressed N failure lines` summary promptly when
  a failure flood stops, instead of only on the next failure.
- The same flood bracketing now covers access denials: an `access_denied` flood from one
  client address (authenticated abuse or a junk-JWT spammer) is stored one-to-one for the
  first few then coalesced into an `access_denied_flood` `started`/`resolved` pair, so it
  cannot fill the table 1:1. Junk (`Invalid JWT`) and expired JWTs are now recorded as
  `access_denied` rows (they used to be terminal-only), so a token spammer is visible in the
  table and coalesces under load.

### Testing

- The test suite was consolidated from 534 to 288 tests without dropping coverage:
  upstream LLDAP's tests are untouched; KLLDAP's one-test-per-branch additions became
  scenario and table tests whose assert names the failing row, behaviour already pinned by
  an e2e or the SQL handler is no longer pinned again below it, 25 duplicate or
  language-level tests went, and bindgen's 61 layout tests for the krb5 bindings are off.
  Two upstream cases the fork had dropped are back (unsupported LDAP filters are refused; a
  regular bind's search is narrowed to itself). `#[serial]` tests 30 → 18, server boots in
  `server/tests` 25 → 16. See `docs/testing.md`.

## [0.7.4] unreleased

Everything since 0.7.2: the LLDAP migration path, a full audit of the LDAP layer, a
container test gate, and a code sweep back to LLDAP's shape.

### Security

- Key-file deployments without a `key_seed` silently ran on a built-in deterministic
  key since 0.7.2 (the "startup figment logic" change) — the configured key file was
  ignored. The server now loads the real key file; affected deployments stop at startup
  with "The private key has changed" and must restart once with
  `--force-update-private-key=true` (and `--force-ldap-user-pass-reset=true`), after
  which every user must reset their password. Deployments using `key_seed` are not
  affected.
- Members of `lldap_password_manager` could not change another user's password through
  LDAP Modify `userPassword` (the extended PasswordModify operation worked); LDAP Modify
  now applies the same password rules as the extended operation.
- Adding a user to `lldap_disabled` now also blocks their existing web session (JWT and
  refresh) and refuses a password-reset email, matching the bind/login denial. A leftover
  token previously stayed valid until expiry.
- Kerberos usernames and Keycloak keytab hostnames are validated before they reach
  `kadmin.local` or kadm5: reserved principals (`krbtgt`, `kadmin`, …) and injected
  characters (`/`, newlines) are rejected so a directory user cannot overwrite the TGS
  key or split a `ktadd` query.
- Federation URLs must be `http://` or `https://`; `file://` and other schemes are
  rejected before the server connects. `LLDAP_KEYCLOAK_ADMIN_PASS` has no default
  (`admin` is no longer implied). Exported Keycloak keytabs are `0600`.
- Refresh and password-reset tokens are generated with `OsRng` (they used
  `SmallRng`, weaker than LLDAP). LDAP Password Modify no longer panics when a
  regular user targets another identity (InsufficientAccessRights, as upstream).
- Unauthenticated LDAP subschema searches are refused (same as LLDAP). `ldapadd`
  with `userPassword` now stores the bind password, not only a Kerberos principal.
- Built-in group protection (`lldap_admin`, …) is case-insensitive.
- LDAP/GraphQL cannot delete the last `lldap_admin` member (GraphQL already
  blocked self-delete; LDAP `ldapdelete` on `admin` emptied the admin group).
- User IDs that would become reserved Kerberos principals (`krbtgt`, `kadmin`,
  names with `/` or `@`) are rejected at create.
- Disabled-account login returns the same client error as a failed bind
  (server logs still say the account is disabled).

### Migration from LLDAP

- Stock LLDAP 0.6.x databases (schema ≤ 11) can be adopted: schema v13 re-encodes
  upstream attribute values and JpegPhoto types. Passwords do not carry over (the OPAQUE
  library changed): start once with `--force-update-private-key` and
  `--force-ldap-user-pass-reset` under a fresh key, then users set a new password — which
  is also when a Kerberos principal is created. See
  [docs/migration_guides/v0.7-from-lldap.md](docs/migration_guides/v0.7-from-lldap.md).
- The v12 migration is repaired and idempotent on PostgreSQL (fresh and upgraded).
- Attribute values use one canonical encoding on read and write; DateTime attributes no
  longer corrupt.

### LDAP

- Users, groups and OUs answer filters and scopes per RFC 4511: subtree at a leaf DN
  returns that entry, base-scope lookups no longer scan the directory, OU entries only
  match filters their attributes satisfy, `cn` equality is case-insensitive,
  `displayName` is returned alongside `cn`, `groupid` is exposed and filterable, and
  canonical attribute names (`userid`, `displayname`, timestamps) resolve like their
  aliases.
- SSSD rfc2307 enumeration works out of the box: `memberUid`, `member`/`uniqueMember`,
  `gecos`; `shadow*`/`host`/`userPassword` requests are silent no-ops; unknown filter
  attributes log at debug.
- LDAP ADD no longer silently drops attributes: values the schema knows (custom
  attributes, sshPublicKey, admin-overridable POSIX numbers) persist for users and
  groups; read-only and unknown names are skipped with a warning.

### Kerberos

- Directory writes (users, groups, passwords, attributes, settings) are refused with
  "Kerberos KDC unavailable" until the KDC has come up after boot, so nothing changes that
  the KDC could not follow; logins and reads are never gated. The image enables this with
  `LLDAP_HEALTHCHECK_OPTIONS__KERBEROS=true`; without it (no KDC) writes never wait.
- Custom `LLDAP_UID`/`LLDAP_GID` deployments work with Kerberos: the admin keytab and the
  KDC database are owned by the configured user (they were `lldap:lldap`, so a first boot
  could not read the keytab and keytab export never worked), and `kadmin.local` is called
  with an explicit principal (a uid without a passwd entry has none). The runtime image no longer
  ships `sudo` or `strace`. `krbPrincipalName` is now recorded on the LDAP password paths
  too (Modify `userPassword`, `ldappasswd`, ADD with `userPassword`).
- KDC principals are disabled while a user is in `lldap_disabled` and re-asserted after
  a password sync; the admin keytab is recreated when `/data` is wiped but the KDC
  volume survives.
- The Docker HEALTHCHECK includes Kerberos (`lldap healthcheck --kerberos`): a dead KDC
  or missing admin keytab turns the container unhealthy. The KDC bootstrap is idempotent
  and re-runnable via `kerberos_manager --bootstrap-only`; `krb5kdc` and `kadmind` run in
  the foreground under the manager, which stops both when either exits.
- File locations and the KDC port can be overridden with `LLDAP_KERB_*` variables;
  unset means the container layout is unchanged.

### GraphQL and Keycloak

- Full upstream GraphQL compatibility restored (lldap-cli works unmodified).
- Keycloak federation settings have a single owner, `/data/keycloak_config.toml`
  (`LLDAP_KEYCLOAK_CONFIG`), written from the Federation tab; the admin password stays
  in `LLDAP_KEYCLOAK_ADMIN_PASS`. The realm push builds the LDAP provider DNs from
  LLDAP's base DN. `setPosixSettings` checks authorization before validating ranges.
- GraphQL error messages carry the underlying cause in the message (the
  `extensions.details` field is gone).

### Configuration and container

- Boot scripts prefer `LLDAP_UID`/`LLDAP_GID` (legacy `UID`/`GID` still honored) and no
  longer warn about `LLDAP_KERB_*`/`LLDAP_KEYCLOAK_*` as unknown variables.
- SQLite URLs of the form `sqlite:///data/users.db` are normalized so a missing database
  is created; a loopback `http_url` with password reset enabled logs a warning.
- Fixed: `--healthcheck-http-host`/`--healthcheck-ldap-host` CLI flags had no effect; a
  timed-out healthcheck probe counted as success. `bootstrap.sh` applies `ou` from user
  and group configs (`changeUserOu`/`changeGroupOu`).

### Fixes

- Re-submitting a user's own `uidNumber` was rejected as "already assigned"; group
  `gidNumber` updates accept the same 3000–60000 range as creates and a group may
  re-submit its own `gidNumber`.
- Avatar processing, OU error display, Kerberos loading state and the `.gz` wasm asset
  in the web UI.

### Tests and CI

- GitHub Actions resurrected (Rust workflow with SQLite and PostgreSQL lanes, shellcheck,
  a live-KDC lane); release version single-sourced from `Cargo.toml`.
- Container gate suite (`make gate`): 14 phases exercising the real image from entrypoint
  boot through a custom-UID boot, OU/user lifecycle, Kerberos principal sync/kinit, LDAP
  read/write matrices, keytab export, restart persistence and KDC-death detection; SQLite
  and PostgreSQL lanes, wired into CI (`gate.yml`). `make test-kdc` runs the Kerberos FFI
  against a throwaway KDC. `server/tests` run in parallel on ephemeral ports.
- Comment density and code shape brought back to LLDAP's; the crate layout is documented
  in [docs/architecture.md](docs/architecture.md).

## [0.7.2] 2026-06-16

- User GIDs no longer clash with group GIDs.
- Group `uid` and `memberOf` lookups added to LDAP search.
- Startup no longer fails when `.lldap_initialized` is present.
- Built-in `lldap_*` groups can no longer be deleted or renamed.
- `kadm5.acl` is no longer overwritten on restart; it is sanity-checked and repaired,
  falling back to the default when unrepairable.
- `lldap_sudohost` group added (SSSD `sudoHost`); `lldap_disabled` RFC compliance
  improved.
- Unknown LDAP search attributes log at debug instead of warn.

## [0.7.1] 2026-05-15

Major fork release, integration of MIT Kerberos into a docker container, OU's, redesign of public_schema, LDAP system and more

 - Redesign of schema with consolidation at crates/schema/
 - MIT Kerberos implementation and FFI hands-off management system at crates/kerberos/
 - Redesign of LDAP back-end code at crates/ldap
 - OU integration
 - Ability to disable users
 - POSIX system
 - jpegPhoto / Avatar enhancements
 - Federation page with Keycloak realm setup assistant
 - Migraton to v12 to support new schema and system_settings
 - Updated rust toolchain to 1.95.0
 - Dependency updates, including opaque version 4, graphql .16 and many others

---

Everything below is upstream [LLDAP](https://github.com/lldap/lldap)'s changelog; KLLDAP
forked after 0.6.3.

## [0.6.3] 2026-05-01

Small release, focused on LDAP compatibility, TLS maintenance, dependency upgrades and documentation/examples.

### Added

 - LDAP schema definitions for `memberOf`, `modifyTimestamp` and `pwdChangedTime`
 - Support for configuring the healthcheck listen addresses
 - Usernames are now included in password recovery emails

### Changed

 - JWT `exp` and `iat` claims are now serialized as NumericDate values to comply with RFC7519
 - Migrated to `rustls` 0.23 and centralized TLS handling
 - The login form no longer enforces a password length limit

### Fixed

 - `pwdChangedTime` is now emitted as LDAP GeneralizedTime instead of RFC3339
 - LDAP base-scope searches for non-existent entries now return `NoSuchObject`
 - `cn` equality filters are now case insensitive
 - The server now shuts down the database connection pool gracefully
 - The bootstrap script now handles empty globs correctly

### Security

 - Updated the LDAP dependency stack, including `ldap3_proto`, in response to
   security advisory
   [`GHSA-qcxq-75wr-5cm8`](https://github.com/kanidm/ldap3/security/advisories/GHSA-qcxq-75wr-5cm8),
   where a specially crafted LDAP query could make the server crash

### Cleanups

 - Split GraphQL queries and mutations into smaller modules
 - Refactored configuration and user update logic
 - Upgraded the Rust toolchain and shared dependencies

### New services

 - Apache WebDAV
 - Continuwuity
 - Gerrit
 - Gogs
 - Open WebUI
 - OpenCloud
 - Pocket ID
 - Semaphore
 - TrueNAS

## [0.6.2] 2025-07-21

Small release, focused on LDAP improvements and ongoing maintenance.

### Added

 - LDAP
    - Support for searching groups by their `groupid`
    - Support for `whoamiOID`
    - Support for creating groups
    - Support for subschema entry
 - Custom assets path.
 - New endpoint for requesting client settings

### Changed

 - A missing JWT secret now prevents startup.
 - Attributes with invalid characters (such as underscores) cannot be created anymore.
 - Searching custom (string) attributes is now case insensitive.
 - Using the top-level `firstName`, `lastName` and `avatar` GraphQL fields for users is now deprecated. Use the `attributes` field instead.

### Fixed

 - `lldap_set_password` now uses the system's SSL certificates.

### Cleanups

 - Split the main `lldap` crate into many sub-crates
 - Various dependency version bumps
 - Upgraded to 2024 Rust edition
 - Docs/FAQ improvements

### Bootstrap script

 - Custom attributes support
 - Read the paswsord from a file
 - Resilient to no user or group files

### New services

 - Discord integration (Discord role to LLDAP user)
 - HashiCorp
 - Jellyfin 2FA with Duo
 - Kimai
 - Mailcow
 - Peertube
 - Penpot
 - PgAdmin
 - Project Quay
 - Quadlet
 - Snipe-IT
 - SSSD
 - Stalwart
 - UnifiOS

## [0.6.1] 2024-11-22

Small release, mainly to fix a migration issue with Sqlite and Postgresql.

### Added

 - Added a link to a community terraform provider (#1035)

### Changed

 - The opaque dependency now points to the official crate rather than a fork (#1040)

### Fixed

 - Migration of the DB schema from 7 to 8 is now automatic for sqlite, and fixed for postgres (#1045)
 - The startup warning about `key_seed` applying instead of `key_file` now has instructions on how to silence it (#1032)

### New services

- OneDev

## [0.6.0] 2024-11-09

### Breaking

- The endpoint `/auth/reset/step1` is now `POST` instead of `GET` (#704)

### Added

- Custom attributes are now supported (#67) ! You can add new fields (string, integers, JPEG or dates) to users and query them. That unlocks many integrations with other services, and allows for a deeper/more customized integration. Special thanks to @pixelrazor and @bojidar-bg for their help with the UI.
- Custom object classes (for all users/groups) can now be added (#833)
- Barebones support for Paged Results Control (no paging, no respect for windows, but a correct response with all the results) (#698)
- A daily docker image is tagged and released. (#613)
- A bootstrap script allows reading the list of users/groups from a file and making sure the server contains exactly the same thing. (#654)
- Make it possible to serve lldap behind a sub-path in (#752)
- LLDAP can now be found on a custom package repository for opensuse, fedora, ubuntu, debian and centos ([Repository link](https://software.opensuse.org//download.html?project=home%3AMasgalor%3ALLDAP&package=lldap)). Thanks @Masgalor for setting it up and maintaining it.
- There's now an option to force reset the admin password (#748) optionally on every restart (#959)
- There's a rootless docker container (#755)
- entryDN is now supported (#780)
- Unknown LDAP controls are now detected and ignored (#787, #799)
- A community-developed CLI for scripting (#793)
- Added a way to print raw logs to debug long-running sessions (#992)


### Changed

- The official docker repository is now `lldap/lldap`
- Removed password length limitation in lldap_set_password tool
- Group names and emails are now case insensitive, but keep their casing (#666)
- Better error messages (and exit code (#745)) when changing the private key (#778, #1008), using the wrong SMTP port (#970), using the wrong env variables (#972)
- Allow `member=` filters with plain user names (not full DNs) (#949)
- Correctly detect and refuse anonymous binds (#974)
- Clearer logging (#971, #981, #982)

### Fixed

- Logging out applies globally, not just in the local browser. (#721)
- It's no longer possible to create the same user twice (#745)
- Fix wide substring filters (#738)
- Don't log the database password if provided in the connection URL (#735)
- Fix a panic when postgres uses a different collation (#821)
- The UI now defaults to the user ID for users with no display names (#843)
- Fix searching for users with more than one `memberOf` filter (#872)
- Fix compilation on Windows (#932) and Illumos (#964)
- The UI now correctly detects whether password resets are enabled. (#753)
- Fix a missing lowercasing of username when changing passwords through LDAP (#1012)
- Fix SQLite writers erroring when racing (#1021)
- LDAP sessions no longer buffer their logs until unbind, causing memory leaks (#1025)

### Performance

- Only expand attributes once per query, not per result (#687)

### Security

- When asked to send a password reset to an unknown email, sleep for 3 seconds and don't print the email in the error (#887)

### New services

Linux user accounts can now be managed by LLDAP, using PAM and nslcd.

- Apereo CAS server
- Carpal
- Gitlab
- Grocy
- Harbor
- Home Assistant
- Jenkins
- Kasm
- Maddy
- Mastodon
- Metabase
- MegaRAC-BMC
- Netbox
- OCIS
- Prosody
- Radicale
- SonarQube
- Traccar
- Zitadel

## [0.5.0] 2023-09-14

### Breaking

 - Emails and UUIDs are now enforced to be unique.
   - If you have several users with the same email, you'll have to disambiguate
     them. You can do that by either issuing SQL commands directly
     (`UPDATE users SET email = 'x@x' WHERE user_id = 'bob';`), or by reverting
     to a 0.4.x version of LLDAP and editing the user through the web UI.
     An error will prevent LLDAP 0.5+ from starting otherwise.
   - This was done to prevent account takeover for systems that allow to
     login via email.

### Added

 - The server private key can be set as a seed from an env variable (#504).
   - This is especially useful when you have multiple containers, they don't
     need to share a writeable folder.
 - Added support for changing the password through a plain LDAP Modify
   operation (as opposed to an extended operation), to allow Jellyfin
   to change password (#620).
 - Allow creating a user with multiple objectClass (#612).
 - Emails now have a message ID (#608).
 - Added a warning for browsers that have WASM/JS disabled (#639).
 - Added support for querying OUs in LDAP (#669).
 - Added a button to clear the avatar in the UI (#358).


### Changed

 - Groups are now sorted by name in the web UI (#623).
 - ARM build now uses musl (#584).
 - Improved logging.
 - Default admin user is only created if there are no admins (#563).
   - That allows you to remove the default admin, making it harder to
     bruteforce.

### Fixed

 - Fixed URL parsing with a trailing slash in the password setting utility
   (#597).

In addition to all that, there was significant progress towards #67,
user-defined attributes. That complex feature will unblock integration with many
systems, including PAM authentication.

### New services

 - Ejabberd
 - Ergo
 - LibreNMS
 - Mealie
 - MinIO
 - OpnSense
 - PfSense
 - PowerDnsAdmin
 - Proxmox
 - Squid
 - Tandoor recipes
 - TheLounge
 - Zabbix-web
 - Zulip

## [0.4.3] 2023-04-11

The repository has changed from `nitnelave/lldap` to `lldap/lldap`, both on GitHub
and on DockerHub (although we will keep publishing the images to
`nitnelave/lldap` for the foreseeable future). All data on GitHub has been
migrated, and the new docker images are available both on DockerHub and on the
GHCR under `lldap/lldap`.

### Added

 - EC private keys are not supported for LDAPS.

### Changed

 - SMTP user no longer has a default value (and instead defaults to unauthenticated).

### Fixed

 - WASM payload is now delivered uncompressed to Safari due to a Safari bug.
 - Password reset no longer redirects to login page.
 - NextCloud config should add the "mail" attribute.
 - GraphQL parameters are now urldecoded, to support special characters in usernames.
 - Healthcheck correctly checks the server certificate.

### New services

 - Home Assistant
 - Shaarli

## [0.4.2] - 2023-03-27

### Added

 - Add support for MySQL/MariaDB/PostgreSQL, in addition to SQLite.
 - Healthcheck command for docker setups.
 - User creation through LDAP.
 - IPv6 support.
 - Dev container for VsCode.
 - Add support for DN LDAP filters.
 - Add support for SubString LDAP filters.
 - Add support for LdapCompare operation.
 - Add support for unencrypted/unauthenticated SMTP connection.
 - Add a command to setup the database schema.
 - Add a tool to set a user's password from the command line.
 - Added consistent release artifacts.

### Changed

 - Payload is now compressed, reducing the size to 700kb.
 - entryUUID is returned in the default LDAP fields.
 - Slightly improved support for LDAP browsing tools.
 - Password reset can be identified by email (instead of just username).
 - Various front-end improvements, and support for dark mode.
 - Add content-type header to the password reset email, fixing rendering issues in some clients.
 - Identify groups with "cn" instead of "uid" in memberOf field.

### Removed

 - Removed dependency on nodejs/rollup.

### Fixed

 - Email is now using the async API.
 - Fix handling of empty/null names (display, first, last).
 - Obscured old password field when changing password.
 - Respect user setting to disable password resets.
 - Fix handling of "present" filters with unknown attributes.
 - Fix handling of filters that could lead to an ambiguous SQL query.

### New services

 - Authentik
 - Dell iDRAC
 - Dex
 - Kanboard
 - NextCloud + OIDC or Authelia
 - Nexus
 - SUSE Rancher
 - VaultWarden
 - WeKan
 - WikiJS
 - ZendTo

### Dependencies (highlights)

 - Upgraded Yew to 0.19
 - Upgraded actix to 0.13
 - Upgraded clap to 4
 - Switched from sea-query to sea-orm 0.11

## [0.4.1] - 2022-10-10

### Added

 - Added support for STARTTLS for SMTP.
 - Added support for user profile pictures, including importing them from OpenLDAP.
 - Added support for every config value to be specified in a file.
 - Added support for PKCS1 keys.

### Changed

 - The `dn` attribute is no longer returned as an attribute (it's still part of the response).
 - Empty attributes are no longer returned.
 - The docker image now uses the locally-downloaded assets.

## [0.4.0] - 2022-07-08

### Breaking

The `lldap_readonly` group has been renamed `lldap_password_manager` (migration happens automatically) and a new `lldap_strict_readonly` group was introduced.

### Added
  - A new `lldap_strict_readonly` group allows granting readonly rights to users (not able to change other's passwords, in particular).

### Changed
  - The `lldap_readonly` group is renamed `lldap_password_manager` since it still allows users to change (non-admin) passwords.

### Removed
  - The `lldap_readonly` group was removed.

## [0.3.0] - 2022-07-08

### Breaking
As part of the update, the database will do a one-time automatic migration to
add UUIDs and group creation times.

### Added
  - Added support and documentation for many services:
    - Apache Guacamole
    - Bookstack
    - Calibre
    - Dolibarr
    - Emby
    - Gitea
    - Grafana
    - Jellyfin
    - Matrix Synapse
    - NextCloud
    - Organizr
    - Portainer
    - Seafile
    - Syncthing
    - WG Portal
  - New migration tool from OpenLDAP.
  - New docker images for alternate architectures (arm64, arm/v7).
  - Added support for LDAPS.
  - New readonly group.
  - Added UUID attribute for users and groups.
  - Frontend now uses the refresh tokens to reduce the number of logins needed.

### Changed
  - Much improved logging format.
  - Simplified API login.
  - Allowed non-admins to run search queries on the content they can see.
  - "cn" attribute now returns the Full Name, not Username.
  - Unknown attributes now warn instead of erroring.
    - Introduced a list of attributes to silence those warnings.

### Deprecated
 - Deprecated "cn" as LDAP username, "uid" is the correct attribute.

### Fixed
  - Usernames, objectclass and attribute names are now case insensitive.
  - Handle "1.1" and other wildcard LDAP attributes.
  - Handle "memberOf" attribute.
  - Handle fully-specified scope.

### Security
  - Prevent SQL injections due to interaction between two libraries.

## [0.2.0] - 2021-11-27
