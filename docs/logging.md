# Event logging

KLLDAP records security-relevant events in the database (table `logs`) and prints each of
them to the terminal. The rows are the material for review and for the security policies
that build on them; the terminal lines are LLDAP's usual output plus these events.

## What is recorded

| Kind | When | Actor / target / detail |
|---|---|---|
| `bind` | LDAP simple bind and `/auth/simple/login` (both go through the same login handler) | claimed user; `invalid credentials` (wrong password), `no password given` (a name with an empty password, or with `:` and a code alone: refused before the name is looked up, the same for every name, and never counted toward the lockout; LDAP answers 53, *unwillingToPerform*), `unknown user` (no such account, or an account with no password set — deliberately the same, visible only in this admin-only table; the client response does not differ), `account disabled`, `ou mismatch`, `locked out` ([policies.md](policies.md#lockout)), `Anonymous bind not allowed`, `SASL not supported`, a bad DN; with a second factor ([mfa.md](mfa.md)) the success detail is `totp`, the failures `invalid totp`, `totp replayed`, `totp attempts exceeded`, `totp: unreadable` (the database could not answer), `totp re-enrollment required`, `mfa enrollment required`, and a right password with no code is `totp code required` |
| `login` | web (OPAQUE) login | claimed user; `invalid credentials`, `account disabled`, `locked out`, `the login's start was already finished`, `the login's start is older than two minutes` and `the login's start carries no time or id` (a finish refused before its proof, answered as a wrong password and counted nowhere; the last one only for a sign-in in progress across an upgrade), the same second-factor details, and success detail `mfa enrollment pending` for a user whose resolved value is `always` (server-wide `enable_mfa`, or the OU's `enable-mfa`; [policies.md](policies.md#second-factor)), admitted before enrolling. An enrolled user's ordinary web login is two steps, so it writes `totp code required` and then the success row. That pair is the login, not an attack. A finish sent with `"session": false` (a page checking the password: enrollment, reset two-factor, change password) makes no session; every row it writes, whatever the outcome, says so: `no session` after the row's own detail and a `; ` when there is one (`totp; no session`, `totp code required; no session`), or `no session` alone, so none reads as a sign-in or as an abandoned one. Protocol `kerberos`: a directory user's Kerberos sign-in (kinit), with `ticket issued`, `pre-authentication failed` or `not completed` and the mechanism, `locked out` for a locked user (refused before pre-authentication), `policy: enable-mfa (no fresh proof)` for a user who must give a second factor and has no fresh proof from a directory sign-in ([kerberos.md](kerberos.md#a-second-factor-and-kinit); an `access_denied` row with that detail at a renewal or a service ticket, and with `policy: enable-mfa (factor changed since the code)` for a ticket of the code at kinit issued before the factor last changed), the code at kinit's rows ([kerberos.md](kerberos.md#the-code-at-kinit)): `totp code required (armor ticket; <mechanism>)` (a failure written after the password: the short ticket that is armor only, counted nowhere), `ticket issued (OTP)`, and the failures `invalid totp (OTP)` (counted toward the lockout), `totp replayed (OTP)`, `totp attempts exceeded (OTP)`, `armor is not the user's own ticket: <armor client> (OTP)`, `no six-digit code (OTP)` (nothing of the value is written), `no second factor asked (OTP)`, `totp: unreadable (OTP)` and `pre-authentication not completed (OTP)`, or `policy: <item>` when another directory policy refused it, followed by the item's reason where it gives one (`policy: login-hours (outside login hours)`). A `bind`, `login` or `mfa_enroll` success whose code opened a Kerberos window that could not be stored adds `; proof not stored` to its detail (`totp; proof not stored`) |
| `logout`, `token_refresh` | web session end / refresh | user; `invalid refresh token`, `account disabled`, `policy: unreadable` when the user's `enable-mfa` could not be read (a token's use: `access_denied` with the same detail). A token's use whose user's groups could not be read is refused (401) with an `access_denied` row, `the database did not answer in time` when the read was given up at its bound (2 seconds), else `groups: unreadable`; a refresh answers such a read 500 with no row, as it answers its other reads |
| `password_reset_request`, `password_reset_complete` | reset mail requested / reset token used | target user (also unknown ones — the HTTP response stays silent, the log does not); the token itself is never recorded in this row; a failed reset mail writes the reset link's token to the server log at debug level only. A refused `password_reset_complete` says `wrong or expired reset token` (404), or, when the token could not be read, `the database did not answer in time` (the read given up at its bound) or `reset token: unreadable`, both answered 500 |
| `password_change` | every path: web, GraphQL `setUserPassword`, LDAP `userPassword` modify, password-modify extended operation, `ldapadd` with `userPassword`, admin bootstrap | actor from the request, target user. For a `kerberossync` user one row covers the directory and the KDC: a success row is written in the change's own transaction, a failure row carries the cause (on a directory-only server the full cause, `Kerberos KDC unavailable: <cause>`, which the answer to the user does not carry; so do the `user_create`, `user_update` and `user_delete` rows of a change refused there), and there is no `kerberos_sync` row, except the one that names a Kerberos password policy an `ldapadd` cleared from the principal it took over. A failure row with detail `result unknown: the database did not answer` or `result unknown: the change did not report` is not a verdict: a success row for the same user at the same moment means the change happened. `result unknown: the change did not report` is written when the task doing the change panicked or did not report (it never ran, for example because the server was stopping). A panic after the commit can leave both a success row and that row; the success row decides. An `ldapadd` with a password for a `kerberossync` user writes these details on its `user_create` row |
| `user_create`, `user_update`, `user_delete` | directory writes over GraphQL or LDAP | target user; `user_update` detail lists the changed attribute names (`-name` = removed), never values. On a directory-only server a synced user's delete without its confirmation writes one failure row with the full cause and how to confirm (`Kerberos KDC unavailable: <cause>; or delete the user now …`), and a confirmation for a user without sync one with `a confirmed delete is for a user with Kerberos sync, …` ([kerberos.md](kerberos.md#directory-only)) |
| `group_create`, `group_update`, `group_delete` | | target group name; a `group_update` that renames a group to exactly `lldap_mfa_disabled` ends its detail with `; members exempt from MFA: <n>`, the members it exempts ([mfa.md](mfa.md#modes)) |
| `membership_add`, `membership_remove` | | target user, detail = group name |
| `schema_change` | attribute / object class added or deleted | target name, detail = the operation |
| `system_config_change` | `allowedous` (OU create/delete), `posix_settings` | target key, detail = value; other keys log `updated` |
| `posix_change` | the bulk uidNumber/gidNumber/home/shell reassignments | detail `reassign` |
| `kerberos_sync`, `keytab_export` | principal create/delete/enable/disable, reconcile, the start's mark, a start that goes on directory-only (one failure row with no target, `directory-only: <cause>`; [kerberos.md](kerberos.md#when-the-realm-cannot-open)), a synced user's confirmed delete there (`deleted while the Kerberos realm is closed on this server: the principal is marked, …`) and the next opening's removal of that principal (`removed at start: left by a delete while the realm was closed`), keytab export, a kadmin unlock (a password change writes a `password_change` row instead), the `otp` string that offers the code at kinit put on or taken off a user's principal (`code at kinit offered as the realm opened: …`, `… by the holder's status pass: …`, `code at kinit withdrawn …`, each with the reason), and a Kerberos password policy cleared from a principal the directory adopts or owns: one row per principal, in the transaction that clears it (an adoption, an `ldapadd` with a password that takes the principal over, the start's mark, or the start's clear of one adopted earlier; [kerberos.md](kerberos.md#principals)) | target principal user / host, detail = the operation. A cleared policy's row says `Kerberos password policy <policy> cleared from <principal>@<REALM>: the directory's password-min-length applies`, naming the policy, never a key or a password |
| `keycloak_change` | Federation tab: test connection, save config, push realm | target url / realm |
| `mfa_enroll` | TOTP enrollment: a state minted (`started`), confirmed (`totp`, `replaced`), or refused (`password proof required`, `proof: unreadable` when the used proofs cannot be read or written, `invalid code`, `expired enrollment`, `stale enrollment`, `corrupt enrollment state`, `foreign enrollment state`; a refused current code on a replacement carries the rejection detail); the user's own choice of the code at kinit (`code at kinit on`, `code at kinit off`, refused as `code at kinit: not enrolled` without a factor) | actor = target user |
| `mfa_reset` | a second factor cleared: by an admin or password manager (no detail — the actor says who), by the user (`self`; a refused code carries the rejection detail), by a password reset (`password reset`), by the one-shot admin reset (`forced admin reset`), or for everyone after a private-key rotation (`private key changed`, `system`, no target) | target user |
| `account_lock` | a counted failure, or a web start that no finish removed in time, brings the user's stored count to the lockout threshold; once per lock until an unlock or a success; for a lock that unfinished web starts make, when they join the stored count, about 10 seconds after they began | no actor; target user; protocol of the door; detail `locked: <door>` (`ldap bind`, `simple login`, `web login`, `kerberos`) |
| `account_unlock` | an admin's `unlockUser`, the host tool `lldap unlock`, or kadmin `modprinc -unlock` on a directory user's principal; written in the unlock's own transaction | actor = the admin (none for the tool, the client principal for kadmin); target user; detail `unlockUser`, `lldap unlock` or `kadmin modprinc -unlock` |
| `account_reenable` | an admin's `reenableUser` or the host tool `lldap reenable`: the user's `inactivity-days` count restarts now ([policies.md](policies.md#inactivity)); written in the re-enable's own transaction | actor = the admin (none for the tool); target user; detail `reenableUser` or `lldap reenable` |
| `policy_change` | a named policy created/updated/deleted, attached to or cleared from an OU, inheritance blocked/unblocked, or OU policy state dropped on `deleteOu`; the host tool `lldap policy-unlink` writes its row in its own transaction | target = policy name or the OU (`(root)` for the domain root); update detail lists field names, never values; the host tool's detail is `policy cleared: <name> (lldap policy-unlink)` |
| `access_denied` | a GraphQL field or an LDAP operation refused for lack of rights, a rejected JWT (junk/`Invalid JWT`, `Expired JWT`, logged out, disabled account, groups that could not be read, wrong algorithm, a password-reset token used anywhere but its password's registration: `a reset token is taken only to set its user's password`), a kadmin write refused on a directory user's principal ([kerberos.md](kerberos.md#kadmin-and-directory-users)), a Kerberos renewal, service ticket or S4U2Self refused on a directory policy, a ticket asked for a subject whose principal is gone (`the principal is gone`; protocol `kerberos`) or could not be read (`the principal could not be read`), a renewal or service ticket of a name a delete marked, until the start pass clears the mark (`the user was deleted while the realm was closed`; at AS the `login` failure row says the same), or a non-admin's sign-in with the right password on an admin-only server, whose realm did not open (`only admins may sign in while Kerberos is unavailable`; at the LDAP bind `only admins may bind while Kerberos is unavailable`, target the user), which is then the attempt's only row: no `bind` or `login` success row | actor if known, detail = the refusal message. Like failed binds, the first 8 per client address and protocol are stored one-to-one; a flood past that coalesces into `access_denied_flood`. A kadmin refusal is never coalesced when the actor (the kadmin client) is not the target; one on the client's own principal coalesces per client |
| `server_start`, `admin_bootstrap` | boot, admin created / password forced from the configuration | `system` |
| `log_gap` | events dropped because the writer's queue overflowed | detail = how many |
| `bind_flood` | brackets a flood of failed binds with detail `unknown user` or `no password given` (the two count together) from one client address and protocol: a `started` row the moment the source passes the first 8 failures, then a `resolved` row when it goes quiet (~20 s) or on shutdown | no actor; protocol of the source; `peer` is the socket peer of the flood's first bind, `forwarded_for` the judged client address when it differs from that peer; detail `unknown-user bind flood started`, then `unknown-user bind flood resolved: N binds, M names, Ds` (`M+` past 64), whichever of the two details the binds carry. An unpaired `started` = still ongoing. With 4096 windows open, a further source is counted in one pair with no peer: `unknown-user bind flood from many sources started`, then `... from many sources resolved: N binds, S sources, Ds` |
| `access_denied_flood` | brackets a flood of refusals from one client address and protocol (authenticated abuse or a junk-JWT spammer), or of one kadmin client's refusals on its own principal, the same way `bind_flood` does for binds | no actor (a kadmin flood: the client); protocol of the source, `peer` and `forwarded_for` as for `bind_flood`; detail `access-denied flood started`, then `access-denied flood resolved: N denials, M actors, Ds` (anonymous/junk-JWT counts as one actor); with 4096 windows open, `access-denied flood from many sources started` and `... from many sources resolved: N denials, S sources, Ds` |
| `sign_in_flood` | brackets a flood of sign-ins refused before any credential was proved, each kind of row on its own: failed `bind` rows other than the two `bind_flood` counts, failed `login`, `token_refresh` (`invalid refresh token`), `password_reset_request` and `password_reset_complete` rows, from one client address and protocol, and for a known user from that address for that user ([Rows](#rows)): a `started` row at the ninth refusal, a `resolved` row when the window goes quiet (~20 s) or on shutdown. A row written after the password, the web login's proof, a held refresh token or Kerberos pre-authentication verified is never counted here | no actor; target = the user in a user's own window; protocol of the source, `peer` and `forwarded_for` as for `bind_flood`; detail `<kind> flood started`, then `<kind> flood resolved: N refusals, M names, Ds`, where `<kind>` is the kind of the rows (`bind`, `login`, `token_refresh`, `password_reset_request`, `password_reset_complete`); with 512 windows of one kind open, `<kind> flood from many sources started` and `... from many sources resolved: N refusals, S sources, Ds`, with no peer |

Reserved for the coming Kerberos keytab / computer feature: `computer_create`,
`computer_update`, `computer_delete`, `keytab_rotate` (`keytab_export` keeps
target = principal, detail = purpose). Kinds are stored as text and only ever appended.

Success is a column, not a kind: a wrong password is `bind` with `success = false`.

## Rows

`id` (bigint, the paging cursor), `timestamp` (UTC), `kind`, `success`, `protocol`
(`ldap`, `http` for the `/auth` endpoints, `graphql`, `system` for boot-time work, `kadmin`
for the embedded KDC's kadmin requests, whose actor is the client principal, `kerberos` for the
KDC's own rows: a directory user's sign-in, a ticket refused on a directory policy), `actor`
(who asked — the *claimed* identity for authentication events, the verified one otherwise),
`target` (what was acted upon), `peer` (client address as seen by the server),
`forwarded_for` (the raw `X-Forwarded-For` header, HTTP only, untrusted), `detail` (a short
reason, an operation, attribute names — never values, passwords or tokens). Strings are
capped (255 chars, detail 512) and control characters are stripped. No foreign key: the
history outlives deleted users and groups. The KDC queues one `kerberos` row per Kerberos
sign-in of a directory user (the exchange that only asks for pre-authentication writes none);
service principals and ticket renewals leave none unless refused.

Deliberate double rows: admin bootstrap (`user_create`/`password_change`/`membership_add`
plus `admin_bootstrap`), `kerberos_sync delete` on every user delete.

Deliberate missing rows: a successful `bind` repeated by the same actor over the same
protocol from the same address within `bind_coalesce_seconds` (default 300) is printed but
not stored — service accounts that bind every few seconds would otherwise fill the row
budget. The stored row is the first of each window, so "last seen" is at most one window
early.

A sign-in refused before any credential was proved is stored one-to-one only for the first 8
of its flood window; past that, the burst is bracketed by a `started` row and a `resolved`
row (with the totals and duration) instead of one row per attempt, so nobody without a
password can push real history out of `max_entries`. A window holds one kind of row from
one client address over one protocol: unknown-name and `no password given` binds together
(`bind_flood`), every other failed `bind`, and failed `login`, `token_refresh`,
`password_reset_request` and `password_reset_complete` rows, each on its own
(`sign_in_flood`), and `access_denied` rows (`access_denied_flood`). The client address is
the one `allowed-networks` judges ([Proxies and privacy](#proxies-and-privacy)): the socket
peer, or behind a listed proxy the address taken from `X-Forwarded-For`. LDAP and Kerberos
carry no forwarded address, so clients behind one application server or one NAT share an
address. A window is one incident until it is quiet for ~20 s; a later burst is a separate
incident.

A refusal about a known user has a window for that user: `invalid credentials`, `locked
out`, `account disabled` and `ou mismatch` at a bind; `locked out`, `account disabled` and a
`policy: <item>` refusal when a web login starts; every refusal of a Kerberos sign-in (the
KDC reports only existing principals); `account disabled` and `could not send email` at a
reset request. So each known user's first 8 refusals from an address, of one kind over one
protocol, are kept, for up to 16 users per address at a time; a further user's refusals from
that address count in the address's own window, as do `policy: unreadable` refusals and the
refusals that name no known user: an unknown name, a bad DN, a web login finish whose proof
does not verify (whoever it names), a refresh token the server does not hold, a reset request
for an unknown name, a wrong reset token or one that could not be read.

Always stored one-to-one: every success other than the repeated bind above; every `bind`,
`login` and `token_refresh` row written after the password, the web login's proof, a held refresh token or Kerberos
pre-authentication verified (a policy refusal after the right password, `totp code
required`, every TOTP rejection, `mfa enrollment required`, `refused after
pre-authentication`, a refresh refused for a held token); `account_lock`, `account_unlock`,
`account_reenable` and every write by an admin; a kadmin refusal on another principal. At
most 512 windows of one `sign_in_flood` kind are open at once (4096 for `bind_flood` and for
`access_denied_flood`); a refusal that would open one more is counted in a single row pair
for its kind and protocol, `... flood from many sources`, which keeps no row one-to-one and
resolves like any window. No open window is closed to make room.

## Configuration

```toml
[log_options]
persist = true              # write events to the logs table; the terminal lines stay either way
retention_days = 30         # 0 keeps them forever
max_entries = 50000         # oldest first; 0 means unlimited
bind_coalesce_seconds = 300 # one stored successful bind per actor/protocol/address per window; 0 stores all
```

`LLDAP_LOG_OPTIONS__PERSIST`, `LLDAP_LOG_OPTIONS__RETENTION_DAYS`,
`LLDAP_LOG_OPTIONS__MAX_ENTRIES`, `LLDAP_LOG_OPTIONS__BIND_COALESCE_SECONDS`, or
`--log-persist`, `--log-retention-days`, `--log-max-entries`, `--log-bind-coalesce-seconds`.
A longer history is `retention_days = 90`, `max_entries = 100000` (~150 bytes a row, so
100000 rows are ~15 MB on SQLite). The effective horizon is the smaller of `retention_days`
and `max_entries / rows per day`: with the defaults, 1666 rows a day already shorten it below
30 days, and `logSummary(filter: {kinds: [BIND], success: true, since: "<yesterday>"},
groupBy: [ACTOR])` shows who produces them. A flood of sign-ins refused before a credential
does not eat the horizon: past the first 8 of a window it compresses to two flood rows per
incident (started + resolved), instead of thousands a second.

Events never touch the database on the request path: they go through a bounded queue and
are written in batches by one background task (one INSERT per batch; a trickle waits a
moment to fill a batch, a full queue drains back-to-back). If the queue overflows, the
events are dropped and a `log_gap` row says how many. SQLite writes on one pooled
connection — log INSERT/trim share it with LDAP and GraphQL — while `logs`, `logSummary`
and `logActivity` read on a small read-only pool of their own, so a slow summary no longer
queues binds behind it; a read still briefly holds the file against the writer, so pass
`since` and `kinds` on a busy box. The hourly cleaner deletes rows older than
`retention_days` and beyond `max_entries`; the writer also trims by size after bursts.
Both limits keep applying with `persist = false`, and those deletes run in 1000-row
chunks so a bind can use the write connection in between. The table is part of the v13
schema; a database already at v13 gets it at the next start.

## Terminal lines

Every event is printed with `target: logs`, e.g. `✅ user_delete bob by admin (graphql
10.0.0.5)` or `❌ bind by ghost (ldap 127.0.0.1): unknown user`. Failures are `warn`,
other events `info`, successful `bind`/`login`/`token_refresh` and a
`password_reset_request` `debug`; the per-attempt `Login attempt` and LDAP bind session
lines, a refused sign-in's own warning (a disabled or locked-out user), an unknown LDAP
control and a malformed DN are `debug` too, so a refused sign-in is one terminal line.
Failure lines are rate-limited to 64 per 10 s — the excess is
dropped from the terminal only (the table keeps every stored row); the `suppressed N failure
lines` summary prints on the next failure, or promptly when the flood stops (the writer's
tick flushes it, so `persist = true`). The same limit and the same summary take the
server's own warnings that a request can cause (a policy or lockout that could not be read,
a mail that could not be sent, an LDAP connection's error) and the `info` line of an LDAP write
request. An internal error is said once where it is answered, within the limit: at the LDAP
bind, at an HTTP 500, and where an LDAP search or a GraphQL list of users (`users`, a group's
`users`) cannot read its users. A read or a write the server gives up at its bound (2 seconds
at the doors and for the background reads and writes, 5 for the second factor's prune) says
so in its own words, `the database did not answer in time`: in the line that warns of it, in
an HTTP 500's body, and as the detail of the row a token's use or a reset token's finish
writes for it. A log writer that cannot store says so once when that starts
(`Log events are not being stored`) and once when it ends, with the number lost
(`Log events are stored again after …: N lost`); these two lines are outside the limit. The
embedded KDC's own lines (`target: krb5_klog`) are `debug` below a warning and share the
limit from a warning up. `RUST_LOG=info,logs=debug` shows the
successes as well. What is printed still grows Docker's json-file log; cap it with
`--log-opt max-size=10m --log-opt max-file=3`.

## Querying

Admins read the log over GraphQL with three queries; every other client
(`lldap-cli`, curl, GraphiQL — see [scripting](scripting.md) for a token) uses the same
ones. Non-admins get `Unauthorized to read the logs`, itself an `access_denied` row.

`logs` returns rows, newest first, with keyset paging on `id`:

```graphql
{
  logs(filter: {kinds: [BIND, LOGIN], success: false, since: "2026-08-01T00:00:00Z"}, limit: 50) {
    id
    timestamp
    actor
    peer
    detail
  }
}
```

`filter` (shared by all three queries): `actor`, `target`, `kinds` (a list; empty means
any), `success`, `protocol`, `peer`, `since`/`until` (inclusive), `memberOf` (group display
name) / `memberOfId` — the last two keep the events whose actor is currently a member of
the group. `actor` matches a stored actor equal to the value as given or to the value
lowercased: a kadmin client's principal as typed, a user id (stored lowercased, and it may
hold `@`) in any case; `target` and `peer` match the stored string exactly. `limit`
defaults to 100 (max 1000). `beforeId` continues
from the last `id` of the previous page; `afterId` pages the other way — oldest first, from
the given `id` (`"0"` for the beginning) — which is how another service tails the log: keep
the last `id` seen, ask again with `afterId`, ids are assigned in order by a single writer
so nothing is skipped — though after a burst, rows can still sit in the writer's queue for
a few seconds (the tail fills in late), a `log_gap` row marks anything that was dropped, and
a flood incident (`bind_flood`, `sign_in_flood`, `access_denied_flood`) shows a `started` row
at once and its `resolved` row within ~20 s of the source going quiet. The GraphQL `LogKind` enum is the kinds this binary writes; reserved
`computer_*` / `keytab_rotate` rows (a newer binary, or the coming feature) are skipped when
read, so a page can be shorter than `limit` — pass explicit `kinds` when tailing across
such a downgrade.

`logSummary` counts in the database instead of returning rows — one `GROUP BY` over the
filtered events, most frequent bucket first (then newest), `limit` buckets (default 100,
max 1000). `groupBy` takes any of `ACTOR`, `TARGET`, `KIND`, `PROTOCOL`, `PEER`, `SUCCESS`,
`DAY` (`YYYY-MM-DD`, UTC) and `HOUR` (0-23, UTC; with `DAY` it is an hourly timeline, alone
an hour-of-day profile); no `groupBy` gives one bucket of totals. Each bucket carries the
grouped values, `count`, `first` and `last` (the timestamps of the oldest and newest event
in it, ready to be pasted into `since`/`until` to drill in):

```graphql
{
  logSummary(filter: {kinds: [BIND, LOGIN], success: false, since: "2026-08-17T00:00:00Z"},
             groupBy: [ACTOR, PEER], limit: 20) {
    actor
    peer
    count
    first
    last
  }
}
```

`logActivity` answers "how is this account doing" in three indexed reads:

```graphql
{
  logActivity(actor: "bob") {
    lastSuccess { timestamp protocol peer }
    lastFailure { timestamp detail }
    failuresSinceLastSuccess
  }
}
```

`kinds` defaults to `[BIND, LOGIN]` (the password-checking kinds a lockout counts); pass
`[BIND, LOGIN, TOKEN_REFRESH, PASSWORD_RESET_COMPLETE]` for "is this account still used".
`since` bounds all three fields. `failuresSinceLastSuccess` counts the failure rows stored
after `lastSuccess` (all failure rows in scope when there is none). Past the first 8 of a
flood window the failures are in the flood row's total, not in rows, so during a flood this
number is lower than the failures sent; the counts a lockout judges are in `login_lockouts`.

Every lookup is an index seek: `logs` has indexes on `timestamp` and on `actor`, `kind`,
`target` and `peer` each paired with `timestamp`; a database already at v13 gets them at the
next start. The table stays plain SQL for `sqlite3`/`psql`
(`SELECT timestamp, kind, success, actor, peer, detail FROM logs ORDER BY id DESC LIMIT 50`).

## Policy lookups

The coming account policies read the log for some things and configuration or directory
state for others; this is which source answers what, and the query when it is the log.

| Policy | Source | Lookup |
|---|---|---|
| Account policy settings by group | configuration (a policy object per group; a change is a `system_config_change` row) | `memberOf` on any query selects a group's population |
| Password quality rules | enforced where the password is set (rejections will be `password_change` rows with `success = false` and the rule in `detail`); the OPAQUE web login never shows the server the password, so those rules apply to the LDAP, GraphQL and Kerberos paths | `logs(filter: {kinds: [PASSWORD_CHANGE], success: false, target: "bob"})` |
| Password history, min age | state: previous hashes and `users.password_modified_date`; the log is the trail (who changed it, over which protocol) | `logs(filter: {kinds: [PASSWORD_CHANGE], target: "bob"}, limit: 5) { timestamp actor protocol }` |
| Account expiration | a user attribute; refusals will be `bind`/`login` rows with `detail = "account expired"` | `logs(filter: {kinds: [USER_UPDATE], target: "bob"})` for the trail |
| Inactivity lockout | the OU policy item `inactivity-days`, judged from the table `user_activity`, not from this log ([policies.md](policies.md#inactivity)); refusals are `policy: inactivity-days (inactive)`, and the log still profiles sign-ins within its horizon | per user `logActivity(actor: "bob", kinds: [BIND, LOGIN, TOKEN_REFRESH, PASSWORD_RESET_COMPLETE]) { lastSuccess { timestamp } }`; per group `logSummary(filter: {memberOf: "staff", kinds: [BIND, LOGIN, TOKEN_REFRESH], success: true, since: "<now - 90 days>"}, groupBy: [ACTOR], limit: 1000) { actor last }` — members missing from the buckets are the candidates |
| Progressive delay, max attempts before disable | log for the board and the review; the enforcement counts are in the database (`login_lockouts`, and `totp_steps` for the second factor) | board `logSummary(filter: {kinds: [BIND, LOGIN], success: false, since: "<now - 15 min>"}, groupBy: [ACTOR]) { actor count first last }`; per user `logActivity(actor: "bob") { lastFailure { timestamp peer detail } failuresSinceLastSuccess }`; per source `groupBy: [PEER]` |
| Login time restrictions | the OU policy item `login-hours` (windows read in the one server zone, `login_hours_timezone`); the log profiles usage and audits refusals, `policy: login-hours (outside login hours)` | `logSummary(filter: {actor: "bob", kinds: [BIND, LOGIN], success: true, since: "<now - 30 days>"}, groupBy: [HOUR]) { hour count }` (UTC hours) |
| TOTP guessing, second-factor posture | log: a wrong code is a failed `bind`/`login` like a wrong password, so the lockout lookups above already count it; the detail tells them apart | `logs(filter: {actor: "bob", kinds: [BIND, LOGIN], success: false}) { detail peer }` (`invalid totp`, `totp replayed`, `totp attempts exceeded`, `totp: unreadable`); who still has to enroll where the resolved value is `always`: `logs(filter: {kinds: [LOGIN], success: true})` rows with detail `mfa enrollment pending`; the factor's history `logs(filter: {kinds: [MFA_ENROLL, MFA_RESET], target: "bob"})` |
| IP restrictions | the OU policy item `allowed-networks` (address ranges per OU); the log builds allow lists and finds sources, and audits refusals, `policy: allowed-networks (address not allowed)` | `logSummary(filter: {actor: "bob", kinds: [BIND, LOGIN], success: true, since: ...}, groupBy: [PEER]) { peer count first last }`; sources of failures `logSummary(filter: {success: false, since: ...}, groupBy: [PEER])` |

Limits to keep in mind:

- The writer lags the event by up to 250 ms plus a batch and drops rows under overload
  (`log_gap`). The lockout therefore does not count from this table: it keeps its own,
  `login_lockouts` ([policies.md](policies.md#lockout)).
- The horizon is the retention (30 days / 50000 rows by default): `lastSuccess: null` means
  never, or before the horizon. A directory user's kinit writes one `login` row (protocol
  `kerberos`) for each answer other than the request for pre-authentication, `ticket issued`
  among them; a renewal or a service ticket writes a row only when it is refused, so a user who
  only renews tickets leaves no success row in the horizon.
- Actors of failures are the *claimed* identity: an unknown name counts against nothing real,
  and a bind with an unparseable DN has no actor at all (the DN is the `target`) — and the
  table now says so: unknown names are `bind` rows with detail `unknown user`, then a
  `bind_flood` `started`/`resolved` pair per source, in a window apart from the failed binds
  of real accounts, so a name spray does not use up their rows.
- A real account's failures are not all rows. Kept one-to-one: each known user's first 8
  refusals per client address, protocol and kind of row in a flood window (for up to 16 users
  per address at a time; past that, the address's first 8), and every failure after the
  password or the proof verified (a wrong TOTP code, a policy refusal). Past the first 8 the
  refusals are a count in a `sign_in_flood` row pair. What always remains per user is the one
  `account_lock` row of each lock and the stored counts (`login_lockouts`).
- `memberOf` is today's membership, not the membership at the time of the event.
- Hours and days are UTC; `peer` behind a reverse proxy is the proxy (`forwarded_for` is the
  unverified header).
- Successful binds are coalesced per window (above); counts of them are windows, not binds.
- `logSummary` orders equal counts newest first: a `limit` smaller than the population hides
  the earliest of equally-hit accounts (a 50-user board with `limit: 20` never shows the
  first victims) — board a fixed group with `memberOf`, or pass `limit >=` the population.
- `logActivity` defaults to `kinds: [BIND, LOGIN]`: `access_denied` streaks are invisible
  unless the kinds are passed explicitly.
- Under load a lookup can fail with a pool acquire timeout (a GraphQL error, not an empty
  result) — retry it; do not read it as "no rows".
- Junk (`Invalid JWT`) and expired JWTs are recorded as `access_denied` rows so a token
  spammer is visible; a flood coalesces into `access_denied_flood`. A single routine expiry is
  one bounded row. (Plain, valid-but-expired refresh cycles are the common source; if a
  deployment sees steady `Expired JWT` rows, that is a client not refreshing in time.)

A locked user's refusal is a `bind`/`login` row with `success = false` and detail
`locked out` (a token refresh or use: `token_refresh`/`access_denied`; a renewal or a
service ticket: `access_denied`; an S4U2Self or an S4U2Proxy: `access_denied`, `locked out
(S4U2Self by <service>)` or `locked out (S4U2Proxy by <service>)`), and the lock itself is one `account_lock` row. Past the first 8 of a
flood window ([Rows](#rows)) the refusals written before a credential was proved are a count in
a flood row pair, as other failures are. A refusal by `login-hours`, `allowed-networks` or
`inactivity-days` is a row of the door's kind with the item and its reason, at every door:
`policy: login-hours (outside login hours)`, `policy: allowed-networks (address not allowed)`,
`policy: inactivity-days (inactive)`; for a service asking for the user the service follows, as
for a lock (`policy: inactivity-days (inactive) (S4U2Self by <service>)`, `(S4U2Proxy by
<service>)`). `login-hours` judges no service asking for a user, and a stored value of it that
does not parse refuses as `policy: unreadable` ([policies.md](policies.md#login-hours)). Reserved
for another policy: the detail `account expired`; rejected passwords are `password_change` rows
with `success = false`.

Each refused request writes its own row until its flood window has kept 8, so a client that
asks again writes another. After a
refused service ticket, `kvno` asks once more without referrals, so one refused `kvno` leaves
two `access_denied` rows.

## Proxies and privacy

`peer` is the TCP peer. Behind a reverse proxy that is the proxy; `forwarded_for` then carries
the client chain the proxy sent, unverified — decide what to trust when you read it. With
`trusted_proxies` set, `allowed-networks` judges the address its right-most rule takes from
`X-Forwarded-For` ([allowed-networks.md](allowed-networks.md#whose-address)); the row still
carries `peer` and `forwarded_for` as they came, so a refusal behind a proxy is read in
`forwarded_for`. The flood windows are keyed by that judged address. A flood row is the
exception to "as they came": its `peer` is the socket peer of the window's first event and its
`forwarded_for` is the judged address itself, set only when it differs from that peer. The log
names accounts that were merely *tried* (unknown users, reset requests for unknown
addresses), which is the point of it and also a reason to treat the table as sensitive.

## What builds on it

The same events flow through an in-process sink before they reach the table: that is the
hot path, where the policies can count (rate limits, alerts on privilege changes) without a
database read per request; the lockout keeps its own table, `login_lockouts`. The table is the durable trail and
the lookup for admins and other services (`logs`, `logSummary`, `logActivity`, the same
methods on `LogBackendHandler` for in-process code). The Kerberos side keeps its own state
(last success, failure count, kadmin policies) for the principals that are not directory
users; a directory user's Kerberos failures are counted with the directory's.
The second factor reports through the same rows ([mfa.md](mfa.md)): a TOTP guess is a
failed `bind`/`login` like a wrong password, and the lockout counts it once.
The seam (`crates/domain-handlers/src/logging.rs`), the table, the writer and the queries
are LLDAP-neutral; the Kerberos, Keycloak, OU and POSIX kinds are KLLDAP's.
