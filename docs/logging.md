# Event logging

KLLDAP records security-relevant events in the database (table `logs`) and prints each of
them to the terminal. The rows are the material for review and for the security policies
that build on them; the terminal lines are LLDAP's usual output plus these events.

## What is recorded

| Kind | When | Actor / target / detail |
|---|---|---|
| `bind` | LDAP simple bind and `/auth/simple/login` (both go through the same login handler) | claimed user; `invalid credentials` (wrong password), `unknown user` (no such account, or an account with no password set — deliberately the same, visible only in this admin-only table; the client response does not differ), `account disabled`, `ou mismatch`, `Anonymous bind not allowed`, `SASL not supported`, a bad DN; with a second factor ([mfa.md](mfa.md)) the success detail is `totp`, the failures `invalid totp`, `totp replayed`, `totp attempts exceeded`, `totp re-enrollment required`, `mfa enrollment required` (the missing-code challenge records nothing) |
| `login` | web (OPAQUE) login | claimed user; `invalid credentials`, `account disabled`, the same second-factor details, and success detail `mfa enrollment pending` for a user admitted under `enable_mfa = "always"` before enrolling |
| `logout`, `token_refresh` | web session end / refresh | user; `invalid refresh token`, `account disabled` |
| `password_reset_request`, `password_reset_complete` | reset mail requested / reset token used | target user (also unknown ones — the HTTP response stays silent, the log does not); the token itself is never recorded |
| `password_change` | every path: web, GraphQL `setUserPassword`, LDAP `userPassword` modify, password-modify extended operation, `ldapadd` with `userPassword`, admin bootstrap | actor from the request, target user |
| `user_create`, `user_update`, `user_delete` | directory writes over GraphQL or LDAP | target user; `user_update` detail lists the changed attribute names (`-name` = removed), never values |
| `group_create`, `group_update`, `group_delete` | | target group name |
| `membership_add`, `membership_remove` | | target user, detail = group name |
| `schema_change` | attribute / object class added or deleted | target name, detail = the operation |
| `system_config_change` | `allowedous` (OU create/delete), `posix_settings` | target key, detail = value; other keys log `updated` |
| `posix_change` | the bulk uidNumber/gidNumber/home/shell reassignments | detail `reassign` |
| `kerberos_sync`, `keytab_export` | principal sync/delete/enable/disable, keytab export | target principal user / host, detail = the operation |
| `keycloak_change` | Federation tab: test connection, save config, push realm | target url / realm |
| `mfa_enroll` | TOTP enrollment: a state minted (`started`), confirmed (`totp`, `replaced`), or refused (`invalid code`, `expired enrollment`, `stale enrollment`, `corrupt enrollment state`, `foreign enrollment state`; a refused current code on a replacement carries the rejection detail) | actor = target user |
| `mfa_reset` | a second factor cleared: by an admin or password manager (no detail — the actor says who), by the user (`self`; a refused code carries the rejection detail), by a password reset (`password reset`), by the one-shot admin reset (`forced admin reset`), or for everyone after a private-key rotation (`private key changed`, `system`, no target) | target user |
| `access_denied` | a GraphQL field or an LDAP operation refused for lack of rights, a rejected JWT (junk/`Invalid JWT`, `Expired JWT`, logged out, disabled account, wrong algorithm) | actor if known, detail = the refusal message. Like failed binds, the first 8 per client address and protocol are stored one-to-one; a flood past that coalesces into `access_denied_flood` |
| `server_start`, `admin_bootstrap` | boot, admin created / password forced from the configuration | `system` |
| `log_gap` | events dropped because the writer's queue overflowed | detail = how many |
| `bind_flood` | brackets a flood of unknown-name bind failures from one client address and protocol: a `started` row the moment the source passes the first 8 failures, then a `resolved` row when it goes quiet (~20 s) or on shutdown | no actor; peer and protocol of the source; detail `unknown-user bind flood started`, then `unknown-user bind flood resolved: N binds, M names, Ds` (`M+` past 64). An unpaired `started` = still ongoing |
| `access_denied_flood` | brackets a flood of refusals from one client address and protocol (authenticated abuse or a junk-JWT spammer), the same way `bind_flood` does for binds | no actor; peer and protocol of the source; detail `access-denied flood started`, then `access-denied flood resolved: N denials, M actors, Ds` (anonymous/junk-JWT counts as one actor) |

Reserved for the coming Kerberos keytab / computer feature: `computer_create`,
`computer_update`, `computer_delete`, `keytab_rotate` (`keytab_export` keeps
target = principal, detail = purpose). Kinds are stored as text and only ever appended.

Success is a column, not a kind: a wrong password is `bind` with `success = false`.

## Rows

`id` (bigint, the paging cursor), `timestamp` (UTC), `kind`, `success`, `protocol`
(`ldap`, `http` for the `/auth` endpoints, `graphql`, `system` for boot-time work), `actor`
(who asked — the *claimed* identity for authentication events, the verified one otherwise),
`target` (what was acted upon), `peer` (client address as seen by the server),
`forwarded_for` (the raw `X-Forwarded-For` header, HTTP only, untrusted), `detail` (a short
reason, an operation, attribute names — never values, passwords or tokens). Strings are
capped (255 chars, detail 512) and control characters are stripped. No foreign key: the
history outlives deleted users and groups.

Deliberate double rows: admin bootstrap (`user_create`/`password_change`/`membership_add`
plus `admin_bootstrap`), `kerberos_sync delete` on every user delete.

Deliberate missing rows: a successful `bind` repeated by the same actor over the same
protocol from the same address within `bind_coalesce_seconds` (default 300) is printed but
not stored — service accounts that bind every few seconds would otherwise fill the row
budget. Failed binds against real accounts, other kinds and other addresses are always
stored; the stored row is the first of each window, so "last seen" is at most one window
early. Unknown-name bind failures are stored one-to-one only for the first 8 per address and
protocol; past that, the burst is bracketed by a `bind_flood` `started` row and a `resolved`
row (with the totals and duration) instead of one row per attempt, so a unique-name spray
cannot push real history out of `max_entries`. Each source is one incident until it is quiet
for ~20 s; a later burst from the same source is a separate incident.

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
groupBy: [ACTOR])` shows who produces them. A unique-name bind flood no longer eats the
horizon: past the first 8 per source it compresses to two `bind_flood` rows per incident
(started + resolved), instead of thousands a second.

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
other events `info`, successful `bind`/`login`/`token_refresh` `debug`; the per-attempt
`Login attempt` and LDAP bind session lines are `debug` too, so a failed bind is one
terminal line, not three. Failure lines are rate-limited to 64 per 10 s — the excess is
dropped from the terminal only (the table keeps every stored row); the `suppressed N failure
lines` summary prints on the next failure, or promptly when the flood stops (the writer's
tick flushes it, so `persist = true`). `RUST_LOG=info,logs=debug` shows the
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
the group. `actor` is a user id (lowercased like the stored actors); `target` and `peer`
match the stored string exactly. `limit` defaults to 100 (max 1000). `beforeId` continues
from the last `id` of the previous page; `afterId` pages the other way — oldest first, from
the given `id` (`"0"` for the beginning) — which is how another service tails the log: keep
the last `id` seen, ask again with `afterId`, ids are assigned in order by a single writer
so nothing is skipped — though after a burst, rows can still sit in the writer's queue for
a few seconds (the tail fills in late), a `log_gap` row marks anything that was dropped, and
a `bind_flood` incident shows a `started` row at once and its `resolved` row within ~20 s of
the source going quiet. The GraphQL `LogKind` enum is the kinds this binary writes; reserved
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
`since` bounds all three fields. `failuresSinceLastSuccess` counts the failures recorded
after `lastSuccess` (all failures in scope when there is none).

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
| Inactivity lockout | log, within the retention horizon | per user `logActivity(actor: "bob", kinds: [BIND, LOGIN, TOKEN_REFRESH, PASSWORD_RESET_COMPLETE]) { lastSuccess { timestamp } }`; per group `logSummary(filter: {memberOf: "staff", kinds: [BIND, LOGIN, TOKEN_REFRESH], success: true, since: "<now - 90 days>"}, groupBy: [ACTOR], limit: 1000) { actor last }` — members missing from the buckets are the candidates |
| Progressive delay, max attempts before disable | log for the board and the review; the enforcement counts in memory (see the limits below) | board `logSummary(filter: {kinds: [BIND, LOGIN], success: false, since: "<now - 15 min>"}, groupBy: [ACTOR]) { actor count first last }`; per user `logActivity(actor: "bob") { lastFailure { timestamp peer detail } failuresSinceLastSuccess }`; per source `groupBy: [PEER]` |
| Login time restrictions | configuration (windows and a time zone per group); the log profiles usage and audits refusals | `logSummary(filter: {actor: "bob", kinds: [BIND, LOGIN], success: true, since: "<now - 30 days>"}, groupBy: [HOUR]) { hour count }` (UTC hours) |
| TOTP guessing, second-factor posture | log: a wrong code is a failed `bind`/`login` like a wrong password, so the lockout lookups above already count it; the detail tells them apart | `logs(filter: {actor: "bob", kinds: [BIND, LOGIN], success: false}) { detail peer }` (`invalid totp`, `totp replayed`, `totp attempts exceeded`); who still has to enroll under `"always"`: `logs(filter: {kinds: [LOGIN], success: true})` rows with detail `mfa enrollment pending`; the factor's history `logs(filter: {kinds: [MFA_ENROLL, MFA_RESET], target: "bob"})` |
| IP restrictions | configuration (address ranges per group); the log builds allow lists and finds sources | `logSummary(filter: {actor: "bob", kinds: [BIND, LOGIN], success: true, since: ...}, groupBy: [PEER]) { peer count first last }`; sources of failures `logSummary(filter: {success: false, since: ...}, groupBy: [PEER])` |

Limits to keep in mind:

- The writer lags the event by up to 250 ms plus a batch and drops rows under overload
  (`log_gap`); a lockout that counts from the table would let a burst through, so the
  enforcement will count at the sink (in memory) and use `logActivity` only to rehydrate at
  start.
- The horizon is the retention (30 days / 50000 rows by default): `lastSuccess: null` means
  never, or before the horizon; users who only log in through Kerberos leave no rows here (the
  KDC keeps its own last success and failure count per principal).
- Actors of failures are the *claimed* identity: an unknown name counts against nothing real,
  and a bind with an unparseable DN has no actor at all (the DN is the `target`) — and the
  table now says so: unknown names are `bind` rows with detail `unknown user`, then a
  `bind_flood` `started`/`resolved` pair per source, so a name spray cannot bury the failures
  of real accounts.
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

Reserved for the policies: kinds `account_lock` / `account_unlock` (actor system or admin,
target user, detail = reason); refusals stay `bind`/`login` rows with `success = false` and
the details `locked out`, `outside login hours`, `address not allowed`, `account expired`;
rejected passwords are `password_change` rows with `success = false`.

## Proxies and privacy

`peer` is the TCP peer. Behind a reverse proxy that is the proxy; `forwarded_for` then carries
the client chain the proxy sent, unverified — decide what to trust when you read it. The log
names accounts that were merely *tried* (unknown users, reset requests for unknown
addresses), which is the point of it and also a reason to treat the table as sensitive.

## What builds on it

The same events flow through an in-process sink before they reach the table: that is the
hot path, where the policies count (lockout after repeated failures, rate limits, alerts on
privilege changes) without a database read per request. The table is the durable trail and
the lookup for admins and other services (`logs`, `logSummary`, `logActivity`, the same
methods on `LogBackendHandler` for in-process code). The Kerberos side keeps its own state
(last success, failure count, kadmin policies) that the policies will surface next to it.
The second factor reports through the same rows ([mfa.md](mfa.md)): a TOTP guess is a
failed `bind`/`login` like a wrong password, so a lockout keyed on `LOGIN_KINDS` counts it.
The seam (`crates/domain-handlers/src/logging.rs`), the table, the writer and the queries
are LLDAP-neutral; the Kerberos, Keycloak, OU and POSIX kinds are KLLDAP's.
