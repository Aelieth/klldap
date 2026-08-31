# Changelog

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
