<h1 align="center">KLLDAP - Light LDAP with an integrated Kerberos KDC</h1>

0.8.0 is a pre-release. The new policies and the front end have not yet had thorough testing. Further testing, verification and code review come before it is promoted.


<p align="center">
  <a href="https://github.com/Aelieth/klldap/actions/workflows/rust.yml?query=branch%3A0.8.0">
    <img src="https://github.com/Aelieth/klldap/actions/workflows/rust.yml/badge.svg?branch=0.8.0" alt="Build"/>
  </a>
  <a href="https://github.com/Aelieth/klldap/actions/workflows/gate.yml?query=branch%3A0.8.0">
    <img src="https://github.com/Aelieth/klldap/actions/workflows/gate.yml/badge.svg?branch=0.8.0" alt="Gate"/>
  </a>
</p>

- [About](#about)
- [Installation](docs/install.md)
- [Usage](#usage)
- [Client configuration](#client-configuration)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Contributions](#contributions)

## About

KLLDAP is a hard fork of [LLDAP](https://github.com/lldap/lldap), the lightweight
LDAP authentication server. In 0.8.0 the KDC and kadmin are kerber-rust (v1.2.3)
inside the `lldap` process, and MIT's KDC is no longer in the image's running system.
Users, groups and passwords are managed once, through the web UI, LDAP or
GraphQL; the KDC follows.

<img
  src="https://raw.githubusercontent.com/Aelieth/klldap/main/screenshot.png"
  alt="Screenshot of the user list page"
  width="50%"
  align="right"
/>

On top of LLDAP it adds:

- a Kerberos KDC inside the server, with principals created, updated and
  deleted as users change,
- POSIX accounts and groups (`uidNumber`, `gidNumber`, `homeDirectory`,
  `loginShell`), assignable automatically, for SSSD and PAM,
- admin-controlled organizational units,
- a TOTP second factor, server-wide or per OU, and OU policies for account lockout, password
  length, login hours, allowed networks and inactivity ([docs/policies.md](docs/policies.md)),
- LDAP writes: `ldapadd` users and groups, `ldapmodify` attributes and passwords,
- a Federation tab that sets up a Keycloak realm against KLLDAP (LDAP + Kerberos
  SPNEGO) and exports its keytab,
- `sshPublicKey`, `jpegPhoto`/avatar conversion, disabled accounts
  (`lldap_disabled`).

This is a personal project, developed for a home lab and shared as-is under the
GPL-3.0-only. It is not supported by the LLDAP team; if you do not need Kerberos or
POSIX, use [LLDAP](https://github.com/lldap/lldap). Stock LLDAP 0.6.x databases can
move to KLLDAP with their data (users set a new password), see the
[migration guide](docs/migration_guides/v0.7-from-lldap.md).

## Installation

KLLDAP runs from a Docker image, `aelieth/klldap`, that you build, or from the release
tarball on a host. See [docs/install.md](docs/install.md). A 0.7.2 install follows
[Upgrading from 0.7.2](docs/kerberos.md#upgrading-from-072) before its first 0.8.1 start.

0.8.1 is a pre-release, and its images are not published to a registry. Build the image from
the `Dockerfile` at the `v0.8.1` tag and name it `aelieth/klldap:0.8.1`, the name the examples
use ([docs/install.md](docs/install.md)). It builds for amd64 and arm64; the arm64 image is built
under emulation and is not tested by us.

The rootless image is the `Dockerfile`'s `rootless` target, named `aelieth/klldap:0.8.1-rootless`, for the same platforms as the default image.

KLLDAP 0.8.0 is 64-bit only (x86_64 and arm64); there is no 32-bit or ARMv7 build.

## Usage

The web UI creates users and groups, sets passwords, assigns OUs and POSIX numbers,
and configures Keycloak federation. Users can change their own details and
password. Everything the UI does is also available over the GraphQL API, and the
community CLI [Zepmann/lldap-cli](https://github.com/Zepmann/lldap-cli) works
unmodified; [scripts/bootstrap.sh](scripts/bootstrap.sh) enforces users, groups and
attributes from files. See [docs/scripting.md](docs/scripting.md).

The Kerberos realm is derived from the base DN (`dc=example,dc=com` →
`EXAMPLE.COM`). Users with `kerberosSync` on get a principal whenever their password
is set, and it is disabled while they are in `lldap_disabled`. See
[docs/kerberos.md](docs/kerberos.md).

## Client configuration

The LDAP layout is LLDAP's:

- users are under `ou=people`: `uid=bob,ou=people,dc=example,dc=com`,
- groups under `ou=groups`: `cn=family,ou=groups,dc=example,dc=com`,
- custom OUs are siblings of those or one level below any OU
  (`ou=lab,dc=example,dc=com`, `ou=team,ou=lab,dc=example,dc=com`),
- the admin bind DN is `uid=admin,ou=people,dc=example,dc=com` (`ldap_user_dn`),
- `memberOf` filters work, and groups carry `member`, `uniqueMember` and `memberUid`.

Users and groups also carry the `posixAccount` / `posixGroup` classes and
attributes, so `ldap_schema = rfc2307` or `rfc2307bis` clients such as SSSD work
without mapping. `lldap_admin` grants admin rights; integrations should bind as a
member of `lldap_strict_readonly` or `lldap_password_manager` instead.

Guides: [SSSD + Kerberos + Keycloak](docs/SSSD_LDAP_Kerberos_Setup_Guide.md),
[PAM/nslcd](example_configs/pam/README.md), and per-service samples in
[example_configs](example_configs/README.md).

## Configuration

Configuration comes from `/data/lldap_config.toml`
([template](lldap_config.docker_template.toml)) and environment variables prefixed
`LLDAP_`; nested keys use `__` (`LLDAP_SMTP_OPTIONS__SERVER`). Any value can be
read from a file instead by appending `_FILE` to the variable name
(`LLDAP_JWT_SECRET_FILE=/run/secrets/jwt`).

| Variable | Default | Description |
|---|---|---|
| `LLDAP_JWT_SECRET` | required | Secret signing the web sessions |
| `LLDAP_LDAP_USER_PASS` | required | Initial admin password (only used at first start) |
| `LLDAP_KEY_SEED` / `LLDAP_KEY_FILE` | template seed / `server_key` (in `/app`, not persisted) | Server private key for password storage: set your own seed, or a key file under `/data`; never lose it |
| `LLDAP_LDAP_BASE_DN` | `dc=example,dc=com` | Base DN; also derives the Kerberos realm and domain |
| `LLDAP_LDAP_USER_DN` / `LLDAP_LDAP_USER_EMAIL` | `admin` / empty | Admin username and email |
| `LLDAP_DATABASE_URL` | `sqlite:////data/users.db?mode=rwc` | SQLite, PostgreSQL or MySQL/MariaDB URL |
| `LLDAP_LDAP_HOST` / `LLDAP_LDAP_PORT` | `0.0.0.0` / `3890` | LDAP listener |
| `LLDAP_HTTP_HOST` / `LLDAP_HTTP_PORT` | `0.0.0.0` / `17170` | Web UI and API listener |
| `LLDAP_HTTP_URL` | `http://localhost` | Public URL, used to build password-reset links |
| `LLDAP_VERBOSE` | `false` | Debug logging (`LLDAP_RAW_LOG=1` adds a plain-text log layer) |
| `LLDAP_IGNORED_USER_ATTRIBUTES` / `LLDAP_IGNORED_GROUP_ATTRIBUTES` | `[]` | Requested attributes to drop silently |
| `LLDAP_FORCE_LDAP_USER_PASS_RESET` | `false` | Reset the admin password from `LLDAP_LDAP_USER_PASS` (`true` once, `always`) |
| `LLDAP_FORCE_UPDATE_PRIVATE_KEY` | `false` | Accept a changed private key (invalidates every password) |
| `LLDAP_ENABLE_MFA` | unset | TOTP second factor for every user, overriding the OUs' `enable-mfa`: `off`, `enabled` for users who enroll, `always` for everyone (0.8.0's `false` / `true` still work; `lldap_mfa_disabled` members exempt). Unset, each OU's policy decides. See [docs/mfa.md](docs/mfa.md) |
| `LLDAP_LOGIN_HOURS_TIMEZONE` | `UTC` | The zone the OUs' `login-hours` windows are read in: an IANA name (`America/Chicago`) read once at start from the system's zone files; an unknown name refuses the start. See [docs/policies.md](docs/policies.md#configuration) |
| `LLDAP_TRUSTED_PROXIES` | empty | The reverse proxies whose `X-Forwarded-For` the OUs' `allowed-networks` believe, as one string of comma-separated CIDRs; empty, the header is never read for a decision. See [docs/allowed-networks.md](docs/allowed-networks.md#whose-address) |
| `LLDAP_LDAPS_OPTIONS__ENABLED` / `__PORT` / `__CERT_FILE` / `__KEY_FILE` | `false` / `6360` | LDAPS |
| `LLDAP_SMTP_OPTIONS__ENABLE_PASSWORD_RESET`, `__SERVER`, `__PORT`, `__SMTP_ENCRYPTION`, `__USER`, `__PASSWORD`, `__FROM`, `__REPLY_TO`, `__TLS_ROOT_CERT_FILE` | off | Password-reset mail. `__TLS_ROOT_CERT_FILE` is an optional PEM of the CA that signed the SMTP server |
| `LLDAP_HEALTHCHECK_OPTIONS__HTTP_HOST` / `__LDAP_HOST` | `localhost` | What `lldap healthcheck` probes |
| `LLDAP_LOG_OPTIONS__PERSIST` / `__RETENTION_DAYS` / `__MAX_ENTRIES` / `__BIND_COALESCE_SECONDS` | `true` / `30` / `50000` / `300` | Persistent event log (logins, binds, directory changes, denials) in the `logs` table, see [docs/logging.md](docs/logging.md); `0` removes an age or size limit; the trim also runs with `PERSIST=false`; repeated successful binds are stored once per coalescing window (`0` stores all) |
| `LLDAP_KERBEROS_OPTIONS__ENABLED` / `__REALM` / `__TICKET_LIFETIME` / `__RENEW_LIFETIME` / `__FORWARDABLE` / `__CLIENT_CASE_FOLD` / `__SUPPORTED_ENCTYPES` | `true` / from the base DN / `24h` / `7d` / `true` / `true` / `aes256-cts-hmac-sha1-96` | Kerberos inside the server. `enabled` defaults to true; set it to `false` to run without a realm. Lifetimes take a Kerberos duration (`24h`, `7d`, `36000s`) or a bare number of seconds (`36000`), quoted or not. When enabled, directory writes wait for the KDC after boot and the healthcheck also requires it, `client_case_fold` defaults to true. See [docs/kerberos.md](docs/kerberos.md) |
| `LLDAP_KERBEROS_OPTIONS__MFA_PROOF_WINDOW` / `__MFA_PROOF_SAME_ADDRESS` | `10m` / `false` | How long a sign-in with password and code at a directory door opens kinit for a user who must give a second factor, and whether the kinit must come from that sign-in's address. See [docs/kerberos.md](docs/kerberos.md#a-second-factor-and-kinit) |
| `LLDAP_KERBEROS_OPTIONS__KDC_HOST` / `__KDC_PORT` / `__KADMIN_HOST` / `__KADMIN_PORT` / `__DATA_DIR` / `__ADMIN_KEYTAB` / `__CLIENT_CONFIG` / `__KADMIN_ACL` | `0.0.0.0` / `1088` / `127.0.0.1` / `1749` / `krb5kdc` / `kadm5.keytab` / `krb5.conf` / none | KDC and kadmin listeners, the database directory, the admin keytab and the client config. The image sets the three paths to `/var/kerberos/krb5kdc`, `/data/kadm5.keytab` and `/data/krb5.conf` |
| `LLDAP_KEYCLOAK_OPTIONS__CONFIG_FILE` / `__KEYTAB` | `keycloak_config.toml` / `keytab/keycloak-http.keytab` | Where the Federation tab stores URL, realm and admin user, and the Keycloak HTTP keytab. The image sets `/data/keycloak_config.toml` and `/data/keytab/keycloak-http.keytab` |
| `LLDAP_KEYCLOAK_OPTIONS__ADMIN_PASS` | none | Keycloak admin password used by the Federation tab. `LLDAP_KEYCLOAK_OPTIONS__ADMIN_PASS_FILE` reads it from a file; if both are set, the plain value wins |
| `UID` / `GID` | `1000` / `1000` | User the server runs as. `LLDAP_UID` / `LLDAP_GID` still work and win when set |
| `LLDAP_CONFIG_FILE`, `LLDAP_SERVER_KEY_FILE`, `LLDAP_SERVER_KEY_SEED` | | Command-line equivalents of the config file / key settings |

Ports: `3890` LDAP, `6360` LDAPS (optional), `17170` web UI and API. The KDC
listens on 1088 and is published as `88:1088` (tcp and udp). kadmin listens
on `127.0.0.1:1749` inside the container and is not published. Clients outside
use port 88. The image sets `KRB5_CONFIG=/data/krb5.conf`, so `docker exec` does
not pass it. A root start uses `gosu` to switch user. `--user` on that image
fails, because `gosu` cannot switch user without root. `tini` is the init. The
rootless image starts as user `lldap` and does not change ownership. Volumes: `/data` (config,
database, keytabs) and `/var/kerberos/krb5kdc` (KDC database) — both must persist.

## Documentation

- [Installation](docs/install.md), [migrating from LLDAP](docs/migration_guides/v0.7-from-lldap.md),
  [changing database backend](docs/database_migration.md)
- [Kerberos](docs/kerberos.md), [SSSD + Kerberos + Keycloak guide](docs/SSSD_LDAP_Kerberos_Setup_Guide.md)
- [Scripting (LDAP and GraphQL)](docs/scripting.md), [event logging](docs/logging.md),
  [two-factor authentication](docs/mfa.md), [OU policies](docs/policies.md),
  [allowed networks](docs/allowed-networks.md), [architecture](docs/architecture.md)
- [FAQ](docs/faq.md), [building and testing](docs/testing.md), [changelog](CHANGELOG.md)

## Contributions

Bugs and PRs are welcome, on a best-effort basis; see [CONTRIBUTING.md](CONTRIBUTING.md).
Run `make safety` before opening a PR. Changes that fit upstream LLDAP are better
sent there.

## License

GPL-3.0-only, see [LICENSE](LICENSE). KLLDAP contains LLDAP, © the LLDAP authors.
