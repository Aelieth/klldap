<h1 align="center">KLLDAP - Light LDAP with an integrated Kerberos KDC</h1>

<p align="center">
  <a href="https://github.com/Aelieth/klldap/actions/workflows/rust.yml?query=branch%3A0.7.4">
    <img src="https://github.com/Aelieth/klldap/actions/workflows/rust.yml/badge.svg?branch=0.7.4" alt="Build"/>
  </a>
  <a href="https://github.com/Aelieth/klldap/actions/workflows/gate.yml?query=branch%3A0.7.4">
    <img src="https://github.com/Aelieth/klldap/actions/workflows/gate.yml/badge.svg?branch=0.7.4" alt="Gate"/>
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
LDAP authentication server, with an MIT Kerberos KDC running in the same container.
Users, groups and passwords are managed once, through the web UI, LDAP or
GraphQL; the KDC follows.

<img
  src="https://raw.githubusercontent.com/Aelieth/klldap/main/screenshot.png"
  alt="Screenshot of the user list page"
  width="50%"
  align="right"
/>

On top of LLDAP it adds:

- an MIT Kerberos KDC (`krb5kdc` + `kadmind`) bootstrapped on first start, with
  principals created, updated and deleted as users change,
- POSIX accounts and groups (`uidNumber`, `gidNumber`, `homeDirectory`,
  `loginShell`), assignable automatically, for SSSD and PAM,
- admin-controlled organizational units,
- LDAP writes: `ldapadd` users and groups, `ldapmodify` attributes and passwords,
- a Federation tab that sets up a Keycloak realm against KLLDAP (LDAP + Kerberos
  SPNEGO) and exports its keytab,
- `sshPublicKey`, `jpegPhoto`/avatar conversion, disabled accounts
  (`lldap_disabled`).

This is a personal project, developed for a home lab and shared as-is under the
AGPL-3.0. It is not supported by the LLDAP team; if you do not need Kerberos or
POSIX, use [LLDAP](https://github.com/lldap/lldap). Stock LLDAP 0.6.x databases can
move to KLLDAP with data and passwords intact, see the
[migration guide](docs/migration_guides/v0.7-from-lldap.md).

## Installation

KLLDAP ships as a Docker image, `aelieth/klldap`, because the KDC lives in the
container. See [docs/install.md](docs/install.md).

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
| `LLDAP_LDAPS_OPTIONS__ENABLED` / `__PORT` / `__CERT_FILE` / `__KEY_FILE` | `false` / `6360` | LDAPS |
| `LLDAP_SMTP_OPTIONS__ENABLE_PASSWORD_RESET`, `__SERVER`, `__PORT`, `__SMTP_ENCRYPTION`, `__USER`, `__PASSWORD`, `__FROM`, `__REPLY_TO` | off | Password-reset mail |
| `LLDAP_HEALTHCHECK_OPTIONS__HTTP_HOST` / `__LDAP_HOST` / `__KERBEROS` | `localhost` / `false` | What `lldap healthcheck` probes; the image runs it with `--kerberos` |
| `LLDAP_KERB_REALM_NAME` | derived | Kerberos realm override |
| `LLDAP_KERB_ADMIN_KEYTAB`, `_CONFIG`, `_KRB5_CONF`, `_KDC_CONF`, `_KADM5_ACL`, `_KDC_DIR`, `_KEYCLOAK_KEYTAB`, `_KDC_PORT` (+ `_*_TEMPLATE`) | container layout | Kerberos file locations and KDC port, see [docs/kerberos.md](docs/kerberos.md) |
| `LLDAP_KEYCLOAK_ADMIN_PASS` | `admin` | Keycloak admin password used by the Federation tab |
| `LLDAP_KEYCLOAK_CONFIG` | `/data/keycloak_config.toml` | Where the Federation tab stores URL, realm and admin user |
| `LLDAP_UID` / `LLDAP_GID` | `1000` / `1000` | User the server runs as inside the container (`UID`/`GID` still honored) |
| `LLDAP_CONFIG_FILE`, `LLDAP_SERVER_KEY_FILE`, `LLDAP_SERVER_KEY_SEED` | | Command-line equivalents of the config file / key settings |

Ports: `3890` LDAP, `6360` LDAPS (optional), `17170` web UI and API, `88/tcp+udp`
KDC, `749/tcp` kadmin. Volumes: `/data` (config, database, keytabs) and
`/var/kerberos/krb5kdc` (KDC database) — both must persist.

## Documentation

- [Installation](docs/install.md), [migrating from LLDAP](docs/migration_guides/v0.7-from-lldap.md),
  [changing database backend](docs/database_migration.md)
- [Kerberos](docs/kerberos.md), [SSSD + Kerberos + Keycloak guide](docs/SSSD_LDAP_Kerberos_Setup_Guide.md)
- [Scripting (LDAP and GraphQL)](docs/scripting.md), [architecture](docs/architecture.md)
- [FAQ](docs/faq.md), [building and testing](docs/testing.md), [changelog](CHANGELOG.md)

## Contributions

Bugs and PRs are welcome, on a best-effort basis; see [CONTRIBUTING.md](CONTRIBUTING.md).
Run `make safety` before opening a PR. Changes that fit upstream LLDAP are better
sent there.

## License

AGPL-3.0-only, see [LICENSE](LICENSE). KLLDAP contains LLDAP, © the LLDAP authors.
