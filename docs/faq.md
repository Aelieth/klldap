# Frequently Asked Questions

- [I can't login](#i-cant-log-in)
- [kinit fails for a user](#kinit-fails-for-a-user)
- [Migrating from SQLite](#migrating-from-sqlite)
- How does KLLDAP compare [with LLDAP](#how-does-klldap-compare-with-lldap)? [With OpenLDAP](#how-does-klldap-compare-with-openldap)? [With FreeIPA](#how-does-klldap-compare-with-freeipa)? [With Kanidm](#how-does-klldap-compare-with-kanidm)?
- [Does KLLDAP support vhosts?](#does-klldap-support-vhosts)
- [Is KLLDAP supported? Can we depend on it?](#is-klldap-supported-can-we-depend-on-it)

## I can't log in!

If you just set up the server, can get to the login page but the password you
set isn't working, try the following:

- If you have changed the admin password in the config after the first run, it
  won't be used (unless you force its use with `force_ldap_user_pass_reset`).
  The config password is only for the initial admin creation.
- Make sure that the `/data` folder is persistent, either to a docker volume or
  mounted from the host filesystem.
- Check if there is a `lldap_config.toml` file in `/data`. If there isn't, the
  entrypoint copies `lldap_config.docker_template.toml` there on start; fill in the
  values (passwords, secrets, ...) or set them as environment variables.
- Check if there is a `users.db` file in `/data`. If there isn't, check that the
  container user (`LLDAP_UID`, 1000 by default) can write to `/data`.
- If the log says "The private key has changed", the `key_seed`/`key_file` no longer
  matches the database: restore the right one, or restart once with
  `--force-update-private-key=true --force-ldap-user-pass-reset=true` and have every
  user reset their password.
- If two-factor authentication is on and the account is enrolled, the password field
  takes `yourpassword:123456` — password, a colon, the current code — and the bare
  password is refused. Service accounts that cannot type a code belong in
  `lldap_mfa_disabled`. See [mfa.md](mfa.md).
- Make sure you restart the server.

## kinit fails for a user

- The user needs `kerberosSync` on, and a password set (or changed) after that: the
  principal is created on the password sync. `docker exec klldap kadmin.local -q
  listprincs` shows what exists.
- A user in `lldap_disabled` cannot get tickets by design.
- Check the client's `krb5.conf` realm and KDC address, and that ports 88 (tcp+udp)
  and 749 reach the container. See [kerberos.md](kerberos.md).

## Migrating from SQLite

If you started with an SQLite database and would like to migrate to PostgreSQL or
MySQL/MariaDB, check out the [DB migration docs](database_migration.md).

## How does KLLDAP compare with LLDAP?

KLLDAP is LLDAP plus an MIT Kerberos KDC, POSIX accounts and groups, admin-managed
OUs, LDAP writes and Keycloak federation, in one container. The web UI, the GraphQL
API and the LDAP layout are LLDAP's, and `lldap-cli` works. If you do not need
Kerberos or POSIX, [LLDAP](https://github.com/lldap/lldap) is the maintained,
community-supported project.

## How does KLLDAP compare with OpenLDAP?

[OpenLDAP](https://www.openldap.org) is a full-featured, highly configurable LDAP
server. It is very powerful but complex to set up and maintain.

KLLDAP is opinionated and small: a fixed schema with a few extensions, a web UI, and
no LDAP schema administration.

## How does KLLDAP compare with FreeIPA?

[FreeIPA](http://www.freeipa.org) is a complete identity management solution (LDAP,
Kerberos, DNS, certificates, policies).

KLLDAP covers the LDAP + Kerberos part for a home lab in a single container, without
DNS, certificate management or policy engines.

## How does KLLDAP compare with Kanidm?

[Kanidm](https://kanidm.com) is a modern identity platform with OAuth, WebAuthn and a
read-only LDAPS server.

KLLDAP keeps read-write LDAP and adds an MIT Kerberos KDC; it is an evolution of the
LLDAP code rather than a rewrite.

## Does KLLDAP support vhosts?

No. All users share the same base DN and realm. If you need real multi-tenancy, run
several instances.

## Is KLLDAP supported? Can we depend on it?

KLLDAP is a personal project shared as-is (AGPL-3.0), developed for its author's home
lab; the bus factor is one, and there is no support channel. The suites in
[testing.md](testing.md) are what keeps it honest. Treat it as hobbyist software: use
it where you can maintain or fork it yourself.
