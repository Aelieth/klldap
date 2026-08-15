# Installing KLLDAP

KLLDAP is Docker-only: the MIT Kerberos KDC (`krb5kdc`, `kadmind`) runs inside the
image beside the server, bootstrapped by the entrypoint. There are no packages, and
bare-metal installs are not supported.

- [With Docker](#with-docker)
- [First start](#first-start)
- [With Podman](#with-podman)
- [Migrating from LLDAP](#migrating-from-lldap)

### With Docker

The image is available at `aelieth/klldap`. Persist two folders:

- `/data`: configuration, the SQLite database, the admin keytab, keytabs exported
  for Keycloak, and `keycloak_config.toml`.
- `/var/kerberos/krb5kdc`: the KDC database. Losing it means every Kerberos
  principal has to be recreated.

Configuration is `/data/lldap_config.toml`, copied from
[`lldap_config.docker_template.toml`](../lldap_config.docker_template.toml) on first
start, and any `LLDAP_*` environment variable overrides it (see the table in the
[README](../README.md#configuration)). Set `LLDAP_JWT_SECRET`, `LLDAP_LDAP_USER_PASS`,
`LLDAP_KEY_SEED` (or a `key_file` under `/data`) and `LLDAP_LDAP_BASE_DN`; the base
DN also becomes the Kerberos realm (`dc=example,dc=com` → `EXAMPLE.COM`).

```yaml
volumes:
  lldap_data:
  kerberos_db:

services:
  klldap:
    image: aelieth/klldap:latest
    container_name: klldap
    restart: unless-stopped
    ports:
      - "3890:3890"       # LDAP (do not expose publicly)
      #- "6360:6360"      # LDAPS, with LLDAP_LDAPS_OPTIONS__ENABLED=true
      - "17170:17170"     # Web UI and API
      - "88:88/tcp"       # Kerberos KDC
      - "88:88/udp"
      - "749:749/tcp"     # Kerberos admin (kadmin)
    volumes:
      - lldap_data:/data
      - kerberos_db:/var/kerberos/krb5kdc
    environment:
      - LLDAP_UID=1000
      - LLDAP_GID=1000
      - TZ=Etc/UTC
      - LLDAP_JWT_SECRET=REPLACE_WITH_RANDOM_SECRET
      - LLDAP_KEY_SEED=REPLACE_WITH_RANDOM_SEED
      - LLDAP_LDAP_USER_PASS=CHANGE_ME
      - LLDAP_LDAP_BASE_DN=dc=example,dc=com
      # Optional:
      # - LLDAP_KERB_REALM_NAME=EXAMPLE.COM
      # - LLDAP_KEYCLOAK_ADMIN_PASS=admin
      # - LLDAP_DATABASE_URL=postgres://user:password@postgres/lldap
      # - LLDAP_LDAPS_OPTIONS__ENABLED=true
      # - LLDAP_LDAPS_OPTIONS__CERT_FILE=/data/cert/cert.pem
      # - LLDAP_LDAPS_OPTIONS__KEY_FILE=/data/cert/key.pem
      # - LLDAP_SMTP_OPTIONS__ENABLE_PASSWORD_RESET=true
      # - LLDAP_SMTP_OPTIONS__SERVER=smtp.example.com
      # - LLDAP_SMTP_OPTIONS__PORT=465
      # - LLDAP_SMTP_OPTIONS__SMTP_ENCRYPTION=TLS
      # - LLDAP_SMTP_OPTIONS__USER=no-reply@example.com
      # - LLDAP_SMTP_OPTIONS__PASSWORD=PasswordGoesHere
      # - LLDAP_SMTP_OPTIONS__FROM=no-reply <no-reply@example.com>
      # - LLDAP_HTTP_URL=https://ldap.example.com   # password-reset links are built from it
```

Secrets can come from files instead of the environment by appending `_FILE`
(`LLDAP_JWT_SECRET_FILE=/run/secrets/jwt`).

### First start

The entrypoint starts the server, waits for it to be healthy, then bootstraps the KDC:
it creates the Kerberos database with a random, stash-only master password, the
`admin/admin@REALM` principal and `/data/kadm5.keytab`, renders `krb5.conf`,
`kdc.conf` and `kadm5.acl` from the templates in `/app`, and starts
`krb5kdc` and `kadmind`. Later starts skip what already exists. The container's
healthcheck (`lldap healthcheck --kerberos`) fails until the KDC is up, and directory
writes are refused ("Kerberos KDC unavailable") until it has answered once — logins and
reads work throughout.

Then:

- open `http://your-server:17170` and log in as `admin` with `LLDAP_LDAP_USER_PASS`,
- create users, groups and OUs; turn on `kerberosSync` for users that need a principal
  (it is created when their password is set),
- point Keycloak at KLLDAP from the Federation tab, if you use it.

`docker logs klldap` shows the bootstrap; `docker exec klldap kadmin.local -q listprincs`
lists the principals. See [kerberos.md](kerberos.md) for the details and
[faq.md](faq.md) if you cannot log in.

### With Podman

Untested. The container needs to run as root inside its own namespace (it chowns
`/data`, runs `kdb5_util` and spawns the daemons), which rootless Podman provides;
the [quadlets](../example_configs/podman-quadlets/) are adapted to KLLDAP as a
starting point. Please report what you find.

### Migrating from LLDAP

Stock LLDAP 0.6.x databases (schema 11 or older) can move to KLLDAP with data and
passwords intact: [migration_guides/v0.7-from-lldap.md](migration_guides/v0.7-from-lldap.md).
Moving between database backends is in [database_migration.md](database_migration.md).
