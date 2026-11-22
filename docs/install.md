# Installing KLLDAP

The Kerberos KDC runs inside the `lldap` process. The image is how you run the server.

Images are amd64 and arm64, `aelieth/klldap:0.8.0`. The arm64 image is built under emulation and is not tested by us.

KLLDAP 0.8.0 is 64-bit only (x86_64 and arm64); there is no 32-bit or ARMv7 build.

**Set a restart policy. If a Kerberos thread dies, or the server gives the
Kerberos realm up because its writes stopped reaching the database, the process
exits non-zero, and without a restart policy the container stays down. With
one, the server is back once the database answers again, after the restart and
a thirty-five-second watch.**

- [With Docker](#with-docker)
- [With Podman](#with-podman)
- [Kubernetes, TrueNAS SCALE and package repositories](#kubernetes-truenas-scale-and-package-repositories)
- [Install from the release tarball](#install-from-the-release-tarball)
- [From source](#from-source)
  - [Backend](#backend)
  - [Frontend](#frontend)
- [Cross-compilation](#cross-compilation)
- [Migrating from LLDAP](#migrating-from-lldap)
- [Upgrading from KLLDAP 0.7.2](#upgrading-from-klldap-072)
- [Upgrading from KLLDAP 0.8.0](#upgrading-from-klldap-080)

### With Docker

The image persists two volumes: `/data` (configuration, the SQLite database, keytabs)
and `/var/kerberos/krb5kdc` (the KDC database).

If `UID` and `GID` are not set, the image uses `1000`. `LLDAP_UID` and `LLDAP_GID`
still work, and they win when both names are set. A root start repairs ownership of
`/data`, `/app` and the KDC directory, then `gosu` runs the server as that user.
`tini` is the init. The rootless image starts as user `lldap` and does not change
ownership; `/data` must already be writable by that user. `--user` on the standard
image fails, because `gosu` cannot switch user without root. Use `aelieth/klldap:0.8.0-rootless`,
and the compose `user:` field in place of `UID` and `GID`.

The KDC listens on 1088 and kadmin on `127.0.0.1:1749`. Publish the KDC as `88:1088`
(tcp and udp). kadmin is not published. Those ports need no capability. A port below
1024, set on purpose, binds only where the engine lets any process bind a low port.
Docker does. Podman does not, unless the container is given
`--sysctl net.ipv4.ip_unprivileged_port_start=0` (untested). Elsewhere
the server comes up degraded and says so. There is no reason to change the port
inside the container; adjust the published port instead.

With every capability dropped, add back `CHOWN`, `DAC_OVERRIDE`, `SETGID` and
`SETUID`. The entrypoint changes ownership, and `gosu` switches user. Without
`DAC_OVERRIDE` it stops while creating `/data/keytab`.

On the first start, in the image, the server creates the realm, writes
`/data/kadm5.keytab` and `/data/krb5.conf`, and the healthcheck fails until the
KDC is up. Tools inside the container use that `krb5.conf`, which carries the
inner port. Clients outside use port 88. See [kerberos.md](kerberos.md).

```yaml
volumes:
  lldap_data:
  kerberos_db:

services:
  klldap:
    image: aelieth/klldap:0.8.0
    container_name: klldap
    restart: unless-stopped
    ports:
      - "3890:3890"       # LDAP (do not expose publicly)
      #- "6360:6360"      # LDAPS, with LLDAP_LDAPS_OPTIONS__ENABLED=true
      - "17170:17170"     # Web UI and API
      - "88:1088/tcp"     # Kerberos KDC
      - "88:1088/udp"
    volumes:
      - lldap_data:/data
      - kerberos_db:/var/kerberos/krb5kdc
    environment:
      - UID=1000
      - GID=1000
      - TZ=Etc/UTC
      - LLDAP_JWT_SECRET=REPLACE_WITH_RANDOM_SECRET
      - LLDAP_KEY_SEED=REPLACE_WITH_RANDOM_SEED
      - LLDAP_LDAP_USER_PASS=CHANGE_ME
      - LLDAP_LDAP_BASE_DN=dc=example,dc=com
```

Secrets can come from files instead of the environment by appending `_FILE`
(`LLDAP_JWT_SECRET_FILE=/run/secrets/jwt`).

Then open `http://your-server:17170` and log in as `admin` with `LLDAP_LDAP_USER_PASS`.

### With Podman

KLLDAP runs under rootless Podman. The [quadlets](../example_configs/podman-quadlets/)
publish the KDC as `88:1088` (tcp and udp). Publishing the host's port 88 from a
rootless container is Podman's own limit. Podman says "Podman can not create
containers that bind to ports < 1024"
([rootless.md](https://github.com/containers/podman/blob/main/rootless.md)).

Rootless Podman on the standard image matches Docker on the default ports. The
server runs as uid 1000, holds no capability, and owns UDP 1088. `UID` and
`LLDAP_UID` behave as they do under Docker, and `--user` fails at `gosu`. A root
start with every capability dropped needs the same four. A port below 1024, set
on purpose, comes up degraded.

On the rootless image the same start is uid 1000 with no capability, with or
without every capability dropped, and `UID` is ignored. A different user fails
when it does not own `/data`. When that user owns the volumes, the same start
is healthy as uid 1500 and holds no capability.

Rootful Podman matches rootless Podman on both images. The default start is
healthy as uid 1000, holds no capability, and owns UDP 1088. A port below 1024
comes up degraded, as it does under rootless Podman and unlike Docker.

### Kubernetes, TrueNAS SCALE and package repositories

Nothing here installs KLLDAP. The image is how you run it. Upstream's install page
covers LLDAP's chart, TrueNAS app, packages and FreeBSD port.

### Install from the release tarball

A release has two tarballs, `lldap-x86_64-glibc-v<version>.tar.gz` and
`lldap-aarch64-glibc-v<version>.tar.gz`. There is no 32-bit or ARMv7 tarball.
The aarch64 tarball is built under emulation and is not tested by us.

The x86_64 tarball needs an x86-64-v2 processor or newer, glibc 2.34 or newer,
and libgcc_s, libm and libc. It runs on AlmaLinux 10 and Debian 12.

The tarball contains one directory, named `x86_64` or `aarch64`, with `lldap`,
`index.html`, `static/`, `pkg/`, `lldap_config.docker_template.toml`, `README.md`
and `LICENSE`.

The unit is [lldap.service](../example_configs/lldap.service). It runs
`/opt/nitnelave/lldap run` as user and group `klldap`, with working directory
`/opt/nitnelave`. That directory must be readable and writable by `klldap`.

Unpack that directory's contents into `/opt/nitnelave`, so the binary is
`/opt/nitnelave/lldap`. Copy `lldap_config.docker_template.toml` to
`/opt/nitnelave/lldap_config.toml` and edit it. The unit passes no
`--config-file`, so the server reads `lldap_config.toml` from its working
directory. Keep that file owned by `klldap` and not readable by others.

Set these keys. The template points them at the image's paths:

- `database_url`. The template uses `sqlite:////data/users.db?mode=rwc`. Point
  it under `/opt/nitnelave`, for example
  `sqlite:////opt/nitnelave/users.db?mode=rwc`.
- `assets_path` to `/opt/nitnelave`, the directory that holds `index.html`,
  `static/` and `pkg/`. Left unset it is `./app`, and the web app answers 404.
- `ldap_base_dn`. The realm is the base DN's `dc` components, joined and
  uppercased (`dc=example,dc=com` gives `EXAMPLE.COM`), unless
  `kerberos_options.realm` is set.
- `kerberos_options.data_dir`, `admin_keytab` and `client_config`. The template
  sets `/var/kerberos/krb5kdc`, `/data/kadm5.keytab` and `/data/krb5.conf`. Use
  `/opt/nitnelave/krb5kdc`, `/opt/nitnelave/kadm5.keytab` and
  `/opt/nitnelave/krb5.conf`.
- If you use the Federation tab, `keycloak_options.config_file` and
  `keycloak_options.keytab`. The template sets them under `/data`. Point them
  under `/opt/nitnelave`.

`jwt_secret`, `key_seed` and `ldap_user_pass` go in that file. Replace the
template's `key_seed`. Or set `LLDAP_JWT_SECRET`, `LLDAP_KEY_SEED` and
`LLDAP_LDAP_USER_PASS` in a systemd drop-in of your own, the same kind of file
as the PostgreSQL drop-in under [From source](#from-source).

The KDC listens on 1088, which on a host install needs no capability. For a port
below 1024, see [With Docker](#with-docker). `data_dir` is created at mode 0700
and the admin keytab is written at mode 0600: [Bootstrap](kerberos.md#bootstrap).

From `/opt/nitnelave`, run `/opt/nitnelave/lldap healthcheck`, then log in.

### From source

#### Backend

`prepare-release.sh` builds the server for the machine it runs on: on x86_64 for the x86-64-v2
instruction set, on aarch64 with no CPU flag. On x86_64:

```sh
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=x86-64-v2" cargo build --release -p lldap
```

The binary is `target/release/lldap`.

#### Frontend

`./app/build.sh` needs `wasm-pack` (`cargo install wasm-pack` if it is missing) and `gzip`.
It runs `wasm-pack build --target web --release`.

You can also install it as a systemd service, see
[lldap.service](../example_configs/lldap.service). The shipped unit is for
SQLite. With PostgreSQL on the same host, add a drop-in and leave that unit
as shipped:

    Wants=postgresql.service
    After=postgresql.service
    Restart=on-failure

### Migrating from LLDAP

Stock LLDAP 0.6.x databases (schema 11 or older) can move to KLLDAP with their
data; users set a new password: [migration_guides/v0.7-from-lldap.md](migration_guides/v0.7-from-lldap.md).
Moving between database backends is in [database_migration.md](database_migration.md).

### Upgrading from KLLDAP 0.7.2

Write a dump of the Kerberos realm with the 0.7.2 image before the first 0.8.1 start; 0.8.1
loads it and keeps the MIT files: [kerberos.md](kerberos.md#upgrading-from-072).

At each start, a principal of a directory user without `kerberosSync`, a migrated one
included, is disabled, not deleted, and a `kerberos_sync` log row names it. To use it again,
turn `kerberosSync` on for the user, then change the user's password: the password change is
what brings kinit back. Or remove the principal with kadmin.

On MySQL and MariaDB schema changes are not transactional (the server commits at each DDL
statement), so take a backup before the first 0.8.1 start; if a start is interrupted
mid-migration the next start completes it.

**A 0.7.2 compose file that publishes `88:88` must publish `88:1088`, or the KDC is
unreachable after the upgrade.** If `key_seed` is unset, keep the key file the
first start writes: that write is not synced, and a lost key makes the next
start refuse.

### Upgrading from KLLDAP 0.8.0

Stop every KLLDAP server that uses the database before the first 0.8.1 start, and
do not run 0.8.0 and 0.8.1 side by side. A server that finds the Kerberos realm left
open watches it before it takes it over: 0.8.0 for thirty seconds, 0.8.1 for
thirty-five. A 0.8.1 holder stops serving within thirty seconds of the start of
its last write that reached the database. A 0.8.0 holder can serve that long, and
longer under sustained load. So a 0.8.0 server could take the realm over from a
0.8.1 holder that still serves, or a 0.8.1 server from a busy 0.8.0 holder, and
two servers could serve the realm at once.
