# Building and testing

## Building

The server build does not need Kerberos headers or clang. The Kerberos
end-to-end test needs `kinit` (`krb5-workstation` on Fedora, `krb5-user` on
Debian/Ubuntu).

`cargo build --workspace` builds the server, the tools and every crate. `--workspace`
matters: `default-members` is the server only, so a bare `cargo build`/`cargo test` covers
a fraction of the tree. The frontend builds with `./app/build.sh` (wasm-pack).

## The safety dance

`cargo-deny` has to be on `PATH`; CI uses 0.20.2. `make safety` is the
pre-commit check, in this order:

```sh
cargo fmt --all
cargo build --workspace
cargo test --workspace
cargo clippy --tests --all -- -D warnings
cargo deny check licenses sources
./export_schema.sh && git diff --exit-code schema.graphql   # schema.graphql must not drift
```

`cargo test --workspace` runs the unit tests of every crate and `server/tests`, which
starts the freshly built binary against a temporary SQLite database on ephemeral ports (one
server per test, tests run in parallel): LDAP over the wire, GraphQL over HTTP, the lldap-cli
request shapes, the migration of a genuine LLDAP 0.6.3 database
(`server/tests/fixtures`), and the event log (`server/tests/logs.rs`: boot, act, stop,
inspect the `logs` table, boot again; the summary, activity and tail-cursor queries; two
successful binds within the coalescing window stored once). The Kerberos backend is a recorder in these tests;
nothing needs a KDC. The log sink is process-global like the Kerberos backend: a test that
installs `LogGuard` must be `#[serial]`, and non-serial tests keep recording meanwhile, so
assert on your own markers (a private peer address or actor), not on the whole recording.

The suite is kept small on purpose: upstream LLDAP's tests stay as they are, and KLLDAP's
additions are one scenario per door or handler and table tests whose assert message names
the failing row, not one test per branch. A behaviour pinned at a higher level (an e2e in
`server/tests`, the SQL handler) is not pinned again below it. `#[serial]` is reserved for
the tests that install a process-global recorder.

## The container gate

`make test` builds the local image `klldap-test` from the working tree; `make test-run`
boots it with test secrets and two named volumes, publishing `3890`, `17170`,
`88:1088/tcp` and `88:1088/udp`. It does not publish `1749`. `make gate-rootless`
runs the SQLite gate on the rootless image.

`make gate` builds that image and runs `gate/run-gate.sh` against it: the real
container, entrypoint and all, exercised as CLI invocations (`ldapsearch`, `ldapmodify`,
`kinit`, GraphQL over HTTP) through 35 phases — fresh boot, environment validation,
a custom `LLDAP_UID`/`LLDAP_GID` boot, GraphQL auth, OU lifecycle, the OU policies (their API,
each item at the doors, login hours and inactivity, the lockout, allowed networks), the TOTP
second factor, Kerberos lifecycle (principal, kinit, disable, re-enable), kadmin on directory
users, the KDC's verdict and its fresh-proof window,
bootstrap idempotence, LDAP read and write matrices, Keycloak keytab export, the event
log queries (rows with peers, per-actor summary and activity, the tail cursor, admin-only),
restart persistence (directory data and the logs table), a realm that cannot open, LDAPS,
password-reset mail, compressed requests, static files, the web app and the policies page in a
headless browser, password length at each door and the password pages, and, when their
inputs are given, migration boot, the upgrade from a 0.8.0 image, a password change killed
inside its transaction and a real lldap-cli run. It needs docker, the OpenLDAP client tools
(`openldap-clients` / `ldap-utils`) and python3; `kinit` runs inside the container.

- `make gate-fast` runs the phases against the already built image.
- `make gate-postgres` runs them against a gate-managed PostgreSQL.
- `make lane-mysql` and `make lane-mariadb` start a scratch `mysql:9.7` or
  `mariadb:12.3` on `127.0.0.1`, set `KLLDAP_TEST_DATABASE_URL`, and run the
  ignored lane tests on one thread. The container is removed with its volume.
- `make gate-phase PHASE=kerberos` runs the phases whose name contains the string.
- Results land in `gate/results/<run id>/`, one directory per phase with the exact
  requests, responses and container logs. `GATE_KEEP=1` leaves the containers running.
- `GATE_LLDAP_CLI=/path/to/lldap-cli` enables the lldap-cli phase;
  `GATE_FIXTURE_DATA`/`GATE_FIXTURE_KDC`/`GATE_FIXTURE_BASE_DN` enable the migration
  boot phase against an existing volume set. The header of `gate/run-gate.sh` is the
  full environment contract.

## The Kerberos end-to-end test

`server/tests/kerberos.rs` starts the server with the embedded KDC and drives
`kinit`, `klist` and `kadmin` against it. `make safety` runs it. The host needs
`krb5-workstation` (Fedora) or `krb5-user` (Debian/Ubuntu). It does not use the
host's `/etc/krb5.conf` or the login credential cache.

## CI

`.github/workflows/rust.yml` runs the safety dance, a `licenses` job
(`cargo deny check licenses sources`), a shellcheck
pass, and a PostgreSQL migration lane. `.github/workflows/gate.yml`
builds the image and a second one with the gate's test hooks
(`klldap-test-kill`, as `make test-kill-points` does), and runs the gate
on SQLite and PostgreSQL. Both run on pushes and pull requests.
