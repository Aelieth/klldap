# Building and testing

## Building

The Kerberos FFI needs the libkrb5 headers and clang (for bindgen):

- Fedora: `sudo dnf install krb5-devel clang pkgconf-pkg-config`
- Debian/Ubuntu: `sudo apt-get install libkrb5-dev clang pkg-config`

`cargo build --workspace` builds the server, the tools and every crate. `--workspace`
matters: `default-members` is the server only, so a bare `cargo build`/`cargo test` covers
a fraction of the tree. The frontend builds with `./app/build.sh` (wasm-pack).

## The safety dance

`make safety` is the pre-commit check, in this order:

```sh
cargo fmt --all
cargo build --workspace
cargo test --workspace
cargo clippy --tests --all -- -D warnings
./export_schema.sh && git diff --exit-code schema.graphql   # schema.graphql must not drift
```

`cargo test --workspace` runs the unit tests of every crate and `server/tests`, which
starts the freshly built binary against a temporary SQLite database on ephemeral ports:
LDAP over the wire, GraphQL over HTTP, the lldap-cli request shapes, and the migration of
a genuine LLDAP 0.6.3 database (`server/tests/fixtures`). The Kerberos backend is a
recorder in these tests; nothing needs a KDC.

## The container gate

`make test` builds the local image `klldap-test` from the working tree; `make test-run`
boots it with test secrets on the standard ports and two named volumes.

`make gate` builds that image and runs `gate/run-gate.sh` against it: the real
container, entrypoint and all, exercised as CLI invocations (`ldapsearch`, `ldapmodify`,
`kinit`, GraphQL over HTTP) through 13 phases — fresh boot, environment validation,
GraphQL auth, OU lifecycle, Kerberos lifecycle (principal, kinit, disable, re-enable),
bootstrap idempotence, LDAP read and write matrices, Keycloak keytab export, restart
persistence, KDC death detection, and, when their inputs are given, migration boot and a
real lldap-cli run. It needs docker, the OpenLDAP client tools
(`openldap-clients` / `ldap-utils`) and python3; `kinit` runs inside the container.

- `make gate-fast` runs the phases against the already built image.
- `make gate-postgres` runs them against a gate-managed PostgreSQL.
- `make gate-phase PHASE=kerberos` runs the phases whose name contains the string.
- Results land in `gate/results/<run id>/`, one directory per phase with the exact
  requests, responses and container logs. `GATE_KEEP=1` leaves the containers running.
- `GATE_LLDAP_CLI=/path/to/lldap-cli` enables the lldap-cli phase;
  `GATE_FIXTURE_DATA`/`GATE_FIXTURE_KDC`/`GATE_FIXTURE_BASE_DN` enable the migration
  boot phase against an existing volume set. The header of `gate/run-gate.sh` is the
  full environment contract.

## The live KDC

`make test-kdc` runs the Kerberos FFI tests against a throwaway KDC on ephemeral ports
(`gate/kdc-sandbox.sh`; the tests are `#[ignore]` without it). It needs the KDC packages
on the host: Fedora `krb5-server krb5-workstation`, Debian/Ubuntu
`krb5-kdc krb5-admin-server krb5-user`.

## CI

`.github/workflows/rust.yml` runs the safety dance, the live-KDC lane, a shellcheck pass
and a PostgreSQL migration lane; `.github/workflows/gate.yml` builds the image and runs
the gate on SQLite and PostgreSQL. Both run on pushes and pull requests.
