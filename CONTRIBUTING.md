# How to contribute to KLLDAP

KLLDAP is a personal project maintained by one person, on a best-effort basis. Bug
reports, feature suggestions and PRs are welcome; changes that make sense for LLDAP
itself are better sent [upstream](https://github.com/lldap/lldap), where they reach
more people.

## Building & testing

The server build does not need Kerberos or clang headers. The Kerberos end-to-end
test runs `kinit`, `klist` and `kadmin` on the host, so it needs
`krb5-workstation` (Fedora) or `krb5-user` (Debian/Ubuntu).

Before a change lands, `cargo-deny` has to be on `PATH` (CI pins 0.20.2).
Then run the safety dance:

```sh
make safety   # fmt, build, test, clippy -D warnings, cargo deny check licenses sources, schema.graphql drift check
```

`--workspace` matters — `default-members` is the server only, so a bare `cargo test`
runs a fraction of the suite; `make safety` uses it. `make gate` builds the local image
and runs the container gate against it. [docs/testing.md](docs/testing.md) describes
both.

Code follows upstream LLDAP's shape: `cargo fmt` layout, comments only where the code
cannot speak for itself, tests next to the code, GraphQL changes exported to
`schema.graphql` with `./export_schema.sh`.
