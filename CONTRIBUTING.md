# How to contribute to KLLDAP

KLLDAP is a personal project maintained by one person, on a best-effort basis. Bug
reports, feature suggestions and PRs are welcome; changes that make sense for LLDAP
itself are better sent [upstream](https://github.com/lldap/lldap), where they reach
more people.

## Building & testing

The Kerberos FFI needs the libkrb5 headers and clang (for bindgen):

- Fedora: `sudo dnf install krb5-devel clang pkgconf-pkg-config`
- Debian/Ubuntu: `sudo apt-get install libkrb5-dev clang pkg-config`

Before a change lands, run the safety dance:

```sh
make safety   # fmt, build, test, clippy -D warnings, schema.graphql drift check
```

`--workspace` matters — `default-members` is the server only, so a bare `cargo test`
runs a fraction of the suite; `make safety` uses it. `make gate` builds the local image
and runs the container gate against it; `make test-kdc` runs the Kerberos FFI tests
against a throwaway KDC. [docs/testing.md](docs/testing.md) describes all of them.

Code follows upstream LLDAP's shape: `cargo fmt` layout, comments only where the code
cannot speak for itself, tests next to the code, GraphQL changes exported to
`schema.graphql` with `./export_schema.sh`.
