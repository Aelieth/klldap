# How to contribute to KLLDAP

This project isn't structured or maintained like LLDAP.

If you really want to contribute feel free to contact me,
report a bug / issue, suggest a feature, or open a PR.

Would very much rather you contribute to the main LLDAP line,
this project is self maintained and I may be trying to upstream
some of my changes that make sense.

## Building & testing

The Kerberos FFI needs the libkrb5 headers and clang (for bindgen):

- Fedora: `sudo dnf install krb5-devel clang pkgconf-pkg-config`
- Debian/Ubuntu: `sudo apt-get install libkrb5-dev clang pkg-config`

Before any change lands, run the full check suite. `--workspace` matters —
`default-members` is the server only, so a bare `cargo test` runs a fraction of the suite:

```sh
cargo fmt --all
cargo build --workspace
cargo test --workspace
cargo clippy --tests --all -- -D warnings
./export_schema.sh   # schema.graphql must not drift
```

`make test` builds a local Docker image (`klldap-test`) from this tree;
`make test-run` boots it with test secrets and local volumes.

`make gate` runs the container gate suite against that image (needs docker,
`ldap-utils`/`openldap-clients`, python3). `make test-kdc` runs the Kerberos FFI
tests against a throwaway KDC (Fedora: `sudo dnf install krb5-server krb5-workstation`;
Debian/Ubuntu: `sudo apt-get install krb5-kdc krb5-admin-server krb5-user`).
