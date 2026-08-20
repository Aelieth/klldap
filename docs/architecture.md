# Architecture

The server is entirely written in Rust, using [actix](https://actix.rs) for the
backend and [yew](https://yew.rs) for the frontend. An MIT Kerberos KDC runs beside
it in the same container.

Backend:
* Listens on a port for LDAP protocol.
  * Reads: bind, search (base/one/subtree, filters, `memberOf`, operational
    attributes, subschema, root DSE), compare, whoami.
  * Writes: add users and groups, modify a user's attributes and password (Replace,
    Add, Delete), delete users and groups, and the password-modify extended operation.
* Listens on another port for HTTP traffic.
  * The authentication API, based on JWTs, is under "/auth".
  * The user management API is a GraphQL API under "/api/graphql". The schema
    is defined in `schema.graphql`.
  * The static frontend files are served by this port too.
* Keeps the KDC in step: principals are created, updated, disabled and deleted as
  users are created, get a password, join or leave `lldap_disabled`, or are deleted.
  The KDC's own database lives in `/var/kerberos/krb5kdc`; the admin keytab in
  `/data/kadm5.keytab`.

Note that HTTPS is currently not supported. This can be worked around by using
a reverse proxy in front of the server (for the HTTP API) that wraps/unwraps
the HTTPS messages. LDAPS is supported.

Frontend:
* User management UI, plus OU management, POSIX settings and the Keycloak
  Federation tab.
* Written in Rust compiled to WASM as an SPA with the Yew library.
* Based on components, with a React-like framework.

Data storage:
* The data (users, groups, memberships, OUs, POSIX settings, active JWTs, ...) is
  stored in SQL.
* SQLite by default; PostgreSQL is tested in CI; MySQL/MariaDB is best-effort (see
  [DB Migration](database_migration.md) for how to migrate off of SQLite).
* The attribute schema (names, aliases, types, flags) is compiled in:
  `crates/schema/src/public_schema.rs`. Custom attributes live in the database.

### Code organization

* `server/`: the binary — configuration, the LDAP and HTTP servers, the healthcheck.
* `app/`: the frontend.
  * `src/components`: the pages and their components.
  * `src/infra`: tools and utilities.
* `crates/auth`: the shared structures needed for authentication, the interface
  between front and back-end (OPAQUE structures, JWT format).
* `crates/domain`, `crates/domain-model`, `crates/domain-handlers`: domain types,
  SeaORM models, and the backend-handler traits, including the `KerberosSync` seam
  that ldap/sql/graphql call and the server binds to the real KDC, and the logging seam
  (`logging.rs`: event model, per-request context, sink registry) that the handlers
  record into and the server binds to the SQL writer.
* `crates/sql-backend-handler`: the SQL implementation of the handlers, the
  migrations (v12/v13 are KLLDAP's; v13 carries the `logs` table through
  `ensure_logs`), the log writer (batched, coalescing repeated binds), retention and the
  log lookups (list, summary, activity), and the POSIX validators.
* `crates/access-control`: the permission-checked handles the APIs go through.
* `crates/ldap`: the LDAP protocol layer (search, create, modify, delete, compare,
  password), its DN model and the operational-attribute table.
* `crates/graphql-server`: the GraphQL API, mutations split by concern (users and
  groups, OUs, POSIX, Kerberos, Keycloak) and the admin-only log queries (`logs`,
  `logSummary`, `logActivity`).
* `crates/schema`: the attribute schema hub.
* `crates/kerberos`: the libkadm5/libkrb5 FFI (the only unsafe code), the KDC
  bootstrap and supervision (`kerberos_manager` binary), and the live `KerberosSync`.
* `crates/keycloak`: the Keycloak admin client used by the Federation tab.
* `crates/opaque-handler`: the OPAQUE registration ceremony.
* `crates/validation`, `crates/frontend-options`, `crates/test-utils`.
* `migration-tool/`, `set-password/`: the upstream command-line tools.
* `gate/`: the container gate suite (see [testing.md](testing.md)).

## Authentication

### Passwords

Authentication is done via the OPAQUE protocol, meaning that the passwords are
never sent to the server, but instead the client proves that they know the
correct password (zero-knowledge proof). This is likely overkill, especially
considered that the LDAP interface requires sending the password in cleartext
to the server, but it's one less potential flaw (especially since the LDAP
interface can be restricted to an internal docker-only network while the web
app is exposed to the Internet).

OPAQUE's "passwords" (user-specific blobs of data that can only be used in a
zero-knowledge proof that the password is correct) are hashed using Argon2, the
state of the art in terms of password storage. They are hashed using a secret
provided in the configuration (which can be given as environment variable,
command line argument or a file as well): this should be kept secret and
shouldn't change (it would invalidate all passwords). Note that even if it was
compromised, the attacker wouldn't be able to decrypt the passwords without
running an expensive brute-force search independently for each password.

The KDC needs the plaintext once, to set the principal's key: the web UI encrypts
the password with RSA-OAEP for the `syncKerberosPassword` mutation, the LDAP and
GraphQL password paths already hold it, and after the `kadmin` call it is dropped.
KLLDAP keeps no copy; the KDC stores its own keys in its own database.

The optional TOTP second factor ([mfa.md](mfa.md)) is checked by the same login handler
that checks the password: `SqlBackendHandler::bind` and `login_finish` split
`password:code` and verify it, so the three doors share one decision and the event log sees
one row per login.

### JWTs and refresh tokens

When logging in for the first time, users are provided with a refresh token
that gets stored in an HTTP-only cookie, valid for 30 days. They can use this
token to get a JWT to get access to various servers: the JWT lists the groups
the user belongs to. To simplify the setup, there is a single JWT secret that
should be shared between the authentication server and the application servers;
and users don't get a different token per application server
(this could be implemented, we just didn't have any use case yet).

JWTs are only valid for one day: when they expire, a new JWT can be obtained
from the authentication server using the refresh token. If the user stays
logged in, they would only have to type their password once a month.

#### Logout

In order to handle logout correctly, we rely on a blacklist of JWTs. When a
user logs out, their refresh token is removed from the backend, and all of
their currently valid JWTs are added to a blacklist. Incoming requests are
checked against this blacklist (in-memory, faster than calling the database).
Applications that want to use these JWTs should subscribe to be notified of
blacklisted JWTs (TODO: implement the PubSub service and API).
