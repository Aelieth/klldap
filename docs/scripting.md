# Scripting

Programmatically accessing KLLDAP can be done either through the LDAP protocol,
or via the GraphQL API.

## LDAP

Read queries about users and groups are supported: base, one-level and subtree
searches with the usual filters (`&`, `|`, `!`, equality, substring, presence,
`>=`/`<=` on timestamps and numbers, `memberOf`, `memberUid`), operational
attributes (`+`), the subschema and the root DSE, compare and whoami. Anything not
supported would be considered a missing feature or a bug.

Writes are supported for the common administrative operations:

- `ldapadd` a user under `ou=people` (`inetOrgPerson`; `mail`, `cn`, `givenName`,
  `sn`, `userPassword`, POSIX numbers, `sshPublicKey`, `kerberosSync`, custom
  attributes) or a group under `ou=groups` (`groupOfUniqueNames`/`posixGroup`,
  `gidNumber`, custom attributes). Read-only and unknown attributes are skipped with
  a warning; the user's OU comes from the DN.
- `ldapmodify` on a user: replace/add/delete `mail`, `cn`, `givenName`, `sn`,
  `jpegPhoto`, `sshPublicKey`, and replace `userPassword` (self, admin, or a
  password manager for non-admins). `ou` is changed through GraphQL, not LDAP.
- `ldappasswd`, the password-modify extended operation (RFC 3062), same rules.
- `ldapdelete` of a user or group (admin).

Group membership, OUs and POSIX settings are managed through GraphQL. Meta-queries
about the server beyond the root DSE and subschema are out of scope. Anonymous bind
is not supported.

## `lldap-cli`

The community CLI [Zepmann/lldap-cli](https://github.com/Zepmann/lldap-cli) works
against KLLDAP unmodified (its exact request shapes are replayed in the test suite).
The one visible difference is that the `JPEG_PHOTO` attribute type is displayed as
`AVATAR`; both names are accepted as input.

## GraphQL

The best way to interact with KLLDAP programmatically is via the GraphQL
interface. You can use any language that has a GraphQL library (most of them
do), and use the [GraphQL Schema](../schema.graphql) to guide your queries.

Beyond LLDAP's users, groups, attributes and object classes, the schema exposes:

- OUs: `listOus`, `createOu`, `deleteOu`, `changeUserOu`, `changeGroupOu`.
- POSIX: `posixSettings`, `setPosixSettings`, and the bulk re-assignment mutations
  (`reassignUserUidNumbers`, `reassignUserGidNumbers`, `reassignUserHomedirectories`,
  `reassignUserLoginshells`, `reassignGidNumbers`).
- Kerberos: `kerberosInfo` (whether Kerberos is enabled and the realm's state; the key a
  synced user's password is sealed to comes only from a start, see below and
  [kerberos.md](kerberos.md)), `exportKeytabForKeycloak`.
- Keycloak: `keycloakSuggestedConfig`, `keycloakConfig`, `testKeycloakConnection`,
  `saveKeycloakConfig`, `pushRealmToKeycloak`.
- Event log (admin-only): `logs(filter, limit, beforeId, afterId)` for rows,
  `logSummary(filter, groupBy, limit)` for counts, `logActivity(actor, kinds, since)` for
  one account — see [logging](logging.md).

`setUserPassword(userId, password)` sets a password over the API. An admin may set
anyone's, a password manager may set a non-admin's, and a user may set their own.
The server runs the OPAQUE registration itself, so nothing but the OPAQUE record is
stored, and the KDC principal is updated when the user has `kerberosSync` on. A
password shorter than the user's minimum (8 by default) is refused. Send
mutations by POST: a mutation sent by GET is refused. Queries may use GET. Use the
API over HTTPS only.

A new password must have at least the user's minimum number of characters (8 by
default; the OU policy item `password-min-length`, see [policies.md](policies.md#password-length)),
with no NUL character (U+0000), wherever the server sees its text:
`setUserPassword`, the LDAP password doors, and a synced user's web pages and
`lldap_set_password`. A shorter one is refused and nothing is written. For a user
without sync, the web pages and `lldap_set_password` check the user's minimum (8 by default)
themselves, and refuse a password with a NUL character.
`lldap_set_password` needs a password, from `--password` or `LLDAP_USER_PASSWORD`, and
refuses an empty one before it sends anything. `--bypass-password-policy` skips the minimum
length only (8, and the user's minimum from the register start), never the empty or NUL
check. For a user with `kerberosSync` the server still refuses a shorter password at the
finish; for a user without sync, the minimum is checked by the web pages and
`lldap_set_password` only.

The register start, `/auth/opaque/register/start`, answers the user's minimum in the optional
field `password_min_length` (a number of characters), for every user, beside OPAQUE's own
fields and, for a user with `kerberosSync`, `kerberos_envelope_key`. A script or client that
sets a password through the start and the finish should refuse a shorter password before it
sends the finish: for a user without sync the server never sees the password, so this check is
the only one. A client that ignores the field keeps today's check of 8, so for a user without
sync it lets a password under a higher minimum through. When the user's policy cannot be
read, the start is refused (400) with "the password policy could not be read; try again".

The finish, `/auth/opaque/register/finish`, is taken once, within two minutes of its start,
and only with the bearer token the start was sent with. A second finish for one start, one
with another token, and a late one are refused (401); the client makes a new start. For a
user with `kerberosSync` the envelope's OAEP label is
`klldap-kerberos-envelope-v2:<user id in lower case>:<server_data>`, with `server_data` as
the start answered it, so an envelope opens only for its own start; a Rust client gets the
whole finish from `lldap_auth::kerberos_envelope::finish_with_envelope`.

`lldap_set_password` given `--admin-password` signs in at `/auth/opaque/login/start` and
`/finish` as the web login does, so the admin's password does not reach the server; for an
admin with a second factor it reads the code from its terminal (one line of standard input)
and signs in again with it, and an admin who must still enroll one is refused, as before. That
login asks for the envelope key, and the tool seals a synced user's new password only to the
key the login bound. Given `--token`, it seals to the key as the start answers it; nothing
binds the key then, so give it an `https://` URL. A script asks for the key with
`"kerberos_envelope_key": true` in the login start's body. The answer then carries
`kerberos_envelope_key`, and the client finishes the login in the OPAQUE context
`klldap-kerberos-envelope-key-v1:` followed by the 32 bytes of SHA-256 of that text, or by
`none` when the answer has no key; a login finished in another context fails at the client. A
Rust client gets the finish from `lldap_auth::login::finish_bound`, and tells
`finish_with_envelope` which key it may seal to (`SealTo::Bound` with the key its login bound,
or `SealTo::Answered`).

### Getting a token

You'll need a JWT (authentication token) to issue GraphQL queries. Your view of
the system will be limited by the rights of your user. In particular, regular
users can only see themselves and the groups they belong to (but not other
members of these groups, for instance).

#### Manually

Log in to the web front-end of KLLDAP. Then open the developer tools (F12), find
the "Storage > Cookies", and you'll find the "token" cookie with your JWT.

![Cookies menu with a JWT](cookie.png)

#### Automatically

The easiest way is to send a json POST request to `/auth/simple/login` with
`{"username": "john", "password": "1234"}` in the body.
Then you'll receive a JSON response with:

```
{
  "token": "Yh6RJV...",
  "refreshToken": "dww5jwU...",
}
```

### Using the token

You can use the token directly, either as a cookie, or as a bearer auth token
(add an "Authorization" header with contents `"Bearer <token>"`).

The JWT is valid for 1 day (unless you log out explicitly).
A token from a password-reset link lives five minutes, as the link's cookie does, is taken only
by the register start and finish of its user's password, and ends when that finish sets the
password (at once on that server; on other servers sharing the database when they next start,
as a logout does). Anywhere else, GraphQL included, it is answered as an invalid token (401
`Invalid JWT`).
You can use the refresh token to query `/auth/refresh` and get another JWT. The
refresh token is valid for 30 days.

### Testing your GraphQL queries

You can go to `/api/graphql/playground` to test your queries and explore the
data in the playground. You'll need to provide the JWT in the headers:

```
{ "Authorization": "Bearer abcdef123..." }
```

Then you can enter your query, for instance:

```graphql
{
  user(userId:"admin") {
    displayName
    ou
    sshPublicKeys
  }
  groups {
    id
    displayName
    users {
      id
      email
    }
  }
}
```

The schema is on the right, along with some basic docs. As an admin, the event log is one
query away:

```graphql
{
  logs(filter: {kinds: [BIND], success: false}, limit: 20) {
    timestamp
    actor
    peer
    detail
  }
  logSummary(filter: {kinds: [BIND, LOGIN], success: false}, groupBy: [ACTOR]) {
    actor
    count
    last
  }
}
```
