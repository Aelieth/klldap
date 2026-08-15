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
- Kerberos: `kerberosInfo` (the RSA public key the web UI encrypts passwords with),
  `syncKerberosPassword`, `exportKeytabForKeycloak`.
- Keycloak: `keycloakSuggestedConfig`, `keycloakConfig`, `testKeycloakConnection`,
  `saveKeycloakConfig`, `pushRealmToKeycloak`.

`setUserPassword(userId, password)` sets a password over the API (self or admin): the
server runs the OPAQUE registration itself, so nothing but the OPAQUE record is stored,
and the KDC principal is updated when the user has `kerberosSync` on. Use it over
HTTPS only, like the rest of the API.

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

The schema is on the right, along with some basic docs.
