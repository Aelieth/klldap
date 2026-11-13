# Kerberos

KLLDAP runs a Kerberos KDC inside the `lldap` process, on its own threads, and
keeps it in step with the user database. Nothing Kerberos-specific has to be
configured for the common case: the realm comes from the base DN, the database
is created on first start, and principals follow the users.

## Realm

The realm is the base DN's `dc` components, joined and uppercased: `dc=example,dc=com`
gives realm `EXAMPLE.COM` and domain `example.com`. `kerberos_options.realm`
(`LLDAP_KERBEROS_OPTIONS__REALM`) overrides the realm. Principals are `<user id>@REALM`.

## Bootstrap

There is no `kerberos_manager`, and no separate `krb5kdc` or `kadmind` process.
When `kerberos_options.enabled` is true, the server opens the realm itself:

1. creates `data_dir` (default `krb5kdc`) at mode 0700 and opens or
   creates the database (`principal`) and the stash (`.k5.<REALM>`). The master
   key is random and lives only in the stash. A directory that already exists
   with a looser mode is tightened to 0700 when this process owns it; otherwise
   the server warns and continues,
2. writes `admin/admin@REALM` to `admin_keytab` (default `kadm5.keytab`) at
   mode 0600, owned by the service user, on every boot,
3. writes the client `krb5.conf` to `client_config` (default `krb5.conf`),
4. binds the KDC on UDP and TCP at `kdc_host`:`kdc_port` (default `0.0.0.0:1088`) and
   kadmin at `kadmin_host`:`kadmin_port` (default `127.0.0.1:1749`), then serves them on the threads
   `krb5-kdc` and `krb5-kadmind`.

`/data/kerberos_config.toml` is gone. The realm settings are `[kerberos_options]`.

Keep `/data/kadm5.keytab` out of any backup that is not secured as tightly as
the machine itself. It is rewritten at every boot, and it is the admin
credential for the realm.

**If either Kerberos thread dies, the process exits non-zero. Without a restart
policy, the container stays down.**

### When the realm cannot open

If Kerberos is enabled and the realm does not
open at startup (for example, the KDC port is taken, or the realm's database or
directory cannot be read), the server starts in a degraded state instead of
exiting:

- LDAP, LDAPS and the web interface listen on loopback only (`127.0.0.1`, or
  `::1` when the configured host is IPv6). The KDC and kadmin do not listen.
- Only members of `lldap_admin` can sign in. Another user with the right
  password is refused with LDAP result 52 (unavailable) or HTTP 503; a wrong
  password is still invalid credentials (49, 401). Other users' existing
  sessions are refused too.
- Directory changes are refused, with the cause.
- `/health` answers 503 with the cause, and `lldap healthcheck` prints it and
  fails.
- The log names the cause: `the Kerberos realm <REALM> did not open: …`.

Fix the cause and restart. At startup the server tries the realm again and, if
it opens, serves normally. Nothing in the product repairs the realm. In a
container, loopback is the container's own, so reach the server with `docker
exec klldap /app/lldap healthcheck --config-file /data/lldap_config.toml`.

`enabled` defaults to true, and the image no longer sets it. The container's
healthcheck (`lldap healthcheck`) then also requires the KDC port to accept
connections and the admin keytab to exist, otherwise the container reports
unhealthy, and **directory writes (users, groups, passwords, attributes,
settings) are refused with "Kerberos KDC unavailable" until the KDC has
answered once after boot**. Logins and reads are never gated. Set `enabled`
to false to run without a realm: writes never wait and no principals are synced.

`admin/admin@REALM *` is always granted. `kadmin_acl` is optional extra
ACL text, read at boot.

## Principals

- `kerberosSync` (attribute `kerberossync`, alias `kerberos_sync`) is a per-user
  switch that admins set. While it is on, every password set — web UI,
  `setUserPassword`, LDAP Modify `userPassword`, `ldappasswd`, LDAP ADD with
  `userPassword` — creates or updates the principal. A password must be valid
  UTF-8 on every door. New principals require preauthentication
  (`REQUIRES_PRE_AUTH`). Turning the switch off deletes the principal; deleting
  the user deletes it too.
- Users in `lldap_disabled` have their principal disabled (`DISALLOW_ALL_TIX`),
  and a password sync while disabled leaves it disabled. Leaving the group
  re-enables it.
- The read-only, admin-visible `krbPrincipalName` attribute shows the principal
  recorded for the user.
- The web UI never sends a plaintext password: it encrypts it with the RSA key
  from the `kerberosInfo` query for `syncKerberosPassword`; the server decrypts
  it and updates the embedded KDC.

kadmin listens on the container's loopback. The image sets
`KRB5_CONFIG=/data/krb5.conf`, so `docker exec` does not pass it:

```sh
docker exec klldap \
  kadmin -k -t /data/kadm5.keytab -p admin/admin -q listprincs
docker exec klldap \
  kadmin -k -t /data/kadm5.keytab -p admin/admin -q "getprinc bob"
```

On a host, skip `docker exec` and set `KRB5_CONFIG=krb5.conf`, the file in
the unit's working directory.

`getprinc` shows attributes such as `REQUIRES_PRE_AUTH` and `DISALLOW_ALL_TIX`.

## Ports and clients

The KDC listens on 1088 and is published as `88:1088` (tcp and udp).
kadmin listens on the container's loopback (`127.0.0.1:1749`). kadmin is not
published, and it is used with `docker exec`. Clients outside use port 88.
The image sets `KRB5_CONFIG=/data/krb5.conf`. kpasswd (`464`) is not published: passwords
are changed through KLLDAP, which updates the KDC.

The `krb5.conf` the server writes (`client_config`, default `/data/krb5.conf`)
is for tools inside the container, and it carries the inner port. With the
default `kdc_host` it names `127.0.0.1` as the KDC and `kadmin_host` as the
admin server. Remote clients write their own and use port 88. The
[SSSD guide](SSSD_LDAP_Kerberos_Setup_Guide.md) has complete client and browser
configurations.

## Keycloak

The Federation tab's **Export keytab** creates `HTTP/<hostname>@REALM` with a
fresh random key and writes `keycloak_options.keytab` (default
`keytab/keycloak-http.keytab`, the types in `supported_enctypes`).
Mount that directory read-only into Keycloak; **Push To Keycloak** creates a
realm with KLLDAP as an LDAP + Kerberos user-federation provider. See
[the SSSD guide, section 7](SSSD_LDAP_Kerberos_Setup_Guide.md#7-keycloak-integration--spnego-sso).

## Configuration

`[kerberos_options]` in `lldap_config.toml`, or `LLDAP_KERBEROS_OPTIONS__<NAME>`:

| Option | Default |
|---|---|
| `enabled` | `true` |
| `realm` | derived from the base DN |
| `ticket_lifetime` | `24h` |
| `renew_lifetime` | `7d` |
| `forwardable` | `true` |
| `supported_enctypes` | `aes256-cts-hmac-sha1-96` |
| `kdc_host` / `kdc_port` | `0.0.0.0` / `1088` |
| `kadmin_host` / `kadmin_port` | `127.0.0.1` / `1749` |
| `kadmin_acl` | none |
| `data_dir` | `krb5kdc` (mode 0700) |
| `admin_keytab` | `kadm5.keytab` (mode 0600) |
| `client_config` | `krb5.conf` |

`data_dir`, `admin_keytab`, `client_config`, `kadmin_acl`,
`keycloak_options.keytab` and `keycloak_options.config_file` take the path
itself. Their `_FILE` forms, in the environment or the file, stop the start
and name the key.

`ticket_lifetime` and `renew_lifetime` are written with a unit (`24h`, `7d`,
`36000s`). A bare number in the environment is refused, and zero is refused:
to the KDC a zero ticket life means no limit. `renew_lifetime` is also the
KDC's longest renewable life. A principal keeps the ticket life it was created
with. At every start the server brings krbtgt and the users to the configured
lives. The Keycloak HTTP principal, `admin/admin` and the kadmin services keep
theirs, so a raised `ticket_lifetime` does not reach them. A lowered one still
caps them through the realm's value.

The image sets `data_dir`, `admin_keytab` and `client_config`, and
`keycloak_options.keytab` (default `keytab/keycloak-http.keytab`) and
`keycloak_options.config_file` (default `keycloak_config.toml`), to
`/var/kerberos/krb5kdc`, `/data/kadm5.keytab`, `/data/krb5.conf`,
`/data/keytab/keycloak-http.keytab` and `/data/keycloak_config.toml`. Inside
the image that environment overrides the same keys in the config file.

`supported_enctypes` takes one type name per item. It accepts
`aes256-cts-hmac-sha1-96`, `aes128-cts-hmac-sha1-96`,
`aes256-cts-hmac-sha384-192` and `aes128-cts-hmac-sha256-128`. A family name
such as `aes` or `default`, a `+` or `-` prefix, or two names in one item is
refused at startup, naming the item. `des3-cbc-sha1`, `arcfour-hmac` and
their aliases are refused as deprecated
([RFC 8429 section 7](https://www.rfc-editor.org/rfc/rfc8429)). `camellia128-cts-cmac`,
`camellia256-cts-cmac` and the `camellia` family are refused because the
embedded KDC does not serve them. `des-cbc-crc` and `des-cbc-md5` are not
encryption types this KDC knows. `allow_rc4` and `allow_des3` stay off. See
[MIT's encryption types](https://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html)
and
[krb5.conf](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html).

When the first listed type changes, the next start gives `krbtgt/REALM`,
`kadmin/admin` and `kadmin/changepw` new keys in the listed types and keeps
the old ones, so tickets issued before the change still work. The old key
versions are removed once `ticket_lifetime` plus `renew_lifetime` has passed,
at a start or by the hourly cleanup. A roll that fails leaves the realm closed
with the cause, as any realm that does not open. A user's own keys take the
new types at that user's next password change.

The old `LLDAP_KERB_*` variables are unknown. They warn at startup and are
ignored. So do `kdc_bind`, `kadmin_bind`, `kadmin_acl_file`,
`max_renewable_life` and `kerberos_options.keycloak_keytab`. Use the options
above. `keycloak_keytab` is `keycloak_options.keytab`.

## Upgrading from 0.7.2

0.7.2 kept the realm in MIT's db2 format, which 0.8.0 cannot read. Before the first 0.8.0
start, write a dump of it into the same directory with the 0.7.2 image, either in the running
0.7.2 container or in a one-off container on the same KDC volume:

    docker exec <your 0.7.2 container> kdb5_util -r <REALM> dump /var/kerberos/krb5kdc/principal.dump
    docker run --rm --entrypoint kdb5_util -v <kdc volume>:/var/kerberos/krb5kdc \
        aelieth/klldap:0.7.2 -r <REALM> dump /var/kerberos/krb5kdc/principal.dump

On its first start, 0.8.0 finds `principal.dump` beside the stash, loads it, and moves the MIT
files (`principal`, `principal.kadm5`, `principal.ok`, `principal.kadm5.lock`, `kadm5.acl`,
`kdc.conf` and the dump) into `mit-db2.bak/` in the same directory, mode 0700. Nothing is
deleted: remove that directory once the realm works. The dump holds every principal's key
data, encrypted in the master key, so keep the backup as safe as the database.

What carries over: the realm, the master key (the stash stays), every principal with its keys
and attributes, and `admin/admin`, whose keytab is written again from its key. What does not:
grants in `kadm5.acl` beyond the admin line (name them in `kadmin_acl`), and MIT's logs.

A configuration that does not set `kerberos_options.enabled` now starts a
realm. Set `enabled = false` to stay without one.

Without a dump the realm does not open: the server comes up in the degraded state and the
cause names the file to write. A dump for a realm other than `kerberos_options.realm`, or a
dump without its stash, is refused the same way, and nothing is moved.

0.7.2 took the realm's name from `realm_name` in `kerberos_config.toml`. Where that was set to
something other than the name the base DN gives, set `kerberos_options.realm` to it before the
first 0.8.0 start; otherwise the migration is refused and the cause names both realms.

## Losing a volume

- `data_dir` lost (database and stash go together; the default path is
  `krb5kdc`, and in the image `/var/kerberos/krb5kdc`): the next start creates a
  fresh database and rewrites
  the admin keytab. Existing users have no principal until their password is
  next set (or an admin sets one for them); the Keycloak keytab has to be
  exported again.
- `data_dir` lost after a migration, with `mit-db2.bak/` still there: the realm does not
  open, and the cause names the backup, so a lost database is not silently replaced by a
  new realm. Restore the database, or move `mit-db2.bak/` away to start a fresh realm.
- `/data` lost: the directory database and `server_key` are gone with it.
  Restore them from backup. The admin keytab is rewritten from the surviving
  KDC database on the next boot.
