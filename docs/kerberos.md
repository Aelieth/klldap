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

1. creates `data_dir` (default `/var/kerberos/krb5kdc`) at mode 0700 and opens or
   creates the database (`principal`) and the stash (`.k5.<REALM>`). The master
   key is random and lives only in the stash. A directory that already exists
   with a looser mode is tightened to 0700 when this process owns it; otherwise
   the server warns and continues,
2. writes `admin/admin@REALM` to `admin_keytab` (default `/data/kadm5.keytab`) at
   mode 0600, owned by the service user, on every boot,
3. writes the client `krb5.conf` to `client_config` (default `/data/krb5.conf`),
4. binds the KDC on UDP and TCP at `kdc_bind:kdc_port` (default `0.0.0.0:88`) and
   kadmin at `kadmin_bind` (default `127.0.0.1:749`), then serves them on the
   threads `krb5-kdc` and `krb5-kadmind`.

`/data/kerberos_config.toml` is gone. The realm settings are `[kerberos_options]`.

Keep `/data/kadm5.keytab` out of any backup that is not secured as tightly as
the machine itself. It is rewritten at every boot, and it is the admin
credential for the realm.

**If either Kerberos thread dies, the process exits non-zero. Without a restart
policy, the container stays down.**

The image sets `LLDAP_KERBEROS_OPTIONS__ENABLED=true`. The container's
healthcheck (`lldap healthcheck`) then also requires the KDC port to accept
connections and the admin keytab to exist, otherwise the container reports
unhealthy, and **directory writes (users, groups, passwords, attributes,
settings) are refused with "Kerberos KDC unavailable" until the KDC has
answered once after boot**. Logins and reads are never gated. Outside the
image, leave `enabled` unset: writes never wait and no principals are synced.

`admin/admin@REALM *` is always granted. `kadmin_acl_file` is optional extra
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

kadmin listens on the container's loopback. Run it with `docker exec` and
`KRB5_CONFIG=/data/krb5.conf`:

```sh
docker exec -e KRB5_CONFIG=/data/krb5.conf klldap \
  kadmin -k -t /data/kadm5.keytab -p admin/admin -q listprincs
docker exec -e KRB5_CONFIG=/data/krb5.conf klldap \
  kadmin -k -t /data/kadm5.keytab -p admin/admin -q "getprinc bob"
```

`getprinc` shows attributes such as `REQUIRES_PRE_AUTH` and `DISALLOW_ALL_TIX`.

## Ports and clients

The image publishes `88/tcp+udp` (the KDC). kadmin listens on the container's
loopback (`kadmin_bind`, default `127.0.0.1:749`) and is used with `docker exec`
and `KRB5_CONFIG=/data/krb5.conf`. kpasswd (`464`) is not published: passwords
are changed through KLLDAP, which updates the KDC.

The `krb5.conf` the server writes (`client_config`, default `/data/krb5.conf`)
is for tools inside the container. With the default `kdc_bind` it names
`127.0.0.1` as the KDC and `kadmin_bind` as the admin server. Remote clients
write their own. The
[SSSD guide](SSSD_LDAP_Kerberos_Setup_Guide.md) has complete client and browser
configurations.

## Keycloak

The Federation tab's **Export keytab** creates `HTTP/<hostname>@REALM` with a
fresh random key and writes `keycloak_keytab` (default
`/data/keytab/keycloak-http.keytab`, aes256 and aes128, the types Java accepts).
Mount that directory read-only into Keycloak; **Push To Keycloak** creates a
realm with KLLDAP as an LDAP + Kerberos user-federation provider. See
[the SSSD guide, section 7](SSSD_LDAP_Kerberos_Setup_Guide.md#7-keycloak-integration--spnego-sso).

## Configuration

`[kerberos_options]` in `lldap_config.toml`, or `LLDAP_KERBEROS_OPTIONS__<NAME>`:

| Option | Default |
|---|---|
| `enabled` | `false` (`true` in the image) |
| `realm` | derived from the base DN |
| `ticket_lifetime` / `renew_lifetime` / `max_renewable_life` | `24h` / `7d` / `7d` |
| `forwardable` | `true` |
| `supported_enctypes` | `aes256-cts-hmac-sha1-96` |
| `kdc_bind` / `kdc_port` | `0.0.0.0` / `88` |
| `kadmin_bind` | `127.0.0.1:749` |
| `kadmin_acl_file` | none |
| `data_dir` | `/var/kerberos/krb5kdc` (mode 0700) |
| `admin_keytab` | `/data/kadm5.keytab` (mode 0600) |
| `keycloak_keytab` | `/data/keytab/keycloak-http.keytab` |
| `client_config` | `/data/krb5.conf` |

`supported_enctypes` accepts `aes256-cts-hmac-sha1-96`,
`aes128-cts-hmac-sha1-96`, `aes256-cts-hmac-sha384-192` and
`aes128-cts-hmac-sha256-128`. `des3-cbc-sha1`, `arcfour-hmac`
and their aliases are refused at startup as deprecated
([RFC 8429 section 7](https://www.rfc-editor.org/rfc/rfc8429)). `camellia128-cts-cmac`,
`camellia256-cts-cmac` and the `camellia` family are refused because the
embedded KDC does not serve them; that is not a deprecation. `des-cbc-crc` and
`des-cbc-md5` are not encryption types this KDC knows. The name `default` is
refused too, because it expands to AES plus 3DES, RC4 and Camellia;
`default -des3 -rc4 -camellia` is the four AES types. `allow_rc4` and
`allow_des3` stay off, which is MIT's default. See
[MIT's encryption types](https://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html)
and
[krb5.conf](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html).

The old `LLDAP_KERB_*` variables are unknown. They warn at startup and are
ignored. Use the options above.

## Losing a volume

- `data_dir` lost (database and stash go together; the default path is
  `/var/kerberos/krb5kdc`): the next start creates a fresh database and rewrites
  the admin keytab. Existing users have no principal until their password is
  next set (or an admin sets one for them); the Keycloak keytab has to be
  exported again.
- `/data` lost: the directory database and `server_key` are gone with it.
  Restore them from backup. The admin keytab is rewritten from the surviving
  KDC database on the next boot.
