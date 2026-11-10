# Kerberos

KLLDAP runs an MIT Kerberos KDC (`krb5kdc` and `kadmind`) inside its container and keeps
it in step with the user database. Nothing Kerberos-specific has to be configured for the
common case: the realm comes from the base DN, the KDC bootstraps itself on first start,
and principals follow the users.

## Realm

The realm is the base DN's `dc` components, joined and uppercased: `dc=example,dc=com`
gives realm `EXAMPLE.COM` and domain `example.com`. `kerberos_options.realm`
(`LLDAP_KERBEROS_OPTIONS__REALM`) overrides the realm. Principals are `<user id>@REALM`.

## Bootstrap

The entrypoint starts the server, waits until it is healthy, then runs
`kerberos_manager`, which:

1. reads `/data/kerberos_config.toml`, which the server rewrites at every boot from
   `[kerberos_options]` (realm, base DN, `ticket_lifetime`, `renew_lifetime`,
   `forwardable`; hand edits are overwritten),
2. renders `/etc/krb5.conf`, `/var/kerberos/krb5kdc/kdc.conf` and
   `/var/kerberos/krb5kdc/kadm5.acl` from the templates in `/app`,
3. creates the KDC database (`kdb5_util create -s`) with a random master password that
   is only stashed, never shown or stored elsewhere,
4. creates `admin/admin@REALM` with a random key and writes it to `/data/kadm5.keytab`
   (mode 640, owned by the server user, i.e. `LLDAP_UID:LLDAP_GID`, like the KDC database
   itself); every KDC operation KLLDAP performs uses this keytab through libkadm5,
5. starts `krb5kdc` and `kadmind` in the foreground, waits for port 88, populates a
   credential cache from the keytab, and then supervises them: if either exits, the other
   is stopped and the manager exits, so the healthcheck reports the KDC down instead of a
   half-working one.

Every step is idempotent: existing databases, principals and files are kept, and a
missing keytab is recreated from the surviving database (`/data` and
`/var/kerberos/krb5kdc` are separate volumes; either can be lost alone).
`kerberos_manager --bootstrap-only` runs steps 1–4 and exits. `kadm5.acl` is not
overwritten on restart; it is checked for the `admin/admin@REALM *` grant and repaired
(or restored from the template when unparsable), so extra grants survive.

The image sets `LLDAP_KERBEROS_OPTIONS__ENABLED=true`, which tells the server that a KDC is
part of the deployment. The container's healthcheck (`lldap healthcheck`) then also requires
the KDC port to accept connections and the admin keytab to exist, otherwise the container
reports unhealthy, and **directory writes (users, groups,
passwords, attributes, settings) are refused with "Kerberos KDC unavailable" until the KDC
has answered once after boot**, so nothing changes that the KDC could not follow. Logins
and reads are never gated, and a KDC that dies later does not block writes — that is the
healthcheck's job. Outside the image (no KDC), leave the option unset: writes never wait
and no principals are synced.

The KDC's master password is random and exists only as the stash file `.k5.<REALM>` in
`/var/kerberos/krb5kdc`, next to the database it unlocks; `kadmin.local` and `kdb5_util`
(dump, load) work from the stash. Back that volume up as a whole.

## Principals

- `kerberosSync` (attribute `kerberossync`, alias `kerberos_sync`) is a per-user switch
  that admins set. While it is on, every password set — web UI, `setUserPassword`, LDAP
  Modify `userPassword`, `ldappasswd`, LDAP ADD with `userPassword` — creates or updates
  the principal. A password must be valid UTF-8 on every door. Turning it off deletes
  the principal; deleting the user deletes it too.
- Users in `lldap_disabled` have their principal disabled (`DISALLOW_ALL_TIX`), and a
  password sync while disabled leaves it disabled. Leaving the group re-enables it.
- The read-only, admin-visible `krbPrincipalName` attribute shows the principal recorded
  for the user.
- The web UI never sends a plaintext password: it encrypts it with the RSA key from the
  `kerberosInfo` query for `syncKerberosPassword`; the server decrypts, calls
  `kadmin`, and drops it.

`docker exec klldap kadmin.local -q listprincs` shows what the KDC holds;
`docker exec klldap kadmin.local -q "getprinc bob@EXAMPLE.COM"` shows attributes such
as `DISALLOW_ALL_TIX`.

## Ports and clients

The image publishes `88/tcp+udp` (KDC) and `749/tcp` (kadmin). kpasswd (`464`) is not
published: passwords are changed through KLLDAP, which updates the KDC. Clients need a
`krb5.conf` pointing at the container for the realm; the
[SSSD guide](SSSD_LDAP_Kerberos_Setup_Guide.md) has complete client and browser
configurations.

## Keycloak

The Federation tab's **Export keytab** creates `HTTP/<hostname>@REALM` with a fresh
random key and writes `/data/keytab/keycloak-http.keytab` (aes256 and aes128, the types
Java accepts). Mount `/data/keytab` read-only into Keycloak; **Push To Keycloak** creates
a realm with KLLDAP as an LDAP + Kerberos user-federation provider. See
[the SSSD guide, section 7](SSSD_LDAP_Kerberos_Setup_Guide.md#7-keycloak-integration--spnego-sso).

## Configuration

`[kerberos_options]` in `lldap_config.toml`, or `LLDAP_KERBEROS_OPTIONS__<NAME>`:

| Option | Default |
|---|---|
| `enabled` | `false` (`true` in the image) |
| `realm` | derived from the base DN |
| `ticket_lifetime` / `renew_lifetime` | `24h` / `7d` |
| `forwardable` | `true` |

File locations and the KDC port are still read from the environment by the KDC bootstrap
and the server:

| Variable | Default |
|---|---|
| `LLDAP_KERB_CONFIG` / `LLDAP_KERB_CONFIG_TEMPLATE` | `/data/kerberos_config.toml` / `/app/kerberos_config.template.toml` |
| `LLDAP_KERB_KRB5_CONF` / `LLDAP_KERB_KRB5_TEMPLATE` | `/etc/krb5.conf` / `/app/krb5.template.conf` |
| `LLDAP_KERB_KDC_CONF` / `LLDAP_KERB_KDC_TEMPLATE` | `/var/kerberos/krb5kdc/kdc.conf` / `/app/kdc.template.conf` |
| `LLDAP_KERB_KADM5_ACL` / `LLDAP_KERB_KADM5_ACL_TEMPLATE` | `/var/kerberos/krb5kdc/kadm5.acl` / `/app/kadm5.template.acl` |
| `LLDAP_KERB_KDC_DIR` | `/var/kerberos/krb5kdc` |
| `LLDAP_KERB_ADMIN_KEYTAB` | `/data/kadm5.keytab` |
| `LLDAP_KERB_KEYCLOAK_KEYTAB` | `/data/keytab/keycloak-http.keytab` |
| `LLDAP_KERB_KDC_PORT` | `88` |

Unset variables keep the container layout; they exist for tests and unusual layouts.

## Losing a volume

- `/var/kerberos/krb5kdc` lost (database and stash go together): the next start creates
  a fresh KDC database and admin keytab. Existing users have no principal until their
  password is next set (or an admin sets one for them); the Keycloak keytab has to be
  exported again.
- `/data` lost: the admin keytab is regenerated against the surviving KDC database. The
  LLDAP database and `server_key` are gone with it, though — restore them from backup.
