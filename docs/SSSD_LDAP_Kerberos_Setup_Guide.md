# SSSD + LDAP + Kerberos Setup Guide

This guide provides a complete, production-oriented configuration for **SSSD** using a hybrid **LDAP + Kerberos** model.

- **Identity (users, groups, POSIX attributes)**: Provided by LDAP (LLDAP)
- **Authentication**: Provided by Kerberos
- Covers both **insecure/testing** and **secure/production** setups
- Includes SELinux configuration for standard and non-standard ports

---

## 1. Prerequisites (article based on Fedora, adjust to your distro)


sudo dnf install sssd sssd-ldap sssd-krb5 krb5-workstation oddjob -y
sudo authselect select sssd with-mkhomedir

---

## 2. Kerberos Client Configuration (`/etc/krb5.conf`)

Proper `krb5.conf` configuration is essential for both SSSD and browser SPNEGO to work correctly.

### 2.1 Recommended `/etc/krb5.conf` (for TESTLABBY.LOCAL)

ini
# To opt out of the system crypto-policies configuration of krb5, remove the
# symlink at /etc/krb5.conf.d/crypto-policies which will not be recreated.
includedir /etc/krb5.conf.d/

[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log

[libdefaults]
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt
    spake_preauth_groups = edwards25519
    dns_canonicalize_hostname = fallback
    qualify_shortname = ""
    default_realm = TESTLABBY.LOCAL
    default_ccache_name = KEYRING:persistent:%{uid}

[realms]
    TESTLABBY.LOCAL = {
        kdc = 10.10.10.162
        admin_server = 10.10.10.162
        kpasswd_server = 10.10.10.162
    }

[domain_realm]
    .testlabby.local = TESTLABBY.LOCAL
    testlabby.local = TESTLABBY.LOCAL

### 2.1 Alternative: More Verbose Production Version

ini
[libdefaults]
    default_realm = TESTLABBY.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    proxiable = false
    rdns = false
    default_ccache_name = KEYRING:persistent:%{uid}
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    TESTLABBY.LOCAL = {
        kdc = 10.10.10.162:88
        admin_server = 10.10.10.162:749
        kpasswd_server = 10.10.10.162:464
    }

[domain_realm]
    .testlabby.local = TESTLABBY.LOCAL
    testlabby.local = TESTLABBY.LOCAL


This version explicitly prefers **AES256** encryption, which helps avoid the "Cannot find key of appropriate type" errors with Java applications like Keycloak.

# Test it
kinit youruser@TESTLABBY.LOCAL
klist


---

## 3. Insecure / Testing Configuration (Plain LDAP)

Use this configuration during initial testing or in trusted internal networks.

### `sssd.conf` – Insecure Template

[sssd]
services = nss, pam
domains = klldap

[nss]
filter_users = root,daemon,bin,sys,adm,disk,mem,kmem,wheel
filter_groups = root,bin,daemon,sys,adm,disk,mem,kmem,wheel

[domain/klldap]
    # === Identity Provider (LDAP) ===
    id_provider = ldap
    ldap_uri = ldap://10.10.10.162:3890
    ldap_search_base = dc=testlabby,dc=local
    ldap_user_search_base = ou=people,dc=testlabby,dc=local
    ldap_group_search_base = ou=groups,dc=testlabby,dc=local

    ldap_schema = rfc2307bis
    ldap_user_object_class = posixAccount
    ldap_user_name = uid
    ldap_user_uid_number = uidNumber
    ldap_user_gid_number = gidNumber
    ldap_user_home_directory = homeDirectory
    ldap_user_shell = loginShell

    ldap_group_object_class = posixGroup
    ldap_group_name = cn
    ldap_group_gid_number = gidNumber
    # rfc2307 (SSSD default) also works: KLLDAP emits memberUid (login names)
    # and gecos (= displayName). Set ldap_user_uuid = entryUUID only if you
    # want UUIDs; not required for getent/login.

    ldap_default_bind_dn = uid=admin,ou=people,dc=testlabby,dc=local
    ldap_default_authtok = YourSecureAdminPassword

    # Disable TLS checks for plain LDAP
    ldap_id_use_start_tls = false
    ldap_tls_reqcert = never
    ldap_auth_disable_tls_never_use_in_production = true
    ldap_id_mapping = false

    # === Authentication Provider (Kerberos) ===
    auth_provider = krb5
    chpass_provider = krb5

    krb5_server = 10.10.10.162
    krb5_realm = TESTLABBY.LOCAL
    krb5_kpasswd = 10.10.10.162

    krb5_validate = false
    krb5_store_password_if_offline = true

    access_provider = permit
    enumerate = false
    cache_credentials = true
    use_fully_qualified_names = false


**Apply the configuration:**


sudo chmod 600 /etc/sssd/sssd.conf
sudo chown root:root /etc/sssd/sssd.conf
sudo sssctl config-check
sudo systemctl restart sssd

---

## 4. Secure Production Configuration (Recommended)

Use **StartTLS** or **LDAPS** in production.

### Minimal Secure Production Template

[sssd]
services = nss, pam
domains = klldap

[nss]
filter_users = root,daemon,bin,sys,adm,disk,mem,kmem,wheel
filter_groups = root,bin,daemon,sys,adm,disk,mem,kmem,wheel

[domain/klldap]
    # === Identity from LDAP ===
    id_provider = ldap
    ldap_uri = ldaps://your-ldap-server:6360          # Use ldaps:// for LDAPS
    ldap_search_base = dc=example,dc=com
    ldap_user_search_base = ou=people,dc=example,dc=com
    ldap_group_search_base = ou=groups,dc=example,dc=com

    ldap_schema = rfc2307bis
    ldap_user_object_class = posixAccount
    ldap_user_name = uid
    ldap_user_uid_number = uidNumber
    ldap_user_gid_number = gidNumber
    ldap_user_home_directory = homeDirectory
    ldap_user_shell = loginShell

    ldap_group_object_class = posixGroup
    ldap_group_name = cn
    ldap_group_gid_number = gidNumber
    # rfc2307 (SSSD default) also works: KLLDAP emits memberUid and gecos.

    ldap_default_bind_dn = uid=binduser,ou=service,dc=example,dc=com
    ldap_default_authtok = YourSecureBindPassword

    # === TLS / Security Settings ===
    ldap_id_use_start_tls = true
    ldap_tls_reqcert = demand
    # ldap_tls_cacert = /etc/pki/tls/certs/ca-bundle.crt   # Uncomment if using custom CA

    # === Kerberos Authentication ===
    auth_provider = krb5
    chpass_provider = krb5

    krb5_server = your-kerberos-server
    krb5_realm = EXAMPLE.COM
    krb5_kpasswd = your-kerberos-server

    krb5_validate = true                    # Recommended in production (requires host keytab)
    krb5_store_password_if_offline = true

    access_provider = permit                # Consider "ldap" or "simple" for stricter control
    enumerate = false
    cache_credentials = true
    use_fully_qualified_names = false


**Notes for Production:**
- Prefer **StartTLS** (`ldap_id_use_start_tls = true`) over plain LDAP.
- Set `krb5_validate = true` after deploying a host keytab.
- Use a dedicated bind user with minimal privileges.
- Consider changing `access_provider` to `ldap` for group-based access control.

---

## 5. SELinux Configuration

### Standard Ports (Usually Pre-Allowed)

| Port | Service     | SELinux Type      |
|------|-------------|-------------------|
| 389  | LDAP        | `ldap_port_t`     |
| 636  | LDAPS       | `ldap_port_t`     |
| 88   | Kerberos    | `kerberos_port_t` |
| 464  | kpasswd     | `kerberos_port_t` |

### Non-Standard LDAP Port (e.g. 3890)


# Allow custom LDAP port - any SELinux OS will need this opened for standard, or 6360 for secure
sudo semanage port -a -t ldap_port_t -p tcp 3890
sudo semanage port -a -t ldap_port_t -p tcp 6360

# Verify
sudo semanage port -l | grep ldap_port_t


### Useful SELinux Commands


# Add custom port
sudo semanage port -a -t ldap_port_t -p tcp 3890 # Insecure
sudo semanage port -a -t ldap_port_t -p tcp 6360 # Secure

# Remove a port
sudo semanage port -d -t ldap_port_t -p tcp 3890

# List allowed ports
sudo semanage port -l | grep -E 'ldap_port_t|kerberos_port_t'

# Check for AVC denials (useful for troubleshooting)
sudo ausearch -m avc -ts recent


After changing port policy, restart SSSD:


sudo systemctl restart sssd


---

## 6. Verification Commands


# Check domain status
sssctl domain-status lldap

# Validate configuration
sudo sssctl config-check

# Test user and group resolution
getent passwd youruser
id youruser
getent group yourgroup

# Check Kerberos ticket after login
klist

# View SSSD logs
sudo journalctl -u sssd -f


## 7. Keycloak Integration & SPNEGO SSO

This section covers integrating your LLDAP + Kerberos setup with **Keycloak** for web-based SSO using SPNEGO (Kerberos).

### 7.1 Docker Networking & Volume Recommendations

For the best experience:

- Run both the **KLLDAP** and **Keycloak** containers on the **same Docker host** and preferably on the **same Docker network**.
- Share the keytab directory from KLLDAP to Keycloak as a read-only volume:

# Example docker-compose snippet for Keycloak
services:
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    volumes:
      - /path/to/klldap/data/keytab:/keytab:ro
    # ... rest of config


Inside Keycloak, the keytab will be available at `/keytab/keycloak-http.keytab`.

If the containers are on different machines, you will need to securely copy the keytab and update the path in Keycloak.

### 7.2 Create a Dedicated Bind User (Recommended)

Instead of using the admin account, create a low-privilege user for Keycloak:

1. Create a new user in LLDAP (e.g. `keycloak`).
2. Add this user to the **`lldap_strict_readonly`** group.

This user will be used by Keycloak for LDAP searches. It is much more secure than using the admin account.

### 7.3 Web UI Flow (Federation Page)

The project includes a **Keycloak Federation** interface (see `KeycloakSettings` component).

#### Step-by-step:

1. **Go to the Federation page** in the web UI.
2. **Test Connection** (left side):
   - Fill in your Keycloak URL, Realm (usually `master`), and Admin credentials.
   - The admin password can come from the environment variable `LLDAP_KEYCLOAK_ADMIN_PASS`.
   - Click **Test Settings**. This tests against the master realm.
3. Once the test succeeds, the right side ("New Realm Settings") becomes active.
4. Fill in:
   - **Realm Name** (auto-suggested)
   - **LLDAP URL** (e.g. `ldap://lldap:3890` or external address)
   - **Sync Username** → Use the dedicated user you created in the `lldap_strict_readonly` group
   - **Sync Password**
   - Optional: Enable HSTS and Brute Force Protection
5. Click the buttons:
   - **Export keytab** — Creates/updates the Keycloak service keytab in the shared volume.
   - **Push To Keycloak** — Creates a new realm in Keycloak pre-configured with your LLDAP as an LDAP + Kerberos User Federation provider, along with sensible mappers.

> **Note**: After pushing, you will likely want to review and adjust settings inside the Keycloak admin console.

### 7.4 Browser Configuration for SPNEGO

For automatic Kerberos login in the browser:

#### Firefox

1. Go to `about:config`
2. Set the following preferences:

   - `network.negotiate-auth.trusted-uris` → `.yourdomain.local, keycloak.yourdomain.local`
   - `network.negotiate-auth.delegation-uris` → `.yourdomain.local, keycloak.yourdomain.local`

#### Chrome / Chromium / Edge

These browsers usually inherit SPNEGO settings from the operating system. On Linux you can launch with:


google-chrome --auth-server-whitelist="*.yourdomain.local" \
              --auth-negotiate-delegate-whitelist="*.yourdomain.local"


### 7.5 Testing SPNEGO

Recommended test URL after logging into your desktop:


http://keycloak.yourdomain.local:8080/realms/your-realm/account


If everything is configured correctly, you should be logged in automatically without entering credentials.

You can also test from the command line:


klist
curl -v --negotiate -u : http://keycloak.yourdomain.local:8080/realms/your-realm/account


---

---

## 8. Troubleshooting

### Common Issues and Solutions

| Symptom                                      | Likely Cause                              | Solution |
|---------------------------------------------|-------------------------------------------|----------|
| `SSSD is offline`                           | Connection refused or SELinux blocking    | Check network, firewall, and SELinux ports |
| `Permission denied` on LDAP connect         | SELinux blocking non-standard port        | Run `semanage port -a -t ldap_port_t -p tcp 3890` |
| Encryption type error (`AES256`)            | Keytab missing strong encryption types    | Regenerate keytab with `aes256-cts-hmac-sha1-96` |
| SPNEGO not working in browser               | Wrong hostname or Browser not configured  | Use matching hostname + configure Firefox `trusted-uris` |
| `krb5_validate = true` breaks login         | No host keytab or incorrect permissions   | Create host keytab or set `krb5_validate = false` |
| User lookup works but authentication fails  | Kerberos misconfiguration                 | Verify `krb5.conf` and `krb5_server` |
| Keytab changes not picked up by Keycloak    | Keycloak cached old path / permissions    | Restart Keycloak after updating keytab |
| `groups: cannot find name for group ID`     | Group not present in LDAP or caching      | Create matching group in LDAP + clear cache |

### Useful Debug Commands


# Increase SSSD debug level temporarily
sudo sssctl debug-level 9
sudo systemctl restart sssd

# Check SELinux denials in real time
sudo ausearch -m avc -ts recent | tail -20

# Test raw LDAP connection
ldapsearch -x -H ldap://your-server:3890 -b "dc=example,dc=com" -s base

# Test Kerberos directly
kinit youruser@YOUR.REALM
klist

### Common Log Locations

- SSSD logs: `/var/log/sssd/`
- Journal: `journalctl -u sssd`
- Keycloak logs: Inside the Keycloak container

---

## 9. Best Practices & Recommendations

- Use **StartTLS** or **LDAPS** in production.
- Deploy a **host keytab** and enable `krb5_validate = true`.
- Use dedicated, low-privilege bind accounts.
- Keep `enumerate = false` for performance.
- Regularly rotate Kerberos keys and service keytabs.
- Document your custom LDAP port usage clearly.
- Prefer `access_provider = ldap` over `permit` when possible for better access control.

---

## Appendix: Quick Start Commands


# Apply configuration
sudo chmod 600 /etc/sssd/sssd.conf
sudo sssctl config-check
sudo systemctl restart sssd

# Allow custom LDAP port (SELinux)
sudo semanage port -a -t ldap_port_t -p tcp 3890

# Check everything
sssctl domain-status lldap && getent passwd testuser && klist

---

**Document Version:** 1.1
**Last Updated:** 2026-05-16

This guide was created based on real-world deployment experience with LLDAP + custom Kerberos integration and Keycloak SPNEGO.

---

## Appendix B: Docker Compose Example (Keytab Sharing)

yaml
services:
  lldap:
    image: lldap/lldap:latest
    volumes:
      - ./data:/data
    # ...

  keycloak:
    image: quay.io/keycloak/keycloak:latest
    volumes:
      - ./data/keytab:/keytab:ro
    environment:
      - KEYCLOAK_ADMIN=admin
      - KEYCLOAK_ADMIN_PASSWORD=${LLDAP_KEYCLOAK_ADMIN_PASS}
    # ...


Make sure both containers can resolve each other (same Docker network is ideal).

---

This completes the integration documentation between LLDAP’s Kerberos features and Keycloak SPNEGO.

---

### Key Customizations Explained

| Setting                              | Value                          | Reason |
|--------------------------------------|--------------------------------|--------|
| `default_realm`                      | `TESTLABBY.LOCAL`              | Your Kerberos realm |
| `dns_lookup_realm` / `dns_lookup_kdc`| `false`                        | Using IP addresses instead of DNS |
| `default_ccache_name`                | `KEYRING:persistent:%{uid}`    | Modern, session-friendly credential cache |
| `forwardable`                        | `true`                         | Allows credential forwarding (useful for SPNEGO) |
| `[realms]` section                   | Points to your KDC IP          | Required when not using DNS SRV records |
| `[domain_realm]`                     | Maps your domain to the realm  | Enables automatic realm detection |

---

## Summary

You now have a complete end-to-end configuration covering:

- SSSD (LDAP identity + Kerberos auth)
- SELinux port labeling
- Kerberos client (`krb5.conf`)
- Keycloak SPNEGO integration
- Docker volume sharing for keytabs
- Browser configuration

This setup enables seamless desktop login → automatic web SSO via Kerberos tickets.
