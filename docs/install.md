# Installing KLLDAP

KLLDAP is currently **Docker-only**.  
This is a personal hobby project / half-brother fork of LLDAP developed for my own home-lab use. The Docker container is the exact environment I build and test against.

**Podman** (rootless) is **not supported** at this time. MIT Kerberos requires root privileges inside the container for kadmin.local, keytab creation, and database initialization. You are welcome to experiment, but it is not tested or guaranteed to work.

- [With Docker](#with-docker)
- [With Podman](#with-podman)
- [Other methods](#other-methods)

### With Docker

The image is available at `aelieth/klldap`.

You should persist two folders:
- `/data` — contains LLDAP config, users, groups, and keycloak_config.toml
- `/var/kerberos/krb5kdc` — contains the Kerberos database (critical — do not lose this)

On first run the container automatically bootstraps the full MIT Kerberos KDC (creates database, admin principal, keytab, renders configs, starts krb5kdc and kadmind).

```yaml
version: "3"

volumes:
  lldap_data:
    driver: local
  kerberos_db:
    driver: local

services:
  klldap:
    image: aelieth/klldap:latest
    container_name: klldap
    restart: unless-stopped
    ports:
      # LDAP (not recommended to expose publicly)
      - "3890:3890"
      # For LDAPS (LDAP Over SSL), enable port if LLDAP_LDAPS_OPTIONS__ENABLED set true, look env below
      #- "6360:6360"
      # Web UI
      - "17170:17170"
      # Kerberos KDC
      - "88:88/tcp"
      - "88:88/udp"
      # Kerberos admin
      - "749:749/tcp"
    volumes:
      - lldap_data:/data
      - kerberos_db:/var/kerberos/krb5kdc
      # Alternatively, you can mount local folders:
      # - "./lldap_data:/data"
      # - "./kerberos_db:/var/kerberos/krb5kdc"
    environment:
      - UID=####
      - GID=####
      - TZ=####/####
      - LLDAP_JWT_SECRET=REPLACE_WITH_RANDOM_SECRET
      - LLDAP_LDAP_USER_PASS=CHANGE_ME
      - LLDAP_LDAP_BASE_DN=dc=example,dc=com
      # KLLDAP-specific (optional)
      - LLDAP_KEYCLOAK_ADMIN_PASS=admin
      - LLDAP_KERB_REALM_NAME=EXAMPLE.COM
      # Original LLDAP options still fully supported:
      # - LLDAP_DATABASE_URL=mysql://mysql-user:password@mysql-server/my-database
      # - LLDAP_DATABASE_URL=postgres://postgres-user:password@postgres-server/my-database
      # - LLDAP_LDAPS_OPTIONS__ENABLED=true
      # - LLDAP_LDAPS_OPTIONS__CERT_FILE=/path/to/certfile.crt
      # - LLDAP_LDAPS_OPTIONS__KEY_FILE=/path/to/keyfile.key
      # - LLDAP_SMTP_OPTIONS__ENABLE_PASSWORD_RESET=true
      # - LLDAP_SMTP_OPTIONS__SERVER=smtp.example.com
      # - LLDAP_SMTP_OPTIONS__PORT=465
      # - LLDAP_SMTP_OPTIONS__SMTP_ENCRYPTION=TLS
      # - LLDAP_SMTP_OPTIONS__USER=no-reply@example.com
      # - LLDAP_SMTP_OPTIONS__PASSWORD=PasswordGoesHere
      # - LLDAP_SMTP_OPTIONS__FROM=no-reply <no-reply@example.com>
      # - LLDAP_SMTP_OPTIONS__REPLY_TO=Do not reply <no-reply@example.com>
      # Required for working password-reset links (the emailed URL is built from it):
      # - LLDAP_HTTP_URL=https://your-real-ui-url
```

After first start:

Visit http://your-server:17170
Default admin login: admin / whatever you set for LLDAP_LDAP_USER_PASS
Use the Federation tab to configure and push to Keycloak.

The container will automatically bootstrap the Kerberos KDC on first run (creates database, admin keytab, renders config files).
## With Podman
Podman is currently not supported.
The integrated MIT Kerberos KDC requires root privileges inside the container. Podman’s default rootless mode does not work reliably with KLLDAP.
You are free to experiment, but no support or guarantees are provided.


## Other methods
Kubernetes – Not officially supported yet (you can try the upstream LLDAP Kubernetes examples, but Kerberos will need extra work).
From source / bare metal – Possible but not recommended. This is a personal hobby project developed exclusively for Docker.
Package repositories – None exist. KLLDAP is not packaged anywhere.

# Note: KLLDAP is a personal hobby project for my own home-lab use. The Docker container is the only target I actively develop and test against. Use at your own risk.
For configuration details see the Environment Variables section in the main README.
