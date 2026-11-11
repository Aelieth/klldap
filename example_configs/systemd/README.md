# KLLDAP under systemd

The image is the supported install. This directory is one example of running
the same server on a host. The server's defaults stay the image's; the example
configuration names the host's paths.

The unit grants `CAP_NET_BIND_SERVICE` in the ambient set, so the binary needs
no setcap and the server is never started as root.

1. Create the `klldap` user and group. The unit does not create them. It runs
   the server as that user (`systemd.exec(5)`, `User=, Group=`).
2. Install the `lldap` binary at `/usr/local/bin/lldap`.
3. Install the web assets at `/usr/local/share/klldap/app`. The server only
   reads them. `ProtectSystem=strict` mounts that tree read-only for the
   service (`systemd.exec(5)`, `ProtectSystem=`).
4. Install `lldap_config.toml` at `/etc/klldap/lldap_config.toml`, owner
   `root:klldap`, mode `0640`. The server reads it as the service user. The
   example holds no secret.
5. Set `ldap_base_dn` in that file before the first start. The Kerberos realm
   follows from it, and changing it later means starting the realm over. Left
   commented, the default `dc=example,dc=com` makes the realm `EXAMPLE.COM`.
6. Install `/etc/klldap/klldap.env`, owner `root`, mode `0600`, with
   `LLDAP_JWT_SECRET` and `LLDAP_LDAP_USER_PASS`. systemd reads this file
   itself, before it switches user (`systemd.exec(5)`, `EnvironmentFile=`).
   The "-" in `EnvironmentFile=-/etc/klldap/klldap.env` means a missing file
   is not an error for systemd (`systemd.exec(5)`, `EnvironmentFile=`). The
   server then stops at start for want of the JWT secret, and says so.
7. `systemctl enable --now klldap.service`.

`StateDirectory=klldap` creates `/var/lib/klldap` when the unit starts and
gives it to the service user (`systemd.exec(5)`, `StateDirectory=`). That
directory is excluded from `ProtectSystem=strict`, so it is the one tree the
service can write (`systemd.exec(5)`, `ProtectSystem=`). The server creates
the database, the realm directory, and the keytabs there. Do not create
`keycloak_config.toml`; a missing one stays on the defaults.

Client tools use `KRB5_CONFIG=/var/lib/klldap/krb5.conf`. The server does not
write `/etc/krb5.conf`.
