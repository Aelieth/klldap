<h1 align="center">KLLDAP - Enhanced Light LDAP with Kerberos</h1>

*DISCLAIMER:
Personal project and first foray into Rust. Use at your own risk with optimistic caution!
You may report issues don't expect me to be on top of them as this is a hobby project.
Built with aid of Grok / xAI. Thanks Grok and all of my agents.
-----------

## About

This is a major fork of [LLDAP](https://github.com/lldap/lldap) with integrated MIT Kerberos
KDC, POSIX extensions, admin-controlled Organizational Units, and Keycloak federation support.

<img
  src="https://raw.githubusercontent.com/Aelieth/klldap/refs/heads/main/screenshot.png"
  alt="Screenshot of the user list page"
  width="50%"
  align="right"
/>

KLLDAP is not supported by LLDAP or its team, this is project by a lone network admin that
needed Kerberos and full POSIX compliance and compatibility on his home hosted systems.

Refer to [LLDAP](https://github.com/lldap/lldap) for a more community supported version.

## Installation

KLLDAP only supports Docker images at this time. Why? MIT Kerberos is a must in order to get
Kerberos functionality with the system. Kerberos is setup to be tight-knit and secure by
being contained within the same environment as LLDAP, acting in unison with one another.

## Schema System – Single Source of Truth
- All LDAP attributes for users, groups, and system settings defined in one central place: `crates/schema/src/public_schema.rs`
- `PublicSchema::get()` is the live, canonical definition used everywhere (GraphQL, SQL, LDAP, frontend, Kerberos sync)
- Three clean categories:
  - User attributes (core + POSIX + Kerberos + SSH + ou)
  - Group attributes
  - System attributes (new section for allowedous and future settings)
- Every attribute carries full metadata: name, aliases, type, list support, visibility, editability, hardcoded flag, and readonly status
- Database migration v12 clears old tables and re-seeds everything directly from `PublicSchema::get()`
- Runtime code always pulls from the database but stays 100% consistent with the PublicSchema definition

## Kerberos Integration – MIT KDC
- Hands off integration: Bootstrap handled by custom startup binary `crates/kerberos/src/bin/kerberos_manager.rs` on first container start
- Password-less operation after bootstrap: uses kadm5.keytab for all admin actions
- Realm and domain are automatically derived from LLDAP_LDAP_BASE_DN — zero manual configuration needed
- Full MIT Kerberos Key Distribution Center (krb5kdc + kadmind) runs inside the Docker container via FFI bindings to libkadm5 and krb5
- Automatic principal management: on every user create / password change / delete, principals are created / updated / deleted in the KDC
- Secure password handling: RSA 2048 OAEP+SHA-256 encryption between frontend and backend kerberos

## Federation – Keycloak
- Dedicated “Federation” tab in the web UI (`app/src/components/federation.rs`) for Keycloak + Kerberos integration
- Loads and saves `keycloak_config.toml` via GraphQL
- One-click “Test Settings” button validates admin credentials
- “Push To Keycloak” button (enabled after successful test + sync password) auto-creates realm, LDAP+Kerberos provider, and lldap-web client
- “Export keytab” button generates ready-to-use keytab for Keycloak HTTP principal

## Federation - POSIX
- Dedicated POSIX section - autofill and assignment of POSIX attributes across users or groups
- POSIX automatic incremented attributes on user / group creation 
- Prevents POSIX duplicate uid or gid numbers for sanity

## Frontend – Quality of Life Improvements
- Reusable OuSelector component renders tree-style dropdowns for 1-level hierarchical OUs using “\” separator
- OuTable header combines OU filtering, Create OU, and Delete OU actions in one row
- User table features real-time OU filtering, multi-field search, bulk selection with intelligent Select All, bulk Change OU, and bulk delete
- Fully modular design — same OuSelector and OuTable will be reused for the Group table

## LDAP Standardized support following RFC guidelines
- Full standards compliant refactor with RFC guidelines, utilizing dynamic new public_schema information
- Modularized and memory efficient for lookups with POSIX and SSSD
- LDAP can now be read and connected to via Directory Studios, even as strict as Apache
- User and group creation supported, user attribute modifications support with limitations

## Other improvements / Bugfixes
- #1399 [FEATURE REQUEST] Change Avatar Data Type to MEDIUMBLOB? → Fixed through BLOB size to be consistent among databases
- #401 [FEATURE REQUEST] Avatar supports upload of JPG, JPEG, BMP, and PNG formats converting to JPG now with 512x512 resolution and <512KB size support
- #1202 [BUG] Attributes with the same name can be created with different types → Fixed with strict cross-schema check in add_user_attribute / add_group_attribute. Same name (even matching type) now blocked entirely.
- #739 [FEATURE REQUEST] SSSD integration support → POSIX groups added. Extra user and group classes inetOrgPerson, posixAccount, and posixGroup mappings.
- #1165 [BUG] Users and groups objects are seen as containers, instead of leafs
- #750 [FEATURE REQUEST] Ability to disable LDAP users → lldap_disabled group added, if a user is added to this group they become inactive and grayed out on the user list, ldap search does not return them, and if they attempt to login they are returned "Account disabled. Contact administrator." Admin side can easily disable user with a button on the user_details_form.rs
- #1308 [FEATURE REQUEST] Implement GreaterOrEqual filter for builtin timestamps → extended ldap user.rs and group.rs with handler.rs extensions with appropriate GreaterOrEqual / LessOrEqual for timestamps
- #1425 [BUG] (&(objectClass=person)(...)) still performs group search, logging warnings → simple intercept fix inside of the convert_group_filter
- #712 [FEATURE REQUEST] SSH public key support (ssHPublicKey attribute, list type, POSIX-style) — add to PublicSchema + migration + LDAP exposure. → ssHPublicKey added to public_schema with ldapsearch functionality. Admins may enter keys for users or users may modify their own keys.

## Future Plans
- Continued integration of LLDAP features
- Multifactor auth
- SMB integration with kerberos auth 
- Password / lockout policies
- Account expiration
- Long: Kerberos database directly integrated into LLDAP's
- Very long: Integrate Kerberos or all FFI calls for dynamic custom integration, no docker required

---

**KLLDAP** is built turtle-step style: one file at a time, full builds verified, security-first,
and designed to be reliable - because I want to use it too!

## Environment Variables

Only the variables that are actually needed for KLLDAP. Everything else is either defaulted inside the container or configured
via the new Federation tab or toml files.
Please see LLDAP variables for the remaining LLDAP remaining toml and env var information!

| Variable                  | Required | Default                          | Description |
|---------------------------|----------|----------------------------------|---------------------------------------------------|
| LLDAP_JWT_SECRET          | Yes      | (must be set)                    | JWT signing secret for web sessions               |
| LLDAP_LDAP_USER_PASS      | Yes      | (must be set)                    | Initial admin password                            |
| LLDAP_LDAP_BASE_DN        | Yes      | dc=example,dc=com                | LDAP base DN — also used to derive Kerberos realm |
| LLDAP_KEYCLOAK_ADMIN_PASS | No       | admin                            | Keycloak admin password (used by Federation tab)  |
| LLDAP_KERB_REALM_NAME     | No       | Derived from LLDAP_LDAP_BASE_DN  | Optional override for Kerberos realm name         |

Persisted non-secret config in /data/kerberos_config.toml on first run.

## Volumes

- /data: LLDAP config, users, groups.
- /var/kerberos/krb5kdc: Kerberos database (critical!).

## Exposed Ports

- 3890: LLDAP LDAP
- 17170: LLDAP Web UI
- 88/tcp+udp: Kerberos KDC
- 749/tcp: Kerberos admin

## License

AGPL-3.0 (matches upstream LLDAP). See LICENSE file.

## Credits

- LLDAP server: lldap/lldap
- Keycloak integration inspiration: keycloak/keycloak

This repository is under active development. Built for home/lab SSO.
