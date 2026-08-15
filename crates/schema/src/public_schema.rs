//! Built-in attribute schema for users, groups, and system data.
//!
//! Attributes are declared with the `A::{editable, readonly, generated, hidden}` builders. Each sets
//! a combination of the five `AttributeSchema` flags: four inherited from upstream LLDAP — `is_list`,
//! `is_visible`, `is_editable`, `is_hardcoded` — plus KLLDAP's own `is_readonly` (no upstream analog;
//! it is also what makes an attribute advertise `NO-USER-MODIFICATION` over LDAP).
//!
//! Every builder sets `is_hardcoded = true` (built-in: undeletable, value read from a typed field,
//! never a stored custom attribute) and `is_list = false` unless `.list()` is chained.
//!
//! - `editable`  — `is_editable = true`. Visible to all; writable by regular users *and* admins.
//!   (mail, displayName, firstName, lastName, avatar, sshPublicKey)
//! - `generated` — all defaults (`is_editable = false`, `is_readonly = false`). Visible to all; a
//!   regular user cannot set it, but an **admin can override** it. For server-assigned POSIX/Kerberos
//!   values (uidNumber, gidNumber, homeDirectory, loginShell, kerberos sync).
//! - `readonly`  — `is_readonly = true`. Visible to all; **write-blocked for everyone, admins
//!   included**, and advertised `NO-USER-MODIFICATION` in the LDAP schema. (userId, uuid, timestamps,
//!   ou, groupId)
//! - `hidden`    — `is_visible = false` (+ `is_readonly = true`). **Admin-only**: stripped from both
//!   the schema and the returned values for non-admins; also write-blocked. (krbPrincipalName;
//!   system allowedOUs)
//!
//! Enforcement (`graphql-server` mutation path): `is_readonly` is checked before `is_editable`, so
//! `readonly` freezes a value for all while `generated` blocks only regular users.
use crate::schema::{AttributeList, AttributeSchema, AttributeType, PosixSettings, Schema};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// Per-user switch for KDC principal sync; the schema attribute name behind `kerberosSync`.
pub const KERBEROS_SYNC: &str = "kerberossync";

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct PublicSchema(pub Schema);

impl PublicSchema {
    pub fn get() -> Self {
        Self::shared().clone()
    }

    /// Shared static instance — the schema is a compile-time constant.
    pub fn shared() -> &'static Self {
        static SCHEMA: LazyLock<PublicSchema> = LazyLock::new(PublicSchema::build);
        &SCHEMA
    }

    fn build() -> Self {
        use AttributeSchema as A;
        use AttributeType::{Avatar, DateTime, Integer, String};

        #[rustfmt::skip]
        let user_attributes = vec![
            // --- Core (LLDAP-descended) ---
            A::editable("avatar", Avatar)
                .aliases(&["jpegphoto", "jpegPhoto", "jpeg_photo"]),
            A::readonly("creationdate", DateTime)
                .aliases(&["creation_date", "createTimestamp"]),
            A::editable("displayname", String)
                .aliases(&["display_name", "cn", "commonname"]),
            A::editable("firstname", String)
                .aliases(&["first_name", "givenName", "given_name"]),
            A::editable("lastname", String)
                .aliases(&["last_name", "sn", "surname"]),
            A::editable("mail", String)
                .aliases(&["email"]),
            A::readonly("modifieddate", DateTime)
                .aliases(&["modified_date", "modifyTimestamp"]),
            A::readonly("passwordmodifieddate", DateTime)
                .aliases(&["password_modified_date", "pwdChangedTime"]),
            A::readonly("userid", String)
                .aliases(&["user_id", "uid", "id"]),
            A::readonly("uuid", String)
                .aliases(&["entryUUID", "entryuuid"]),

            // --- POSIX ---
            A::generated("uidnumber", Integer)
                .aliases(&["uid_number", "uidNumber"]),
            A::generated("gidnumber", Integer)
                .aliases(&["gid_number", "gidNumber"]),
            A::generated("homedirectory", String)
                .aliases(&["home_directory", "homeDirectory"]),
            A::generated("loginshell", String)
                .aliases(&["login_shell", "loginShell"]),

            // --- Kerberos ---
            A::generated(KERBEROS_SYNC, Integer).aliases(&["kerberos_sync", "kerberosSync"]),
            A::hidden("krbprincipalname", String)
                .aliases(&["krb_principal_name", "krbPrincipalName"]),

            // --- SSH ---
            A::editable("sshpublickey", String)
                .aliases(&["sshPublicKey", "ssHPublicKey", "ssh_public_key"])
                .list(),

            // --- OU ---
            A::readonly("ou", String)
                .aliases(&["organizationalunit", "organizationalUnit"]),
        ];

        #[rustfmt::skip]
        let group_attributes = vec![
            // --- Core ---
            A::readonly("groupid", Integer)
                .aliases(&["group_id"]),
            A::readonly("creationdate", DateTime)
                .aliases(&["creation_date", "createTimestamp"]),
            A::readonly("modifieddate", DateTime)
                .aliases(&["modified_date", "modifyTimestamp"]),
            A::readonly("uuid", String)
                .aliases(&["entryUUID", "entryuuid"]),
            A::editable("displayname", String)
                .aliases(&["display_name", "cn", "commonname"]),

            // --- OU ---
            A::readonly("ou", String)
                .aliases(&["organizationalunit", "organizationalUnit"]),

            // --- POSIX ---
            A::generated("gidnumber", Integer)
                .aliases(&["gid_number", "gidNumber"]),
        ];

        #[rustfmt::skip]
        let system_attributes = vec![
            // --- Access control ---
            A::hidden("allowedous", String)
                .aliases(&["allowedOUs", "AllowedOUs"])
                .list(),
        ];

        PublicSchema(Schema {
            user_attributes: AttributeList {
                attributes: user_attributes,
            },
            group_attributes: AttributeList {
                attributes: group_attributes,
            },
            system_attributes: AttributeList {
                attributes: system_attributes,
            },
            posix_settings: PosixSettings {
                user_uidnumber_assign: false,
                user_uidnumber_start: 3001,
                user_uidnumber_max: 3999,
                user_gidnumber_assign: false,
                user_gidnumber_start: 3001,
                user_loginshell_assign: false,
                user_loginshell_default: "/bin/bash".to_string(),
                user_homedirectory_assign: false,
                user_homedirectory_prefix: "/home".to_string(),
                group_gidnumber_assign: false,
                group_gidnumber_start: 3001,
                group_gidnumber_max: 3999,
            },
            extra_user_object_classes: vec![
                "inetOrgPerson".into(),
                "posixAccount".into(),
                "ldapPublicKey".into(),
            ],
            extra_group_object_classes: vec!["posixGroup".into()],
        })
    }

    pub fn get_schema(&self) -> &Schema {
        &self.0
    }

    pub fn user_attributes(&self) -> &AttributeList {
        &self.0.user_attributes
    }

    pub fn group_attributes(&self) -> &AttributeList {
        &self.0.group_attributes
    }

    pub fn system_attributes(&self) -> &AttributeList {
        &self.0.system_attributes
    }

    pub fn posix_settings(&self) -> &PosixSettings {
        &self.0.posix_settings
    }

    pub fn posix_settings_mut(&mut self) -> &mut PosixSettings {
        &mut self.0.posix_settings
    }

    pub fn resolve_user_canonical_name(&self, name_or_alias: &str) -> Option<&str> {
        self.user_attributes().resolve_canonical_name(name_or_alias)
    }

    pub fn resolve_group_canonical_name(&self, name_or_alias: &str) -> Option<&str> {
        self.group_attributes()
            .resolve_canonical_name(name_or_alias)
    }
}
