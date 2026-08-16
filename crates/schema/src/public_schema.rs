//! The built-in attribute schema. Attributes are declared with the `AttributeSchema::{editable,
//! generated, readonly, hidden}` builders; every one is hardcoded and single-valued unless
//! `.list()` is chained.
//!
//! - `editable`: visible to all, writable by users and admins (mail, displayName, avatar, ...).
//! - `generated`: visible to all, settable only by admins; the server assigns the value
//!   (uidNumber, gidNumber, homeDirectory, loginShell, kerberosSync).
//! - `readonly`: visible to all, writable by nobody, advertised NO-USER-MODIFICATION over LDAP
//!   (userId, uuid, timestamps, ou, groupId).
//! - `hidden`: readonly and stripped from the schema and values for non-admins
//!   (krbPrincipalName, allowedOUs).
//!
//! The mutation path checks `is_readonly` before `is_editable`, so `readonly` freezes a value
//! for everyone while `generated` blocks only regular users.
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

    pub fn shared() -> &'static Self {
        static SCHEMA: LazyLock<PublicSchema> = LazyLock::new(PublicSchema::build);
        &SCHEMA
    }

    fn build() -> Self {
        use AttributeSchema as A;
        use AttributeType::{Avatar, DateTime, Integer, String};

        let user_attributes = vec![
            // Core
            AttributeSchema {
                aliases: vec!["jpegphoto".into(), "jpegPhoto".into(), "jpeg_photo".into()],
                ..A::editable("avatar", Avatar)
            },
            AttributeSchema {
                aliases: vec!["creation_date".into(), "createTimestamp".into()],
                ..A::readonly("creationdate", DateTime)
            },
            AttributeSchema {
                aliases: vec!["display_name".into(), "cn".into(), "commonname".into()],
                ..A::editable("displayname", String)
            },
            AttributeSchema {
                aliases: vec!["first_name".into(), "givenName".into(), "given_name".into()],
                ..A::editable("firstname", String)
            },
            AttributeSchema {
                aliases: vec!["last_name".into(), "sn".into(), "surname".into()],
                ..A::editable("lastname", String)
            },
            AttributeSchema {
                aliases: vec!["email".into()],
                ..A::editable("mail", String)
            },
            AttributeSchema {
                aliases: vec!["modified_date".into(), "modifyTimestamp".into()],
                ..A::readonly("modifieddate", DateTime)
            },
            AttributeSchema {
                aliases: vec!["password_modified_date".into(), "pwdChangedTime".into()],
                ..A::readonly("passwordmodifieddate", DateTime)
            },
            AttributeSchema {
                aliases: vec!["user_id".into(), "uid".into(), "id".into()],
                ..A::readonly("userid", String)
            },
            AttributeSchema {
                aliases: vec!["entryUUID".into(), "entryuuid".into()],
                ..A::readonly("uuid", String)
            },
            // POSIX
            AttributeSchema {
                aliases: vec!["uid_number".into(), "uidNumber".into()],
                ..A::generated("uidnumber", Integer)
            },
            AttributeSchema {
                aliases: vec!["gid_number".into(), "gidNumber".into()],
                ..A::generated("gidnumber", Integer)
            },
            AttributeSchema {
                aliases: vec!["home_directory".into(), "homeDirectory".into()],
                ..A::generated("homedirectory", String)
            },
            AttributeSchema {
                aliases: vec!["login_shell".into(), "loginShell".into()],
                ..A::generated("loginshell", String)
            },
            // Kerberos
            AttributeSchema {
                aliases: vec!["kerberos_sync".into(), "kerberosSync".into()],
                ..A::generated(KERBEROS_SYNC, Integer)
            },
            AttributeSchema {
                aliases: vec!["krb_principal_name".into(), "krbPrincipalName".into()],
                ..A::hidden("krbprincipalname", String)
            },
            // SSH
            AttributeSchema {
                aliases: vec![
                    "sshPublicKey".into(),
                    "ssHPublicKey".into(),
                    "ssh_public_key".into(),
                ],
                ..A::editable("sshpublickey", String).list()
            },
            // OU
            AttributeSchema {
                aliases: vec!["organizationalunit".into(), "organizationalUnit".into()],
                ..A::readonly("ou", String)
            },
        ];

        let group_attributes = vec![
            // Core
            AttributeSchema {
                aliases: vec!["group_id".into()],
                ..A::readonly("groupid", Integer)
            },
            AttributeSchema {
                aliases: vec!["creation_date".into(), "createTimestamp".into()],
                ..A::readonly("creationdate", DateTime)
            },
            AttributeSchema {
                aliases: vec!["modified_date".into(), "modifyTimestamp".into()],
                ..A::readonly("modifieddate", DateTime)
            },
            AttributeSchema {
                aliases: vec!["entryUUID".into(), "entryuuid".into()],
                ..A::readonly("uuid", String)
            },
            AttributeSchema {
                aliases: vec!["display_name".into(), "cn".into(), "commonname".into()],
                ..A::editable("displayname", String)
            },
            // OU
            AttributeSchema {
                aliases: vec!["organizationalunit".into(), "organizationalUnit".into()],
                ..A::readonly("ou", String)
            },
            // POSIX
            AttributeSchema {
                aliases: vec!["gid_number".into(), "gidNumber".into()],
                ..A::generated("gidnumber", Integer)
            },
        ];

        let system_attributes = vec![
            // Access control
            AttributeSchema {
                aliases: vec!["allowedOUs".into(), "AllowedOUs".into()],
                ..A::hidden("allowedous", String).list()
            },
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
