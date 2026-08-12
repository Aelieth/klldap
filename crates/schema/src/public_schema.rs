use crate::schema::{AttributeList, AttributeSchema, AttributeType, PosixSettings, Schema};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

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
        PublicSchema(Schema {
            user_attributes: AttributeList {
                attributes: vec![
                    // ==================== CORE LLDAP ATTRIBUTES ====================
                    AttributeSchema {
                        name: "avatar".into(),
                        aliases: vec!["jpegphoto".into(), "jpegPhoto".into()],
                        attribute_type: AttributeType::Avatar,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "creationdate".into(),
                        aliases: vec!["creation_date".into(), "createTimestamp".into()],
                        attribute_type: AttributeType::DateTime,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                    AttributeSchema {
                        name: "displayname".into(),
                        aliases: vec!["display_name".into(), "cn".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "firstname".into(),
                        aliases: vec!["first_name".into(), "givenName".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "lastname".into(),
                        aliases: vec!["last_name".into(), "sn".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "mail".into(),
                        aliases: vec!["email".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "modifieddate".into(),
                        aliases: vec!["modified_date".into(), "modifyTimestamp".into()],
                        attribute_type: AttributeType::DateTime,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                    AttributeSchema {
                        name: "passwordmodifieddate".into(),
                        aliases: vec!["password_modified_date".into(), "pwdChangedTime".into()],
                        attribute_type: AttributeType::DateTime,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                    AttributeSchema {
                        name: "userid".into(),
                        aliases: vec!["user_id".into(), "uid".into(), "id".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                    AttributeSchema {
                        name: "uuid".into(),
                        aliases: vec!["entryuuid".into(), "entryUUID".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                    // POSIX, Kerberos, SSH, ou (still visible on users/groups)
                    AttributeSchema {
                        name: "uidnumber".into(),
                        aliases: vec!["uid_number".into(), "uidNumber".into()],
                        attribute_type: AttributeType::Integer,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "gidnumber".into(),
                        aliases: vec!["gid_number".into(), "gidNumber".into()],
                        attribute_type: AttributeType::Integer,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "homedirectory".into(),
                        aliases: vec!["home_directory".into(), "homeDirectory".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "loginshell".into(),
                        aliases: vec!["login_shell".into(), "loginShell".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "kerberossync".into(),
                        aliases: vec!["kerberos_sync".into(), "kerberosSync".into()],
                        attribute_type: AttributeType::Integer,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "krbprincipalname".into(),
                        aliases: vec!["krb_principal_name".into(), "krbPrincipalName".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: false,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                    AttributeSchema {
                        name: "sshpublickey".into(),
                        aliases: vec!["sshPublicKey".into(), "ssHPublicKey".into()],
                        attribute_type: AttributeType::String,
                        is_list: true,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "ou".into(),
                        aliases: vec!["organizationalunit".into(), "organizationalUnit".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                ],
            },
            group_attributes: AttributeList {
                attributes: vec![
                    AttributeSchema {
                        name: "groupid".into(),
                        aliases: vec!["group_id".into()],
                        attribute_type: AttributeType::Integer,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                    AttributeSchema {
                        name: "creationdate".into(),
                        aliases: vec!["creation_date".into(), "createTimestamp".into()],
                        attribute_type: AttributeType::DateTime,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                    AttributeSchema {
                        name: "modifieddate".into(),
                        aliases: vec!["modified_date".into(), "modifyTimestamp".into()],
                        attribute_type: AttributeType::DateTime,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                    AttributeSchema {
                        name: "uuid".into(),
                        aliases: vec!["entryuuid".into(), "entryUUID".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                    AttributeSchema {
                        name: "displayname".into(),
                        aliases: vec!["display_name".into(), "cn".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "ou".into(),
                        aliases: vec!["organizationalunit".into(), "organizationalUnit".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                    // POSIX
                    AttributeSchema {
                        name: "gidnumber".into(),
                        aliases: vec!["gid_number".into(), "gidNumber".into()],
                        attribute_type: AttributeType::Integer,
                        is_list: false,
                        is_visible: true,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                ],
            },
            // ==================== SYSTEM ATTRIBUTES ====================
            system_attributes: AttributeList {
                attributes: vec![AttributeSchema {
                    name: "allowedous".into(),
                    aliases: vec!["allowedOUs".into(), "AllowedOUs".into()],
                    attribute_type: AttributeType::String,
                    is_list: true,
                    is_visible: false,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                }],
            },
            // === Full POSIX settings  ===
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
