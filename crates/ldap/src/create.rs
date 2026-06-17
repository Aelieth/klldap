// crates/ldap/src/create.rs
// LDAP ADD for users/groups → our clean EAV backend
// Uses the new attributes.rs + SchemaManager pipeline for canonical name handling
use crate::{
    core::{
        error::{LdapError, LdapResult},
        utils::LdapInfo,
    },
    dn::{
        UserOrGroupName, get_internal_ou_from_dn_parts,
        get_user_or_group_id_from_distinguished_name, parse_distinguished_name,
    },
    handler::make_add_response,
};
use ldap3_proto::proto::{
    LdapAddRequest, LdapAttribute, LdapOp, LdapPartialAttribute, LdapResultCode,
};
use lldap_access_control::AdminBackendHandler;
use lldap_domain::{
    deserialize,
    requests::{CreateGroupRequest, CreateUserRequest},
    types::{Attribute, AttributeType, Email, GroupName, UserId},
};
use std::collections::HashMap;
use tracing::instrument;

#[instrument(skip_all, level = "debug")]
pub(crate) async fn create_user_or_group(
    backend_handler: &impl AdminBackendHandler,
    ldap_info: &LdapInfo,
    request: LdapAddRequest,
) -> LdapResult<Vec<LdapOp>> {
    let base_dn_str = &ldap_info.base_dn_str;
    let dn_parts = parse_distinguished_name(&request.dn)?;
    let internal_ou = get_internal_ou_from_dn_parts(&dn_parts);
    match get_user_or_group_id_from_distinguished_name(&request.dn, &ldap_info.base_dn) {
        UserOrGroupName::User(user_id) => {
            create_user(backend_handler, user_id, request.attributes, internal_ou).await
        }
        UserOrGroupName::Group(group_name) => {
            create_group(backend_handler, group_name, request.attributes, internal_ou).await
        }
        err => Err(err.into_ldap_error(
            &request.dn,
            format!(r#""uid=id,ou=people,{base_dn_str}" or "cn=id,ou=groups,{base_dn_str}""#),
        )),
    }
}

#[instrument(skip_all, level = "debug")]
async fn create_user(
    backend_handler: &impl AdminBackendHandler,
    user_id: UserId,
    attributes: Vec<LdapAttribute>,
    internal_ou: String,
) -> LdapResult<Vec<LdapOp>> {
    fn parse_attribute(mut attr: LdapPartialAttribute) -> LdapResult<(String, Vec<u8>)> {
        if attr.vals.len() > 1 {
            Err(LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!("Expected a single value for attribute {}", attr.atype),
            })
        } else {
            attr.atype.make_ascii_lowercase();
            match attr.vals.pop() {
                Some(val) => Ok((attr.atype, val)),
                None => Err(LdapError {
                    code: LdapResultCode::ConstraintViolation,
                    message: format!("Missing value for attribute {}", attr.atype),
                }),
            }
        }
    }

    let mut attributes: HashMap<String, Vec<u8>> = attributes
        .into_iter()
        .filter(|a| !a.atype.eq_ignore_ascii_case("objectclass"))
        .map(parse_attribute)
        .collect::<LdapResult<_>>()?;

    // Default kerberossync = 0 if not provided (matches PublicSchema)
    if !attributes.contains_key("kerberossync") {
        attributes.insert("kerberossync".to_string(), b"0".to_vec());
    }

    // Set/override ou from DN (full internal form, e.g. "service" or "office\\floor1")
    // This ensures custom OU hierarchy is persisted for bind/search DN construction.
    attributes.insert("ou".to_string(), internal_ou.clone().into_bytes());

    let get_attribute = |name: &str| {
        attributes.get(name).map(Vec::as_slice).map(|v| {
            std::str::from_utf8(v)
                .map(str::to_owned)
                .map_err(|e| LdapError {
                    code: LdapResultCode::ConstraintViolation,
                    message: format!("Attribute value is invalid UTF-8: {e:#?}"),
                })
        })
    };

    let mut new_user_attributes: Vec<Attribute> = Vec::new();

    // Map standard POSIX attributes
    if let Some(first_name) = get_attribute("givenname").transpose()? {
        new_user_attributes.push(Attribute {
            name: "first_name".into(),
            value: deserialize::deserialize_attribute_value(
                &[first_name],
                AttributeType::String,
                false,
            )
            .map_err(|e| LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!("Invalid first_name value: {e}"),
            })?,
        });
    }
    if let Some(last_name) = get_attribute("sn").transpose()? {
        new_user_attributes.push(Attribute {
            name: "last_name".into(),
            value: deserialize::deserialize_attribute_value(
                &[last_name],
                AttributeType::String,
                false,
            )
            .map_err(|e| LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!("Invalid last_name value: {e}"),
            })?,
        });
    }
    if let Some(avatar) = get_attribute("avatar")
        .or_else(|| get_attribute("jpegphoto"))
        .transpose()?
    {
        new_user_attributes.push(Attribute {
            name: "avatar".into(),
            value: deserialize::deserialize_attribute_value(
                &[avatar],
                AttributeType::Avatar,
                false,
            ) // ← TOTAL RIP-OUT: was JpegPhoto
            .map_err(|e| LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!("Invalid avatar value: {e}"),
            })?,
        });
    }

    // Always push ou (from DN) into custom attributes so backend stores the hierarchy value.
    // get_user_ou() will then return it for correct EntryDn in search results.
    new_user_attributes.push(Attribute {
        name: "ou".into(),
        value: deserialize::deserialize_attribute_value(
            std::slice::from_ref(&internal_ou),
            AttributeType::String,
            false,
        )
        .map_err(|e| LdapError {
            code: LdapResultCode::ConstraintViolation,
            message: format!("Invalid ou value: {e}"),
        })?,
    });

    // kerberossync handling (respect client-provided value, default to 0 only if missing)
    let kerberossync_enabled = if let Some(ksync_str) = get_attribute("kerberossync").transpose()? {
        new_user_attributes.push(Attribute {
            name: "kerberossync".into(),
            value: deserialize::deserialize_attribute_value(
                std::slice::from_ref(&ksync_str),
                AttributeType::Integer,
                false,
            )
            .map_err(|e| LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!("Invalid kerberossync value: {e}"),
            })?,
        });
        ksync_str == "1"
    } else {
        new_user_attributes.push(Attribute {
            name: "kerberossync".into(),
            value: deserialize::deserialize_attribute_value(
                &["0".to_string()],
                AttributeType::Integer,
                false,
            )
            .map_err(|e| LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!("Invalid default kerberossync value: {e}"),
            })?,
        });
        false
    };

    backend_handler
        .create_user(CreateUserRequest {
            user_id: user_id.clone(),
            email: Email::from(
                get_attribute("mail")
                    .or_else(|| get_attribute("email"))
                    .transpose()?
                    .unwrap_or_default(),
            ),
            display_name: get_attribute("cn").transpose()?,
            attributes: new_user_attributes,
        })
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Could not create user: {e:#?}"),
        })?;

    // Fire Kerberos sync on create if kerberossync=1 and password was supplied
    if kerberossync_enabled
        && let Some(pw_bytes) = attributes
            .get("userpassword")
            .or_else(|| attributes.get("userPassword"))
        && let Ok(plain) = std::str::from_utf8(pw_bytes)
    {
        let _ = lldap_kerberos::sync_kerberos_principal(user_id.as_str(), plain);
    }

    Ok(vec![make_add_response(
        LdapResultCode::Success,
        String::new(),
    )])
}

#[instrument(skip_all, level = "debug")]
async fn create_group(
    backend_handler: &impl AdminBackendHandler,
    group_name: GroupName,
    _attributes: Vec<LdapAttribute>,
    internal_ou: String,
) -> LdapResult<Vec<LdapOp>> {
    let mut group_attributes: Vec<Attribute> = Vec::new();
    group_attributes.push(Attribute {
        name: "ou".into(),
        value: deserialize::deserialize_attribute_value(
            std::slice::from_ref(&internal_ou),
            AttributeType::String,
            false,
        )
        .map_err(|e| LdapError {
            code: LdapResultCode::ConstraintViolation,
            message: format!("Invalid ou value: {e}"),
        })?,
    });
    backend_handler
        .create_group(CreateGroupRequest {
            display_name: group_name,
            attributes: group_attributes,
        })
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Could not create group: {e:#?}"),
        })?;
    Ok(vec![make_add_response(
        LdapResultCode::Success,
        String::new(),
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::tests::setup_bound_admin_handler;
    use lldap_domain::{deserialize, types::*};
    use lldap_test_utils::MockTestBackendHandler;
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_create_user() {
        let mut mock = MockTestBackendHandler::new();

        mock.expect_create_user()
            .with(mockall::predicate::function(|req: &CreateUserRequest| {
                req.user_id == UserId::new("bob")
                    && req.email == Email::from("")
                    && req.display_name == Some("Bob".to_string())
                    && req.attributes.iter().any(|a| a.name.as_str() == "ou")
                    && req
                        .attributes
                        .iter()
                        .any(|a| a.name.as_str() == "kerberossync")
            }))
            .times(1)
            .return_once(|_| Ok(()));

        let ldap_handler = setup_bound_admin_handler(mock).await;

        let request = LdapAddRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_owned(),
            attributes: vec![LdapPartialAttribute {
                atype: "cn".to_owned(),
                vals: vec![b"Bob".to_vec()],
            }],
        };

        assert_eq!(
            ldap_handler.create_user_or_group(request).await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }

    #[tokio::test]
    async fn test_create_group() {
        let mut mock = MockTestBackendHandler::new();
        let ou_attr = Attribute {
            name: "ou".into(),
            value: deserialize::deserialize_attribute_value(
                &["groups".to_string()],
                AttributeType::String,
                false,
            )
            .expect("valid ou for test"),
        };
        mock.expect_create_group()
            .with(eq(CreateGroupRequest {
                display_name: GroupName::new("bob"),
                attributes: vec![ou_attr],
                ..Default::default()
            }))
            .times(1)
            .return_once(|_| Ok(GroupId(5)));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapAddRequest {
            dn: "cn=bob,ou=groups,dc=example,dc=com".to_owned(),
            attributes: vec![LdapPartialAttribute {
                atype: "cn".to_owned(),
                vals: vec![b"Bobby".to_vec()],
            }],
        };
        assert_eq!(
            ldap_handler.create_user_or_group(request).await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }

    #[tokio::test]
    async fn test_create_user_multiple_object_class() {
        let mut mock = MockTestBackendHandler::new();

        mock.expect_create_user()
            .with(mockall::predicate::function(|req: &CreateUserRequest| {
                req.user_id == UserId::new("bob")
                    && req.email == Email::from("")
                    && req.display_name == Some("Bob".to_string())
                    && req.attributes.iter().any(|a| a.name.as_str() == "ou")
                    && req
                        .attributes
                        .iter()
                        .any(|a| a.name.as_str() == "kerberossync")
            }))
            .times(1)
            .return_once(|_| Ok(()));

        let ldap_handler = setup_bound_admin_handler(mock).await;

        let request = LdapAddRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_owned(),
            attributes: vec![
                LdapPartialAttribute {
                    atype: "cn".to_owned(),
                    vals: vec![b"Bob".to_vec()],
                },
                LdapPartialAttribute {
                    atype: "objectClass".to_owned(),
                    vals: vec![
                        b"top".to_vec(),
                        b"person".to_vec(),
                        b"inetOrgPerson".to_vec(),
                    ],
                },
            ],
        };

        assert_eq!(
            ldap_handler.create_user_or_group(request).await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }
}
