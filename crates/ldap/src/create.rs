use crate::{
    core::{
        error::{LdapError, LdapResult},
        utils::{LdapInfo, typed_attribute},
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
    requests::{CreateGroupRequest, CreateUserRequest},
    types::{Attribute, AttributeType, Email, GroupName, UserId},
};
use lldap_domain_handlers::kerberos::kerberos_backend;
use lldap_schema::{AttributeList, KERBEROS_SYNC, PublicSchema};
use std::collections::HashMap;
use tracing::{instrument, warn};

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

fn constraint_violation(message: String) -> LdapError {
    LdapError {
        code: LdapResultCode::ConstraintViolation,
        message,
    }
}

fn single_value(mut attribute: LdapPartialAttribute) -> LdapResult<(String, Vec<u8>)> {
    if attribute.vals.len() > 1 {
        return Err(constraint_violation(format!(
            "Expected a single value for attribute {}",
            attribute.atype
        )));
    }
    attribute.atype.make_ascii_lowercase();
    match attribute.vals.pop() {
        Some(value) => Ok((attribute.atype, value)),
        None => Err(constraint_violation(format!(
            "Missing value for attribute {}",
            attribute.atype
        ))),
    }
}

fn parse_attributes(attributes: Vec<LdapAttribute>) -> LdapResult<HashMap<String, Vec<u8>>> {
    attributes
        .into_iter()
        .filter(|a| !a.atype.eq_ignore_ascii_case("objectclass"))
        .map(single_value)
        .collect()
}

fn utf8_value(name: &str, value: &[u8]) -> LdapResult<String> {
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|e| constraint_violation(format!("Attribute {name} is not valid UTF-8: {e}")))
}

// Attributes the schema knows and lets clients write persist; readonly and unknown names are
// skipped with a warning. The live schema is only read when something is left to place.
async fn schema_attributes(
    backend_handler: &impl AdminBackendHandler,
    attributes: &HashMap<String, Vec<u8>>,
    consumed: &[&str],
    list: fn(&PublicSchema) -> &AttributeList,
) -> LdapResult<Vec<Attribute>> {
    let leftovers: Vec<&String> = attributes
        .keys()
        .filter(|name| {
            let canonical = list(PublicSchema::shared())
                .resolve_canonical_name(name)
                .unwrap_or(name.as_str());
            !consumed.contains(&canonical)
        })
        .collect();
    if leftovers.is_empty() {
        return Ok(Vec::new());
    }
    let schema = backend_handler.get_schema().await.map_err(|e| LdapError {
        code: LdapResultCode::OperationsError,
        message: format!("Could not read the schema: {e:#?}"),
    })?;
    let mut result = Vec::new();
    for name in leftovers {
        let Some(attribute_schema) = list(&schema).get_by_name_or_alias(name) else {
            warn!("LDAP add: ignoring attribute {name} (not in the schema)");
            continue;
        };
        if attribute_schema.is_readonly {
            warn!("LDAP add: ignoring read-only attribute {name}");
            continue;
        }
        let Ok(value) = std::str::from_utf8(&attributes[name]) else {
            warn!("LDAP add: ignoring attribute {name} (value is not valid UTF-8)");
            continue;
        };
        result.push(typed_attribute(
            &attribute_schema.name,
            &[value.to_owned()],
            attribute_schema.attribute_type,
            attribute_schema.is_list,
        )?);
    }
    Ok(result)
}

#[instrument(skip_all, level = "debug")]
async fn create_user(
    backend_handler: &impl AdminBackendHandler,
    user_id: UserId,
    attributes: Vec<LdapAttribute>,
    internal_ou: String,
) -> LdapResult<Vec<LdapOp>> {
    let mut attributes = parse_attributes(attributes)?;
    // kerberossync defaults to 0, matching PublicSchema; the OU comes from the DN in full
    // internal form so bind and search rebuild the same DN.
    attributes
        .entry(KERBEROS_SYNC.to_string())
        .or_insert_with(|| b"0".to_vec());
    attributes.insert("ou".to_string(), internal_ou.into_bytes());
    let text = |name: &str| {
        attributes
            .get(name)
            .map(|v| utf8_value(name, v))
            .transpose()
    };

    let mut new_user_attributes = Vec::new();
    if let Some(first_name) = text("givenname")? {
        new_user_attributes.push(typed_attribute(
            "first_name",
            &[first_name],
            AttributeType::String,
            false,
        )?);
    }
    if let Some(last_name) = text("sn")? {
        new_user_attributes.push(typed_attribute(
            "last_name",
            &[last_name],
            AttributeType::String,
            false,
        )?);
    }
    if let Some(avatar) = text("avatar")?.or(text("jpegphoto")?) {
        new_user_attributes.push(typed_attribute(
            "avatar",
            &[avatar],
            AttributeType::Avatar,
            false,
        )?);
    }
    for name in ["ou", KERBEROS_SYNC] {
        let attribute_type = PublicSchema::shared()
            .user_attributes()
            .get_by_name_or_alias(name)
            .map(|a| a.attribute_type)
            .unwrap_or(AttributeType::String);
        if let Some(value) = text(name)? {
            new_user_attributes.push(typed_attribute(name, &[value], attribute_type, false)?);
        }
    }
    let consumed = [
        "userid",
        "mail",
        "displayname",
        "firstname",
        "lastname",
        "avatar",
        "ou",
        KERBEROS_SYNC,
        "userpassword",
    ];
    new_user_attributes.extend(
        schema_attributes(
            backend_handler,
            &attributes,
            &consumed,
            PublicSchema::user_attributes,
        )
        .await?,
    );

    let kerberossync_enabled = lldap_domain::types::kerberos_sync_enabled(&new_user_attributes);
    backend_handler
        .create_user(CreateUserRequest {
            user_id: user_id.clone(),
            email: Email::from(text("mail")?.or(text("email")?).unwrap_or_default()),
            display_name: text("cn")?,
            attributes: new_user_attributes,
        })
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Could not create user: {e:#?}"),
        })?;

    if kerberossync_enabled
        && let Some(password) = attributes.get("userpassword")
        && let Ok(plain) = std::str::from_utf8(password)
    {
        match kerberos_backend().sync_principal(user_id.as_str(), plain) {
            Ok(()) => {
                if let Err(e) = backend_handler
                    .ensure_kerberos_principal_consistency(&user_id, true)
                    .await
                {
                    warn!("Failed to record Kerberos principal name for {user_id}: {e}");
                }
            }
            Err(e) => warn!("Kerberos principal sync failed after LDAP user create: {e}"),
        }
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
    attributes: Vec<LdapAttribute>,
    internal_ou: String,
) -> LdapResult<Vec<LdapOp>> {
    let attributes = parse_attributes(attributes)?;
    let mut group_attributes = vec![typed_attribute(
        "ou",
        &[internal_ou],
        AttributeType::String,
        false,
    )?];
    group_attributes.extend(
        schema_attributes(
            backend_handler,
            &attributes,
            &["displayname", "ou"],
            PublicSchema::group_attributes,
        )
        .await?,
    );
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
    use lldap_test_utils::recording_kerberos::{KerberosOp, RecordingGuard};
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use serial_test::serial;

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
    async fn test_create_user_persists_schema_known_extra_attributes() {
        let mut mock = MockTestBackendHandler::new();

        mock.expect_get_schema().times(1).returning(|| {
            let mut schema = PublicSchema::get();
            schema
                .0
                .user_attributes
                .attributes
                .push(lldap_schema::AttributeSchema {
                    name: "gatecustom".to_owned(),
                    aliases: vec![],
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: true,
                    is_hardcoded: false,
                    is_readonly: false,
                });
            Ok(schema)
        });
        mock.expect_create_user()
            .with(mockall::predicate::function(|req: &CreateUserRequest| {
                let value_of = |n: &str| {
                    req.attributes
                        .iter()
                        .find(|a| a.name.as_str() == n)
                        .map(|a| a.value.clone())
                };
                value_of("gatecustom")
                    == Some(AttributeValue::String(Cardinality::Singleton(
                        "brought by ldapadd".to_owned(),
                    )))
                    && value_of("sshpublickey").is_some()
                    && value_of("uidnumber")
                        == Some(AttributeValue::Integer(Cardinality::Singleton(4242)))
                    && value_of("creationdate").is_none()
                    && value_of("junkattr").is_none()
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
                    atype: "gatecustom".to_owned(),
                    vals: vec![b"brought by ldapadd".to_vec()],
                },
                LdapPartialAttribute {
                    atype: "sshPublicKey".to_owned(),
                    vals: vec![b"ssh-rsa AAAATestKey gate@test".to_vec()],
                },
                LdapPartialAttribute {
                    atype: "uidNumber".to_owned(),
                    vals: vec![b"4242".to_vec()],
                },
                LdapPartialAttribute {
                    atype: "createTimestamp".to_owned(),
                    vals: vec![b"20200101000000Z".to_vec()],
                },
                LdapPartialAttribute {
                    atype: "junkattr".to_owned(),
                    vals: vec![b"dropped with a warning".to_vec()],
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
    async fn test_create_group_persists_schema_known_attributes() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema()
            .times(1)
            .returning(|| Ok(PublicSchema::get()));
        mock.expect_create_group()
            .with(eq(CreateGroupRequest {
                display_name: GroupName::new("builders"),
                attributes: vec![
                    Attribute {
                        name: "ou".into(),
                        value: "groups".to_string().into(),
                    },
                    Attribute {
                        name: "gidnumber".into(),
                        value: 4242i64.into(),
                    },
                ],
            }))
            .times(1)
            .return_once(|_| Ok(GroupId(5)));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapAddRequest {
            dn: "cn=builders,ou=groups,dc=example,dc=com".to_owned(),
            attributes: vec![
                LdapPartialAttribute {
                    atype: "objectClass".to_owned(),
                    vals: vec![b"posixGroup".to_vec()],
                },
                LdapPartialAttribute {
                    atype: "gidNumber".to_owned(),
                    vals: vec![b"4242".to_vec()],
                },
                LdapPartialAttribute {
                    atype: "member".to_owned(),
                    vals: vec![b"uid=bob,ou=people,dc=example,dc=com".to_vec()],
                },
                LdapPartialAttribute {
                    atype: "creationDate".to_owned(),
                    vals: vec![b"20260101000000Z".to_vec()],
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

    fn add_user_request(extra: Vec<LdapPartialAttribute>) -> LdapAddRequest {
        let mut attributes = vec![LdapPartialAttribute {
            atype: "cn".to_owned(),
            vals: vec![b"Bob".to_vec()],
        }];
        attributes.extend(extra);
        LdapAddRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_owned(),
            attributes,
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_create_user_with_password_syncs() {
        let guard = RecordingGuard::install();
        let mut mock = MockTestBackendHandler::new();
        mock.expect_create_user().times(1).return_once(|_| Ok(()));
        mock.expect_ensure_kerberos_principal_consistency()
            .with(eq(UserId::new("bob")), eq(true))
            .times(1)
            .return_once(|_, _| Ok(()));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler
                .create_user_or_group(add_user_request(vec![
                    LdapPartialAttribute {
                        atype: "kerberossync".to_owned(),
                        vals: vec![b"1".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "userPassword".to_owned(),
                        vals: vec![b"s3cret".to_vec()],
                    },
                ]))
                .await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
        assert_eq!(
            guard.recorder().take_ops(),
            vec![KerberosOp::SyncPrincipal {
                username: "bob".into(),
                password: "s3cret".into(),
            }]
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_create_user_without_sync_skips_principal() {
        let guard = RecordingGuard::install();
        let mut mock = MockTestBackendHandler::new();
        mock.expect_create_user().times(1).return_once(|_| Ok(()));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler
                .create_user_or_group(add_user_request(vec![LdapPartialAttribute {
                    atype: "userPassword".to_owned(),
                    vals: vec![b"s3cret".to_vec()],
                }]))
                .await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
        assert!(guard.recorder().take_ops().is_empty());
    }

    #[tokio::test]
    #[serial]
    async fn test_create_user_sync_without_password_skips_principal() {
        let guard = RecordingGuard::install();
        let mut mock = MockTestBackendHandler::new();
        mock.expect_create_user().times(1).return_once(|_| Ok(()));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler
                .create_user_or_group(add_user_request(vec![LdapPartialAttribute {
                    atype: "kerberossync".to_owned(),
                    vals: vec![b"1".to_vec()],
                }]))
                .await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
        assert!(guard.recorder().take_ops().is_empty());
    }
}
