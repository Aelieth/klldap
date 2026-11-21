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
    password::password_change_error,
};
use ldap3_proto::proto::{
    LdapAddRequest, LdapAttribute, LdapOp, LdapPartialAttribute, LdapResultCode,
};
use lldap_access_control::AdminBackendHandler;
use lldap_domain::{
    requests::{CreateGroupRequest, CreateUserRequest},
    types::{Attribute, AttributeType, Email, GroupName, UserId},
};
use lldap_domain_handlers::kerberos::{KerberosState, settled_state};
use lldap_domain_handlers::logging::LogKind;
use lldap_domain_handlers::password::{
    PASSWORD_MIN_LENGTH, PasswordSync, change_password_everywhere, create_synced_user,
    min_length_in_ou, password_rules, realm_not_ready, record_failed,
};
use lldap_schema::{AttributeList, KERBEROS_SYNC, PublicSchema};
use std::collections::HashMap;
use tracing::{instrument, warn};
use zeroize::Zeroizing;

#[instrument(skip_all, level = "debug")]
pub(crate) async fn create_user_or_group(
    backend_handler: &impl AdminBackendHandler,
    ldap_info: &LdapInfo,
    request: &mut LdapAddRequest,
) -> LdapResult<Vec<LdapOp>> {
    let password = take_password(&mut request.attributes);
    let attributes = std::mem::take(&mut request.attributes);
    let base_dn_str = &ldap_info.base_dn_str;
    let dn_parts = parse_distinguished_name(&request.dn)?;
    let internal_ou = get_internal_ou_from_dn_parts(&dn_parts);
    match get_user_or_group_id_from_distinguished_name(&request.dn, &ldap_info.base_dn) {
        UserOrGroupName::User(user_id) => {
            create_user(backend_handler, user_id, attributes, password, internal_ou).await
        }
        UserOrGroupName::Group(group_name) => {
            create_group(
                backend_handler,
                group_name,
                attributes,
                password,
                internal_ou,
            )
            .await
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

type Taken = Vec<(String, Zeroizing<Vec<Vec<u8>>>)>;

/// Every `userPassword` attribute, out of the request before anything reads it; wiped on drop.
fn take_password(attributes: &mut Vec<LdapAttribute>) -> Taken {
    let mut taken = Vec::new();
    attributes.retain_mut(|a| {
        let password = a.atype.eq_ignore_ascii_case("userpassword");
        if password {
            let vals = Zeroizing::new(std::mem::take(&mut a.vals));
            taken.push((std::mem::take(&mut a.atype), vals));
        }
        !password
    });
    taken
}

fn one_password(taken: Taken) -> LdapResult<Option<Zeroizing<Vec<u8>>>> {
    let mut password = None;
    for (atype, mut vals) in taken {
        if vals.len() > 1 {
            return Err(constraint_violation(format!(
                "Expected a single value for attribute {atype}"
            )));
        }
        let missing = format!("Missing value for attribute {}", atype.to_ascii_lowercase());
        password = Some(Zeroizing::new(
            vals.pop().ok_or_else(|| constraint_violation(missing))?,
        ));
    }
    Ok(password)
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
    password: Taken,
    internal_ou: String,
) -> LdapResult<Vec<LdapOp>> {
    let password = one_password(password)?;
    let mut attributes = parse_attributes(attributes)?;
    // kerberossync defaults to 0, matching PublicSchema; the OU comes from the DN in full
    // internal form so bind and search rebuild the same DN.
    attributes
        .entry(KERBEROS_SYNC.to_string())
        .or_insert_with(|| b"0".to_vec());
    attributes.insert("ou".to_string(), internal_ou.as_bytes().to_vec());
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
    let plain_password = password
        .as_deref()
        .map(|bytes| std::str::from_utf8(bytes.as_slice()))
        .transpose()
        .map_err(|_| constraint_violation("userPassword must be valid UTF-8".to_string()))?;
    let request = CreateUserRequest {
        user_id: user_id.clone(),
        email: Email::from(text("mail")?.or(text("email")?).unwrap_or_default()),
        display_name: text("cn")?,
        attributes: new_user_attributes,
    };
    let min = match plain_password {
        Some(_) => min_length_in_ou(backend_handler, &internal_ou, &user_id, LogKind::UserCreate)
            .await
            .map_err(password_change_error)?,
        None => PASSWORD_MIN_LENGTH,
    };
    if let Some(plain) = plain_password
        && kerberossync_enabled
    {
        if backend_handler.get_user_details(&user_id).await.is_ok() {
            return Err(LdapError {
                code: LdapResultCode::OperationsError,
                message: format!("Could not create user: {user_id} already exists"),
            });
        }
        create_synced_user(backend_handler, request, plain, min)
            .await
            .map_err(|e| {
                warn!("LDAP Add of {user_id} failed: {e}");
                password_change_error(e)
            })?;
        return Ok(vec![make_add_response(
            LdapResultCode::Success,
            String::new(),
        )]);
    }
    if plain_password.is_some()
        && let KerberosState::NotReady(cause) = settled_state()
    {
        let refused = realm_not_ready(&cause);
        record_failed(LogKind::UserCreate, &user_id, &refused);
        return Err(password_change_error(refused));
    }
    if let Some(Err(e)) = plain_password.map(|plain| password_rules(plain, min)) {
        record_failed(LogKind::UserCreate, &user_id, &e);
        return Err(password_change_error(e));
    }
    backend_handler
        .create_user(request)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Could not create user: {e:#?}"),
        })?;

    if let Some(plain) = plain_password {
        change_password_everywhere(backend_handler, &user_id, plain, PasswordSync::Off, min)
            .await
            .map_err(|e| LdapError {
                code: LdapResultCode::Other,
                message: format!("Error while setting the password: {e}"),
            })?;
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
    password: Taken,
    internal_ou: String,
) -> LdapResult<Vec<LdapOp>> {
    let ignored = one_password(password)?.is_some();
    let attributes = parse_attributes(attributes)?;
    if ignored {
        warn!("LDAP add: ignoring attribute userpassword (not in the schema)");
    }
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
    use crate::handler::LdapHandler;
    use crate::handler::tests::{setup_bound_admin_handler, setup_bound_handler_with_group};
    use crate::password::tests::{
        expect_password_registration, expect_registration_start, install, kdc_rows,
    };
    use lldap_domain::{deserialize, types::*};
    use lldap_domain_model::error::DomainError;
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

        let mut request = LdapAddRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_owned(),
            attributes: vec![LdapPartialAttribute {
                atype: "cn".to_owned(),
                vals: vec![b"Bob".to_vec()],
            }],
        };

        assert_eq!(
            ldap_handler.create_user_or_group(&mut request).await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }

    #[tokio::test]
    async fn test_create_user_rejects_non_utf8_password() {
        let mock = MockTestBackendHandler::new();
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let mut request = LdapAddRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_owned(),
            attributes: vec![LdapPartialAttribute {
                atype: "userPassword".to_owned(),
                vals: vec![vec![0xff, 0xfe]],
            }],
        };
        assert_eq!(
            ldap_handler.create_user_or_group(&mut request).await,
            Err(LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: "userPassword must be valid UTF-8".to_string(),
            })
        );
    }

    #[test]
    fn test_the_password_leaves_the_add_request_before_any_other_attribute() {
        let attribute = |atype: &str, vals: &[&str]| LdapPartialAttribute {
            atype: atype.to_owned(),
            vals: vals.iter().map(|v| v.as_bytes().to_vec()).collect(),
        };
        type Row = (
            &'static str,
            Vec<LdapPartialAttribute>,
            Result<Option<&'static str>, &'static str>,
        );
        let rows: [Row; 5] = [
            ("no password", vec![], Ok(None)),
            (
                "one value",
                vec![attribute("userPassword", &["s3cret"])],
                Ok(Some("s3cret")),
            ),
            (
                "the last of two attributes",
                vec![
                    attribute("userpassword", &["first"]),
                    attribute("USERPASSWORD", &["last"]),
                ],
                Ok(Some("last")),
            ),
            (
                "two values",
                vec![attribute("userPassword", &["a", "b"])],
                Err("Expected a single value for attribute userPassword"),
            ),
            (
                "no value",
                vec![attribute("userPassword", &[])],
                Err("Missing value for attribute userpassword"),
            ),
        ];
        for (label, passwords, expected) in rows {
            let mut attributes = vec![attribute("cn", &["Bob"])];
            attributes.extend(passwords);
            let got = one_password(take_password(&mut attributes))
                .map(|p| p.map(|p| String::from_utf8_lossy(&p).into_owned()))
                .map_err(|e| e.message);
            let left: Vec<_> = attributes.iter().map(|a| a.atype.as_str()).collect();
            let expected = expected
                .map(|p| p.map(str::to_owned))
                .map_err(str::to_owned);
            assert_eq!((got, left), (expected, vec!["cn"]), "{label}");
        }
    }

    #[tokio::test]
    async fn test_an_add_reads_its_password_before_any_other_attribute() {
        let two = |atype: &str, a: &str, b: &str| LdapPartialAttribute {
            atype: atype.to_owned(),
            vals: vec![a.as_bytes().to_vec(), b.as_bytes().to_vec()],
        };
        for dn in [
            "uid=bob,ou=people,dc=example,dc=com",
            "cn=bob,ou=groups,dc=example,dc=com",
        ] {
            let ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
            let mut request = LdapAddRequest {
                dn: dn.to_owned(),
                attributes: vec![two("cn", "Bob", "Bobby"), two("userPassword", "a", "b")],
            };
            assert_eq!(
                ldap_handler.create_user_or_group(&mut request).await,
                Err(constraint_violation(
                    "Expected a single value for attribute userPassword".to_owned()
                )),
                "{dn}"
            );
        }
    }

    #[tokio::test]
    async fn test_the_password_bytes_of_an_add_are_zeroed_whichever_check_refuses_it() {
        let attribute = |atype: &str, vals: Vec<Vec<u8>>| LdapPartialAttribute {
            atype: atype.to_owned(),
            vals,
        };
        let answer = |code, message: &str| vec![make_add_response(code, message.to_owned())];
        let unauthorized = answer(
            LdapResultCode::InsufficentAccessRights,
            "Unauthorized write",
        );
        type Row = (
            &'static str,
            Option<&'static str>,
            LdapPartialAttribute,
            Vec<LdapOp>,
            Vec<LdapPartialAttribute>,
        );
        let rows: [Row; 3] = [
            (
                "unbound",
                None,
                attribute("userPassword", vec![b"s3cret".to_vec()]),
                unauthorized.clone(),
                vec![
                    attribute("cn", vec![b"Bob".to_vec()]),
                    attribute("userPassword", vec![vec![0; 6]]),
                ],
            ),
            (
                "not an admin",
                Some("regular"),
                attribute("USERPASSWORD", vec![b"s3cret".to_vec()]),
                unauthorized,
                vec![
                    attribute("cn", vec![b"Bob".to_vec()]),
                    attribute("USERPASSWORD", vec![vec![0; 6]]),
                ],
            ),
            (
                "an admin, two values",
                Some("lldap_admin"),
                attribute("userPassword", vec![b"one".to_vec(), b"two".to_vec()]),
                answer(
                    LdapResultCode::ConstraintViolation,
                    "Expected a single value for attribute userPassword",
                ),
                vec![],
            ),
        ];
        let pairs = |attributes: Vec<LdapPartialAttribute>| -> Vec<(String, Vec<Vec<u8>>)> {
            attributes.into_iter().map(|a| (a.atype, a.vals)).collect()
        };
        for (label, group, password, expected, left) in rows {
            let mock = MockTestBackendHandler::new();
            let ldap_handler = match group {
                Some(group) => setup_bound_handler_with_group(mock, group).await,
                None => LdapHandler::new_for_tests(mock, "dc=example,dc=com"),
            };
            let mut op = LdapOp::AddRequest(LdapAddRequest {
                dn: "uid=bob,ou=people,dc=example,dc=com".to_owned(),
                attributes: vec![attribute("cn", vec![b"Bob".to_vec()]), password],
            });
            let response = ldap_handler.answer_and_wipe(&mut op).await;
            let LdapOp::AddRequest(request) = op else {
                unreachable!()
            };
            assert_eq!(
                (response, pairs(request.attributes)),
                (expected, pairs(left)),
                "{label}"
            );
        }
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

        let mut request = LdapAddRequest {
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
            ldap_handler.create_user_or_group(&mut request).await,
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
        let mut request = LdapAddRequest {
            dn: "cn=bob,ou=groups,dc=example,dc=com".to_owned(),
            attributes: vec![LdapPartialAttribute {
                atype: "cn".to_owned(),
                vals: vec![b"Bobby".to_vec()],
            }],
        };
        assert_eq!(
            ldap_handler.create_user_or_group(&mut request).await,
            Ok(vec![make_add_response(
                LdapResultCode::Success,
                String::new()
            )])
        );
    }

    #[derive(Clone, Default)]
    struct Warnings(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    struct Message(String);

    impl tracing::field::Visit for Message {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }

    impl tracing::Subscriber for Warnings {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                let mut message = Message(String::new());
                event.record(&mut message);
                self.0.lock().unwrap().push(message.0);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[tokio::test]
    async fn test_a_group_add_with_a_password_warns_and_does_not_keep_it() {
        const WARNING: &str = "LDAP add: ignoring attribute userpassword (not in the schema)";
        type Row = (&'static str, &'static [&'static str], LdapResult<()>, usize);
        let rows: [Row; 3] = [
            ("one value", &["s3cret"], Ok(()), 1),
            (
                "two values",
                &["a", "b"],
                Err(constraint_violation(
                    "Expected a single value for attribute userPassword".to_owned(),
                )),
                0,
            ),
            (
                "no value",
                &[],
                Err(constraint_violation(
                    "Missing value for attribute userpassword".to_owned(),
                )),
                0,
            ),
        ];
        for (label, vals, expected, warned) in rows {
            let warnings = Warnings::default();
            let _default = tracing::subscriber::set_default(warnings.clone());
            let mut mock = MockTestBackendHandler::new();
            mock.expect_create_group()
                .with(eq(CreateGroupRequest {
                    display_name: GroupName::new("bob"),
                    attributes: vec![Attribute {
                        name: "ou".into(),
                        value: "groups".to_string().into(),
                    }],
                }))
                .times(usize::from(expected.is_ok()))
                .return_once(|_| Ok(GroupId(5)));
            let ldap_handler = setup_bound_admin_handler(mock).await;
            let mut request = LdapAddRequest {
                dn: "cn=bob,ou=groups,dc=example,dc=com".to_owned(),
                attributes: vec![LdapPartialAttribute {
                    atype: "userPassword".to_owned(),
                    vals: vals.iter().map(|v| v.as_bytes().to_vec()).collect(),
                }],
            };
            let expected =
                expected.map(|()| vec![make_add_response(LdapResultCode::Success, String::new())]);
            assert_eq!(
                ldap_handler.create_user_or_group(&mut request).await,
                expected,
                "{label}"
            );
            assert_eq!(
                warnings.0.lock().unwrap().clone(),
                vec![WARNING.to_owned(); warned],
                "{label}"
            );
        }
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
        let mut request = LdapAddRequest {
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
            ldap_handler.create_user_or_group(&mut request).await,
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

        let mut request = LdapAddRequest {
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
            ldap_handler.create_user_or_group(&mut request).await,
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

    fn add_rows(user: &str) -> Vec<String> {
        vec![
            format!("create {user}"),
            format!("password {user}"),
            format!("synced {user}"),
            "log user_create".to_owned(),
            "log password_change".to_owned(),
        ]
    }

    fn synced_with_password() -> Vec<LdapPartialAttribute> {
        vec![
            LdapPartialAttribute {
                atype: "kerberossync".to_owned(),
                vals: vec![b"1".to_vec()],
            },
            LdapPartialAttribute {
                atype: "userPassword".to_owned(),
                vals: vec![b"s3cret-pw".to_vec()],
            },
        ]
    }

    #[tokio::test]
    #[serial]
    async fn test_create_user_kerberos_matrix() {
        let guard = RecordingGuard::install();
        let cases = [
            ("kerberossync with a password", true, true),
            ("a password without kerberossync", false, true),
            ("kerberossync without a password", true, false),
        ];
        for (label, synced, with_password) in cases {
            let one_transaction = synced && with_password;
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_policy_levels()
                .times(usize::from(with_password))
                .returning(|_| Ok(vec![]));
            mock.expect_get_user_details()
                .returning(|u| Err(DomainError::EntityNotFound(u.to_string())));
            mock.expect_create_user()
                .times(usize::from(!one_transaction))
                .return_once(|_| Ok(()));
            if one_transaction {
                expect_registration_start(&mut mock, "bob");
                mock.expect_registration_finish().times(0);
            } else if with_password {
                expect_password_registration(&mut mock, "bob");
            }
            mock.expect_ensure_kerberos_principal_consistency().times(0);
            let mut extra = vec![];
            if synced {
                extra.push(LdapPartialAttribute {
                    atype: "kerberossync".to_owned(),
                    vals: vec![b"1".to_vec()],
                });
            }
            if with_password {
                extra.push(LdapPartialAttribute {
                    atype: "userPassword".to_owned(),
                    vals: vec![b"s3cret-pw".to_vec()],
                });
            }
            let ldap_handler = setup_bound_admin_handler(mock).await;
            assert_eq!(
                ldap_handler
                    .create_user_or_group(&mut add_user_request(extra))
                    .await,
                Ok(vec![make_add_response(
                    LdapResultCode::Success,
                    String::new()
                )]),
                "{label}"
            );
            let expected = if one_transaction {
                vec![KerberosOp::CommitPassword {
                    username: "bob".into(),
                    password: "s3cret-pw".into(),
                    rows: add_rows("bob"),
                }]
            } else {
                vec![]
            };
            assert_eq!(guard.recorder().take_ops(), expected, "{label}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_create_user_with_a_password_is_one_transaction_or_nothing() {
        for (kdc, code, message) in kdc_rows() {
            let (guard, _offline, reached) = install(kdc.clone());
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_policy_levels().returning(|_| Ok(vec![]));
            mock.expect_get_user_details()
                .returning(|u| Err(DomainError::EntityNotFound(u.to_string())));
            mock.expect_create_user().times(0);
            mock.expect_delete_user().times(0);
            if reached {
                expect_registration_start(&mut mock, "bob");
            } else {
                mock.expect_registration_start().times(0);
            }
            mock.expect_registration_finish().times(0);
            let ldap_handler = setup_bound_admin_handler(mock).await;
            let expected = match code {
                LdapResultCode::Success => Ok(vec![make_add_response(code, message)]),
                code => Err(LdapError { code, message }),
            };
            assert_eq!(
                ldap_handler
                    .create_user_or_group(&mut add_user_request(synced_with_password()))
                    .await,
                expected,
                "{kdc:?}"
            );
            let ops = guard.map(|g| g.recorder().take_ops()).unwrap_or_default();
            let rows: Vec<_> = ops
                .into_iter()
                .map(|op| match op {
                    KerberosOp::CommitPassword { rows, .. } => rows,
                    other => panic!("{other:?}"),
                })
                .collect();
            let expected = match reached {
                true => vec![add_rows("bob")],
                false => vec![],
            };
            assert_eq!(rows, expected, "{kdc:?}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_an_add_with_a_short_password_makes_nothing() {
        use lldap_domain_handlers::password::PASSWORD_HAS_NUL;
        let refusals = [
            ("pässwör", "the password must be at least 8 characters"),
            ("a\0aaaaaaa", PASSWORD_HAS_NUL),
        ];
        for (synced, (password, refusal)) in [false, true]
            .into_iter()
            .flat_map(|synced| refusals.map(|row| (synced, row)))
        {
            let guard = RecordingGuard::install();
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_policy_levels().returning(|_| Ok(vec![]));
            mock.expect_get_user_details()
                .returning(|u| Err(DomainError::EntityNotFound(u.to_string())));
            mock.expect_create_user().times(0);
            mock.expect_registration_start().times(0);
            mock.expect_registration_finish().times(0);
            let mut extra = vec![LdapPartialAttribute {
                atype: "userPassword".to_owned(),
                vals: vec![password.as_bytes().to_vec()],
            }];
            if synced {
                extra.push(LdapPartialAttribute {
                    atype: "kerberossync".to_owned(),
                    vals: vec![b"1".to_vec()],
                });
            }
            let ldap_handler = setup_bound_admin_handler(mock).await;
            assert_eq!(
                (
                    ldap_handler
                        .create_user_or_group(&mut add_user_request(extra))
                        .await,
                    guard.recorder().take_ops()
                ),
                (
                    Err(LdapError {
                        code: LdapResultCode::UnwillingToPerform,
                        message: refusal.to_owned(),
                    }),
                    vec![]
                ),
                "synced {synced}, {password:?}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_plain_add_with_a_password_while_not_ready_makes_nothing() {
        use lldap_domain_handlers::password::realm_not_ready;
        use lldap_test_utils::recording_kerberos::{DEGRADED_CAUSE, DegradedGuard};
        use lldap_test_utils::recording_log::LogGuard;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_policy_levels().returning(|_| Ok(vec![]));
        mock.expect_get_user_details()
            .returning(|u| Err(DomainError::EntityNotFound(u.to_string())));
        mock.expect_create_user().times(0);
        mock.expect_registration_start().times(0);
        mock.expect_registration_finish().times(0);
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let _degraded = DegradedGuard::install();
        let log = LogGuard::install_on_this_thread();
        let password = vec![LdapPartialAttribute {
            atype: "userPassword".to_owned(),
            vals: vec![b"Bob-Pass-1".to_vec()],
        }];
        let got = ldap_handler
            .create_user_or_group(&mut add_user_request(password))
            .await;
        let rows: Vec<_> = log
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.target.as_deref() == Some("bob"))
            .map(|e| (e.kind, e.success, e.detail))
            .collect();
        let refused = realm_not_ready(DEGRADED_CAUSE).to_string();
        assert_eq!(
            (got, rows),
            (
                Err(LdapError {
                    code: LdapResultCode::Unavailable,
                    message: refused.clone(),
                }),
                vec![(LogKind::UserCreate, false, Some(refused))]
            )
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_synced_add_with_kerberos_disabled_makes_nothing() {
        use lldap_domain_handlers::kerberos::CREATE_WITHOUT_SYNC;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_policy_levels().returning(|_| Ok(vec![]));
        mock.expect_get_user_details()
            .returning(|u| Err(DomainError::EntityNotFound(u.to_string())));
        mock.expect_create_user().times(0);
        mock.expect_registration_start().times(0);
        mock.expect_registration_finish().times(0);
        let ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler
                .create_user_or_group(&mut add_user_request(synced_with_password()))
                .await,
            Err(LdapError {
                code: LdapResultCode::UnwillingToPerform,
                message: CREATE_WITHOUT_SYNC.to_owned(),
            })
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_create_synced_user_that_exists_is_refused_as_before() {
        let guard = RecordingGuard::install();
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_policy_levels().returning(|_| Ok(vec![]));
        mock.expect_get_user_details().returning(|u| {
            Ok(User {
                user_id: u.clone(),
                ..Default::default()
            })
        });
        mock.expect_create_user().times(0);
        mock.expect_registration_start().times(0);
        mock.expect_registration_finish().times(0);
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let got = ldap_handler
            .create_user_or_group(&mut add_user_request(synced_with_password()))
            .await;
        assert!(
            matches!(&got, Err(e) if e.code == LdapResultCode::OperationsError),
            "{got:?}"
        );
        assert_eq!(guard.recorder().take_ops(), vec![]);
    }

    fn sales_add(synced: bool, password: &str) -> LdapAddRequest {
        let mut attributes = vec![LdapPartialAttribute {
            atype: "userPassword".to_owned(),
            vals: vec![password.as_bytes().to_vec()],
        }];
        if synced {
            attributes.push(LdapPartialAttribute {
                atype: "kerberossync".to_owned(),
                vals: vec![b"1".to_vec()],
            });
        }
        LdapAddRequest {
            dn: "uid=bob,ou=Sales,ou=people,dc=example,dc=com".to_owned(),
            attributes,
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_an_add_is_held_to_the_minimum_of_the_ou_its_dn_names() {
        use lldap_domain_handlers::policies::{AttachedPolicy, PolicyId, PolicyLevel};
        use lldap_test_utils::recording_log::LogGuard;
        let (eleven, twelve) = ("Eleven-11ch", "Twelve-12chr");
        let short = "the password must be at least 12 characters";
        let unreadable = "the password policy could not be read; try again";
        type Row = (bool, bool, &'static str, Option<&'static str>);
        let rows: [Row; 6] = [
            (false, true, eleven, Some(short)),
            (true, true, eleven, Some(short)),
            (false, true, twelve, None),
            (true, true, twelve, None),
            (false, false, twelve, Some(unreadable)),
            (true, false, twelve, Some(unreadable)),
        ];
        assert_eq!((eleven.chars().count(), twelve.chars().count()), (11, 12));
        for (synced, readable, password, refusal) in rows {
            let guard = RecordingGuard::install();
            let log = LogGuard::install_on_this_thread();
            let levels = match readable {
                true => Ok(vec![PolicyLevel {
                    ou_key: "people\\sales".to_owned(),
                    blocked: false,
                    policy: Some(AttachedPolicy {
                        id: PolicyId(1),
                        name: "sales".to_owned(),
                        items: [("password-min-length".to_owned(), "12".to_owned())].into(),
                    }),
                }]),
                false => Err(DomainError::InternalError("down".to_owned())),
            };
            let made = refusal.is_none();
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_policy_levels()
                .withf(|ou| ou == "people\\sales")
                .times(1)
                .return_once(move |_| levels);
            mock.expect_get_user_details()
                .returning(|u| Err(DomainError::EntityNotFound(u.to_string())));
            mock.expect_create_user()
                .times(usize::from(made && !synced))
                .return_once(|_| Ok(()));
            match (made, synced) {
                (true, false) => expect_password_registration(&mut mock, "bob"),
                (true, true) => {
                    expect_registration_start(&mut mock, "bob");
                    mock.expect_registration_finish().times(0);
                }
                (false, _) => {
                    mock.expect_registration_start().times(0);
                    mock.expect_registration_finish().times(0);
                }
            }
            let ldap_handler = setup_bound_admin_handler(mock).await;
            let got = ldap_handler
                .create_user_or_group(&mut sales_add(synced, password))
                .await;
            let failed: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| !e.success)
                .map(|e| (e.kind, e.target, e.detail))
                .collect();
            let ops = match (made, synced) {
                (true, true) => vec![KerberosOp::CommitPassword {
                    username: "bob".into(),
                    password: password.into(),
                    rows: add_rows("bob"),
                }],
                _ => vec![],
            };
            let (answer, rows) = match refusal {
                None => (
                    Ok(vec![make_add_response(
                        LdapResultCode::Success,
                        String::new(),
                    )]),
                    vec![],
                ),
                Some(refusal) => (
                    Err(LdapError {
                        code: LdapResultCode::UnwillingToPerform,
                        message: refusal.to_owned(),
                    }),
                    vec![(
                        LogKind::UserCreate,
                        Some("bob".to_owned()),
                        Some(refusal.to_owned()),
                    )],
                ),
            };
            assert_eq!(
                (got, guard.recorder().take_ops(), failed),
                (answer, ops, rows),
                "synced {synced}, readable {readable}, {password}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_an_add_whose_dn_names_no_ou_is_held_to_the_roots_minimum() {
        use lldap_domain_handlers::policies::{AttachedPolicy, PolicyId, PolicyLevel};
        use lldap_test_utils::recording_log::LogGuard;
        let eleven = "Eleven-11ch";
        let short = "the password must be at least 12 characters";
        for (root_policy, refusal) in [(false, None), (true, Some(short))] {
            let _guard = RecordingGuard::install();
            let log = LogGuard::install_on_this_thread();
            let policy = root_policy.then(|| AttachedPolicy {
                id: PolicyId(1),
                name: "root".to_owned(),
                items: [("password-min-length".to_owned(), "12".to_owned())].into(),
            });
            let levels = vec![PolicyLevel {
                ou_key: String::new(),
                blocked: false,
                policy,
            }];
            let made = refusal.is_none();
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_policy_levels()
                .withf(|ou| ou.is_empty())
                .times(1)
                .return_once(move |_| Ok(levels));
            mock.expect_get_user_details()
                .returning(|u| Err(DomainError::EntityNotFound(u.to_string())));
            mock.expect_create_user()
                .times(usize::from(made))
                .return_once(|_| Ok(()));
            match made {
                true => expect_password_registration(&mut mock, "bob"),
                false => {
                    mock.expect_registration_start().times(0);
                    mock.expect_registration_finish().times(0);
                }
            }
            let ldap_handler = setup_bound_admin_handler(mock).await;
            let mut request = sales_add(false, eleven);
            request.dn = "uid=bob,dc=example,dc=com".to_owned();
            let got = ldap_handler.create_user_or_group(&mut request).await;
            let failed: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| !e.success)
                .map(|e| (e.kind, e.target, e.detail))
                .collect();
            let (answer, rows) = match refusal {
                None => (
                    Ok(vec![make_add_response(
                        LdapResultCode::Success,
                        String::new(),
                    )]),
                    vec![],
                ),
                Some(refusal) => (
                    Err(LdapError {
                        code: LdapResultCode::UnwillingToPerform,
                        message: refusal.to_owned(),
                    }),
                    vec![(
                        LogKind::UserCreate,
                        Some("bob".to_owned()),
                        Some(refusal.to_owned()),
                    )],
                ),
            };
            assert_eq!(
                (got, failed),
                (answer, rows),
                "no OU in the DN reads the root's key; a root policy of 12: {root_policy}"
            );
        }
    }
}
