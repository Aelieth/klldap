use crate::{
    core::{
        error::{LdapError, LdapResult},
        utils::{LdapInfo, typed_attribute},
    },
    dn::get_user_id_from_distinguished_name,
    handler::make_modify_response,
    password,
};
use ldap3_proto::proto::{LdapModify, LdapModifyRequest, LdapModifyType, LdapOp, LdapResultCode};
use lldap_access_control::{
    AccessControlledBackendHandler, UserReadableBackendHandler, UserWriteableBackendHandler,
};
use lldap_auth::access_control::ValidationResults;
use lldap_domain::{
    requests::UpdateUserRequest,
    types::{Attribute, AttributeName, AttributeType, AttributeValue, Cardinality, Email, UserId},
};
use lldap_domain_handlers::handler::BackendHandler;
use lldap_opaque_handler::OpaqueHandler;
use lldap_schema::PublicSchema;
use zeroize::Zeroizing;

// The profile attribute an LDAP Modify targets, after folding wire-name aliases (sn, cn, surname,
// jpegphoto, ...) to the schema canonical name. Bridges canonical → DB attribute name / field.
enum ModifyTarget {
    FirstName,
    LastName,
    DisplayName,
    Email,
    Avatar,
    SshPublicKey,
    Ou,
    Unsupported,
}

fn modify_target(atype_lower: &str) -> ModifyTarget {
    let canonical = PublicSchema::shared()
        .resolve_user_canonical_name(atype_lower)
        .unwrap_or(atype_lower);
    match canonical {
        "firstname" => ModifyTarget::FirstName,
        "lastname" => ModifyTarget::LastName,
        "displayname" => ModifyTarget::DisplayName,
        "mail" => ModifyTarget::Email,
        "avatar" => ModifyTarget::Avatar,
        "sshpublickey" => ModifyTarget::SshPublicKey,
        "ou" => ModifyTarget::Ou,
        _ => ModifyTarget::Unsupported,
    }
}

async fn handle_password_modify<Handler: BackendHandler + OpaqueHandler>(
    backend_handler: &AccessControlledBackendHandler<Handler>,
    readable_handler: &impl UserReadableBackendHandler,
    opaque_handler: &impl OpaqueHandler,
    user_id: UserId,
    credentials: &ValidationResults,
    user_is_admin: bool,
    change: &LdapModify,
) -> LdapResult<()> {
    if change.operation != LdapModifyType::Replace {
        return Err(unwilling(format!(
            r#"Unsupported operation: `{:?}` for `{}`"#,
            change.operation, change.modification.atype
        )));
    }
    if !credentials.can_change_password(&user_id, user_is_admin) {
        return Err(LdapError {
            code: LdapResultCode::InsufficentAccessRights,
            message: format!(
                r#"User `{}` cannot modify the password of user `{}`"#,
                credentials.user, user_id
            ),
        });
    }
    let [value] = change.modification.vals.as_slice() else {
        return Err(LdapError {
            code: LdapResultCode::InvalidAttributeSyntax,
            message: format!(
                r#"Wrong number of values for password attribute: {}"#,
                change.modification.vals.len()
            ),
        });
    };
    let plain_pass = std::str::from_utf8(value).map_err(|_| LdapError {
        code: LdapResultCode::ConstraintViolation,
        message: "userPassword must be valid UTF-8".to_string(),
    })?;
    let plain_pass = Zeroizing::new(plain_pass.to_owned());
    password::change_password(
        backend_handler,
        readable_handler,
        opaque_handler,
        &user_id,
        &plain_pass,
    )
    .await
}

async fn handle_profile_modify(
    readable_handler: &impl UserReadableBackendHandler,
    writeable_handler: &impl UserWriteableBackendHandler,
    user_id: UserId,
    credentials: &ValidationResults,
    user_is_admin: bool,
    change: &LdapModify,
) -> LdapResult<()> {
    if !credentials.can_change_password(&user_id, user_is_admin) {
        return Err(LdapError {
            code: LdapResultCode::InsufficentAccessRights,
            message: format!(
                r#"User `{}` cannot modify attributes of user `{}`"#,
                credentials.user, user_id
            ),
        });
    }
    let atype = change.modification.atype.as_str();
    let target = modify_target(&atype.to_ascii_lowercase());
    if change.operation == LdapModifyType::Delete
        && matches!(target, ModifyTarget::Email | ModifyTarget::DisplayName)
    {
        return Err(LdapError {
            code: LdapResultCode::InsufficentAccessRights,
            message: format!(
                r#"Deletion of `{atype}` is not allowed via LDAP Modify (use GraphQL or protected path)"#
            ),
        });
    }

    let mut request = UpdateUserRequest {
        user_id: user_id.clone(),
        email: None,
        display_name: None,
        delete_attributes: Vec::new(),
        insert_attributes: Vec::new(),
    };
    let values = utf8_values(&change.modification.vals);
    match change.operation {
        LdapModifyType::Replace => replace_values(&mut request, &target, &values, atype)?,
        LdapModifyType::Add => {
            add_values(readable_handler, &mut request, &target, &values, atype).await?
        }
        LdapModifyType::Delete => {
            delete_values(readable_handler, &mut request, &target, &values, atype).await?
        }
    }

    writeable_handler
        .update_user(request)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Error while updating user via LDAP Modify: {e:#?}"),
        })
}

fn unwilling(message: String) -> LdapError {
    LdapError {
        code: LdapResultCode::UnwillingToPerform,
        message,
    }
}

fn no_values(atype: &str) -> LdapError {
    LdapError {
        code: LdapResultCode::InvalidAttributeSyntax,
        message: format!("No values provided for {atype}"),
    }
}

fn utf8_values(vals: &[Vec<u8>]) -> Vec<String> {
    vals.iter()
        .filter_map(|v| std::str::from_utf8(v).ok().map(str::to_owned))
        .collect()
}

// The targets Replace and Add share; returns false when the caller must decide.
fn scalar_update(
    request: &mut UpdateUserRequest,
    target: &ModifyTarget,
    values: &[String],
) -> LdapResult<bool> {
    let insert = |name, typ| typed_attribute(name, values, typ, false);
    match target {
        ModifyTarget::FirstName => request
            .insert_attributes
            .push(insert("first_name", AttributeType::String)?),
        ModifyTarget::LastName => request
            .insert_attributes
            .push(insert("last_name", AttributeType::String)?),
        ModifyTarget::DisplayName => request.display_name = Some(values[0].clone()),
        ModifyTarget::Email => request.email = Some(Email::from(values[0].clone())),
        ModifyTarget::Avatar => request
            .insert_attributes
            .push(insert("avatar", AttributeType::Avatar)?),
        _ => return Ok(false),
    }
    Ok(true)
}

fn replace_values(
    request: &mut UpdateUserRequest,
    target: &ModifyTarget,
    values: &[String],
    atype: &str,
) -> LdapResult<()> {
    if values.is_empty() {
        return Err(no_values(atype));
    }
    if scalar_update(request, target, values)? {
        return Ok(());
    }
    match target {
        ModifyTarget::SshPublicKey => {
            request.insert_attributes.push(ssh_keys_attribute(values)?);
            Ok(())
        }
        ModifyTarget::Ou => Err(unwilling(
            "Direct modification of 'ou' via LDAP Modify is not supported.".to_string(),
        )),
        _ => Err(unwilling(format!(
            "Unsupported attribute for LDAP Modify: {atype} (supported: givenName, sn, cn, mail, avatar, sshPublicKey, userPassword)"
        ))),
    }
}

async fn add_values(
    readable_handler: &impl UserReadableBackendHandler,
    request: &mut UpdateUserRequest,
    target: &ModifyTarget,
    values: &[String],
    atype: &str,
) -> LdapResult<()> {
    if values.is_empty() {
        return Err(no_values(atype));
    }
    if matches!(target, ModifyTarget::SshPublicKey) {
        let mut keys = current_ssh_keys(readable_handler, &request.user_id).await?;
        for value in values {
            if !keys.contains(value) {
                keys.push(value.clone());
            }
        }
        request.insert_attributes.push(ssh_keys_attribute(&keys)?);
        return Ok(());
    }
    if scalar_update(request, target, values)? {
        return Ok(());
    }
    Err(unwilling(format!("Add not supported for {atype}")))
}

async fn delete_values(
    readable_handler: &impl UserReadableBackendHandler,
    request: &mut UpdateUserRequest,
    target: &ModifyTarget,
    values: &[String],
    atype: &str,
) -> LdapResult<()> {
    let attribute = match target {
        ModifyTarget::SshPublicKey => {
            if !values.is_empty() {
                let remaining: Vec<String> = current_ssh_keys(readable_handler, &request.user_id)
                    .await?
                    .into_iter()
                    .filter(|key| !values.contains(key))
                    .collect();
                if !remaining.is_empty() {
                    request
                        .insert_attributes
                        .push(ssh_keys_attribute(&remaining)?);
                    return Ok(());
                }
            }
            "sshpublickey"
        }
        ModifyTarget::FirstName => "first_name",
        ModifyTarget::LastName => "last_name",
        ModifyTarget::Avatar => "avatar",
        _ => return Err(unwilling(format!("Deletion not supported for {atype}"))),
    };
    request
        .delete_attributes
        .push(AttributeName::from(attribute));
    Ok(())
}

fn ssh_keys_attribute(keys: &[String]) -> LdapResult<Attribute> {
    typed_attribute("sshpublickey", keys, AttributeType::String, true)
}

async fn current_ssh_keys(
    readable_handler: &impl UserReadableBackendHandler,
    user_id: &UserId,
) -> LdapResult<Vec<String>> {
    let user = readable_handler
        .get_user_details(user_id)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::OperationsError,
            message: format!("Failed to read current user: {e}"),
        })?;
    Ok(user
        .attributes
        .iter()
        .find(|a| a.name.as_str() == "sshpublickey")
        .and_then(|a| match &a.value {
            AttributeValue::String(Cardinality::Unbounded(list)) => Some(list.clone()),
            AttributeValue::String(Cardinality::Singleton(key)) => Some(vec![key.clone()]),
            _ => None,
        })
        .unwrap_or_default())
}

pub(crate) async fn handle_modify_request<Handler: BackendHandler + OpaqueHandler>(
    opaque_handler: &impl OpaqueHandler,
    backend_handler: &AccessControlledBackendHandler<Handler>,
    ldap_info: &LdapInfo,
    credentials: &ValidationResults,
    request: &LdapModifyRequest,
) -> LdapResult<Vec<LdapOp>> {
    match get_user_id_from_distinguished_name(
        &request.dn,
        &ldap_info.base_dn,
        &ldap_info.base_dn_str,
    ) {
        Ok(uid) => {
            for change in &request.changes {
                let readable_handler = backend_handler
                    .get_readable_handler(credentials, uid.clone())
                    .ok_or_else(|| LdapError {
                        code: LdapResultCode::InsufficentAccessRights,
                        message: format!(
                            "User `{}` cannot modify user `{}`",
                            credentials.user.as_str(),
                            uid.as_str()
                        ),
                    })?;
                let user_is_admin = readable_handler
                    .get_user_groups(&uid)
                    .await
                    .map_err(|e| LdapError {
                        code: LdapResultCode::OperationsError,
                        message: format!("Internal error while requesting user's groups: {e:#?}"),
                    })?
                    .iter()
                    .any(|g| g.display_name == "lldap_admin".into());
                // Password changes are governed by can_change_password, not by write access.
                if change
                    .modification
                    .atype
                    .eq_ignore_ascii_case("userpassword")
                {
                    handle_password_modify(
                        backend_handler,
                        readable_handler,
                        opaque_handler,
                        uid.clone(),
                        credentials,
                        user_is_admin,
                        change,
                    )
                    .await?;
                    continue;
                }
                let writeable_handler = backend_handler
                    .get_writeable_handler(credentials, uid.clone())
                    .ok_or_else(|| LdapError {
                        code: LdapResultCode::InsufficentAccessRights,
                        message: format!(
                            "User `{}` cannot modify user `{}` (no write permission)",
                            credentials.user.as_str(),
                            uid.as_str()
                        ),
                    })?;
                handle_profile_modify(
                    readable_handler,
                    writeable_handler,
                    uid.clone(),
                    credentials,
                    user_is_admin,
                    change,
                )
                .await?;
            }

            Ok(vec![make_modify_response(
                LdapResultCode::Success,
                String::new(),
            )])
        }
        Err(e) => Err(LdapError {
            code: LdapResultCode::InvalidDNSyntax,
            message: format!("Invalid username: {e}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::tests::{
        setup_bound_admin_handler, setup_bound_handler_with_group,
        setup_bound_password_manager_handler,
    };
    use crate::handler::{LdapHandler, make_extended_response};
    use crate::password::tests::{
        committed, expect_password_change, expect_registration_start, install, kdc_rows,
    };
    use ldap3_proto::proto::LdapResult as LdapResultOp;
    use lldap_domain::types::{GroupDetails, GroupId, User, UserId};
    use lldap_domain_model::error::DomainError;
    use lldap_test_utils::recording_kerberos::RecordingGuard;
    use lldap_test_utils::{MockTestBackendHandler, setup_default_ldap_mock, setup_default_schema};
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::collections::HashSet;
    use std::panic::AssertUnwindSafe;
    use std::task::Poll;

    fn make_password_modify_request(target_user: &str) -> LdapModifyRequest {
        LdapModifyRequest {
            dn: format!("uid={target_user},ou=people,dc=example,dc=com"),
            changes: vec![LdapModify {
                operation: LdapModifyType::Replace,
                modification: ldap3_proto::LdapPartialAttribute {
                    atype: "userPassword".to_string(),
                    vals: vec![b"newpassword".to_vec()],
                },
            }],
        }
    }

    fn make_modify_success_response() -> Vec<LdapOp> {
        vec![LdapOp::ModifyResponse(LdapResultOp {
            code: LdapResultCode::Success,
            matcheddn: "".to_string(),
            message: "".to_string(),
            referral: vec![],
        })]
    }

    fn make_modify_failure_response(code: LdapResultCode, message: &str) -> Vec<LdapOp> {
        vec![LdapOp::ModifyResponse(LdapResultOp {
            code,
            matcheddn: "".to_string(),
            message: message.to_string(),
            referral: vec![],
        })]
    }

    #[tokio::test]
    #[serial]
    async fn test_modify_password_of_regular_as_admin() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        expect_password_change(&mut mock, "bob");
        let ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler
                .do_modify_request(&make_password_modify_request("bob"))
                .await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_modify_password_of_regular_as_regular() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        expect_password_change(&mut mock, "test");
        let ldap_handler = setup_bound_handler_with_group(mock, "regular").await;
        assert_eq!(
            ldap_handler
                .do_modify_request(&make_password_modify_request("test"))
                .await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_modify_password_of_regular_as_password_manager() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        expect_password_change(&mut mock, "bob");
        let ldap_handler = setup_bound_password_manager_handler(mock).await;
        assert_eq!(
            ldap_handler
                .do_modify_request(&make_password_modify_request("bob"))
                .await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_password_of_other_regular_as_regular() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_get_user_groups()
            .with(mockall::predicate::eq(UserId::new("bob")))
            .returning(|_| {
                let mut set = HashSet::new();
                set.insert(GroupDetails {
                    group_id: GroupId(1),
                    display_name: "lldap_admin".into(),
                    creation_date: chrono::Utc::now().naive_utc(),
                    modified_date: chrono::Utc::now().naive_utc(),
                    uuid: lldap_domain::types::Uuid::from_name_and_date(
                        "bob",
                        &chrono::Utc::now().naive_utc(),
                    ),
                    attributes: vec![],
                });
                Ok(set)
            });

        let ldap_handler = setup_bound_handler_with_group(mock, "regular").await;
        assert_eq!(
            ldap_handler
                .do_modify_request(&make_password_modify_request("bob"))
                .await,
            make_modify_failure_response(
                LdapResultCode::InsufficentAccessRights,
                "User `test` cannot modify user `bob`"
            )
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_modify_password_of_admin_as_admin() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        expect_password_change(&mut mock, "test");
        let ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler
                .do_modify_request(&make_password_modify_request("test"))
                .await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_password_invalid_number_of_values() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        let ldap_handler = setup_bound_admin_handler(mock).await;

        let request = LdapModifyRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
            changes: vec![LdapModify {
                operation: LdapModifyType::Replace,
                modification: ldap3_proto::LdapPartialAttribute {
                    atype: "userPassword".to_string(),
                    vals: vec![b"one".to_vec(), b"two".to_vec()],
                },
            }],
        };
        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_failure_response(
                LdapResultCode::InvalidAttributeSyntax,
                "Wrong number of values for password attribute: 2"
            )
        );
    }

    #[tokio::test]
    async fn test_modify_password_rejects_non_utf8() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapModifyRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
            changes: vec![LdapModify {
                operation: LdapModifyType::Replace,
                modification: ldap3_proto::LdapPartialAttribute {
                    atype: "userPassword".to_string(),
                    vals: vec![vec![0xff, 0xfe]],
                },
            }],
        };
        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_failure_response(
                LdapResultCode::ConstraintViolation,
                "userPassword must be valid UTF-8"
            )
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_the_password_bytes_of_a_modify_are_zeroed_on_every_exit() {
        type Row = (
            &'static str,
            Option<&'static str>,
            Vec<Vec<u8>>,
            Vec<LdapOp>,
        );
        let rows: [Row; 5] = [
            (
                "changed",
                Some("lldap_admin"),
                vec![b"newpassword".to_vec()],
                make_modify_success_response(),
            ),
            (
                "two values",
                Some("lldap_admin"),
                vec![b"one".to_vec(), b"two".to_vec()],
                make_modify_failure_response(
                    LdapResultCode::InvalidAttributeSyntax,
                    "Wrong number of values for password attribute: 2",
                ),
            ),
            (
                "not UTF-8",
                Some("lldap_admin"),
                vec![vec![0xff, 0xfe]],
                make_modify_failure_response(
                    LdapResultCode::ConstraintViolation,
                    "userPassword must be valid UTF-8",
                ),
            ),
            (
                "refused",
                Some("regular"),
                vec![b"newpassword".to_vec()],
                make_modify_failure_response(
                    LdapResultCode::InsufficentAccessRights,
                    "User `test` cannot modify user `bob`",
                ),
            ),
            (
                "unbound",
                None,
                vec![b"newpassword".to_vec()],
                vec![make_extended_response(
                    LdapResultCode::InsufficentAccessRights,
                    "No user currently bound".to_string(),
                )],
            ),
        ];
        for (label, group, vals, expected) in rows {
            let mut mock = MockTestBackendHandler::new();
            setup_default_ldap_mock(&mut mock);
            if expected == make_modify_success_response() {
                expect_password_change(&mut mock, "bob");
                mock.expect_update_user().times(1).return_once(|_| Ok(()));
            }
            let ldap_handler = match group {
                Some(group) => setup_bound_handler_with_group(mock, group).await,
                None => LdapHandler::new_for_tests(mock, "dc=example,dc=com"),
            };
            let mut request = make_password_modify_request("bob");
            request.changes[0].modification.vals = vals.clone();
            let cn = modify_request("bob", LdapModifyType::Replace, "cn", &["Bob"]);
            request.changes.extend(cn.changes);
            let mut op = LdapOp::ModifyRequest(request);
            let response = ldap_handler.answer_and_wipe(&mut op).await;
            let LdapOp::ModifyRequest(request) = op else {
                unreachable!()
            };
            let zeroed: Vec<Vec<u8>> = vals.iter().map(|v| vec![0; v.len()]).collect();
            let left: Vec<_> = request
                .changes
                .iter()
                .map(|c| c.modification.vals.clone())
                .collect();
            assert_eq!(
                (response, left),
                (expected, vec![zeroed, vec![b"Bob".to_vec()]]),
                "{label}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_the_password_bytes_of_a_modify_are_zeroed_when_its_answer_is_dropped_or_panics() {
        let rows = [
            ("dropped while it waits", false, "pending"),
            ("panicked", true, "a test fault"),
        ];
        for (label, panics, expected) in rows {
            let mut mock = MockTestBackendHandler::new();
            setup_default_ldap_mock(&mut mock);
            if panics {
                mock.expect_registration_start()
                    .returning(|_| panic!("a test fault"));
            } else {
                expect_registration_start(&mut mock, "bob");
            }
            let ldap_handler = setup_bound_admin_handler(mock).await;
            let mut request = make_password_modify_request("bob");
            let cn = modify_request("bob", LdapModifyType::Replace, "cn", &["Bob"]);
            request.changes.extend(cn.changes);
            let mut op = LdapOp::ModifyRequest(request);
            let mut answer = Box::pin(ldap_handler.answer_and_wipe(&mut op));
            let polled = std::future::poll_fn(|cx| {
                let poll = AssertUnwindSafe(|| answer.as_mut().poll(cx));
                Poll::Ready(std::panic::catch_unwind(poll))
            })
            .await;
            let outcome = match polled {
                Ok(Poll::Pending) => "pending",
                Ok(Poll::Ready(_)) => "answered",
                Err(payload) => payload.downcast_ref::<&str>().copied().unwrap_or("?"),
            };
            // Leaked, not dropped: after the panic only the unwinding can have zeroed the bytes.
            if panics {
                std::mem::forget(answer);
            } else {
                drop(answer);
            }
            let LdapOp::ModifyRequest(request) = op else {
                unreachable!()
            };
            let left: Vec<_> = request
                .changes
                .into_iter()
                .map(|c| c.modification.vals)
                .collect();
            assert_eq!(
                (outcome, left),
                (expected, vec![vec![vec![0; 11]], vec![b"Bob".to_vec()]]),
                "{label}"
            );
        }
    }

    fn modify_request(
        user: &str,
        operation: LdapModifyType,
        atype: &str,
        vals: &[&str],
    ) -> LdapModifyRequest {
        modify_request_at(
            &format!("uid={user},ou=people,dc=example,dc=com"),
            operation,
            atype,
            vals,
        )
    }

    fn modify_request_at(
        dn: &str,
        operation: LdapModifyType,
        atype: &str,
        vals: &[&str],
    ) -> LdapModifyRequest {
        LdapModifyRequest {
            dn: dn.to_string(),
            changes: vec![LdapModify {
                operation,
                modification: ldap3_proto::LdapPartialAttribute {
                    atype: atype.to_string(),
                    vals: vals.iter().map(|v| v.as_bytes().to_vec()).collect(),
                },
            }],
        }
    }

    const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==";

    fn inserts(req: &UpdateUserRequest, name: &str) -> bool {
        req.insert_attributes
            .iter()
            .any(|a| a.name.as_str() == name)
    }

    #[tokio::test]
    async fn test_modify_replace_routes_wire_names() {
        type Check = fn(&UpdateUserRequest) -> bool;
        type Case<'a> = (
            &'a str,
            &'a str,
            &'a str,
            LdapModifyType,
            &'a str,
            &'a [&'a str],
            Check,
        );
        let cases: Vec<Case> = vec![
            (
                "givenName as self",
                "regular",
                "test",
                LdapModifyType::Replace,
                "givenName",
                &["Alice"],
                |r| inserts(r, "first_name"),
            ),
            (
                "sn as admin",
                "lldap_admin",
                "bob",
                LdapModifyType::Replace,
                "sn",
                &["Smith"],
                |r| inserts(r, "last_name"),
            ),
            (
                "mail as admin",
                "lldap_admin",
                "bob",
                LdapModifyType::Replace,
                "mail",
                &["bob.smith@example.com"],
                |r| r.email.is_some(),
            ),
            (
                "cn as self",
                "regular",
                "test",
                LdapModifyType::Replace,
                "cn",
                &["Test User"],
                |r| r.display_name == Some("Test User".to_string()),
            ),
            (
                "avatar as admin",
                "lldap_admin",
                "bob",
                LdapModifyType::Replace,
                "avatar",
                &[PNG],
                |r| inserts(r, "avatar"),
            ),
            (
                "sshPublicKey as admin",
                "lldap_admin",
                "bob",
                LdapModifyType::Replace,
                "sshPublicKey",
                &[
                    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABCCCBAQCExampleRSAKeyForTestingOnly2048bit testuser@otherlab",
                ],
                |r| inserts(r, "sshpublickey"),
            ),
            (
                "surname",
                "lldap_admin",
                "bob",
                LdapModifyType::Replace,
                "surname",
                &["Smith"],
                |r| inserts(r, "last_name"),
            ),
            (
                "commonname",
                "lldap_admin",
                "bob",
                LdapModifyType::Replace,
                "commonname",
                &["Bob"],
                |r| r.display_name == Some("Bob".to_string()),
            ),
            (
                "given_name",
                "lldap_admin",
                "bob",
                LdapModifyType::Replace,
                "given_name",
                &["Alice"],
                |r| inserts(r, "first_name"),
            ),
            (
                "jpeg_photo",
                "lldap_admin",
                "bob",
                LdapModifyType::Replace,
                "jpeg_photo",
                &[PNG],
                |r| inserts(r, "avatar"),
            ),
            (
                "ssh_public_key",
                "lldap_admin",
                "bob",
                LdapModifyType::Replace,
                "ssh_public_key",
                &["ssh-rsa AAAAB3NzaC1yc2E testuser@host"],
                |r| inserts(r, "sshpublickey"),
            ),
            (
                "Add givenName",
                "lldap_admin",
                "bob",
                LdapModifyType::Add,
                "givenName",
                &["Alice"],
                |r| inserts(r, "first_name"),
            ),
            (
                "Delete givenName",
                "lldap_admin",
                "bob",
                LdapModifyType::Delete,
                "givenName",
                &[],
                |r| {
                    r.delete_attributes
                        .iter()
                        .any(|a| a.as_str() == "first_name")
                },
            ),
        ];
        for (label, group, target, operation, atype, vals, check) in cases {
            let mut mock = MockTestBackendHandler::new();
            setup_default_ldap_mock(&mut mock);
            let target_id = UserId::new(target);
            mock.expect_update_user()
                .withf(move |req| req.user_id == target_id && check(req))
                .times(1)
                .return_once(|_| Ok(()));
            let ldap_handler = setup_bound_handler_with_group(mock, group).await;
            assert_eq!(
                ldap_handler
                    .do_modify_request(&modify_request(target, operation, atype, vals))
                    .await,
                make_modify_success_response(),
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn test_modify_refusals() {
        let bob = "uid=bob,ou=people,dc=example,dc=com";
        type Case<'a> = (
            &'a str,
            &'a str,
            &'a str,
            LdapModifyType,
            &'a str,
            &'a [&'a str],
            LdapResultCode,
            &'a str,
        );
        let cases: Vec<Case> = vec![
            (
                "password under a foreign base DN",
                "lldap_admin",
                "uid=bob,ou=people,dc=example,dc=fr",
                LdapModifyType::Replace,
                "userPassword",
                &["newpassword"],
                LdapResultCode::InvalidDNSyntax,
                "Invalid username: Not a subtree of the base tree",
            ),
            (
                "mail as password manager",
                "lldap_password_manager",
                bob,
                LdapModifyType::Replace,
                "mail",
                &["bob.smith@example.com"],
                LdapResultCode::InsufficentAccessRights,
                "User `test` cannot modify user `bob` (no write permission)",
            ),
            (
                "Replace of an unsupported attribute",
                "lldap_admin",
                bob,
                LdapModifyType::Replace,
                "title",
                &["Manager"],
                LdapResultCode::UnwillingToPerform,
                "Unsupported attribute for LDAP Modify: title (supported: givenName, sn, cn, mail, avatar, sshPublicKey, userPassword)",
            ),
            (
                "Delete of mail",
                "lldap_admin",
                bob,
                LdapModifyType::Delete,
                "mail",
                &[],
                LdapResultCode::InsufficentAccessRights,
                "Deletion of `mail` is not allowed via LDAP Modify (use GraphQL or protected path)",
            ),
            (
                "Delete of email",
                "lldap_admin",
                bob,
                LdapModifyType::Delete,
                "email",
                &[],
                LdapResultCode::InsufficentAccessRights,
                "Deletion of `email` is not allowed via LDAP Modify (use GraphQL or protected path)",
            ),
            (
                "Delete of cn",
                "lldap_admin",
                bob,
                LdapModifyType::Delete,
                "cn",
                &[],
                LdapResultCode::InsufficentAccessRights,
                "Deletion of `cn` is not allowed via LDAP Modify (use GraphQL or protected path)",
            ),
            (
                "Delete of displayname",
                "lldap_admin",
                bob,
                LdapModifyType::Delete,
                "displayname",
                &[],
                LdapResultCode::InsufficentAccessRights,
                "Deletion of `displayname` is not allowed via LDAP Modify (use GraphQL or protected path)",
            ),
            (
                "Delete of commonname",
                "lldap_admin",
                bob,
                LdapModifyType::Delete,
                "commonname",
                &[],
                LdapResultCode::InsufficentAccessRights,
                "Deletion of `commonname` is not allowed via LDAP Modify (use GraphQL or protected path)",
            ),
            (
                "Replace of ou",
                "lldap_admin",
                bob,
                LdapModifyType::Replace,
                "ou",
                &["labs"],
                LdapResultCode::UnwillingToPerform,
                "Direct modification of 'ou' via LDAP Modify is not supported.",
            ),
            (
                "Replace without values",
                "lldap_admin",
                bob,
                LdapModifyType::Replace,
                "givenName",
                &[],
                LdapResultCode::InvalidAttributeSyntax,
                "No values provided for givenName",
            ),
            (
                "Add without values",
                "lldap_admin",
                bob,
                LdapModifyType::Add,
                "givenName",
                &[],
                LdapResultCode::InvalidAttributeSyntax,
                "No values provided for givenName",
            ),
            (
                "Add of an unsupported attribute",
                "lldap_admin",
                bob,
                LdapModifyType::Add,
                "title",
                &["Boss"],
                LdapResultCode::UnwillingToPerform,
                "Add not supported for title",
            ),
            (
                "Delete of an unsupported attribute",
                "lldap_admin",
                bob,
                LdapModifyType::Delete,
                "title",
                &[],
                LdapResultCode::UnwillingToPerform,
                "Deletion not supported for title",
            ),
        ];
        for (label, group, dn, operation, atype, vals, code, message) in cases {
            let mut mock = MockTestBackendHandler::new();
            setup_default_ldap_mock(&mut mock);
            let ldap_handler = setup_bound_handler_with_group(mock, group).await;
            assert_eq!(
                ldap_handler
                    .do_modify_request(&modify_request_at(dn, operation, atype, vals))
                    .await,
                make_modify_failure_response(code, message),
                "{label}"
            );
        }
    }

    fn user_with_ssh_keys(
        keys: &[&str],
    ) -> impl Fn(&UserId) -> Result<User, DomainError> + 'static {
        let keys: Vec<String> = keys.iter().map(|k| (*k).to_owned()).collect();
        move |uid| {
            Ok(User {
                user_id: uid.clone(),
                attributes: vec![Attribute {
                    name: "sshpublickey".into(),
                    value: AttributeValue::String(Cardinality::Unbounded(keys.clone())),
                }],
                ..Default::default()
            })
        }
    }

    fn mock_with_ssh_keys(keys: &[&str]) -> MockTestBackendHandler {
        let mut mock = MockTestBackendHandler::new();
        setup_default_schema(&mut mock);
        mock.expect_get_allowed_ous()
            .returning(|| Ok(vec!["people".to_string(), "groups".to_string()]));
        mock.expect_get_user_details()
            .returning(user_with_ssh_keys(keys));
        mock.expect_get_user_groups()
            .returning(|_| Ok(HashSet::new()));
        mock
    }

    fn ssh_keys_of(req: &UpdateUserRequest) -> Option<Vec<String>> {
        req.insert_attributes
            .iter()
            .find(|a| a.name.as_str() == "sshpublickey")
            .map(|a| match &a.value {
                AttributeValue::String(Cardinality::Unbounded(list)) => list.clone(),
                AttributeValue::String(Cardinality::Singleton(key)) => vec![key.clone()],
                other => panic!("unexpected sshpublickey value {other:?}"),
            })
    }

    #[tokio::test]
    async fn test_modify_ssh_key_list_ops() {
        type Case<'a> = (
            &'a str,
            &'a [&'a str],
            LdapModifyType,
            &'a [&'a str],
            Option<Vec<&'a str>>,
        );
        let cases: Vec<Case> = vec![
            (
                "Add merges with the stored keys and dedups",
                &["ssh-ed25519 AAA old"],
                LdapModifyType::Add,
                &["ssh-ed25519 BBB new", "ssh-ed25519 AAA old"],
                Some(vec!["ssh-ed25519 AAA old", "ssh-ed25519 BBB new"]),
            ),
            (
                "Delete of one value keeps the rest",
                &["ssh-ed25519 AAA", "ssh-ed25519 BBB"],
                LdapModifyType::Delete,
                &["ssh-ed25519 AAA"],
                Some(vec!["ssh-ed25519 BBB"]),
            ),
            (
                "Delete without values removes the attribute",
                &["ssh-ed25519 AAA"],
                LdapModifyType::Delete,
                &[],
                None,
            ),
            (
                "Delete of the last value removes the attribute",
                &["ssh-ed25519 AAA"],
                LdapModifyType::Delete,
                &["ssh-ed25519 AAA"],
                None,
            ),
        ];
        for (label, existing, operation, vals, kept) in cases {
            let mut mock = mock_with_ssh_keys(existing);
            let kept: Option<Vec<String>> =
                kept.map(|keys| keys.into_iter().map(str::to_owned).collect());
            mock.expect_update_user()
                .withf(move |req| match &kept {
                    Some(keys) => ssh_keys_of(req) == Some(keys.clone()),
                    None => {
                        req.insert_attributes.is_empty()
                            && req.delete_attributes == vec![AttributeName::from("sshpublickey")]
                    }
                })
                .times(1)
                .return_once(|_| Ok(()));
            let ldap_handler = setup_bound_admin_handler(mock).await;
            assert_eq!(
                ldap_handler
                    .do_modify_request(&modify_request("bob", operation, "sshPublicKey", vals))
                    .await,
                make_modify_success_response(),
                "{label}"
            );
        }
    }

    fn synced_user(uid: &lldap_domain::types::UserId) -> lldap_domain::types::User {
        lldap_domain::types::User {
            user_id: uid.clone(),
            email: format!("{}@example.com", uid.as_str()).into(),
            display_name: None,
            creation_date: chrono::Utc::now().naive_utc(),
            modified_date: chrono::Utc::now().naive_utc(),
            password_modified_date: chrono::Utc::now().naive_utc(),
            uuid: lldap_domain::types::Uuid::from_name_and_date(
                uid.as_str(),
                &chrono::Utc::now().naive_utc(),
            ),
            attributes: vec![Attribute {
                name: "kerberossync".into(),
                value: 1i64.into(),
            }],
            krb_principal_name: None,
            mfa_type: None,
        }
    }

    fn lldap_disabled_membership() -> HashSet<GroupDetails> {
        let mut set = HashSet::new();
        set.insert(GroupDetails {
            group_id: GroupId(2),
            display_name: "lldap_disabled".into(),
            creation_date: chrono::Utc::now().naive_utc(),
            modified_date: chrono::Utc::now().naive_utc(),
            uuid: lldap_domain::types::Uuid::from_name_and_date(
                "lldap_disabled",
                &chrono::Utc::now().naive_utc(),
            ),
            attributes: vec![],
        });
        set
    }

    // A kerberossync=1 user's password and keys change in one transaction; a user already in
    // lldap_disabled is committed alike, as the change reads that state under its lock.
    #[tokio::test]
    #[serial]
    async fn test_modify_password_kerberos_matrix() {
        use mockall::predicate::eq;
        const CAUSE: &str = "the database did not answer";
        let cases = [
            ("sync enabled", true, false, false),
            ("sync disabled", false, false, false),
            ("in lldap_disabled", true, true, false),
            ("the change fails: nothing written", true, false, true),
            ("in lldap_disabled, the change fails", true, true, true),
        ];
        for (label, synced, disabled, fails) in cases {
            let guard = if fails {
                RecordingGuard::install_failing(CAUSE)
            } else {
                RecordingGuard::install()
            };
            let mut mock = MockTestBackendHandler::new();
            if synced {
                mock.expect_get_user_details()
                    .with(eq(UserId::new("bob")))
                    .returning(|uid| Ok(synced_user(uid)));
            }
            if disabled {
                mock.expect_get_user_groups()
                    .with(eq(UserId::new("bob")))
                    .returning(|_| Ok(lldap_disabled_membership()));
            }
            setup_default_ldap_mock(&mut mock);
            if synced {
                expect_registration_start(&mut mock, "bob");
                mock.expect_registration_finish().times(0);
                mock.expect_ensure_kerberos_principal_consistency().times(0);
            } else {
                expect_password_change(&mut mock, "bob");
            }
            let expected_response = if fails {
                make_modify_failure_response(
                    LdapResultCode::Other,
                    &format!("password change failed: {CAUSE}"),
                )
            } else {
                make_modify_success_response()
            };
            let ldap_handler = setup_bound_admin_handler(mock).await;
            assert_eq!(
                ldap_handler
                    .do_modify_request(&make_password_modify_request("bob"))
                    .await,
                expected_response,
                "{label}"
            );
            let expected = match synced {
                true => vec![committed("bob", "newpassword")],
                false => vec![],
            };
            assert_eq!(guard.recorder().take_ops(), expected, "{label}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_short_password_is_refused_at_modify_and_password_modify() {
        use lldap_domain_handlers::password::PASSWORD_HAS_NUL;
        let dn = "uid=bob,ou=people,dc=example,dc=com";
        let refusals = [
            (
                "Short-7",
                "pässwör",
                "the password must be at least 8 characters",
            ),
            ("a\0aaaaaaa", "b\0bbbbbbb", PASSWORD_HAS_NUL),
        ];
        for (synced, (replaced, sent, refusal)) in [false, true]
            .into_iter()
            .flat_map(|synced| refusals.map(|row| (synced, row)))
        {
            let guard = RecordingGuard::install();
            let mut mock = MockTestBackendHandler::new();
            if synced {
                mock.expect_get_user_details()
                    .returning(|uid| Ok(synced_user(uid)));
            }
            setup_default_ldap_mock(&mut mock);
            mock.expect_registration_start().times(0);
            mock.expect_registration_finish().times(0);
            mock.expect_ensure_kerberos_principal_consistency().times(0);
            let mut ldap_handler = setup_bound_admin_handler(mock).await;
            let modify = LdapModifyRequest {
                dn: dn.to_owned(),
                changes: vec![LdapModify {
                    operation: LdapModifyType::Replace,
                    modification: ldap3_proto::LdapPartialAttribute {
                        atype: "userPassword".to_string(),
                        vals: vec![replaced.as_bytes().to_vec()],
                    },
                }],
            };
            let modified = ldap_handler.do_modify_request(&modify).await;
            let extended = LdapOp::ExtendedRequest(
                ldap3_proto::proto::LdapPasswordModifyRequest {
                    user_identity: Some(dn.to_owned()),
                    old_password: None,
                    new_password: Some(sent.to_string()),
                }
                .into(),
            );
            let extended = ldap_handler.handle_ldap_message(extended).await;
            assert_eq!(
                (modified, extended, guard.recorder().take_ops()),
                (
                    make_modify_failure_response(LdapResultCode::UnwillingToPerform, refusal),
                    Some(vec![make_extended_response(
                        LdapResultCode::UnwillingToPerform,
                        refusal.to_owned()
                    )]),
                    vec![]
                ),
                "synced {synced}, {sent:?}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_the_users_minimum_is_asked_at_modify_and_password_modify() {
        use lldap_domain_handlers::logging::LogKind;
        use lldap_test_utils::recording_log::LogGuard;
        let dn = "uid=bob,ou=people,dc=example,dc=com";
        let eleven = "Eleven-11ch";
        let rows: [(bool, Option<usize>, &str); 4] = [
            (
                false,
                Some(12),
                "the password must be at least 12 characters",
            ),
            (
                true,
                Some(12),
                "the password must be at least 12 characters",
            ),
            (
                false,
                None,
                "the password policy could not be read; try again",
            ),
            (
                true,
                None,
                "the password policy could not be read; try again",
            ),
        ];
        assert_eq!(eleven.chars().count(), 11);
        for (synced, min, refusal) in rows {
            let guard = RecordingGuard::install();
            let log = LogGuard::install_on_this_thread();
            let mut mock = MockTestBackendHandler::new();
            mock.expect_password_min_length()
                .with(mockall::predicate::eq(UserId::new("bob")))
                .times(2)
                .returning(move |_| {
                    min.ok_or_else(|| DomainError::InternalError("down".to_owned()))
                });
            if synced {
                mock.expect_get_user_details()
                    .returning(|uid| Ok(synced_user(uid)));
            }
            setup_default_ldap_mock(&mut mock);
            mock.expect_registration_start().times(0);
            mock.expect_registration_finish().times(0);
            mock.expect_ensure_kerberos_principal_consistency().times(0);
            let mut ldap_handler = setup_bound_admin_handler(mock).await;
            let modify = LdapModifyRequest {
                dn: dn.to_owned(),
                changes: vec![LdapModify {
                    operation: LdapModifyType::Replace,
                    modification: ldap3_proto::LdapPartialAttribute {
                        atype: "userPassword".to_string(),
                        vals: vec![eleven.as_bytes().to_vec()],
                    },
                }],
            };
            let modified = ldap_handler.do_modify_request(&modify).await;
            let extended = LdapOp::ExtendedRequest(
                ldap3_proto::proto::LdapPasswordModifyRequest {
                    user_identity: Some(dn.to_owned()),
                    old_password: None,
                    new_password: Some(eleven.to_owned()),
                }
                .into(),
            );
            let extended = ldap_handler.handle_ldap_message(extended).await;
            let logged: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.kind == LogKind::PasswordChange)
                .map(|e| (e.target, e.success, e.detail))
                .collect();
            let row = || (Some("bob".to_owned()), false, Some(refusal.to_owned()));
            assert_eq!(
                (modified, extended, guard.recorder().take_ops(), logged),
                (
                    make_modify_failure_response(LdapResultCode::UnwillingToPerform, refusal),
                    Some(vec![make_extended_response(
                        LdapResultCode::UnwillingToPerform,
                        refusal.to_owned()
                    )]),
                    vec![],
                    vec![row(), row()]
                ),
                "synced {synced}, {refusal}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_modify_password_answers_each_outcome_of_a_synced_change() {
        for (kdc, code, message) in kdc_rows() {
            let (guard, _offline, reached) = install(kdc.clone());
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_user_details()
                .returning(|uid| Ok(synced_user(uid)));
            setup_default_ldap_mock(&mut mock);
            if reached {
                expect_registration_start(&mut mock, "bob");
            } else {
                mock.expect_registration_start().times(0);
            }
            mock.expect_registration_finish().times(0);
            let ldap_handler = setup_bound_admin_handler(mock).await;
            let expected = match code {
                LdapResultCode::Success => make_modify_success_response(),
                code => make_modify_failure_response(code, &message),
            };
            assert_eq!(
                ldap_handler
                    .do_modify_request(&make_password_modify_request("bob"))
                    .await,
                expected,
                "{kdc:?}"
            );
            let ops = guard.map(|g| g.recorder().take_ops()).unwrap_or_default();
            assert_eq!(ops.len(), usize::from(reached), "{kdc:?}");
        }
    }
}
