use crate::{
    core::{
        error::{LdapError, LdapResult},
        utils::{LdapInfo, get_user_id_from_distinguished_name},
    },
    handler::make_modify_response,
    password,
};
use ldap3_proto::proto::{LdapModify, LdapModifyRequest, LdapModifyType, LdapOp, LdapResultCode};
use lldap_access_control::{UserReadableBackendHandler, UserWriteableBackendHandler};
use lldap_auth::access_control::ValidationResults;
use lldap_domain::{
    deserialize,
    requests::UpdateUserRequest,
    types::{Attribute, AttributeName, AttributeType, Email, UserId},
};
use lldap_opaque_handler::OpaqueHandler;
use tracing::warn;

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
    let canonical = lldap_domain::public_schema::PublicSchema::shared()
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

fn typed_insert_attribute(
    name: &str,
    vals: &[String],
    typ: AttributeType,
    is_list: bool,
) -> LdapResult<Attribute> {
    Ok(Attribute {
        name: name.into(),
        value: deserialize::deserialize_attribute_value(vals, typ, is_list).map_err(|e| {
            LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!("Invalid {name} value: {e}"),
            }
        })?,
    })
}

async fn handle_modify_change(
    readable_handler: &impl UserReadableBackendHandler,
    writeable_handler: &impl UserWriteableBackendHandler,
    opaque_handler: &impl OpaqueHandler,
    user_id: UserId,
    credentials: &ValidationResults,
    user_is_admin: bool,
    change: &LdapModify,
) -> LdapResult<()> {
    let atype_lower = change.modification.atype.to_ascii_lowercase();

    if atype_lower == "userpassword" {
        if change.operation != LdapModifyType::Replace {
            return Err(LdapError {
                code: LdapResultCode::UnwillingToPerform,
                message: format!(
                    r#"Unsupported operation: `{:?}` for `{}`"#,
                    change.operation, change.modification.atype
                ),
            });
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

        if let [value] = &change.modification.vals.as_slice() {
            password::change_password(opaque_handler, user_id.clone(), value)
                .await
                .map_err(|e| LdapError {
                    code: LdapResultCode::Other,
                    message: format!("Error while changing the password: {e:#?}"),
                })?;

            if let Ok(plain_pass) = std::str::from_utf8(value) {
                let user = match readable_handler.get_user_details(&user_id).await {
                    Ok(u) => u,
                    Err(e) => {
                        warn!("Failed to fetch user for Kerberos sync check: {}", e);
                        return Ok(());
                    }
                };

                let sync_enabled =
                    lldap_domain::types::kerberos_sync_enabled(&user.attributes, "kerberossync");

                if let Err(e) = lldap_kerberos::sync_kerberos_if_enabled(
                    sync_enabled,
                    user_id.as_str(),
                    plain_pass,
                ) {
                    warn!("Kerberos sync failed after LDAP password change: {}", e);
                }

                // A first password for an already-disabled user would otherwise mint a live principal.
                if sync_enabled
                    && let Ok(groups) = readable_handler.get_user_groups(&user_id).await
                    && groups
                        .iter()
                        .any(|g| g.display_name == "lldap_disabled".into())
                {
                    lldap_kerberos::reassert_kerberos_disabled(user_id.as_str());
                }
            }
            Ok(())
        } else {
            Err(LdapError {
                code: LdapResultCode::InvalidAttributeSyntax,
                message: format!(
                    r#"Wrong number of values for password attribute: {}"#,
                    change.modification.vals.len()
                ),
            })
        }
    } else {
        // === Profile attributes: now support Add / Replace / Delete ===
        if !credentials.can_change_password(&user_id, user_is_admin) {
            return Err(LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: format!(
                    r#"User `{}` cannot modify attributes of user `{}`"#,
                    credentials.user, user_id
                ),
            });
        }

        // Protect mail (Email) and cn/displayname (DisplayName) from deletion.
        if change.operation == LdapModifyType::Delete
            && matches!(
                modify_target(&atype_lower),
                ModifyTarget::Email | ModifyTarget::DisplayName
            )
        {
            return Err(LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: format!(
                    r#"Deletion of `{}` is not allowed via LDAP Modify (use GraphQL or protected path)"#,
                    change.modification.atype
                ),
            });
        }

        let mut email: Option<Email> = None;
        let mut display_name: Option<String> = None;
        let mut insert_attributes: Vec<Attribute> = Vec::new();
        let mut delete_attributes: Vec<AttributeName> = Vec::new();

        match change.operation {
            LdapModifyType::Replace => {
                let vals: Vec<String> = change
                    .modification
                    .vals
                    .iter()
                    .filter_map(|v| std::str::from_utf8(v).ok().map(|s| s.to_string()))
                    .collect();

                if vals.is_empty() {
                    return Err(LdapError {
                        code: LdapResultCode::InvalidAttributeSyntax,
                        message: format!("No values provided for {}", change.modification.atype),
                    });
                }

                match modify_target(&atype_lower) {
                    ModifyTarget::FirstName => insert_attributes.push(typed_insert_attribute(
                        "first_name",
                        &vals,
                        AttributeType::String,
                        false,
                    )?),
                    ModifyTarget::LastName => insert_attributes.push(typed_insert_attribute(
                        "last_name",
                        &vals,
                        AttributeType::String,
                        false,
                    )?),
                    ModifyTarget::DisplayName => display_name = Some(vals[0].clone()),
                    ModifyTarget::Email => email = Some(Email::from(vals[0].clone())),
                    ModifyTarget::Avatar => insert_attributes.push(typed_insert_attribute(
                        "avatar",
                        &vals,
                        AttributeType::Avatar,
                        false,
                    )?),
                    ModifyTarget::SshPublicKey => insert_attributes.push(typed_insert_attribute(
                        "sshpublickey",
                        &vals,
                        AttributeType::String,
                        true,
                    )?),
                    ModifyTarget::Ou => {
                        return Err(LdapError {
                            code: LdapResultCode::UnwillingToPerform,
                            message:
                                "Direct modification of 'ou' via LDAP Modify is not supported."
                                    .to_string(),
                        });
                    }
                    ModifyTarget::Unsupported => {
                        return Err(LdapError {
                            code: LdapResultCode::UnwillingToPerform,
                            message: format!(
                                "Unsupported attribute for LDAP Modify: {} (supported: givenName, sn, cn, mail, avatar, sshPublicKey, userPassword)",
                                change.modification.atype
                            ),
                        });
                    }
                }
            }

            LdapModifyType::Add => {
                let new_vals: Vec<String> = change
                    .modification
                    .vals
                    .iter()
                    .filter_map(|v| std::str::from_utf8(v).ok().map(|s| s.to_string()))
                    .collect();

                if new_vals.is_empty() {
                    return Err(LdapError {
                        code: LdapResultCode::InvalidAttributeSyntax,
                        message: format!("No values provided for {}", change.modification.atype),
                    });
                }

                if matches!(modify_target(&atype_lower), ModifyTarget::SshPublicKey) {
                    let user = readable_handler
                        .get_user_details(&user_id)
                        .await
                        .map_err(|e| LdapError {
                            code: LdapResultCode::OperationsError,
                            message: format!("Failed to read current user: {e}"),
                        })?;

                    let mut existing: Vec<String> = user
                        .attributes
                        .iter()
                        .find(|a| a.name.as_str() == "sshpublickey")
                        .and_then(|a| match &a.value {
                            lldap_domain::types::AttributeValue::String(
                                lldap_domain::types::Cardinality::Unbounded(list),
                            ) => Some(list.clone()),
                            lldap_domain::types::AttributeValue::String(
                                lldap_domain::types::Cardinality::Singleton(s),
                            ) => Some(vec![s.clone()]),
                            _ => None,
                        })
                        .unwrap_or_default();

                    for v in new_vals {
                        if !existing.contains(&v) {
                            existing.push(v);
                        }
                    }

                    insert_attributes.push(Attribute {
                        name: "sshpublickey".into(),
                        value: deserialize::deserialize_attribute_value(
                            &existing,
                            AttributeType::String,
                            true,
                        )
                        .map_err(|e| LdapError {
                            code: LdapResultCode::ConstraintViolation,
                            message: format!("Invalid sshPublicKey value: {e}"),
                        })?,
                    });
                } else {
                    match modify_target(&atype_lower) {
                        ModifyTarget::FirstName => insert_attributes.push(typed_insert_attribute(
                            "first_name",
                            &new_vals,
                            AttributeType::String,
                            false,
                        )?),
                        ModifyTarget::LastName => insert_attributes.push(typed_insert_attribute(
                            "last_name",
                            &new_vals,
                            AttributeType::String,
                            false,
                        )?),
                        ModifyTarget::DisplayName => display_name = Some(new_vals[0].clone()),
                        ModifyTarget::Email => email = Some(Email::from(new_vals[0].clone())),
                        ModifyTarget::Avatar => insert_attributes.push(typed_insert_attribute(
                            "avatar",
                            &new_vals,
                            AttributeType::Avatar,
                            false,
                        )?),
                        _ => {
                            return Err(LdapError {
                                code: LdapResultCode::UnwillingToPerform,
                                message: format!(
                                    "Add not supported for {}",
                                    change.modification.atype
                                ),
                            });
                        }
                    }
                }
            }

            LdapModifyType::Delete => {
                let delete_vals: Vec<String> = change
                    .modification
                    .vals
                    .iter()
                    .filter_map(|v| std::str::from_utf8(v).ok().map(|s| s.to_string()))
                    .collect();

                if matches!(modify_target(&atype_lower), ModifyTarget::SshPublicKey) {
                    if delete_vals.is_empty() {
                        // No specific values → delete whole attribute
                        delete_attributes.push(AttributeName::from("sshpublickey"));
                    } else {
                        // Specific keys provided → remove only those exact keys
                        let user =
                            readable_handler
                                .get_user_details(&user_id)
                                .await
                                .map_err(|e| LdapError {
                                    code: LdapResultCode::OperationsError,
                                    message: format!("Failed to read current user: {e}"),
                                })?;

                        let existing: Vec<String> = user
                            .attributes
                            .iter()
                            .find(|a| a.name.as_str() == "sshpublickey")
                            .and_then(|a| match &a.value {
                                lldap_domain::types::AttributeValue::String(
                                    lldap_domain::types::Cardinality::Unbounded(list),
                                ) => Some(list.clone()),
                                lldap_domain::types::AttributeValue::String(
                                    lldap_domain::types::Cardinality::Singleton(s),
                                ) => Some(vec![s.clone()]),
                                _ => None,
                            })
                            .unwrap_or_default();

                        let remaining: Vec<String> = existing
                            .into_iter()
                            .filter(|k| !delete_vals.contains(k))
                            .collect();

                        if remaining.is_empty() {
                            delete_attributes.push(AttributeName::from("sshpublickey"));
                        } else {
                            insert_attributes.push(Attribute {
                                name: "sshpublickey".into(),
                                value: deserialize::deserialize_attribute_value(
                                    &remaining,
                                    AttributeType::String,
                                    true,
                                )
                                .map_err(|e| LdapError {
                                    code: LdapResultCode::ConstraintViolation,
                                    message: format!("Invalid sshPublicKey value: {e}"),
                                })?,
                            });
                        }
                    }
                } else {
                    // Non-sshPublicKey delete (whole attribute)
                    match modify_target(&atype_lower) {
                        ModifyTarget::FirstName => {
                            delete_attributes.push(AttributeName::from("first_name"))
                        }
                        ModifyTarget::LastName => {
                            delete_attributes.push(AttributeName::from("last_name"))
                        }
                        ModifyTarget::Avatar => {
                            delete_attributes.push(AttributeName::from("avatar"))
                        }
                        _ => {
                            return Err(LdapError {
                                code: LdapResultCode::UnwillingToPerform,
                                message: format!(
                                    "Deletion not supported for {}",
                                    change.modification.atype
                                ),
                            });
                        }
                    }
                }
            }
        }

        let update_req = UpdateUserRequest {
            user_id: user_id.clone(),
            email,
            display_name,
            delete_attributes,
            insert_attributes,
        };

        writeable_handler
            .update_user(update_req)
            .await
            .map_err(|e| LdapError {
                code: LdapResultCode::OperationsError,
                message: format!("Error while updating user via LDAP Modify: {e:#?}"),
            })?;

        Ok(())
    }
}

pub(crate) async fn handle_modify_request<'cred, UserBackendHandler, WriteBackendHandler>(
    opaque_handler: &impl OpaqueHandler,
    get_readable_handler: impl Fn(&'cred ValidationResults, UserId) -> Option<&'cred UserBackendHandler>,
    get_writeable_handler: impl Fn(
        &'cred ValidationResults,
        UserId,
    ) -> Option<&'cred WriteBackendHandler>,
    ldap_info: &LdapInfo,
    credentials: &'cred ValidationResults,
    request: &LdapModifyRequest,
) -> LdapResult<Vec<LdapOp>>
where
    UserBackendHandler: UserReadableBackendHandler + 'cred,
    WriteBackendHandler: UserWriteableBackendHandler + 'cred,
{
    match get_user_id_from_distinguished_name(
        &request.dn,
        &ldap_info.base_dn,
        &ldap_info.base_dn_str,
    ) {
        Ok(uid) => {
            for change in &request.changes {
                let readable_handler =
                    get_readable_handler(credentials, uid.clone()).ok_or_else(|| LdapError {
                        code: LdapResultCode::InsufficentAccessRights,
                        message: format!(
                            "User `{}` cannot modify user `{}`",
                            credentials.user.as_str(),
                            uid.as_str()
                        ),
                    })?;

                let writeable_handler = get_writeable_handler(credentials, uid.clone())
                    .ok_or_else(|| LdapError {
                        code: LdapResultCode::InsufficentAccessRights,
                        message: format!(
                            "User `{}` cannot modify user `{}` (no write permission)",
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

                handle_modify_change(
                    readable_handler,
                    writeable_handler,
                    opaque_handler,
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
    use ldap3_proto::proto::LdapResult as LdapResultOp;
    use lldap_domain::types::{GroupDetails, GroupId, UserId};
    use lldap_test_utils::{MockTestBackendHandler, setup_default_ldap_mock};
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    fn setup_password_change_expectations(mock: &mut MockTestBackendHandler, user: &str) {
        use lldap_auth::{opaque, registration};
        let mut rng = rand::rngs::OsRng;
        let registration_start_request =
            opaque::client::registration::start_registration("password".as_bytes(), &mut rng)
                .unwrap();

        let request = registration::ClientRegistrationStartRequest {
            username: user.into(),
            registration_start_request: registration_start_request.message,
        };

        let start_response = opaque::server::registration::start_registration(
            &opaque::server::ServerSetup::new(&mut rng),
            request.registration_start_request,
            &request.username,
        )
        .unwrap();

        mock.expect_registration_start()
            .times(1)
            .return_once(move |_| {
                Ok(registration::ServerRegistrationStartResponse {
                    server_data: "".to_string(),
                    registration_response: start_response.message,
                })
            });
        mock.expect_registration_finish()
            .times(1)
            .return_once(|_| Ok(()));
    }

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

    // ========================================================================
    // PASSWORD TESTS
    // ========================================================================

    #[tokio::test]
    async fn test_modify_password_of_regular_as_admin() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "bob");
        let ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler
                .do_modify_request(&make_password_modify_request("bob"))
                .await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_password_of_regular_as_regular() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "test");
        let ldap_handler = setup_bound_handler_with_group(mock, "regular").await;
        assert_eq!(
            ldap_handler
                .do_modify_request(&make_password_modify_request("test"))
                .await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_password_of_regular_as_password_manager() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "bob");
        let ldap_handler = setup_bound_password_manager_handler(mock).await;
        assert_eq!(
            ldap_handler
                .do_modify_request(&make_password_modify_request("bob"))
                .await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_password_bad_primary_dn() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        let ldap_handler = setup_bound_admin_handler(mock).await;

        let request = LdapModifyRequest {
            dn: "uid=bob,ou=people,dc=example,dc=fr".to_string(),
            changes: vec![LdapModify {
                operation: LdapModifyType::Replace,
                modification: ldap3_proto::LdapPartialAttribute {
                    atype: "userPassword".to_string(),
                    vals: vec![b"newpassword".to_vec()],
                },
            }],
        };
        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_failure_response(
                LdapResultCode::InvalidDNSyntax,
                "Invalid username: Not a subtree of the base tree"
            )
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
                "User `test` cannot modify user `bob` (no write permission)"
            )
        );
    }

    #[tokio::test]
    async fn test_modify_password_of_admin_as_admin() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "test");
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

    // ========================================================================
    // NEW PROFILE ATTRIBUTE MODIFY TESTS (givenName, sn, cn, mail, avatar, sshPublicKey)
    // ========================================================================

    fn make_profile_modify_request(
        target_user: &str,
        attr: &str,
        value: &str,
    ) -> LdapModifyRequest {
        LdapModifyRequest {
            dn: format!("uid={target_user},ou=people,dc=example,dc=com"),
            changes: vec![LdapModify {
                operation: LdapModifyType::Replace,
                modification: ldap3_proto::LdapPartialAttribute {
                    atype: attr.to_string(),
                    vals: vec![value.as_bytes().to_vec()],
                },
            }],
        }
    }

    #[tokio::test]
    async fn test_modify_givenname_as_self() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        // Expect update_user call with first_name
        mock.expect_update_user()
            .with(mockall::predicate::function(
                |req: &lldap_domain::requests::UpdateUserRequest| {
                    req.user_id == UserId::new("test")
                        && req
                            .insert_attributes
                            .iter()
                            .any(|a| a.name.as_str() == "first_name")
                },
            ))
            .times(1)
            .return_once(|_| Ok(()));

        let ldap_handler = setup_bound_handler_with_group(mock, "regular").await;
        let request = make_profile_modify_request("test", "givenName", "Alice");
        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_sn_as_admin() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_update_user()
            .with(mockall::predicate::function(
                |req: &lldap_domain::requests::UpdateUserRequest| {
                    req.user_id == UserId::new("bob")
                        && req
                            .insert_attributes
                            .iter()
                            .any(|a| a.name.as_str() == "last_name")
                },
            ))
            .times(1)
            .return_once(|_| Ok(()));

        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_profile_modify_request("bob", "sn", "Smith");
        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_mail_as_admin() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_update_user()
            .with(mockall::predicate::function(
                |req: &lldap_domain::requests::UpdateUserRequest| {
                    req.user_id == UserId::new("bob") && req.email.is_some()
                },
            ))
            .times(1)
            .return_once(|_| Ok(()));

        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_profile_modify_request("bob", "mail", "bob.smith@example.com");
        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_cn_displayname_as_self() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_update_user()
            .with(mockall::predicate::function(
                |req: &lldap_domain::requests::UpdateUserRequest| {
                    req.user_id == UserId::new("test")
                        && req.display_name == Some("Test User".to_string())
                },
            ))
            .times(1)
            .return_once(|_| Ok(()));

        let ldap_handler = setup_bound_handler_with_group(mock, "regular").await;
        let request = make_profile_modify_request("test", "cn", "Test User");
        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_avatar_and_sshpublickey_as_admin() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_update_user()
            .times(2) // one for avatar, one for ssh
            .returning(|_| Ok(()));

        let ldap_handler = setup_bound_admin_handler(mock).await;

        let avatar_req = make_profile_modify_request(
            "bob",
            "avatar",
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==",
        );
        assert_eq!(
            ldap_handler.do_modify_request(&avatar_req).await,
            make_modify_success_response()
        );

        let ssh_req = make_profile_modify_request(
            "bob",
            "sshPublicKey",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABCCCBAQCExampleRSAKeyForTestingOnly2048bit testuser@otherlab",
        );
        assert_eq!(
            ldap_handler.do_modify_request(&ssh_req).await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_unsupported_attribute() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        let ldap_handler = setup_bound_admin_handler(mock).await;

        let request = make_profile_modify_request("bob", "title", "Manager");

        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_failure_response(
                LdapResultCode::UnwillingToPerform,
                "Unsupported attribute for LDAP Modify: title (supported: givenName, sn, cn, mail, avatar, sshPublicKey, userPassword)"
            )
        );
    }

    fn make_delete_modify_request(user: &str, atype: &str) -> LdapModifyRequest {
        LdapModifyRequest {
            dn: format!("uid={user},ou=people,dc=example,dc=com"),
            changes: vec![LdapModify {
                operation: LdapModifyType::Delete,
                modification: ldap3_proto::LdapPartialAttribute {
                    atype: atype.to_string(),
                    vals: vec![],
                },
            }],
        }
    }

    #[tokio::test]
    async fn test_modify_delete_of_protected_attributes_rejected() {
        for atype in ["mail", "email", "cn", "displayname", "commonname"] {
            let mut mock = MockTestBackendHandler::new();
            setup_default_ldap_mock(&mut mock);
            let ldap_handler = setup_bound_admin_handler(mock).await;
            assert_eq!(
                ldap_handler
                    .do_modify_request(&make_delete_modify_request("bob", atype))
                    .await,
                make_modify_failure_response(
                    LdapResultCode::InsufficentAccessRights,
                    &format!(
                        "Deletion of `{atype}` is not allowed via LDAP Modify (use GraphQL or protected path)"
                    )
                )
            );
        }
    }

    fn make_add_modify_request(user: &str, atype: &str, value: &str) -> LdapModifyRequest {
        LdapModifyRequest {
            dn: format!("uid={user},ou=people,dc=example,dc=com"),
            changes: vec![LdapModify {
                operation: LdapModifyType::Add,
                modification: ldap3_proto::LdapPartialAttribute {
                    atype: atype.to_string(),
                    vals: vec![value.as_bytes().to_vec()],
                },
            }],
        }
    }

    // Pins that the 5 non-schema wire-names (schema aliases since Stage 1) still route to the
    // right sink on Replace — guards the ModifyTarget collapse.
    #[tokio::test]
    async fn test_modify_replace_non_schema_wire_names() {
        async fn check(
            atype: &str,
            value: &str,
            pred: fn(&lldap_domain::requests::UpdateUserRequest) -> bool,
        ) {
            let mut mock = MockTestBackendHandler::new();
            setup_default_ldap_mock(&mut mock);
            mock.expect_update_user()
                .with(mockall::predicate::function(
                    move |req: &lldap_domain::requests::UpdateUserRequest| {
                        req.user_id == UserId::new("bob") && pred(req)
                    },
                ))
                .times(1)
                .return_once(|_| Ok(()));
            let ldap_handler = setup_bound_admin_handler(mock).await;
            let request = make_profile_modify_request("bob", atype, value);
            assert_eq!(
                ldap_handler.do_modify_request(&request).await,
                make_modify_success_response()
            );
        }

        const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==";
        check("surname", "Smith", |r| {
            r.insert_attributes
                .iter()
                .any(|a| a.name.as_str() == "last_name")
        })
        .await;
        check("commonname", "Bob", |r| {
            r.display_name == Some("Bob".to_string())
        })
        .await;
        check("given_name", "Alice", |r| {
            r.insert_attributes
                .iter()
                .any(|a| a.name.as_str() == "first_name")
        })
        .await;
        check("jpeg_photo", PNG, |r| {
            r.insert_attributes
                .iter()
                .any(|a| a.name.as_str() == "avatar")
        })
        .await;
        check(
            "ssh_public_key",
            "ssh-rsa AAAAB3NzaC1yc2E testuser@host",
            |r| {
                r.insert_attributes
                    .iter()
                    .any(|a| a.name.as_str() == "sshpublickey")
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_modify_add_givenname_inserts_first_name() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        mock.expect_update_user()
            .with(mockall::predicate::function(
                |req: &lldap_domain::requests::UpdateUserRequest| {
                    req.user_id == UserId::new("bob")
                        && req
                            .insert_attributes
                            .iter()
                            .any(|a| a.name.as_str() == "first_name")
                },
            ))
            .times(1)
            .return_once(|_| Ok(()));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_add_modify_request("bob", "givenName", "Alice");
        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_delete_givenname_deletes_first_name() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        mock.expect_update_user()
            .with(mockall::predicate::function(
                |req: &lldap_domain::requests::UpdateUserRequest| {
                    req.user_id == UserId::new("bob")
                        && req
                            .delete_attributes
                            .iter()
                            .any(|a| a.as_str() == "first_name")
                },
            ))
            .times(1)
            .return_once(|_| Ok(()));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_delete_modify_request("bob", "givenName");
        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_success_response()
        );
    }

    // Setting a password for a kerberossync=1 user already in lldap_disabled must still
    // succeed — re-asserting -allow_tix is best-effort and no-ops without a KDC.
    #[tokio::test]
    async fn test_modify_password_born_disabled_reasserts_and_succeeds() {
        use mockall::predicate::eq;
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "bob");

        // bob is kerberossync-managed …
        mock.expect_get_user_details()
            .with(eq(UserId::new("bob")))
            .returning(|uid| {
                Ok(lldap_domain::types::User {
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
                })
            });
        // … and already disabled.
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .returning(|_| {
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
                Ok(set)
            });

        let ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler
                .do_modify_request(&make_password_modify_request("bob"))
                .await,
            make_modify_success_response()
        );
    }
}
