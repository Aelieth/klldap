use crate::api::{Context, FullHandler, field_error_callback};
use crate::mutation::Success;
use juniper::{FieldError, FieldResult, graphql_value};
use lldap_access_control::{
    AdminBackendHandler, ReadonlyBackendHandler, UserWriteableBackendHandler,
};
use lldap_domain::{
    requests::{UpdateGroupRequest, UpdateUserRequest},
    types::{AttributeName, GroupId},
};
use lldap_domain_handlers::handler::SystemConfigBackendHandler;
use lldap_opaque_handler::OpaqueHandler;
use tracing::{debug, debug_span, info, warn};

pub(super) async fn create_ou<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    name: String,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] create_ou");
    span.in_scope(|| debug!(?name));

    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized OU creation"))?;

    let name_lower = name.trim().to_lowercase();
    if name_lower.is_empty()
        || name_lower == "all"
        || name_lower == "people"
        || name_lower == "groups"
    {
        return Err("Invalid OU name (cannot be empty or built-in)".into());
    }

    let parts: Vec<&str> = name.splitn(2, '\\').collect();
    let (primary, secondary) = match parts.len() {
        1 => (name.as_str(), None),
        2 => (parts[0], Some(parts[1])),
        _ => {
            return Err(FieldError::new(
                "Invalid OU format: only one level of secondary OU allowed (primary\\secondary)",
                juniper::Value::null(),
            ));
        }
    };

    if primary.len() < 2
        || primary.len() > 64
        || !primary
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        || primary.starts_with('-')
        || primary.starts_with('_')
        || primary.ends_with('-')
        || primary.ends_with('_')
    {
        return Err(FieldError::new(
            "Invalid primary OU name: 2-64 characters, only a-z A-Z 0-9 - _ allowed. No spaces or special characters.",
            juniper::Value::null(),
        ));
    }
    if let Some(sec) = secondary
        && (sec.trim().is_empty()
            || sec.len() < 2
            || sec.len() > 64
            || !sec
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            || sec.starts_with('-')
            || sec.starts_with('_')
            || sec.ends_with('-')
            || sec.ends_with('_'))
    {
        return Err(FieldError::new(
            "Invalid secondary OU name: 2-64 characters, only a-z A-Z 0-9 - _ allowed. No spaces or special characters.",
            juniper::Value::null(),
        ));
    }

    let mut current_ous = handler
        .get_allowed_ous()
        .await
        .map_err(|_e| FieldError::new("Failed to load allowedous", juniper::Value::null()))?;

    let name_lower = name.to_lowercase();
    if current_ous
        .iter()
        .any(|existing| existing.to_lowercase() == name_lower)
    {
        return Err(FieldError::new(
            format!("Organizational Unit '{}' already exists", name),
            juniper::Value::null(),
        ));
    }

    if secondary.is_some()
        && !current_ous
            .iter()
            .any(|p| p.to_lowercase() == primary.to_lowercase())
    {
        return Err(FieldError::new(
            format!(
                "Primary OU '{}' does not exist. Create it first before adding a secondary.",
                primary
            ),
            juniper::Value::null(),
        ));
    }

    current_ous.push(name.clone());
    current_ous.sort();

    handler
        .set_system_config("allowedous", serde_json::to_string(&current_ous).unwrap())
        .await
        .map_err(|_e| FieldError::new("Failed to save updated OU list", juniper::Value::null()))?;

    Ok(Success::new())
}

pub(super) async fn delete_ou<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    name: String,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] delete_ou");
    span.in_scope(|| debug!(?name));

    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized OU deletion"))?;

    let name_lower = name.trim().to_lowercase();
    if name_lower == "people" || name_lower == "groups" || name_lower == "all" {
        return Err("Cannot delete built-in OU 'people', 'groups', or 'All'".into());
    }

    let mut current_ous = handler
        .get_allowed_ous()
        .await
        .map_err(|_e| FieldError::new("Failed to load allowedous", juniper::Value::null()))?;

    let has_children = current_ous.iter().any(|ou| {
        let parts: Vec<&str> = ou.splitn(2, '\\').collect();
        parts.len() == 2 && parts[0].to_lowercase() == name_lower
    });

    if has_children {
        return Err(FieldError::new(
            format!(
                "Cannot delete primary OU '{}' because it still contains secondary OUs. Delete the secondary OUs first.",
                name
            ),
            juniper::Value::null(),
        ));
    }

    // === Reassign users and groups still in this OU to default OUs ===
    // This ensures no user/group is left pointing to a deleted OU.
    // Best-effort reassignment using the same pattern as change_user_ou / change_group_ou.

    // Reassign users still using this OU → move to "people"
    if let Ok(users) = handler.list_users(None, false).await {
        for user_and_groups in users {
            let current_ou = user_and_groups
                .user
                .attributes
                .iter()
                .find(|attr| attr.name.as_str() == "ou")
                .and_then(|attr| match &attr.value {
                    lldap_domain::types::AttributeValue::String(
                        lldap_domain::types::Cardinality::Singleton(s),
                    ) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_default();

            if current_ou.to_lowercase() == name_lower {
                let insert_attributes = vec![lldap_domain::types::Attribute {
                    name: AttributeName::from("ou"),
                    value: lldap_domain::types::AttributeValue::String(
                        lldap_domain::types::Cardinality::Singleton("people".to_string()),
                    ),
                }];

                let update_req = UpdateUserRequest {
                    user_id: user_and_groups.user.user_id.clone(),
                    email: None,
                    display_name: None,
                    delete_attributes: vec![],
                    insert_attributes,
                };

                if let Err(e) = handler.update_user(update_req).await {
                    warn!(
                        "Failed to reassign user {} from deleted OU '{}': {}",
                        user_and_groups.user.user_id, name, e
                    );
                } else {
                    info!(
                        "Reassigned user {} from deleted OU '{}' to 'people'",
                        user_and_groups.user.user_id, name
                    );
                }
            }
        }
    }

    // Reassign groups still using this OU → move to "groups"
    if let Ok(groups) = handler.list_groups(None).await {
        for group in groups {
            let current_ou = group
                .attributes
                .iter()
                .find(|attr| attr.name.as_str() == "ou")
                .and_then(|attr| match &attr.value {
                    lldap_domain::types::AttributeValue::String(
                        lldap_domain::types::Cardinality::Singleton(s),
                    ) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_default();

            if current_ou.to_lowercase() == name_lower {
                let insert_attributes = vec![lldap_domain::types::Attribute {
                    name: AttributeName::from("ou"),
                    value: lldap_domain::types::AttributeValue::String(
                        lldap_domain::types::Cardinality::Singleton("groups".to_string()),
                    ),
                }];

                let update_req = UpdateGroupRequest {
                    group_id: group.id,
                    display_name: None,
                    delete_attributes: vec![],
                    insert_attributes,
                };

                if let Err(e) = handler.update_group(update_req).await {
                    warn!(
                        "Failed to reassign group {} from deleted OU '{}': {}",
                        group.id.0, name, e
                    );
                } else {
                    info!(
                        "Reassigned group {} from deleted OU '{}' to 'groups'",
                        group.id.0, name
                    );
                }
            }
        }
    }

    // Now safe to remove the OU from the allowed list
    current_ous.retain(|o| o.to_lowercase() != name_lower);

    handler
        .set_system_config("allowedous", serde_json::to_string(&current_ous).unwrap())
        .await
        .map_err(|_e| FieldError::new("Failed to save updated OU list", juniper::Value::null()))?;

    info!("Organizational Unit '{}' deleted.", name);
    Ok(Success::new())
}

pub(super) async fn change_user_ou<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    user_ids: Vec<String>,
    new_ou: String,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] change_user_ou");
    span.in_scope(|| debug!(?user_ids, ?new_ou));

    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized OU change"))?;

    let name_lower = new_ou.trim().to_lowercase();
    if name_lower == "all" {
        return Err("Cannot move users to built-in OU 'All'".into());
    }

    for user_id_str in user_ids {
        let user_id = lldap_domain::types::UserId::new(&user_id_str);

        let insert_attributes = vec![lldap_domain::types::Attribute {
            name: lldap_domain::types::AttributeName::from("ou"),
            value: lldap_domain::types::AttributeValue::String(
                lldap_domain::types::Cardinality::Singleton(new_ou.clone()),
            ),
        }];

        let update_req = lldap_domain::requests::UpdateUserRequest {
            user_id: user_id.clone(),
            email: None,
            display_name: None,
            delete_attributes: vec![],
            insert_attributes,
        };

        handler.update_user(update_req).await.map_err(|e| {
            FieldError::new(
                format!("Failed to change OU for user {}", user_id_str),
                graphql_value!({ "details": (e.to_string()) }),
            )
        })?;
        info!("Changed OU for user {} to '{}'", user_id_str, new_ou);
    }

    Ok(Success::new())
}

pub(super) async fn change_group_ou<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    group_ids: Vec<i32>,
    new_ou: String,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] change_group_ou");
    span.in_scope(|| debug!(?group_ids, ?new_ou));

    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized OU change"))?;

    let name_lower = new_ou.trim().to_lowercase();
    if name_lower == "all" {
        return Err("Cannot move groups to built-in OU 'All'".into());
    }

    for group_id in group_ids {
        let group_id_typed = GroupId(group_id);

        let insert_attributes = vec![lldap_domain::types::Attribute {
            name: lldap_domain::types::AttributeName::from("ou"),
            value: lldap_domain::types::AttributeValue::String(
                lldap_domain::types::Cardinality::Singleton(new_ou.clone()),
            ),
        }];

        let update_req = lldap_domain::requests::UpdateGroupRequest {
            group_id: group_id_typed,
            display_name: None,
            delete_attributes: vec![],
            insert_attributes,
        };

        handler.update_group(update_req).await.map_err(|e| {
            FieldError::new(
                format!("Failed to change OU for group {}", group_id),
                graphql_value!({ "details": (e.to_string()) }),
            )
        })?;
        info!("Changed OU for group {} to '{}'", group_id, new_ou);
    }

    Ok(Success::new())
}
