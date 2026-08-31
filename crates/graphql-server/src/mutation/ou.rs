use crate::api::{Context, FullHandler, field_error_callback};
use crate::mutation::Success;
use anyhow::anyhow;
use juniper::FieldResult;
use lldap_access_control::{
    AdminBackendHandler, ReadonlyBackendHandler, UserWriteableBackendHandler,
};
use lldap_domain::{
    requests::{UpdateGroupRequest, UpdateUserRequest},
    types::{Attribute, GroupId, UserId},
};
use lldap_domain_handlers::handler::{PolicyBackendHandler, SystemConfigBackendHandler};
use lldap_opaque_handler::OpaqueHandler;
use tracing::{debug, debug_span, info, warn};

const OU_NAME_RULES: &str =
    "2-64 characters, only a-z A-Z 0-9 - _ allowed. No spaces or special characters.";

fn is_valid_ou_component(name: &str) -> bool {
    (2..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !name.starts_with(['-', '_'])
        && !name.ends_with(['-', '_'])
}

fn ou_attribute(ou: &str) -> Attribute {
    Attribute {
        name: "ou".into(),
        value: ou.to_owned().into(),
    }
}

fn is_in_ou(attributes: &[Attribute], ou_lower: &str) -> bool {
    attributes.iter().any(|attribute| {
        attribute.name.as_str() == "ou"
            && attribute
                .value
                .as_str()
                .is_some_and(|ou| ou.to_lowercase() == ou_lower)
    })
}

async fn set_allowed_ous(
    handler: &impl SystemConfigBackendHandler,
    ous: &[String],
) -> FieldResult<()> {
    handler
        .set_system_config("allowedous", serde_json::to_string(ous)?)
        .await
        .map_err(|e| anyhow!("Failed to save updated OU list: {e}"))?;
    Ok(())
}

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
    if name_lower.is_empty() || ["all", "people", "groups"].contains(&name_lower.as_str()) {
        return Err("Invalid OU name (cannot be empty or built-in)".into());
    }
    let (primary, secondary) = match name.split_once('\\') {
        Some((primary, secondary)) => (primary, Some(secondary)),
        None => (name.as_str(), None),
    };
    if !is_valid_ou_component(primary) {
        return Err(anyhow!("Invalid primary OU name: {OU_NAME_RULES}").into());
    }
    if secondary.is_some_and(|secondary| !is_valid_ou_component(secondary)) {
        return Err(anyhow!("Invalid secondary OU name: {OU_NAME_RULES}").into());
    }
    let mut ous = handler
        .get_allowed_ous()
        .await
        .map_err(|e| anyhow!("Failed to load allowedous: {e}"))?;
    if ous
        .iter()
        .any(|existing| existing.to_lowercase() == name_lower)
    {
        return Err(anyhow!("Organizational Unit '{name}' already exists").into());
    }
    if secondary.is_some() && !ous.iter().any(|ou| ou.eq_ignore_ascii_case(primary)) {
        return Err(anyhow!(
            "Primary OU '{primary}' does not exist. Create it first before adding a secondary."
        )
        .into());
    }
    if let Err(e) = handler.delete_ou_policy_state(&name_lower).await {
        warn!("Failed to purge stale policy state for recreated OU '{name}': {e}");
    }
    ous.push(name);
    ous.sort();
    set_allowed_ous(handler, &ous).await?;
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
    if ["people", "groups", "all"].contains(&name_lower.as_str()) {
        return Err("Cannot delete built-in OU 'people', 'groups', or 'All'".into());
    }
    let mut ous = handler
        .get_allowed_ous()
        .await
        .map_err(|e| anyhow!("Failed to load allowedous: {e}"))?;
    if ous.iter().any(|ou| {
        ou.split_once('\\')
            .is_some_and(|(primary, _)| primary.to_lowercase() == name_lower)
    }) {
        return Err(anyhow!(
            "Cannot delete primary OU '{name}' because it still contains secondary OUs. Delete the secondary OUs first."
        )
        .into());
    }
    // Members of the deleted OU fall back to the default OUs, best effort.
    if let Ok(users) = handler.list_users(None, false).await {
        for user in users.into_iter().map(|u| u.user) {
            if !is_in_ou(&user.attributes, &name_lower) {
                continue;
            }
            let request = UpdateUserRequest {
                user_id: user.user_id.clone(),
                insert_attributes: vec![ou_attribute("people")],
                ..Default::default()
            };
            match handler.update_user(request).await {
                Ok(()) => info!(
                    "Reassigned user {} from deleted OU '{name}' to 'people'",
                    user.user_id
                ),
                Err(e) => warn!(
                    "Failed to reassign user {} from deleted OU '{name}': {e}",
                    user.user_id
                ),
            }
        }
    }
    if let Ok(groups) = handler.list_groups(None).await {
        for group in groups {
            if !is_in_ou(&group.attributes, &name_lower) {
                continue;
            }
            let request = UpdateGroupRequest {
                group_id: group.id,
                display_name: None,
                delete_attributes: vec![],
                insert_attributes: vec![ou_attribute("groups")],
            };
            match handler.update_group(request).await {
                Ok(()) => info!(
                    "Reassigned group {} from deleted OU '{name}' to 'groups'",
                    group.id.0
                ),
                Err(e) => warn!(
                    "Failed to reassign group {} from deleted OU '{name}': {e}",
                    group.id.0
                ),
            }
        }
    }
    ous.retain(|ou| ou.to_lowercase() != name_lower);
    set_allowed_ous(handler, &ous).await?;
    if let Err(e) = handler.delete_ou_policy_state(&name_lower).await {
        warn!("Failed to drop policy state for deleted OU '{name}': {e}");
    }
    info!("Organizational Unit '{name}' deleted.");
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
    if new_ou.trim().eq_ignore_ascii_case("all") {
        return Err("Cannot move users to built-in OU 'All'".into());
    }
    for user_id in user_ids {
        let request = UpdateUserRequest {
            user_id: UserId::new(&user_id),
            insert_attributes: vec![ou_attribute(&new_ou)],
            ..Default::default()
        };
        handler
            .update_user(request)
            .await
            .map_err(|e| anyhow!("Failed to change OU for user {user_id}: {e}"))?;
        info!("Changed OU for user {user_id} to '{new_ou}'");
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
    if new_ou.trim().eq_ignore_ascii_case("all") {
        return Err("Cannot move groups to built-in OU 'All'".into());
    }
    for group_id in group_ids {
        let request = UpdateGroupRequest {
            group_id: GroupId(group_id),
            display_name: None,
            delete_attributes: vec![],
            insert_attributes: vec![ou_attribute(&new_ou)],
        };
        handler
            .update_group(request)
            .await
            .map_err(|e| anyhow!("Failed to change OU for group {group_id}: {e}"))?;
        info!("Changed OU for group {group_id} to '{new_ou}'");
    }
    Ok(Success::new())
}
