use crate::api::{Context, FullHandler, field_error_callback};
use crate::mutation::Success;
use crate::query::policy::GraphQLPolicy;
use anyhow::anyhow;
use juniper::{FieldResult, GraphQLInputObject};
use lldap_domain_handlers::handler::{PolicyBackendHandler, SystemConfigBackendHandler};
use lldap_domain_handlers::policies::{
    CreatePolicyRequest, PolicyId, ROOT_OU_KEY, UpdatePolicyRequest, canonical_ou_key,
    validate_items, validate_policy_name,
};
use lldap_opaque_handler::OpaqueHandler;
use std::collections::BTreeMap;
use tracing::{Instrument, debug, debug_span};

#[derive(GraphQLInputObject)]
pub struct PolicyItemInput {
    pub key: String,
    pub value: String,
}

fn fold_items(items: Option<Vec<PolicyItemInput>>) -> FieldResult<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for item in items.unwrap_or_default() {
        if map.insert(item.key.clone(), item.value).is_some() {
            return Err(format!("Duplicate policy item '{}'", item.key).into());
        }
    }
    validate_items(&map).map_err(|e| anyhow!(e))?;
    Ok(map)
}

async fn require_registered_ou(
    handler: &impl SystemConfigBackendHandler,
    ou_key: &str,
) -> FieldResult<()> {
    if ou_key == ROOT_OU_KEY {
        return Ok(());
    }
    let ous = handler
        .get_allowed_ous()
        .await
        .map_err(|e| anyhow!("Failed to load allowedous: {e}"))?;
    if ous
        .iter()
        .any(|existing| canonical_ou_key(existing) == ou_key)
    {
        Ok(())
    } else {
        Err(anyhow!("Unknown OU '{ou_key}'").into())
    }
}

pub(super) async fn create_policy<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    name: String,
    description: Option<String>,
    items: Option<Vec<PolicyItemInput>>,
) -> FieldResult<GraphQLPolicy> {
    let span = debug_span!("[GraphQL mutation] create_policy");
    span.in_scope(|| debug!(?name));
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized to write policies",
        ))?;
    let name = validate_policy_name(&name).map_err(|e| anyhow!(e))?;
    let items = fold_items(items)?;
    let lower = name.to_lowercase();
    if handler
        .list_policies()
        .await
        .map_err(|e| anyhow!("Failed to list policies: {e}"))?
        .iter()
        .any(|p| p.name.to_lowercase() == lower)
    {
        return Err(anyhow!("A policy named '{name}' already exists").into());
    }
    let id = handler
        .create_policy(CreatePolicyRequest {
            name,
            description: description.unwrap_or_default(),
            items,
        })
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to create policy: {e}"))?;
    Ok(handler
        .get_policy(id)
        .await
        .map_err(|e| anyhow!("Failed to load created policy: {e}"))?
        .into())
}

pub(super) async fn update_policy<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    policy_id: i32,
    name: Option<String>,
    description: Option<String>,
    items: Option<Vec<PolicyItemInput>>,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] update_policy");
    span.in_scope(|| debug!(policy_id));
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized to write policies",
        ))?;
    let name = name
        .map(|n| validate_policy_name(&n).map_err(|e| anyhow!(e)))
        .transpose()?;
    let items = items.map(|i| fold_items(Some(i))).transpose()?;
    if let Some(name) = &name {
        let lower = name.to_lowercase();
        if handler
            .list_policies()
            .await
            .map_err(|e| anyhow!("Failed to list policies: {e}"))?
            .iter()
            .any(|p| p.id.0 != policy_id && p.name.to_lowercase() == lower)
        {
            return Err(anyhow!("A policy named '{name}' already exists").into());
        }
    }
    handler
        .update_policy(UpdatePolicyRequest {
            id: PolicyId(policy_id),
            name,
            description,
            items,
        })
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to update policy: {e}"))?;
    Ok(Success::new())
}

pub(super) async fn delete_policy<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    policy_id: i32,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] delete_policy");
    span.in_scope(|| debug!(policy_id));
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized to write policies",
        ))?;
    handler
        .delete_policy(PolicyId(policy_id))
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to delete policy: {e}"))?;
    Ok(Success::new())
}

pub(super) async fn set_ou_policy<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    ou: String,
    policy_id: i32,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] set_ou_policy");
    span.in_scope(|| debug!(?ou, policy_id));
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized to write policies",
        ))?;
    let ou_key = canonical_ou_key(&ou);
    require_registered_ou(handler, &ou_key).await?;
    handler
        .set_ou_policy(&ou_key, PolicyId(policy_id))
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to set OU policy: {e}"))?;
    Ok(Success::new())
}

pub(super) async fn clear_ou_policy<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    ou: String,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] clear_ou_policy");
    span.in_scope(|| debug!(?ou));
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized to write policies",
        ))?;
    handler
        .clear_ou_policy(&canonical_ou_key(&ou))
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to clear OU policy: {e}"))?;
    Ok(Success::new())
}

pub(super) async fn set_ou_policy_inheritance<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    ou: String,
    blocked: bool,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] set_ou_policy_inheritance");
    span.in_scope(|| debug!(?ou, blocked));
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized to write policies",
        ))?;
    let ou_key = canonical_ou_key(&ou);
    if ou_key == ROOT_OU_KEY {
        return Err("The domain root cannot block inheritance".into());
    }
    require_registered_ou(handler, &ou_key).await?;
    handler
        .set_ou_policy_inheritance(&ou_key, blocked)
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to set OU inheritance: {e}"))?;
    Ok(Success::new())
}
