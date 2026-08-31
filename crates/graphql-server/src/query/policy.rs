use crate::api::{Context, FullHandler, field_error_callback};
use anyhow::anyhow;
use juniper::{FieldResult, GraphQLObject};
use lldap_domain_handlers::handler::PolicyBackendHandler;
use lldap_domain_handlers::policies::{
    EffectiveItem, OuPolicyState, POLICY_ITEM_CATALOG, Policy, PolicyId, PolicyItemSpec,
    PolicyScope, canonical_ou_key, resolve_effective_items,
};
use lldap_opaque_handler::OpaqueHandler;
use std::str::FromStr;
use tracing::{Instrument, debug, debug_span};

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    juniper::GraphQLEnum,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[graphql(name = "PolicyScope")]
#[strum(serialize_all = "snake_case")]
pub enum GraphQLPolicyScope {
    User,
    Group,
    Computer,
    Server,
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    juniper::GraphQLEnum,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[graphql(name = "PolicyValueKind")]
#[strum(serialize_all = "snake_case")]
pub enum GraphQLPolicyValueKind {
    Bool,
    Int,
    Enum,
    String,
    StringList,
}

impl From<PolicyScope> for GraphQLPolicyScope {
    fn from(scope: PolicyScope) -> Self {
        Self::from_str(<&'static str>::from(scope)).expect("PolicyScope mirror")
    }
}

fn value_kind(spec: &PolicyItemSpec) -> GraphQLPolicyValueKind {
    use lldap_domain_handlers::policies::PolicyValueType;
    match spec.value_type {
        PolicyValueType::Bool => GraphQLPolicyValueKind::Bool,
        PolicyValueType::Int { .. } => GraphQLPolicyValueKind::Int,
        PolicyValueType::Enum { .. } => GraphQLPolicyValueKind::Enum,
        PolicyValueType::String { .. } => GraphQLPolicyValueKind::String,
        PolicyValueType::StringList { .. } => GraphQLPolicyValueKind::StringList,
    }
}

#[derive(GraphQLObject)]
pub struct GraphQLPolicyItem {
    pub key: String,
    pub value: String,
}

#[derive(GraphQLObject)]
pub struct GraphQLPolicy {
    pub id: i32,
    pub name: String,
    pub description: String,
    pub items: Vec<GraphQLPolicyItem>,
    /// Lowercase OU keys; the empty string is the domain root.
    pub linked_ous: Vec<String>,
}

#[derive(GraphQLObject)]
pub struct GraphQLPolicyCatalogItem {
    pub key: String,
    pub scope: GraphQLPolicyScope,
    pub value_kind: GraphQLPolicyValueKind,
    pub int_min: Option<i32>,
    pub int_max: Option<i32>,
    pub allowed_values: Option<Vec<String>>,
    pub default_value: String,
    pub enforced: bool,
    pub description: String,
}

#[derive(GraphQLObject)]
pub struct GraphQLEffectivePolicyItem {
    pub key: String,
    pub scope: GraphQLPolicyScope,
    pub value: String,
    pub enforced: bool,
    pub source_policy_id: Option<i32>,
    pub source_policy_name: Option<String>,
    pub source_ou: Option<String>,
}

#[derive(GraphQLObject)]
pub struct GraphQLOuPolicyState {
    pub ou: String,
    pub policy_id: Option<i32>,
    pub policy_name: Option<String>,
    pub block_inheritance: bool,
}

impl From<Policy> for GraphQLPolicy {
    fn from(policy: Policy) -> Self {
        Self {
            id: policy.id.0,
            name: policy.name,
            description: policy.description,
            items: policy
                .items
                .into_iter()
                .map(|(key, value)| GraphQLPolicyItem { key, value })
                .collect(),
            linked_ous: policy.linked_ous,
        }
    }
}

impl From<&PolicyItemSpec> for GraphQLPolicyCatalogItem {
    fn from(spec: &PolicyItemSpec) -> Self {
        use lldap_domain_handlers::policies::PolicyValueType;
        let (int_min, int_max, allowed_values) = match spec.value_type {
            PolicyValueType::Int { min, max } => (Some(min as i32), Some(max as i32), None),
            PolicyValueType::Enum { allowed } => (
                None,
                None,
                Some(allowed.iter().map(|s| (*s).to_owned()).collect()),
            ),
            _ => (None, None, None),
        };
        Self {
            key: spec.key.to_owned(),
            scope: spec.scope.into(),
            value_kind: value_kind(spec),
            int_min,
            int_max,
            allowed_values,
            default_value: spec.default_value.to_owned(),
            enforced: spec.enforced,
            description: spec.description.to_owned(),
        }
    }
}

impl From<EffectiveItem> for GraphQLEffectivePolicyItem {
    fn from(item: EffectiveItem) -> Self {
        Self {
            key: item.key,
            scope: item.scope.into(),
            value: item.value,
            enforced: item.enforced,
            source_policy_id: item.source.as_ref().map(|s| s.policy_id.0),
            source_policy_name: item.source.as_ref().map(|s| s.policy_name.clone()),
            source_ou: item.source.as_ref().map(|s| s.ou_key.clone()),
        }
    }
}

impl From<OuPolicyState> for GraphQLOuPolicyState {
    fn from(state: OuPolicyState) -> Self {
        Self {
            ou: state.ou_key,
            policy_id: state.policy_id.map(|id| id.0),
            policy_name: state.policy_name,
            block_inheritance: state.block_inheritance,
        }
    }
}

pub(super) async fn policies<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<Vec<GraphQLPolicy>> {
    let span = debug_span!("[GraphQL query] policies");
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized to read policies"))?;
    Ok(handler
        .list_policies()
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to list policies: {e}"))?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub(super) async fn policy<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    policy_id: i32,
) -> FieldResult<GraphQLPolicy> {
    let span = debug_span!("[GraphQL query] policy");
    span.in_scope(|| debug!(policy_id));
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized to read policies"))?;
    Ok(handler
        .get_policy(PolicyId(policy_id))
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to load policy: {e}"))?
        .into())
}

pub(super) fn policy_item_catalog<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<Vec<GraphQLPolicyCatalogItem>> {
    let span = debug_span!("[GraphQL query] policy_item_catalog");
    context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized to read policies"))?;
    Ok(POLICY_ITEM_CATALOG.iter().map(Into::into).collect())
}

pub(super) async fn effective_policy_items<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    ou: String,
) -> FieldResult<Vec<GraphQLEffectivePolicyItem>> {
    let span = debug_span!("[GraphQL query] effective_policy_items");
    span.in_scope(|| debug!(?ou));
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized to read policies"))?;
    let levels = handler
        .get_policy_levels(&canonical_ou_key(&ou))
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to load policy levels: {e}"))?;
    Ok(resolve_effective_items(POLICY_ITEM_CATALOG, &levels)
        .into_iter()
        .map(Into::into)
        .collect())
}

pub(super) async fn ou_policy_states<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<Vec<GraphQLOuPolicyState>> {
    let span = debug_span!("[GraphQL query] ou_policy_states");
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized to read policies"))?;
    Ok(handler
        .list_ou_policy_states()
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to load OU policy states: {e}"))?
        .into_iter()
        .map(Into::into)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lldap_domain_handlers::policies::PolicyScope;
    use pretty_assertions::assert_eq;
    use strum::IntoEnumIterator;

    #[test]
    fn test_policy_scope_mirror_round_trip() {
        for scope in PolicyScope::iter() {
            let graphql = GraphQLPolicyScope::from(scope);
            assert_eq!(<&'static str>::from(graphql), <&'static str>::from(scope));
        }
        assert_eq!(
            GraphQLPolicyScope::iter().count(),
            PolicyScope::iter().count()
        );
    }
}
