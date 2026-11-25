use super::attribute::AttributeValue;
use super::group::Group;
use crate::api::Context;
use chrono::{DateTime, TimeZone, Utc};
use juniper::{FieldResult, GraphQLObject, graphql_object};
use lldap_access_control::UserReadableBackendHandler;
use lldap_domain::types::{
    MFA_TYPE_TOTP, User as DomainUser, UserAndGroups as DomainUserAndGroups,
};
use lldap_domain_handlers::handler::{
    BackendHandler, LockoutBackendHandler, MfaBackendHandler, SignInState as DomainSignInState,
};
use lldap_domain_handlers::instant::to_utc;
use lldap_domain_handlers::mfa::MfaPolicy;
use lldap_opaque_handler::OpaqueHandler;
use lldap_schema::PublicSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{Instrument, debug, debug_span};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
/// Represents a single user.
pub struct User<Handler: BackendHandler> {
    user: DomainUser,
    attributes: Vec<AttributeValue<Handler>>,
    schema: Arc<PublicSchema>,
    groups: Option<Vec<Group<Handler>>>,
    alone: bool,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

impl<Handler: BackendHandler> User<Handler> {
    pub fn from_user(mut user: DomainUser, schema: Arc<PublicSchema>) -> FieldResult<Self> {
        let attributes = AttributeValue::<Handler>::user_attributes_from_schema(&mut user, &schema);
        Ok(Self {
            user,
            attributes,
            schema,
            groups: None,
            alone: false,
            _phantom: std::marker::PhantomData,
        })
    }

    pub fn asked_alone(self) -> Self {
        Self {
            alone: true,
            ..self
        }
    }
}

impl<Handler: BackendHandler> User<Handler> {
    pub fn from_user_and_groups(
        DomainUserAndGroups { user, groups }: DomainUserAndGroups,
        schema: Arc<PublicSchema>,
    ) -> FieldResult<Self> {
        let mut user = Self::from_user(user, schema.clone())?;
        if let Some(groups) = groups {
            user.groups = Some(
                groups
                    .into_iter()
                    .map(|g| Group::<Handler>::from_group_details(g, schema.clone()))
                    .collect::<FieldResult<Vec<_>>>()?,
            );
        }
        Ok(user)
    }
}

/// Whether the doors refuse a user now (admins only).
#[derive(PartialEq, Eq, Debug, GraphQLObject)]
pub struct SignInState {
    /// Refused by the lockout now.
    locked: bool,
    /// The lock's end; null while it holds until an admin unlocks, or when not locked.
    locked_until: Option<DateTime<Utc>>,
    /// Refused by inactivity-days now.
    inactive: bool,
    /// When the idle time passed the limit; null when not inactive.
    inactive_since: Option<DateTime<Utc>>,
}

impl From<DomainSignInState> for SignInState {
    fn from(state: DomainSignInState) -> Self {
        Self {
            locked: state.locked,
            locked_until: state.locked_until.map(to_utc),
            inactive: state.inactive_since.is_some(),
            inactive_since: state.inactive_since.map(to_utc),
        }
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler + OpaqueHandler> User<Handler> {
    fn id(&self) -> &str {
        self.user.user_id.as_str()
    }

    fn email(&self) -> &str {
        self.user.email.as_str()
    }

    fn display_name(&self) -> &str {
        self.user.display_name.as_deref().unwrap_or("")
    }

    fn first_name(&self) -> &str {
        let canonical = self
            .schema
            .resolve_user_canonical_name("first_name")
            .unwrap_or("firstname");
        self.attributes
            .iter()
            .find(|a| a.name() == canonical)
            .and_then(|a| a.attribute.value.as_str())
            .unwrap_or_default()
    }

    fn last_name(&self) -> &str {
        let canonical = self
            .schema
            .resolve_user_canonical_name("last_name")
            .unwrap_or("lastname");
        self.attributes
            .iter()
            .find(|a| a.name() == canonical)
            .and_then(|a| a.attribute.value.as_str())
            .unwrap_or_default()
    }

    fn avatar(&self) -> Option<String> {
        self.attributes
            .iter()
            .find(|a| a.name() == "avatar")
            .and_then(|a| {
                super::serialize_attribute_to_graphql(&a.attribute.value)
                    .into_iter()
                    .next()
            })
    }

    /// The OU of the user, "people" by default. Admin-editable.
    fn ou(&self) -> String {
        let canonical = self
            .schema
            .resolve_user_canonical_name("ou")
            .unwrap_or("ou");
        self.attributes
            .iter()
            .find(|a| a.name() == canonical)
            .and_then(|a| a.attribute.value.as_str())
            .unwrap_or("people")
            .to_string()
    }

    /// SSH public keys, one per authorized_keys line.
    fn ssh_public_keys(&self) -> Vec<String> {
        let canonical = self
            .schema
            .resolve_user_canonical_name("sshpublickey")
            .unwrap_or("sshpublickey");
        self.attributes
            .iter()
            .find(|a| a.name() == canonical)
            .map(|a| super::serialize_attribute_to_graphql(&a.attribute.value))
            .unwrap_or_default()
    }

    fn creation_date(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.from_utc_datetime(&self.user.creation_date)
    }

    fn uuid(&self) -> &str {
        self.user.uuid.as_str()
    }

    /// Whether the user is a member of the built-in lldap_disabled group.
    fn is_disabled(&self) -> bool {
        self.groups
            .as_ref()
            .is_some_and(|groups| groups.iter().any(|g| g.display_name == "lldap_disabled"))
    }

    /// Whether the user has a second factor enrolled (admin or self).
    fn mfa_enrolled(&self, context: &Context<Handler>) -> Option<bool> {
        (context.validation_result.is_admin()
            || context.validation_result.user == self.user.user_id)
            .then(|| self.user.mfa_type.as_deref() == Some(MFA_TYPE_TOTP))
    }

    /// The user's resolved enable_mfa: off, enabled or always (self).
    async fn mfa_mode(&self, context: &Context<Handler>) -> Option<String> {
        let user = &self.user.user_id;
        if context.validation_result.user != *user {
            return None;
        }
        let mode = context.get_mfa_self_handler().mfa_mode(user).await;
        Some(mode.unwrap_or(MfaPolicy::Always).item().to_owned())
    }

    /// Whether the doors refuse the user now: the lock and inactivity (admins only, and only under `user(userId)`).
    async fn sign_in_state(&self, context: &Context<Handler>) -> FieldResult<Option<SignInState>> {
        let handler = context.get_admin_handler().filter(|_| self.alone);
        let Some(handler) = handler else {
            return Ok(None);
        };
        let span = debug_span!("[GraphQL query] user::sign_in_state");
        let state = handler
            .sign_in_state(&self.user.user_id)
            .instrument(span)
            .await?;
        Ok(Some(state.into()))
    }

    /// User-defined attributes, including ou and sshpublickey for legacy clients.
    fn attributes(&self) -> &[AttributeValue<Handler>] {
        &self.attributes
    }

    /// The groups to which this user belongs.
    async fn groups(&self, context: &Context<Handler>) -> FieldResult<Vec<Group<Handler>>> {
        let span = debug_span!("[GraphQL query] user::groups");
        span.in_scope(|| {
            debug!(user_id = ?self.user.user_id);
        });
        let handler = context
            .get_readable_handler(self.user.user_id.clone())
            .expect("We shouldn't be able to get there without readable permission");
        let domain_groups = handler
            .get_user_groups(&self.user.user_id)
            .instrument(span)
            .await?;
        let mut groups = domain_groups
            .into_iter()
            .map(|g| Group::<Handler>::from_group_details(g, self.schema.clone()))
            .collect::<FieldResult<Vec<Group<Handler>>>>()?;
        groups.sort_by(|g1, g2| g1.display_name.cmp(&g2.display_name));
        Ok(groups)
    }
}
