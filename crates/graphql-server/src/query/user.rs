use super::attribute::AttributeValue;
use super::group::Group;
use crate::api::Context;
use chrono::TimeZone;
use juniper::{FieldResult, graphql_object};
use lldap_access_control::UserReadableBackendHandler;
use lldap_domain::types::{
    MFA_TYPE_TOTP, User as DomainUser, UserAndGroups as DomainUserAndGroups,
};
use lldap_domain_handlers::handler::BackendHandler;
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
            _phantom: std::marker::PhantomData,
        })
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
