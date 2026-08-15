use super::attribute::AttributeValue;
use crate::api::{Context, field_error_callback};
use crate::query::user::User;
use chrono::TimeZone;
use juniper::{FieldResult, graphql_object};
use lldap_access_control::ReadonlyBackendHandler;
use lldap_domain::types::{Group as DomainGroup, GroupDetails, GroupId};
use lldap_domain_handlers::handler::{BackendHandler, UserRequestFilter as DomainRequestFilter};
use lldap_opaque_handler::OpaqueHandler;
use lldap_schema::PublicSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{Instrument, debug, debug_span};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
/// Represents a single group.
pub struct Group<Handler: BackendHandler> {
    pub group_id: i32,
    pub display_name: String,
    creation_date: chrono::NaiveDateTime,
    uuid: String,
    attributes: Vec<AttributeValue<Handler>>,
    pub member_count: i32,
    pub schema: Arc<PublicSchema>,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

impl<Handler: BackendHandler> Group<Handler> {
    pub fn from_group(
        mut group: DomainGroup,
        schema: Arc<PublicSchema>,
    ) -> FieldResult<Group<Handler>> {
        let attributes =
            AttributeValue::<Handler>::group_attributes_from_schema(&mut group, &schema);
        Ok(Self {
            group_id: group.id.0,
            display_name: group.display_name.to_string(),
            creation_date: group.creation_date,
            uuid: group.uuid.into_string(),
            attributes,
            member_count: group.users.len() as i32,
            schema,
            _phantom: std::marker::PhantomData,
        })
    }

    pub fn from_group_details(
        mut group_details: GroupDetails,
        schema: Arc<PublicSchema>,
    ) -> FieldResult<Group<Handler>> {
        let attributes = AttributeValue::<Handler>::group_details_attributes_from_schema(
            &mut group_details,
            &schema,
        );
        Ok(Self {
            group_id: group_details.group_id.0,
            display_name: group_details.display_name.to_string(),
            creation_date: group_details.creation_date,
            uuid: group_details.uuid.into_string(),
            attributes,
            member_count: 0, // single-group details view does not preload the full list
            schema,
            _phantom: std::marker::PhantomData,
        })
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler + OpaqueHandler> Group<Handler> {
    fn id(&self) -> i32 {
        self.group_id
    }
    fn display_name(&self) -> String {
        self.display_name.clone()
    }
    fn creation_date(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.from_utc_datetime(&self.creation_date)
    }
    fn uuid(&self) -> String {
        self.uuid.clone()
    }

    /// Single-layer OU (defaults to "groups" — editable by admin only)
    fn ou(&self) -> String {
        let canonical = self
            .schema
            .resolve_group_canonical_name("ou")
            .unwrap_or("ou");
        self.attributes
            .iter()
            .find(|a| a.name() == canonical)
            .and_then(|a| a.attribute.value.as_str())
            .unwrap_or("groups")
            .to_string()
    }

    /// Real member count (used by group_table.rs)
    fn member_count(&self) -> i32 {
        self.member_count
    }

    /// User-defined attributes (includes ou for legacy clients).
    fn attributes(&self) -> &[AttributeValue<Handler>] {
        &self.attributes
    }

    /// The users that belong to this group.
    async fn users(&self, context: &Context<Handler>) -> FieldResult<Vec<User<Handler>>> {
        let span = debug_span!("[GraphQL query] group::users");
        span.in_scope(|| {
            debug!(name = %self.display_name);
        });
        let handler = context
            .get_readonly_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized access to group data",
            ))?;
        let domain_users = handler
            .list_users(
                Some(DomainRequestFilter::MemberOfId(GroupId(self.group_id))),
                false,
            )
            .instrument(span)
            .await?;
        domain_users
            .into_iter()
            .map(|u| User::<Handler>::from_user_and_groups(u, self.schema.clone()))
            .collect::<FieldResult<Vec<_>>>()
    }
}
