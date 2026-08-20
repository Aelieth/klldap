use crate::api::Context;
use chrono::TimeZone;
use juniper::{FieldResult, graphql_object};
use lldap_domain::types::{
    Attribute as DomainAttribute, AttributeValue as DomainAttributeValue, Cardinality,
    Group as DomainGroup, GroupDetails, User as DomainUser,
};
use lldap_domain_handlers::handler::BackendHandler;
use lldap_opaque_handler::OpaqueHandler;
use lldap_schema::{AttributeSchema as SchemaAttributeSchema, PublicSchema};
use serde::{Deserialize, Serialize};

// GraphQL-facing projection of lldap_schema::AttributeType. The shared enum doubles as a
// sea-orm value, so the deprecated JPEG_PHOTO alias lives only here and never becomes a
// legal DB value; output conversion never emits it.
#[derive(PartialEq, Eq, Debug, Clone, Copy, juniper::GraphQLEnum)]
#[graphql(name = "AttributeType")]
pub enum GraphQLAttributeType {
    String,
    Integer,
    Avatar,
    DateTime,
    #[graphql(deprecated = "Legacy alias for AVATAR")]
    JpegPhoto,
}

impl From<GraphQLAttributeType> for lldap_domain::types::AttributeType {
    fn from(t: GraphQLAttributeType) -> Self {
        match t {
            GraphQLAttributeType::String => Self::String,
            GraphQLAttributeType::Integer => Self::Integer,
            GraphQLAttributeType::Avatar | GraphQLAttributeType::JpegPhoto => Self::Avatar,
            GraphQLAttributeType::DateTime => Self::DateTime,
        }
    }
}

impl From<lldap_domain::types::AttributeType> for GraphQLAttributeType {
    fn from(t: lldap_domain::types::AttributeType) -> Self {
        use lldap_domain::types::AttributeType;
        match t {
            AttributeType::String => Self::String,
            AttributeType::Integer => Self::Integer,
            AttributeType::Avatar => Self::Avatar,
            AttributeType::DateTime => Self::DateTime,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct AttributeSchema<Handler: BackendHandler> {
    schema: SchemaAttributeSchema,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

impl<Handler: BackendHandler> From<SchemaAttributeSchema> for AttributeSchema<Handler> {
    fn from(schema: SchemaAttributeSchema) -> Self {
        Self {
            schema,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler + OpaqueHandler> AttributeSchema<Handler> {
    fn name(&self) -> String {
        self.schema.name.clone()
    }

    fn aliases(&self) -> Vec<String> {
        self.schema.aliases.clone()
    }

    fn attribute_type(&self) -> GraphQLAttributeType {
        self.schema.attribute_type.into()
    }

    fn is_list(&self) -> bool {
        self.schema.is_list
    }

    fn is_visible(&self) -> bool {
        self.schema.is_visible
    }

    fn is_editable(&self) -> bool {
        self.schema.is_editable
    }

    fn is_hardcoded(&self) -> bool {
        self.schema.is_hardcoded
    }

    fn is_readonly(&self) -> bool {
        self.schema.is_readonly
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct AttributeValue<Handler: BackendHandler> {
    pub(super) attribute: DomainAttribute,
    pub(super) schema: AttributeSchema<Handler>,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler + OpaqueHandler> AttributeValue<Handler> {
    pub(crate) fn name(&self) -> &str {
        self.attribute.name.as_str()
    }

    fn value(&self) -> FieldResult<Vec<String>> {
        Ok(serialize_attribute_to_graphql(&self.attribute.value))
    }

    fn schema(&self) -> &AttributeSchema<Handler> {
        &self.schema
    }
}

impl<Handler: BackendHandler> AttributeValue<Handler> {
    fn from_value(attr: DomainAttribute, schema: SchemaAttributeSchema) -> Self {
        Self {
            attribute: attr,
            schema: schema.into(),
            _phantom: std::marker::PhantomData,
        }
    }

    fn from_schema(a: DomainAttribute, schema_list: &lldap_schema::AttributeList) -> Option<Self> {
        schema_list
            .get_by_name_or_alias(a.name.as_str())
            .map(|s| Self::from_value(a, s.clone()))
    }
}

pub fn serialize_attribute_to_graphql(attribute_value: &DomainAttributeValue) -> Vec<String> {
    let convert_date = |&date| chrono::Utc.from_utc_datetime(&date).to_rfc3339();

    match attribute_value {
        DomainAttributeValue::String(Cardinality::Singleton(s)) => vec![s.clone()],
        DomainAttributeValue::String(Cardinality::Unbounded(l)) => l.clone(),
        DomainAttributeValue::Integer(Cardinality::Singleton(i)) => vec![i.to_string()],
        DomainAttributeValue::Integer(Cardinality::Unbounded(l)) => {
            l.iter().map(|i| i.to_string()).collect()
        }
        DomainAttributeValue::DateTime(Cardinality::Singleton(dt)) => vec![convert_date(dt)],
        DomainAttributeValue::DateTime(Cardinality::Unbounded(l)) => {
            l.iter().map(convert_date).collect()
        }
        DomainAttributeValue::Avatar(Cardinality::Singleton(p)) => {
            let b64 = lldap_domain::images::avatar_to_graphql_base64(p.as_bytes());
            vec![b64]
        }
        DomainAttributeValue::Avatar(Cardinality::Unbounded(l)) => {
            let result: Vec<String> = l
                .iter()
                .map(|p| lldap_domain::images::avatar_to_graphql_base64(p.as_bytes()))
                .collect();
            result
        }
    }
}

// Callers pass the canonical schema name (s.name); alias arms would be unreachable.
fn get_hardcoded_user_value(user: &DomainUser, name: &str) -> Option<DomainAttributeValue> {
    match name {
        "userid" => Some(user.user_id.clone().into_string().into()),
        "creationdate" => Some(user.creation_date.into()),
        "modifieddate" => Some(user.modified_date.into()),
        "passwordmodifieddate" => Some(user.password_modified_date.into()),
        "mail" => Some(user.email.clone().into_string().into()),
        "uuid" => Some(user.uuid.clone().into_string().into()),
        "displayname" => user.display_name.as_ref().map(|d| d.clone().into()),
        _ => None,
    }
}

fn get_hardcoded_group_value(group: &DomainGroup, name: &str) -> Option<DomainAttributeValue> {
    match name {
        "groupid" => Some((group.id.0 as i64).into()),
        "creationdate" => Some(group.creation_date.into()),
        "modifieddate" => Some(group.modified_date.into()),
        "uuid" => Some(group.uuid.clone().into_string().into()),
        "displayname" => Some(group.display_name.clone().into_string().into()),
        _ => None,
    }
}

fn get_hardcoded_group_details_value(
    group: &GroupDetails,
    name: &str,
) -> Option<DomainAttributeValue> {
    match name {
        "groupid" => Some((group.group_id.0 as i64).into()),
        "creationdate" => Some(group.creation_date.into()),
        "modifieddate" => Some(group.modified_date.into()),
        "uuid" => Some(group.uuid.clone().into_string().into()),
        "displayname" => Some(group.display_name.clone().into_string().into()),
        _ => None,
    }
}

impl<Handler: BackendHandler> AttributeValue<Handler> {
    pub fn user_attributes_from_schema(
        user: &mut DomainUser,
        schema: &PublicSchema,
    ) -> Vec<AttributeValue<Handler>> {
        let user_attributes = std::mem::take(&mut user.attributes);
        let schema_list = schema.user_attributes();

        let mut all = schema_list
            .attributes
            .iter()
            .filter(|a| a.is_hardcoded)
            .filter_map(|s| {
                get_hardcoded_user_value(user, &s.name).map(|v| {
                    AttributeValue::from_value(
                        DomainAttribute {
                            name: s.name.clone().into(),
                            value: v,
                        },
                        s.clone(),
                    )
                })
            })
            .collect::<Vec<_>>();

        user_attributes
            .into_iter()
            .flat_map(|a| Self::from_schema(a, schema_list))
            .for_each(|v| all.push(v));

        all
    }

    pub fn group_attributes_from_schema(
        group: &mut DomainGroup,
        schema: &PublicSchema,
    ) -> Vec<AttributeValue<Handler>> {
        let group_attributes = std::mem::take(&mut group.attributes);
        let schema_list = schema.group_attributes();

        let mut all = schema_list
            .attributes
            .iter()
            .filter(|a| a.is_hardcoded)
            .filter_map(|s| {
                get_hardcoded_group_value(group, &s.name).map(|v| {
                    AttributeValue::from_value(
                        DomainAttribute {
                            name: s.name.clone().into(),
                            value: v,
                        },
                        s.clone(),
                    )
                })
            })
            .collect::<Vec<_>>();

        group_attributes
            .into_iter()
            .flat_map(|a| Self::from_schema(a, schema_list))
            .for_each(|v| all.push(v));

        all
    }

    pub fn group_details_attributes_from_schema(
        group: &mut GroupDetails,
        schema: &PublicSchema,
    ) -> Vec<AttributeValue<Handler>> {
        let group_attributes = std::mem::take(&mut group.attributes);
        let schema_list = schema.group_attributes();

        let mut all = schema_list
            .attributes
            .iter()
            .filter(|a| a.is_hardcoded)
            .filter_map(|s| {
                get_hardcoded_group_details_value(group, &s.name).map(|v| {
                    AttributeValue::from_value(
                        DomainAttribute {
                            name: s.name.clone().into(),
                            value: v,
                        },
                        s.clone(),
                    )
                })
            })
            .collect::<Vec<_>>();

        group_attributes
            .into_iter()
            .flat_map(|a| Self::from_schema(a, schema_list))
            .for_each(|v| all.push(v));

        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use lldap_domain::types::{GroupId, UserId, Uuid};

    fn ts() -> chrono::NaiveDateTime {
        Utc.timestamp_opt(42, 0).unwrap().naive_utc()
    }

    #[test]
    fn test_hardcoded_user_values_resolve_canonical_only() {
        let user = DomainUser {
            user_id: UserId::new("bob"),
            email: "bob@example.com".into(),
            display_name: Some("Bob".to_string()),
            creation_date: ts(),
            uuid: Uuid::from_name_and_date("bob", &ts()),
            attributes: vec![],
            modified_date: ts(),
            password_modified_date: ts(),
            krb_principal_name: None,
            mfa_type: None,
        };
        for name in [
            "userid",
            "creationdate",
            "modifieddate",
            "passwordmodifieddate",
            "mail",
            "uuid",
            "displayname",
        ] {
            assert!(
                get_hardcoded_user_value(&user, name).is_some(),
                "canonical {name}"
            );
        }
        for alias in ["uid", "user_id", "creation_date", "display_name", "cn"] {
            assert!(
                get_hardcoded_user_value(&user, alias).is_none(),
                "alias {alias}"
            );
        }
        assert!(get_hardcoded_user_value(&user, "nope").is_none());
    }

    #[test]
    fn test_hardcoded_group_values_resolve_canonical_only() {
        let group = DomainGroup {
            id: GroupId(1),
            display_name: "group".into(),
            creation_date: ts(),
            uuid: Uuid::from_name_and_date("group", &ts()),
            users: vec![],
            attributes: vec![],
            modified_date: ts(),
        };
        for name in [
            "groupid",
            "creationdate",
            "modifieddate",
            "uuid",
            "displayname",
        ] {
            assert!(
                get_hardcoded_group_value(&group, name).is_some(),
                "canonical {name}"
            );
        }
        for alias in ["creation_date", "display_name", "cn"] {
            assert!(
                get_hardcoded_group_value(&group, alias).is_none(),
                "alias {alias}"
            );
        }

        let details = GroupDetails {
            group_id: GroupId(1),
            display_name: "group".into(),
            creation_date: ts(),
            uuid: Uuid::from_name_and_date("group", &ts()),
            attributes: vec![],
            modified_date: ts(),
        };
        for name in [
            "groupid",
            "creationdate",
            "modifieddate",
            "uuid",
            "displayname",
        ] {
            assert!(
                get_hardcoded_group_details_value(&details, name).is_some(),
                "canonical {name}"
            );
        }
        assert!(get_hardcoded_group_details_value(&details, "display_name").is_none());
    }
}
