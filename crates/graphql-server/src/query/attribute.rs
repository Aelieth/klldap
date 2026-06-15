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

    fn attribute_type(&self) -> lldap_domain::types::AttributeType {
        self.schema.attribute_type
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
    fn value(&self) -> FieldResult<Vec<String>> {
        Ok(serialize_attribute_to_graphql(&self.attribute.value))
    }

    fn schema(&self) -> &AttributeSchema<Handler> {
        &self.schema
    }
}

impl<Handler: BackendHandler> AttributeValue<Handler> {
    pub(crate) fn name(&self) -> &str {
        self.attribute.name.as_str()
    }

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

fn get_hardcoded_user_value(user: &DomainUser, name: &str) -> Option<DomainAttributeValue> {
    match name {
        "userid" | "user_id" | "uid" => Some(user.user_id.clone().into_string().into()),
        "creationdate" | "creation_date" => Some(user.creation_date.into()),
        "modifieddate" | "modified_date" => Some(user.modified_date.into()),
        "passwordmodifieddate" | "password_modified_date" => {
            Some(user.password_modified_date.into())
        }
        "mail" => Some(user.email.clone().into_string().into()),
        "uuid" => Some(user.uuid.clone().into_string().into()),
        "displayname" | "display_name" | "cn" => {
            user.display_name.as_ref().map(|d| d.clone().into())
        }
        _ => None,
    }
}

fn get_hardcoded_group_value(group: &DomainGroup, name: &str) -> Option<DomainAttributeValue> {
    match name {
        "groupid" => Some((group.id.0 as i64).into()),
        "creationdate" | "creation_date" => Some(group.creation_date.into()),
        "modifieddate" | "modified_date" => Some(group.modified_date.into()),
        "uuid" => Some(group.uuid.clone().into_string().into()),
        "displayname" | "display_name" | "cn" => {
            Some(group.display_name.clone().into_string().into())
        }
        _ => None,
    }
}

fn get_hardcoded_group_details_value(
    group: &GroupDetails,
    name: &str,
) -> Option<DomainAttributeValue> {
    match name {
        "groupid" => Some((group.group_id.0 as i64).into()),
        "creationdate" | "creation_date" => Some(group.creation_date.into()),
        "modifieddate" | "modified_date" => Some(group.modified_date.into()),
        "uuid" => Some(group.uuid.clone().into_string().into()),
        "displayname" | "display_name" | "cn" => {
            Some(group.display_name.clone().into_string().into())
        }
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
