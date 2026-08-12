use super::attribute::AttributeSchema;
use crate::api::Context;
use juniper::graphql_object;
use lldap_domain_handlers::handler::BackendHandler;
use lldap_ldap::{get_default_group_object_classes, get_default_user_object_classes};
use lldap_opaque_handler::OpaqueHandler;
use serde::{Deserialize, Serialize};

use lldap_schema::{AttributeList as SchemaAttributeList, PublicSchema};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AttributeList<Handler: BackendHandler> {
    attributes: SchemaAttributeList,
    default_classes: Vec<lldap_domain::types::LdapObjectClass>,
    extra_classes: Vec<lldap_domain::types::LdapObjectClass>,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

#[derive(Clone)]
pub struct ObjectClassInfo {
    object_class: String,
    is_hardcoded: bool,
}

#[graphql_object]
impl ObjectClassInfo {
    fn object_class(&self) -> &str {
        &self.object_class
    }

    fn is_hardcoded(&self) -> bool {
        self.is_hardcoded
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler + OpaqueHandler> AttributeList<Handler> {
    fn attributes(&self) -> Vec<AttributeSchema<Handler>> {
        self.attributes
            .attributes
            .clone()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    fn extra_ldap_object_classes(&self) -> Vec<String> {
        self.extra_classes.iter().map(|c| c.to_string()).collect()
    }

    fn ldap_object_classes(&self) -> Vec<ObjectClassInfo> {
        let mut all = self
            .default_classes
            .iter()
            .map(|c| ObjectClassInfo {
                object_class: c.to_string(),
                is_hardcoded: true,
            })
            .collect::<Vec<_>>();

        all.extend(self.extra_classes.iter().map(|c| ObjectClassInfo {
            object_class: c.to_string(),
            is_hardcoded: false,
        }));

        all
    }
}

impl<Handler: BackendHandler> AttributeList<Handler> {
    pub fn new(
        attributes: SchemaAttributeList,
        default_classes: Vec<lldap_domain::types::LdapObjectClass>,
        extra_classes: Vec<lldap_domain::types::LdapObjectClass>,
    ) -> Self {
        Self {
            attributes,
            default_classes,
            extra_classes,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Schema<Handler: BackendHandler> {
    schema: PublicSchema,
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler + OpaqueHandler> Schema<Handler> {
    fn user_schema(&self) -> AttributeList<Handler> {
        AttributeList::<Handler>::new(
            self.schema.user_attributes().clone(),
            get_default_user_object_classes(),
            self.schema
                .get_schema()
                .extra_user_object_classes
                .iter()
                .map(|s| lldap_domain::types::LdapObjectClass::from(s.as_str()))
                .collect(),
        )
    }

    fn group_schema(&self) -> AttributeList<Handler> {
        AttributeList::<Handler>::new(
            self.schema.group_attributes().clone(),
            get_default_group_object_classes(),
            self.schema
                .get_schema()
                .extra_group_object_classes
                .iter()
                .map(|s| lldap_domain::types::LdapObjectClass::from(s.as_str()))
                .collect(),
        )
    }

    fn system_schema(&self) -> AttributeList<Handler> {
        AttributeList::<Handler>::new(
            self.schema.system_attributes().clone(),
            vec![], // no default classes for system attributes
            vec![],
        )
    }
}

impl<Handler: BackendHandler> From<PublicSchema> for Schema<Handler> {
    fn from(value: PublicSchema) -> Self {
        Self {
            schema: value,
            _phantom: std::marker::PhantomData,
        }
    }
}
