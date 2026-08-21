use super::inputs::AttributeValue;
use crate::api::{Context, field_error_callback};
use anyhow::anyhow;
use juniper::FieldResult;
use lldap_access_control::{AdminBackendHandler, ReadonlyBackendHandler};
use lldap_domain::{
    deserialize::deserialize_attribute_value,
    requests::CreateGroupRequest,
    types::{Attribute as DomainAttribute, AttributeName, Email},
};
use lldap_domain_handlers::handler::{BackendHandler, ReadSchemaBackendHandler};
use lldap_opaque_handler::OpaqueHandler;
use lldap_schema::{PublicSchema, schema::AttributeList};
use std::{collections::BTreeMap, sync::Arc};
use tracing::{Instrument, Span};

pub struct UnpackedAttributes {
    pub email: Option<Email>,
    pub display_name: Option<String>,
    pub attributes: Vec<DomainAttribute>,
}

fn validate_ssh_public_key(key: &str) -> Result<(), String> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err("SSH public key cannot be empty".to_string());
    }
    if !(trimmed.starts_with("ssh-")
        || trimmed.starts_with("ecdsa-")
        || trimmed.starts_with("sk-")
        || trimmed.starts_with("ssh-ed25519"))
    {
        return Err(format!(
            "Invalid SSH public key format. Expected to start with ssh-, ecdsa-, sk-, or ssh-ed25519. Got: '{}'",
            trimmed.split_whitespace().next().unwrap_or(trimmed)
        ));
    }
    if !trimmed.contains(' ') {
        return Err("Invalid SSH public key: missing space after key type".to_string());
    }
    if trimmed.len() > 4096 {
        return Err("SSH public key is too long (max 4096 characters)".to_string());
    }
    Ok(())
}

fn resolve_canonical_name(attribute_list: &AttributeList, name: &str) -> String {
    attribute_list
        .resolve_canonical_name(name)
        .unwrap_or(name)
        .to_string()
}

pub fn unpack_attributes(
    attributes: Vec<AttributeValue>,
    schema: &PublicSchema,
    is_admin: bool,
) -> FieldResult<UnpackedAttributes> {
    let user_schema = schema.user_attributes();

    let email = attributes
        .iter()
        .find(|attr| resolve_canonical_name(user_schema, &attr.name) == "mail")
        .cloned()
        .map(|attr| deserialize_attribute(user_schema, attr, is_admin))
        .transpose()?
        .map(|attr| attr.value.into_string().unwrap())
        .map(Email::from);

    let display_name = attributes
        .iter()
        .find(|attr| resolve_canonical_name(user_schema, &attr.name) == "displayname")
        .cloned()
        .map(|attr| deserialize_attribute(user_schema, attr, is_admin))
        .transpose()?
        .map(|attr| attr.value.into_string().unwrap());

    let attributes = attributes
        .into_iter()
        .filter(|attr| {
            let canon = resolve_canonical_name(user_schema, &attr.name);
            canon != "mail" && canon != "displayname"
        })
        .map(|attr| deserialize_attribute(user_schema, attr, is_admin))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(UnpackedAttributes {
        email,
        display_name,
        attributes,
    })
}

pub fn consolidate_attributes(
    attributes: Vec<AttributeValue>,
    first_name: Option<String>,
    last_name: Option<String>,
    avatar: Option<String>,
    schema: &PublicSchema,
) -> Vec<AttributeValue> {
    let user_schema = schema.user_attributes();
    let mut provided_attributes: BTreeMap<String, AttributeValue> = attributes
        .into_iter()
        .map(|x| {
            let canon = resolve_canonical_name(user_schema, &x.name);
            let key = canon.to_ascii_lowercase();
            (
                key,
                AttributeValue {
                    name: x.name.to_ascii_lowercase(),
                    value: x.value,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    // Keyed by canonical name, so the deprecated top-level fields never duplicate an alias
    // already given in the attribute list.
    let field_attrs = [
        ("first_name", first_name),
        ("last_name", last_name),
        ("avatar", avatar),
    ];
    for (name, value) in field_attrs.into_iter() {
        if let Some(val) = value {
            if name == "avatar" && val.trim().is_empty() {
                continue;
            }
            let canon = resolve_canonical_name(user_schema, name);
            let key = canon.to_ascii_lowercase();
            provided_attributes
                .entry(key)
                .or_insert_with(|| AttributeValue {
                    name: name.to_string(),
                    value: vec![val],
                });
        }
    }
    provided_attributes.into_values().collect()
}

pub async fn create_group_with_details<Handler: BackendHandler + OpaqueHandler>(
    context: &Context<Handler>,
    request: super::inputs::CreateGroupInput,
    span: Span,
) -> FieldResult<crate::query::Group<Handler>> {
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized group creation"))?;

    let schema = handler.get_schema().await?;

    let raw_attributes = request.attributes.unwrap_or_default();

    let ou_value = raw_attributes
        .iter()
        .find(|a| resolve_canonical_name(schema.group_attributes(), &a.name) == "ou")
        .and_then(|a| a.value.first().cloned())
        .unwrap_or_else(|| "groups".to_string());

    let attributes_for_unpack: Vec<_> = raw_attributes
        .into_iter()
        .filter(|a| resolve_canonical_name(schema.group_attributes(), &a.name) != "ou")
        .collect();

    let attributes = attributes_for_unpack
        .into_iter()
        .map(|attr| deserialize_attribute(schema.group_attributes(), attr, true))
        .collect::<Result<Vec<_>, _>>()?;

    let mut final_attributes = attributes;
    final_attributes.push(DomainAttribute {
        name: AttributeName::from("ou"),
        value: ou_value.into(),
    });

    let request = CreateGroupRequest {
        display_name: request.display_name.into(),
        attributes: final_attributes,
    };

    let group_id = handler.create_group(request).await?;
    let group_details = handler.get_group_details(group_id).instrument(span).await?;
    crate::query::Group::<Handler>::from_group_details(group_details, Arc::new(schema))
}

pub fn deserialize_attribute(
    attribute_schema: &AttributeList,
    attribute: AttributeValue,
    is_admin: bool,
) -> FieldResult<DomainAttribute> {
    // Stored under the canonical name, never an alias.
    let canonical_name = resolve_canonical_name(attribute_schema, &attribute.name);
    let attribute_name = AttributeName::from(canonical_name.as_str());

    let attr_schema = attribute_schema
        .get_by_name_or_alias(attribute_name.as_str())
        .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", attribute.name))?;

    if attr_schema.is_readonly {
        return Err(anyhow!(
            "Permission denied: Attribute {} is read-only",
            attribute.name
        )
        .into());
    }
    if !is_admin && !attr_schema.is_editable {
        return Err(anyhow!(
            "Permission denied: Attribute {} is not editable by regular users",
            attribute.name
        )
        .into());
    }

    if canonical_name.eq_ignore_ascii_case("sshpublickey") && attr_schema.is_list {
        for key in &attribute.value {
            if let Err(err_msg) = validate_ssh_public_key(key) {
                return Err(anyhow!("Invalid SSH public key: {}", err_msg).into());
            }
        }
    }

    let value = deserialize_attribute_value(
        &attribute.value,
        attr_schema.attribute_type,
        attr_schema.is_list,
    )
    .map_err(|e| anyhow!("Invalid value for attribute {}: {:#}", attribute.name, e))?;
    Ok(DomainAttribute {
        name: attribute_name,
        value,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use lldap_domain::types::{AttributeType, AttributeValue as DomainValue, Cardinality};
    use lldap_schema::schema::{AttributeList, AttributeSchema};
    use pretty_assertions::assert_eq;

    fn attr_input(name: &str, values: &[&str]) -> AttributeValue {
        AttributeValue {
            name: name.to_string(),
            value: values.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn schema_of(attr: AttributeSchema) -> AttributeList {
        AttributeList {
            attributes: vec![attr],
        }
    }

    #[test]
    fn test_deserialize_attribute_inputs() {
        let date = schema_of(AttributeSchema::editable("mydate", AttributeType::DateTime));
        let ints = schema_of(AttributeSchema::editable("myints", AttributeType::Integer).list());
        for (label, schema, name, values, expected) in [
            (
                "rfc3339 datetime",
                &date,
                "mydate",
                vec!["2024-05-01T12:00:00Z"],
                Some(DomainValue::DateTime(Cardinality::Singleton(
                    "2024-05-01T12:00:00".parse().unwrap(),
                ))),
            ),
            (
                "integer list",
                &ints,
                "myints",
                vec!["1", "-2"],
                Some(DomainValue::Integer(Cardinality::Unbounded(vec![1, -2]))),
            ),
            ("empty non-list", &date, "mydate", vec![], None),
            (
                "invalid datetime",
                &date,
                "mydate",
                vec!["not-a-date"],
                None,
            ),
        ] {
            let result = deserialize_attribute(schema, attr_input(name, &values), false);
            match expected {
                Some(value) => assert_eq!(result.unwrap().value, value, "{label}"),
                None => assert!(result.is_err(), "{label}"),
            }
        }
    }
}
