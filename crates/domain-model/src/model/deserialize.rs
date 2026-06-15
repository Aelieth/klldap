use crate::error::DomainError;
use lldap_domain::{
    schema::AttributeList,
    types::{
        Attribute, AttributeName, AttributeType, AttributeValue, Avatar, Cardinality, Serialized,
    },
};

// Value must be a serialized attribute value of the type denoted by typ,
// and either a singleton or unbounded list, depending on is_list.
pub fn deserialize_attribute_value(
    value: &Serialized,
    typ: AttributeType,
    is_list: bool,
) -> AttributeValue {
    match (typ, is_list) {
        (AttributeType::String, false) => {
            let s = std::str::from_utf8(&value.0).unwrap_or("");
            AttributeValue::String(Cardinality::Singleton(s.to_string()))
        }
        (AttributeType::String, true) => {
            let bytes = &value.0;
            if let Ok(list) = serde_json::from_slice::<Vec<String>>(bytes) {
                AttributeValue::String(Cardinality::Unbounded(list))
            } else {
                let s = std::str::from_utf8(bytes).unwrap_or("");
                AttributeValue::String(Cardinality::Unbounded(vec![s.to_string()]))
            }
        }
        (AttributeType::Integer, false) => {
            let s = std::str::from_utf8(&value.0).unwrap_or("0");
            let i: i64 = s.parse().unwrap_or(0);
            AttributeValue::Integer(Cardinality::Singleton(i))
        }
        (AttributeType::Integer, true) => {
            let s = std::str::from_utf8(&value.0).unwrap_or("0");
            let i: i64 = s.parse().unwrap_or(0);
            AttributeValue::Integer(Cardinality::Unbounded(vec![i]))
        }
        (AttributeType::DateTime, false) => {
            AttributeValue::DateTime(Cardinality::Singleton(value.unwrap()))
        }
        (AttributeType::DateTime, true) => {
            AttributeValue::DateTime(Cardinality::Unbounded(value.unwrap()))
        }
        (AttributeType::Avatar, false) => {
            AttributeValue::Avatar(Cardinality::Singleton(Avatar::new(value.0.clone())))
        }
        (AttributeType::Avatar, true) => {
            AttributeValue::Avatar(Cardinality::Unbounded(vec![Avatar::new(value.0.clone())]))
        }
    }
}

pub fn deserialize_attribute(
    name: AttributeName,
    value: &Serialized,
    schema: &AttributeList,
) -> Result<Attribute, DomainError> {
    match schema.get_attribute_type(name.as_str()) {
        Some((typ, is_list)) => Ok(Attribute {
            name,
            value: deserialize_attribute_value(value, typ, is_list),
        }),
        None => Err(DomainError::InternalError(format!(
            "Unable to find schema for attribute named '{}'",
            name.into_string()
        ))),
    }
}
