// Single source of truth helper: resolves attribute descriptions from GraphQL
// (which now comes from crates/schema/public_schema.rs)
// Used by the UI components below to display POSIX + Kerberos fields nicely.
#[derive(Clone, Debug, PartialEq)]
pub struct AttributeDescription<'a> {
    pub attribute_identifier: &'a str,
    pub attribute_name: &'a str,
    pub aliases: Vec<&'a str>,
}

pub mod user {
    use super::AttributeDescription;

    pub fn resolve_user_attribute_description_or_default<'a>(
        name: &'a str,
        aliases: &'a [String], // ← comes directly from GraphQL
    ) -> AttributeDescription<'a> {
        AttributeDescription {
            attribute_identifier: name,
            attribute_name: name,
            aliases: aliases.iter().map(|s| s.as_str()).collect(),
        }
    }
}

pub mod group {
    use super::AttributeDescription;

    pub fn resolve_group_attribute_description_or_default<'a>(
        name: &'a str,
        aliases: &'a [String],
    ) -> AttributeDescription<'a> {
        AttributeDescription {
            attribute_identifier: name,
            attribute_name: name,
            aliases: aliases.iter().map(|s| s.as_str()).collect(),
        }
    }
}
