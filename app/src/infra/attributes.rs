/// Resolves an attribute name and its GraphQL-provided aliases into a display
/// description. Shared by the user and group schema tables.
#[derive(Clone, Debug, PartialEq)]
pub struct AttributeDescription<'a> {
    pub attribute_name: &'a str,
    pub aliases: Vec<&'a str>,
}

pub fn resolve_attribute_description<'a>(
    name: &'a str,
    aliases: &'a [String],
) -> AttributeDescription<'a> {
    AttributeDescription {
        attribute_name: name,
        aliases: aliases.iter().map(|s| s.as_str()).collect(),
    }
}
