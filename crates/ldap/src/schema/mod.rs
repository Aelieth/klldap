pub mod definitions;
pub mod manager;
pub mod operational;

pub use definitions::{ExpandedAttributes, GroupFieldType, UserFieldType};
use lldap_domain::types::AttributeName;
use lldap_schema::PublicSchema;
pub use manager::SchemaManager;
use std::sync::LazyLock;

static SCHEMA_MANAGER: LazyLock<SchemaManager> =
    LazyLock::new(|| SchemaManager::new(PublicSchema::shared()));

pub fn get_schema_manager() -> &'static SchemaManager {
    &SCHEMA_MANAGER
}

pub fn map_user_field(field: &AttributeName, schema: &PublicSchema) -> UserFieldType {
    get_schema_manager().map_user_field(field, schema)
}
