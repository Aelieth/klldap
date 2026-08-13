pub mod definitions;
pub mod manager;
pub mod operational;

pub use definitions::{ExpandedAttributes, GroupFieldType, LogicalAttr, UserFieldType};
pub use manager::SchemaManager;
use std::sync::LazyLock;

static SCHEMA_MANAGER: LazyLock<SchemaManager> =
    LazyLock::new(|| SchemaManager::new(lldap_domain::public_schema::PublicSchema::shared()));

/// Returns the shared SchemaManager built from the static PublicSchema.
pub fn get_schema_manager() -> &'static SchemaManager {
    &SCHEMA_MANAGER
}
