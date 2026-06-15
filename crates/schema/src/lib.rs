#![forbid(unsafe_code)]
pub mod public_schema;
pub mod schema;

pub use public_schema::PublicSchema;
pub use schema::{AttributeList, AttributeSchema, AttributeType, Schema};

// Re-export for convenience
pub use crate::schema::AttributeList as UserAttributeList;
pub use crate::schema::AttributeList as GroupAttributeList;
pub use crate::schema::AttributeList as SystemAttributeList;
