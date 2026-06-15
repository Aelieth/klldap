// This is now just a thin re-export from the real single source of truth
pub use lldap_schema::PublicSchema;

pub fn schema() -> PublicSchema {
    PublicSchema::get()
}
