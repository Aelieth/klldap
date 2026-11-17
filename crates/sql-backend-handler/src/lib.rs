#![forbid(unsafe_code)]
pub(crate) mod logging;
pub(crate) mod sql_backend_handler;
pub(crate) mod sql_durability;
pub(crate) mod sql_group_backend_handler;
pub(crate) mod sql_kerberos_committer;
pub(crate) mod sql_kerberos_handler;
pub(crate) mod sql_log_handler;
pub(crate) mod sql_mfa_handler;
pub(crate) mod sql_opaque_handler;
pub(crate) mod sql_policy_handler;
pub(crate) mod sql_posix_backend_handler;
pub(crate) mod sql_schema_backend_handler;
pub(crate) mod sql_user_backend_handler;
pub use lldap_domain_handlers::handler::PosixSettings;
pub use lldap_opaque_handler::register_password;
pub use sql_backend_handler::SqlBackendHandler;
pub use sql_durability::{sqlite_extra_synchronous, warn_database_durability};
#[cfg(feature = "test-hooks")]
pub use sql_kerberos_committer::start_committer_losing_an_answer;
pub use sql_kerberos_committer::{
    KerberosCommitterHandle, KerberosLost, start_kerberos_committer, start_unregistered_committer,
};
pub use sql_log_handler::{LogRetention, LogWriterHandle, enforce_log_retention, start_log_writer};
pub mod sql_migrations;
pub mod sql_tables;
