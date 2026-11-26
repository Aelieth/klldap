#![forbid(unsafe_code)]
pub(crate) mod logging;
pub(crate) mod sql_activity_handler;
pub(crate) mod sql_backend_handler;
pub(crate) mod sql_delete_marks;
pub(crate) mod sql_durability;
pub(crate) mod sql_group_backend_handler;
pub(crate) mod sql_kerberos_committer;
pub(crate) mod sql_kerberos_handler;
pub(crate) mod sql_lockout_handler;
pub(crate) mod sql_log_handler;
pub(crate) mod sql_mfa_handler;
pub(crate) mod sql_mfa_windows;
pub(crate) mod sql_opaque_handler;
pub(crate) mod sql_policy_handler;
pub(crate) mod sql_policy_read;
pub(crate) mod sql_posix_backend_handler;
pub(crate) mod sql_schema_backend_handler;
pub(crate) mod sql_totp_steps;
pub(crate) mod sql_used_proofs;
pub(crate) mod sql_used_starts;
pub(crate) mod sql_user_backend_handler;
pub use lldap_domain_handlers::handler::PosixSettings;
pub use lldap_opaque_handler::register_password;
pub use sql_activity_handler::reenable_user_on;
pub use sql_backend_handler::SqlBackendHandler;
pub use sql_durability::{sqlite_extra_synchronous, warn_database_durability};
pub use sql_kerberos_committer::{
    KerberosCommitterHandle, KerberosLost, realm_marked_open, start_kerberos_committer,
    start_unregistered_committer,
};
#[cfg(feature = "test-hooks")]
pub use sql_kerberos_committer::{start_committer_losing_an_answer, start_committer_watching_for};
pub use sql_lockout_handler::unlock_login_on;
pub use sql_log_handler::{LogRetention, LogWriterHandle, enforce_log_retention, start_log_writer};
#[cfg(feature = "test-clock")]
pub use sql_mfa_handler::set_enrollment_clock;
pub use sql_policy_handler::{UNLINKED_BY_TOOL, unlink_ou_policy_on};
pub mod sql_migrations;
pub mod sql_tables;
