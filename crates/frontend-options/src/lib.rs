#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Options {
    pub password_reset_enabled: bool,
    #[serde(default)]
    pub mfa_enabled: bool,
    #[serde(default)]
    pub mfa_required: bool,
    /// The explicit server-wide `enable_mfa`, which overrides every OU's.
    #[serde(default)]
    pub mfa_server_wide: Option<String>,
    #[serde(default)]
    pub domain: String,
    /// The zone the OUs' `login-hours` are read in; empty from a server that does not say.
    #[serde(default)]
    pub login_hours_timezone: String,
}
