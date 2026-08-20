#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Options {
    pub password_reset_enabled: bool,
    #[serde(default)]
    pub mfa_enabled: bool,
    #[serde(default)]
    pub mfa_required: bool,
}
