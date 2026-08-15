#![forbid(unsafe_code)]
pub mod client;
pub mod config;

pub use client::KeycloakClient;
pub use config::{KeycloakConfig, SUGGESTED_HOSTNAME, admin_password};
