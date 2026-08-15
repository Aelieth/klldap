#![allow(dead_code)]
use std::env::var;

pub const DB_KEY: &str = "LLDAP_DATABASE_URL";
pub const PRIVATE_KEY_SEED: &str = "LLDAP_KEY_SEED";
pub const JWT_SECRET: &str = "LLDAP_JWT_SECRET";
pub const LDAP_USER_PASSWORD: &str = "LLDAP_LDAP_USER_PASS";

pub fn database_url() -> String {
    let url = var(DB_KEY).ok();
    url.unwrap_or("sqlite://e2e_test.db?mode=rwc".to_string())
}

pub fn admin_dn() -> String {
    let user = var("LLDAP_LDAP_USER_DN").ok();
    user.unwrap_or("admin".to_string())
}

pub fn admin_password() -> String {
    let pass = var("LLDAP_LDAP_USER_PASS").ok();
    pass.unwrap_or("password".to_string())
}

pub fn base_dn() -> String {
    let dn = var("LLDAP_LDAP_BASE_DN").ok();
    dn.unwrap_or("dc=example,dc=com".to_string())
}
