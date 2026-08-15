#![allow(dead_code)]
use std::env::var;
use std::sync::Mutex;

pub const DB_KEY: &str = "LLDAP_DATABASE_URL";
pub const PRIVATE_KEY_SEED: &str = "LLDAP_KEY_SEED";
pub const JWT_SECRET: &str = "LLDAP_JWT_SECRET";
pub const LDAP_USER_PASSWORD: &str = "LLDAP_LDAP_USER_PASS";

pub fn database_url() -> String {
    let url = var(DB_KEY).ok();
    url.unwrap_or("sqlite://e2e_test.db?mode=rwc".to_string())
}

// Ports of the fixture-spawned server; env/defaults still serve an external server.
static PORTS: Mutex<Option<(u16, u16)>> = Mutex::new(None);

pub fn set_ports(ldap_port: u16, http_port: u16) {
    *PORTS.lock().unwrap() = Some((ldap_port, http_port));
}

fn fixture_ports() -> Option<(u16, u16)> {
    *PORTS.lock().unwrap()
}

pub fn ldap_url() -> String {
    let port = fixture_ports()
        .map(|(ldap, _)| ldap.to_string())
        .or_else(|| var("LLDAP_LDAP_PORT").ok())
        .unwrap_or("3890".to_string());
    format!("ldap://localhost:{port}")
}

pub fn http_url() -> String {
    let port = fixture_ports()
        .map(|(_, http)| http.to_string())
        .or_else(|| var("LLDAP_HTTP_PORT").ok())
        .unwrap_or("17170".to_string());
    format!("http://localhost:{port}")
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
