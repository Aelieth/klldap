use anyhow::{Context, Result};
use serde_json::json;
use std::path::Path;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct KeycloakConfig {
    pub url: String,
    pub realm: String,
    pub admin_user: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct KeycloakSuggestedConfig {
    pub url: String,
    pub realm: String,
    pub admin_username: String,
    pub keycloak_hostname: String,
}

#[derive(Debug, Clone)]
pub struct KeycloakRealmGenerationOptions {
    pub realm: String,
    pub use_ldaps: bool,
    pub external_keycloak: bool,
    pub external_keycloak_url: String,
    pub keycloak_hostname: String,
    pub enable_hsts: bool,
    pub enable_brute_force: bool,
}

pub fn get_keycloak_suggested_config() -> KeycloakSuggestedConfig {
    let realm = crate::derive_realm_from_base_dn();
    let domain = crate::derive_domain_from_base_dn();

    KeycloakSuggestedConfig {
        url: format!("http://keycloak.{}", domain),
        realm: realm.to_lowercase(),
        admin_username: "admin".to_string(),
        keycloak_hostname: "keycloak".to_string(),
    }
}

pub fn generate_keycloak_realm_json(options: &KeycloakRealmGenerationOptions) -> Result<String> {
    let realm_lower = options.realm.to_lowercase();
    let realm_upper = crate::derive_realm_from_base_dn();
    let domain = crate::derive_domain_from_base_dn();

    let hostname = if options.external_keycloak && !options.external_keycloak_url.trim().is_empty()
    {
        options.external_keycloak_url.clone()
    } else if options.keycloak_hostname.trim().is_empty()
        || options.keycloak_hostname.trim() == "keycloak"
    {
        format!("keycloak.{}", domain)
    } else {
        options.keycloak_hostname.clone()
    };

    let connection_url = if options.use_ldaps {
        "ldaps://lldap:636".to_string()
    } else {
        "ldap://lldap:389".to_string()
    };

    let ssl_required = if options.use_ldaps {
        "external"
    } else {
        "none"
    };
    let hsts = if options.enable_hsts {
        "max-age=31536000; includeSubDomains"
    } else {
        ""
    };

    let realm_json = json!({
        "realm": realm_lower,
        "enabled": true,
        "sslRequired": ssl_required,
        "registrationAllowed": false,
        "resetPasswordAllowed": false,
        "rememberMe": true,
        "editUsernameAllowed": false,
        "verifyEmail": false,
        "loginWithEmailAllowed": false,
        "duplicateEmailsAllowed": false,
        "registrationEmailAsUsername": false,
        "ssoSessionMaxLifespan": 43200,
        "accessTokenLifespan": 900,
        "clients": [{
            "clientId": "lldap-web",
            "name": "LLDAP Web Apps",
            "enabled": true,
            "protocol": "openid-connect",
            "publicClient": true,
            "standardFlowEnabled": true,
            "implicitFlowEnabled": true,
            "directAccessGrantsEnabled": true,
            "redirectUris": ["*"],
            "webOrigins": ["+"]
        }],
        "components": {
            "org.keycloak.storage.UserStorageProvider": [{
                "name": "lldap-with-kerberos",
                "providerId": "ldap",
                "providerType": "org.keycloak.storage.UserStorageProvider",
                "config": {
                    "vendor": ["other"],
                    "connectionUrl": [connection_url],
                    "bindDn": [format!("uid=keycloak,ou=people,{}", realm_upper.to_lowercase().replace('.', ",dc="))],
                           "bindCredential": ["<ENTER YOUR KEYCLOAK BIND PASSWORD HERE AFTER IMPORT>"],
                           "usersDn": [format!("ou=people,{}", realm_upper.to_lowercase().replace('.', ",dc="))],
                           "groupsDn": [format!("ou=groups,{}", realm_upper.to_lowercase().replace('.', ",dc="))],
                           "userObjectClasses": ["top, person, inetOrgPerson, posixAccount, ldapPublicKey"],
                           "rdnLDAPAttribute": ["uid"],
                           "uuidLDAPAttribute": ["entryUUID"],
                           "usernameLDAPAttribute": ["uid"],
                           "customUserSearchFilter": ["(&(!(objectClass=organizationalUnit))(kerberossync=1))"],
                           "searchScope": ["2"],
                           "validatePasswordPolicy": ["false"],
                           "trustEmail": ["true"],
                           "syncRegistrations": ["true"],
                           "fullSyncPeriod": ["86400"],
                           "changedSyncPeriod": ["300"],
                           "editMode": ["READ_ONLY"],
                           "importEnabled": ["true"],
                           "pagination": ["true"],
                           "allowKerberosAuthentication": ["true"],
                           "kerberosRealm": [realm_upper],
                           "serverPrincipal": [format!("HTTP/{}@{}", hostname, realm_upper)],
                           "keyTab": ["/keytab/keycloak-http.keytab"],
                           "krbPrincipalAttribute": ["krbPrincipalName"],
                           "useKerberosForPasswordAuthentication": ["false"],
                           "useTruststoreSpi": ["always"],
                           "connectionPooling": ["true"],
                           "cachePolicy": ["DEFAULT"],
                           "usePasswordModifyExtendedOp": ["false"],
                           "connectionTrace": ["false"]
                }
            }]
        },
        "browserSecurityHeaders": {
            "strictTransportSecurity": hsts,
            "xFrameOptions": "SAMEORIGIN",
            "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
            "contentSecurityPolicyReportOnly": "",
            "xContentTypeOptions": "nosniff",
            "xRobotsTag": "none",
            "referrerPolicy": "no-referrer"
        },
        "bruteForceProtected": options.enable_brute_force,
        "_comment": "Generated by LLDAP+Kerberos Federation page. Import with --import-realm. Set Bind Credential after import."
    });

    serde_json::to_string_pretty(&realm_json).context("Failed to serialize realm JSON")
}

pub fn load_keycloak_config() -> Result<KeycloakConfig> {
    let config_path = "/data/keycloak_config.toml";
    if Path::new(config_path).exists() {
        let toml_str =
            std::fs::read_to_string(config_path).context("Failed to read keycloak_config.toml")?;
        toml::from_str(&toml_str).context("Failed to parse keycloak_config.toml")
    } else {
        let realm = crate::derive_realm_from_base_dn();
        let domain = crate::derive_domain_from_base_dn();
        Ok(KeycloakConfig {
            url: format!("http://keycloak.{}", domain),
            realm: realm.to_lowercase(),
            admin_user: "admin".to_string(),
        })
    }
}

pub fn save_keycloak_config(config: &KeycloakConfig) -> Result<()> {
    let config_path = "/data/keycloak_config.toml";

    let header = r#"
    # LLDAP + Kerberos + Keycloak federation settings
    # Generated / updated via "Save Settings" button in the UI
    # Password not saved here, set via env var LLDAP_KEYCLOAK_ADMIN_PASS
    # Edit via "Federation" settings in UI.

    "#
    .trim_start_matches('\n');

    let toml_str = toml::to_string_pretty(config).context("Failed to serialize keycloak config")?;

    let full_content = format!("{}{}", header, toml_str);

    std::fs::write(config_path, full_content).context("Failed to write keycloak_config.toml")
}

pub fn get_keycloak_admin_password() -> String {
    std::env::var("LLDAP_KEYCLOAK_ADMIN_PASS").unwrap_or_else(|_| "admin".to_string())
}

pub fn load_full_keycloak_config() -> Result<(KeycloakConfig, String)> {
    let config = load_keycloak_config()?;
    let password = get_keycloak_admin_password();
    Ok((config, password))
}
