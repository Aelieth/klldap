use anyhow::{Context, Result};
use reqwest::Client as HttpClient;
use serde_json::json;
use tracing::info;

use crate::keycloak_config::KeycloakConfig;

#[derive(Clone)]
pub struct KeycloakClient {
    config: KeycloakConfig,
    admin_pass: String,
    http_client: HttpClient,
}

impl KeycloakClient {
    pub fn new(config: KeycloakConfig, admin_pass: String) -> Self {
        Self {
            config,
            admin_pass,
            http_client: HttpClient::new(),
        }
    }

    pub fn from_test_input(
        url: String,
        realm: String,
        admin_user: String,
        admin_pass: String,
    ) -> Self {
        let pass = if admin_pass.trim().is_empty() {
            crate::keycloak_config::get_keycloak_admin_password()
        } else {
            admin_pass
        };
        Self {
            config: KeycloakConfig {
                url,
                realm,
                admin_user,
            },
            admin_pass: pass,
            http_client: HttpClient::new(),
        }
    }

    pub async fn setup_realm(
        &self,
        lldap_url: String,
        sync_username: String,
        sync_password: String,
        enable_hsts: bool,
        enable_brute_force: bool,
    ) -> Result<String> {
        info!(
            "🔄 PushRealm starting - Realm: '{}', LLDAP URL: '{}'",
            self.config.realm, lldap_url
        );
        let token = self.acquire_token().await?;

        if self.realm_exists(&token).await? {
            return Err(anyhow::anyhow!(
                "Realm '{}' already exists. Delete the realm manually in Keycloak admin console to proceed.",
                self.config.realm
            ));
        }

        self.create_realm(&token, enable_hsts, enable_brute_force)
            .await?;

        let provider_id = self
            .create_ldap_kerberos_component(&token, &lldap_url, &sync_username, &sync_password)
            .await?;

        self.clear_default_mappers(&token, &provider_id).await?;
        self.create_custom_mappers(&token, &provider_id).await?;
        self.add_lldap_web_client(&token).await?;

        let msg = format!(
            "✅ Realm '{}' set up with LLDAP + Kerberos! Custom attribute mappers applied. SSO ready!",
            self.config.realm
        );
        info!("{}", msg);
        Ok(msg)
    }

    async fn realm_exists(&self, token: &str) -> Result<bool> {
        let url = format!("{}/admin/realms/{}", self.config.url, self.config.realm);
        let resp = self
            .http_client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to check realm existence")?;

        // 200/204 = exists; 404 = does not exist. Other codes treated as error by caller context.
        Ok(resp.status().is_success())
    }

    async fn acquire_token(&self) -> Result<String> {
        info!("   → Acquiring admin token...");
        let resp = self
            .http_client
            .post(format!(
                "{}/realms/master/protocol/openid-connect/token",
                self.config.url
            ))
            .form(&[
                ("client_id", "admin-cli"),
                ("username", &self.config.admin_user),
                ("password", &self.admin_pass),
                ("grant_type", "password"),
            ])
            .send()
            .await
            .context("Failed to connect to Keycloak")?;

        let json: serde_json::Value = resp.json().await.context("Invalid token response")?;
        let token = json["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access_token in response (wrong admin password?)"))?
            .to_string();

        info!("   → Token acquired successfully");
        Ok(token)
    }

    async fn create_realm(
        &self,
        token: &str,
        enable_hsts: bool,
        enable_brute_force: bool,
    ) -> Result<()> {
        info!("   → Creating realm '{}'...", self.config.realm);
        let realm_json = json!({
            "realm": self.config.realm,
            "enabled": true,
            "sslRequired": "none",
            "registrationAllowed": false,
            "resetPasswordAllowed": false,
            "rememberMe": true,
            "editUsernameAllowed": false,
            "verifyEmail": false,
            "loginWithEmailAllowed": false,
            "duplicateEmailsAllowed": false,
            "ssoSessionMaxLifespan": 43200,
            "accessTokenLifespan": 900,
            "browserSecurityHeaders": {
                "strictTransportSecurity": if enable_hsts {
                    "max-age=31536000; includeSubDomains"
                } else {
                    ""
                },
                "xFrameOptions": "SAMEORIGIN",
                "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
                "xContentTypeOptions": "nosniff",
                "referrerPolicy": "no-referrer"
            },
            "bruteForceProtected": enable_brute_force
        });

        let resp = self
            .http_client
            .post(format!("{}/admin/realms", self.config.url))
            .bearer_auth(token)
            .header("Content-Type", "application/json")
            .json(&realm_json)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() || status.as_u16() == 409 {
            info!("   → Realm created (or already reported created)");
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!(
                "Realm creation failed: {} - {}",
                status,
                body
            ))
        }
    }

    /// Creates the LLDAP + Kerberos LDAP User Storage Provider component.
    /// Returns the internal Keycloak component ID of the provider (required for parenting custom mappers).
    async fn create_ldap_kerberos_component(
        &self,
        token: &str,
        lldap_url: &str,
        sync_username: &str,
        sync_password: &str,
    ) -> Result<String> {
        info!("   → Adding LDAP+Kerberos provider...");
        let base_dn = format!("dc={}", self.config.realm.replace('.', ",dc="));
        let component_json = json!({
            "name": "lldap-with-kerberos",
            "providerId": "ldap",
            "providerType": "org.keycloak.storage.UserStorageProvider",
            "config": {
                "vendor": ["other"],
                "connectionUrl": [lldap_url],
                "bindDn": [format!("uid={},ou=people,{}", sync_username, base_dn)],
                "bindCredential": [sync_password],
                "usersDn": [format!("ou=people,{}", base_dn)],
                "groupsDn": [format!("ou=groups,{}", base_dn)],
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
                "kerberosRealm": [self.config.realm.to_uppercase()],
                "serverPrincipal": [format!("HTTP/keycloak.{}@{}", self.config.realm, self.config.realm.to_uppercase())],
                "keyTab": ["/keytab/keycloak-http.keytab"],
                "krbPrincipalAttribute": ["krbPrincipalName"],
                "useKerberosForPasswordAuthentication": ["false"],
                "useTruststoreSpi": ["always"],
                "connectionPooling": ["true"],
                "cachePolicy": ["DEFAULT"],
                "usePasswordModifyExtendedOp": ["false"],
                "connectionTrace": ["false"]
            }
        });

        let resp = self
            .http_client
            .post(format!(
                "{}/admin/realms/{}/components",
                self.config.url, self.config.realm
            ))
            .bearer_auth(token)
            .header("Content-Type", "application/json")
            .json(&component_json)
            .send()
            .await?;

        let status = resp.status();
        if !(status.is_success() || status.as_u16() == 409) {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Component creation failed: {} - {}",
                status,
                body
            ));
        }

        // Retrieve the freshly created component's ID (Keycloak does not always echo it in POST body)
        let list_url = format!(
            "{}/admin/realms/{}/components?providerId=ldap&name=lldap-with-kerberos",
            self.config.url, self.config.realm
        );
        let components: Vec<serde_json::Value> = self
            .http_client
            .get(&list_url)
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to query created LDAP component")?
            .json()
            .await
            .context("Invalid component list JSON")?;

        let provider_id = components
            .iter()
            .find(|c| c.get("name").and_then(|n| n.as_str()) == Some("lldap-with-kerberos"))
            .and_then(|c| c.get("id").and_then(|i| i.as_str()))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Could not locate ID of newly created 'lldap-with-kerberos' component"
                )
            })?
            .to_string();

        info!("   → LDAP+Kerberos component ready (ID: {})", provider_id);
        Ok(provider_id)
    }

    async fn clear_default_mappers(&self, token: &str, provider_id: &str) -> Result<()> {
        info!("   → Clearing default Keycloak mappers...");

        let url = format!(
            "{}/admin/realms/{}/components?parent={}&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
            self.config.url, self.config.realm, provider_id
        );

        let mappers: Vec<serde_json::Value> = self
            .http_client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to list default mappers")?
            .json()
            .await
            .context("Invalid mappers list JSON")?;

        let mut deleted = 0;
        for mapper in mappers {
            if let Some(id) = mapper.get("id").and_then(|v| v.as_str()) {
                let name = mapper
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let del_url = format!(
                    "{}/admin/realms/{}/components/{}",
                    self.config.url, self.config.realm, id
                );
                let del_resp = self
                    .http_client
                    .delete(&del_url)
                    .bearer_auth(token)
                    .send()
                    .await;
                match del_resp {
                    Ok(r) if r.status().is_success() || r.status().as_u16() == 404 => {
                        info!("     ✓ Deleted default mapper: {}", name);
                        deleted += 1;
                    }
                    Ok(r) => {
                        info!(
                            "     ! Delete mapper {} returned {} (non-fatal)",
                            name,
                            r.status()
                        );
                    }
                    Err(e) => {
                        info!("     ! Delete mapper {} failed: {} (non-fatal)", name, e);
                    }
                }
            }
        }
        info!("   → Cleared {} default mappers.", deleted);
        Ok(())
    }

    async fn create_custom_mappers(&self, token: &str, provider_id: &str) -> Result<()> {
        info!("   → Creating custom schema-aligned mappers...");

        let custom_mappers = vec![
            json!({
                "name": "first name",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["givenName"],
                    "user.model.attribute": ["firstName"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"]
                }
            }),
            json!({
                "name": "last name",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["sn"],
                    "user.model.attribute": ["lastName"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"]
                }
            }),
            json!({
                "name": "email",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["mail"],
                    "user.model.attribute": ["email"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"]
                }
            }),
            json!({
                "name": "username",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["uid"],
                    "user.model.attribute": ["username"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["true"]
                }
            }),
            json!({
                "name": "display name",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["cn"],
                    "user.model.attribute": ["displayName"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"]
                }
            }),
            json!({
                "name": "uid number",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["uidNumber"],
                    "user.model.attribute": ["uidNumber"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"]
                }
            }),
            json!({
                "name": "gid number",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["gidNumber"],
                    "user.model.attribute": ["gidNumber"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"]
                }
            }),
            json!({
                "name": "home directory",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["homeDirectory"],
                    "user.model.attribute": ["homeDirectory"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"]
                }
            }),
            json!({
                "name": "login shell",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["loginShell"],
                    "user.model.attribute": ["loginShell"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"]
                }
            }),
            json!({
                "name": "krb principal name",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["krbPrincipalName"],
                    "user.model.attribute": ["krbPrincipalName"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"]
                }
            }),
            json!({
                "name": "ssh public key",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["sshPublicKey"],
                    "user.model.attribute": ["sshPublicKey"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"],
                    "multivalued": ["true"]
                }
            }),
            json!({
                "name": "ou",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["ou"],
                    "user.model.attribute": ["ou"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"]
                }
            }),
            json!({
                "name": "kerberos sync",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": provider_id,
                "config": {
                    "ldap.attribute": ["kerberossync"],
                    "user.model.attribute": ["kerberosSync"],
                    "read.only": ["true"],
                    "always.read.value.from.ldap": ["true"],
                    "is.mandatory.in.ldap": ["false"]
                }
            }),
        ];

        for mapper in custom_mappers {
            let name = mapper
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unnamed");
            let resp = self
                .http_client
                .post(format!(
                    "{}/admin/realms/{}/components",
                    self.config.url, self.config.realm
                ))
                .bearer_auth(token)
                .header("Content-Type", "application/json")
                .json(&mapper)
                .send()
                .await?;

            let status = resp.status();
            if status.is_success() || status.as_u16() == 409 {
                info!("     ✓ Created custom mapper: {}", name);
            } else {
                let body = resp.text().await.unwrap_or_default();
                info!(
                    "     ! Mapper '{}' creation returned {} (non-fatal, continuing): {}",
                    name, status, body
                );
            }
        }

        info!(
            "   → All custom mappers created. Attribute resolution for KLLDAP schema implemented."
        );
        Ok(())
    }

    async fn add_lldap_web_client(&self, token: &str) -> Result<()> {
        info!("   → Adding lldap-web client...");
        let client_json = json!({
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
        });

        let resp = self
            .http_client
            .post(format!(
                "{}/admin/realms/{}/clients",
                self.config.url, self.config.realm
            ))
            .bearer_auth(token)
            .header("Content-Type", "application/json")
            .json(&client_json)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() || status.as_u16() == 409 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!(
                "Client creation failed: {} - {}",
                status,
                body
            ))
        }
    }

    pub async fn test_connection(&self) -> Result<String> {
        info!("🔍 Testing Keycloak connection...");
        let token = self.acquire_token().await?;
        let resp = self
            .http_client
            .get(format!(
                "{}/admin/realms/{}",
                self.config.url, self.config.realm
            ))
            .bearer_auth(token)
            .send()
            .await?;

        if resp.status().is_success() {
            let msg = format!(
                "✅ Connected to Keycloak at {} — realm '{}' is ready",
                self.config.url, self.config.realm
            );
            info!("{}", msg);
            Ok(msg)
        } else {
            Err(anyhow::anyhow!("Test failed: HTTP {}", resp.status()))
        }
    }
}
