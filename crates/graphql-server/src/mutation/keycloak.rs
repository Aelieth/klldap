use crate::api::{Context, FullHandler, field_error_callback};
use juniper::FieldResult;
use lldap_keycloak::{KeycloakClient, KeycloakConfig};
use lldap_opaque_handler::OpaqueHandler;
use tracing::debug_span;

#[derive(juniper::GraphQLInputObject)]
pub(super) struct TestKeycloakConnectionInput {
    url: String,
    realm: String,
    admin_user: String,
    admin_pass: String,
}

#[derive(juniper::GraphQLObject)]
pub(super) struct TestKeycloakConnectionResponse {
    ok: bool,
    message: String,
}

#[derive(juniper::GraphQLInputObject)]
pub(super) struct SaveKeycloakConfigInput {
    url: String,
    realm: String,
    admin_user: String,
}

#[derive(juniper::GraphQLObject)]
pub(super) struct SaveKeycloakConfigResponse {
    ok: bool,
    message: String,
}

#[derive(juniper::GraphQLObject)]
pub(super) struct PushRealmResponse {
    ok: bool,
    message: String,
}

#[derive(juniper::GraphQLInputObject, Debug)]
pub(super) struct PushRealmToKeycloakInput {
    url: String,
    realm: String,
    admin_user: String,
    admin_pass: String,
    lldap_url: String,
    sync_username: String,
    sync_password: String,
    enable_hsts: bool,
    enable_brute_force: bool,
}

pub(super) async fn test_keycloak_connection<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    input: TestKeycloakConnectionInput,
) -> FieldResult<TestKeycloakConnectionResponse> {
    let span = debug_span!("[GraphQL mutation] test_keycloak_connection");
    context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized Keycloak connection test",
        ))?;

    let client =
        KeycloakClient::from_test_input(input.url, input.realm, input.admin_user, input.admin_pass);

    match client.test_connection().await {
        Ok(message) => Ok(TestKeycloakConnectionResponse { ok: true, message }),
        Err(e) => Ok(TestKeycloakConnectionResponse {
            ok: false,
            message: format!("❌ {}", e),
        }),
    }
}

pub(super) async fn save_keycloak_config<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    input: SaveKeycloakConfigInput,
) -> FieldResult<SaveKeycloakConfigResponse> {
    let span = debug_span!("[GraphQL mutation] save_keycloak_config");
    context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized Keycloak config change",
        ))?;

    let config = KeycloakConfig {
        url: input.url,
        realm: input.realm,
        admin_user: input.admin_user,
    };

    match config.save() {
        Ok(path) => Ok(SaveKeycloakConfigResponse {
            ok: true,
            message: format!(
                "✅ Keycloak settings saved to {} (password remains in-memory/env only)",
                path.display()
            ),
        }),
        Err(e) => Ok(SaveKeycloakConfigResponse {
            ok: false,
            message: format!("❌ Failed to save config: {}", e),
        }),
    }
}

pub(super) async fn push_realm_to_keycloak<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    input: PushRealmToKeycloakInput,
) -> FieldResult<PushRealmResponse> {
    let span = debug_span!("[GraphQL mutation] push_realm_to_keycloak");
    context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized Keycloak realm push",
        ))?;

    let client =
        KeycloakClient::from_test_input(input.url, input.realm, input.admin_user, input.admin_pass);

    let enable_hsts = input.enable_hsts;
    let enable_brute_force = input.enable_brute_force;

    let message = client
        .setup_realm(
            input.lldap_url,
            input.sync_username,
            input.sync_password,
            enable_hsts,
            enable_brute_force,
        )
        .await
        .map_err(|e| juniper::FieldError::new(e.to_string(), juniper::Value::null()))?;

    Ok(PushRealmResponse { ok: true, message })
}
