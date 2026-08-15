use crate::api::{Context, FullHandler, field_error_callback};
use crate::kerberos_transport::decrypt_password;
use anyhow::anyhow;
use juniper::FieldResult;
use lldap_access_control::{UserReadableBackendHandler, UserWriteableBackendHandler};
use lldap_domain::types::{UserId, kerberos_sync_enabled};
use lldap_domain_handlers::kerberos::kerberos_backend;
use lldap_opaque_handler::OpaqueHandler;
use tracing::{debug, debug_span, info, warn};

#[derive(juniper::GraphQLObject)]
pub(super) struct ExportKeytabForKeycloakResponse {
    ok: bool,
    path: String,
    error_msg: String,
}

pub(super) async fn sync_kerberos_password<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    user_id: String,
    encrypted_password: String,
) -> FieldResult<bool> {
    let span = debug_span!("[GraphQL mutation] sync_kerberos_password");
    let _guard = span.enter();
    let target_user_id = UserId::new(&user_id);
    // Users may sync their own principal after a password change.
    let handler = context
        .get_writeable_handler(target_user_id.clone())
        .ok_or_else(field_error_callback(&span, "Unauthorized Kerberos sync"))?;
    let plain_password = decrypt_password(&encrypted_password)
        .map_err(|e| anyhow!("Kerberos password decryption failed: {e}"))?;
    let user = handler
        .get_user_details(&target_user_id)
        .await
        .map_err(|e| anyhow!("Failed to fetch user for Kerberos sync check: {e}"))?;
    let sync_enabled = kerberos_sync_enabled(&user.attributes);
    if sync_enabled {
        kerberos_backend()
            .sync_principal(&user_id, &plain_password)
            .map_err(|e| anyhow!("Kerberos sync failed: {e}"))?;
        info!("Kerberos principal synced for user {user_id}");
        // A first password for an already-disabled user would otherwise mint a live principal.
        if let Ok(groups) = handler.get_user_groups(&target_user_id).await
            && groups
                .iter()
                .any(|g| g.display_name == "lldap_disabled".into())
        {
            kerberos_backend().reassert_disabled(&user_id);
        }
    } else {
        info!("Kerberos sync disabled for user {user_id}, skipping");
    }
    if let Err(e) = handler
        .ensure_kerberos_principal_consistency(&target_user_id, sync_enabled)
        .await
    {
        warn!("Failed to record Kerberos principal name for {target_user_id}: {e}");
    }
    Ok(true)
}

pub(super) async fn export_keytab_for_keycloak<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    hostname: String,
) -> FieldResult<ExportKeytabForKeycloakResponse> {
    let span = debug_span!("[GraphQL mutation] export_keytab_for_keycloak");
    span.in_scope(|| debug!(?hostname));
    context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized keytab export"))?;
    match kerberos_backend().export_keytab_for_keycloak(&hostname) {
        Ok(path) => Ok(ExportKeytabForKeycloakResponse {
            ok: true,
            path,
            error_msg: String::new(),
        }),
        Err(e) => {
            warn!("Keytab export failed: {e}");
            Ok(ExportKeytabForKeycloakResponse {
                ok: false,
                path: String::new(),
                error_msg: e.to_string(),
            })
        }
    }
}
