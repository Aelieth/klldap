use crate::api::{Context, FullHandler, field_error_callback};
use juniper::FieldResult;
use lldap_domain_handlers::kerberos::kerberos_backend;
use lldap_opaque_handler::OpaqueHandler;
use tracing::{debug, debug_span, warn};

#[derive(juniper::GraphQLObject)]
pub(super) struct ExportKeytabForKeycloakResponse {
    ok: bool,
    path: String,
    error_msg: String,
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
    match kerberos_backend()
        .export_keytab_for_keycloak(&hostname)
        .await
    {
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
