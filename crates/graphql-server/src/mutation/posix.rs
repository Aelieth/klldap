use crate::api::{Context, FullHandler, field_error_callback};
use anyhow::anyhow;
use juniper::FieldResult;
use lldap_domain_handlers::handler::{PosixBackendHandler, PosixSettings};
use lldap_opaque_handler::OpaqueHandler;
use tracing::{debug, debug_span};

#[derive(juniper::GraphQLInputObject, Debug)]
pub(super) struct PosixSettingsInput {
    pub user_uidnumber_assign: bool,
    pub user_uidnumber_start: i32,
    pub user_uidnumber_max: i32,
    pub user_gidnumber_assign: bool,
    pub user_gidnumber_start: i32,
    pub user_loginshell_assign: bool,
    pub user_loginshell_default: String,
    pub user_homedirectory_assign: bool,
    pub user_homedirectory_prefix: String,
    pub group_gidnumber_assign: bool,
    pub group_gidnumber_start: i32,
    pub group_gidnumber_max: i32,
}

#[derive(juniper::GraphQLObject)]
pub(super) struct PosixSettingsResponse {
    success: bool,
    message: String,
}

fn response(message: &str) -> FieldResult<PosixSettingsResponse> {
    Ok(PosixSettingsResponse {
        success: true,
        message: message.to_owned(),
    })
}

fn in_range(numbers: &[i32]) -> bool {
    numbers.iter().all(|n| (3000..=60000).contains(n))
}

pub(super) async fn set_posix_settings<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    input: PosixSettingsInput,
) -> FieldResult<PosixSettingsResponse> {
    let span = debug_span!("[GraphQL mutation] set_posix_settings");
    span.in_scope(|| debug!(?input));
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized POSIX settings change",
        ))?;
    // Ranges are only enforced for the assignments that are switched on.
    if input.user_uidnumber_assign
        && !in_range(&[input.user_uidnumber_start, input.user_uidnumber_max])
    {
        return Err("user_uidnumber must be between 3000 and 60000".into());
    }
    if input.user_gidnumber_assign && !in_range(&[input.user_gidnumber_start]) {
        return Err("user_gidnumber_start must be between 3000 and 60000".into());
    }
    if input.group_gidnumber_assign
        && !in_range(&[input.group_gidnumber_start, input.group_gidnumber_max])
    {
        return Err("group_gidnumber must be between 3000 and 60000".into());
    }
    let settings = PosixSettings {
        user_uidnumber_assign: input.user_uidnumber_assign,
        user_uidnumber_start: input.user_uidnumber_start as i64,
        user_uidnumber_max: input.user_uidnumber_max as i64,
        user_gidnumber_assign: input.user_gidnumber_assign,
        user_gidnumber_start: input.user_gidnumber_start as i64,
        user_loginshell_assign: input.user_loginshell_assign,
        user_loginshell_default: input.user_loginshell_default,
        user_homedirectory_assign: input.user_homedirectory_assign,
        user_homedirectory_prefix: input.user_homedirectory_prefix,
        group_gidnumber_assign: input.group_gidnumber_assign,
        group_gidnumber_start: input.group_gidnumber_start as i64,
        group_gidnumber_max: input.group_gidnumber_max as i64,
    };
    handler
        .set_posix_settings(settings)
        .await
        .map_err(|e| anyhow!("Failed to save POSIX settings: {e}"))?;
    response("✅ POSIX settings saved (toggles and ranges updated)")
}

pub(super) async fn reassign_user_uid_numbers<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<PosixSettingsResponse> {
    let span = debug_span!("[GraphQL mutation] reassign_user_uid_numbers");
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized uidNumber reassign",
        ))?;
    handler
        .reassign_user_uid_numbers()
        .await
        .map_err(|e| anyhow!("Failed to reassign user uidNumbers: {e}"))?;
    response("✅ All user uidNumbers have been reassigned")
}

pub(super) async fn reassign_user_gid_numbers<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<PosixSettingsResponse> {
    let span = debug_span!("[GraphQL mutation] reassign_user_gid_numbers");
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized gidNumber reassign",
        ))?;
    handler
        .reassign_user_gid_numbers()
        .await
        .map_err(|e| anyhow!("Failed to reassign user gidNumbers: {e}"))?;
    response("✅ All user gidNumbers have been reassigned")
}

pub(super) async fn reassign_user_homedirectories<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<PosixSettingsResponse> {
    let span = debug_span!("[GraphQL mutation] reassign_user_homedirectories");
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized homeDirectory reassign",
        ))?;
    handler
        .reassign_user_homedirectories()
        .await
        .map_err(|e| anyhow!("Failed to reassign user homeDirectories: {e}"))?;
    response("✅ All user homeDirectories have been reassigned")
}

pub(super) async fn reassign_user_loginshells<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<PosixSettingsResponse> {
    let span = debug_span!("[GraphQL mutation] reassign_user_loginshells");
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized loginShell reassign",
        ))?;
    handler
        .reassign_user_loginshells()
        .await
        .map_err(|e| anyhow!("Failed to reassign user loginShells: {e}"))?;
    response("✅ All user loginShells have been reassigned")
}

pub(super) async fn reassign_gid_numbers<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<PosixSettingsResponse> {
    let span = debug_span!("[GraphQL mutation] reassign_gid_numbers");
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized gidNumber reassign",
        ))?;
    handler
        .reassign_gid_numbers()
        .await
        .map_err(|e| anyhow!("Failed to reassign gidNumbers: {e}"))?;
    response("✅ All group gidNumbers have been reassigned")
}
