use crate::api::{Context, FullHandler, field_error_callback};
use juniper::{FieldError, FieldResult, graphql_value};
use lldap_domain_handlers::handler::{PosixBackendHandler, PosixSettings};
use lldap_opaque_handler::OpaqueHandler;
use tracing::{debug, debug_span};

#[derive(juniper::GraphQLInputObject, Debug)]
pub(super) struct PosixSettingsInput {
    // === Users ===
    pub user_uidnumber_assign: bool,
    pub user_uidnumber_start: i32,
    pub user_uidnumber_max: i32,

    pub user_gidnumber_assign: bool,
    pub user_gidnumber_start: i32,

    pub user_loginshell_assign: bool,
    pub user_loginshell_default: String,

    pub user_homedirectory_assign: bool,
    pub user_homedirectory_prefix: String,

    // === Groups ===
    pub group_gidnumber_assign: bool,
    pub group_gidnumber_start: i32,
    pub group_gidnumber_max: i32,
}

#[derive(juniper::GraphQLObject)]
pub(super) struct PosixSettingsResponse {
    success: bool,
    message: String,
}

fn posix_reassign_response<E: std::fmt::Display>(
    result: Result<(), E>,
    failure_msg: &str,
    success_msg: &str,
) -> FieldResult<PosixSettingsResponse> {
    result.map_err(|e| {
        FieldError::new(failure_msg, graphql_value!({ "details": (e.to_string()) }))
    })?;
    Ok(PosixSettingsResponse {
        success: true,
        message: success_msg.to_string(),
    })
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
        && (input.user_uidnumber_start < 3000
            || input.user_uidnumber_start > 60000
            || input.user_uidnumber_max < 3000
            || input.user_uidnumber_max > 60000)
    {
        return Err(FieldError::new(
            "user_uidnumber must be between 3000 and 60000",
            juniper::Value::null(),
        ));
    }
    if input.user_gidnumber_assign
        && (input.user_gidnumber_start < 3000 || input.user_gidnumber_start > 60000)
    {
        return Err(FieldError::new(
            "user_gidnumber_start must be between 3000 and 60000",
            juniper::Value::null(),
        ));
    }
    if input.group_gidnumber_assign
        && (input.group_gidnumber_start < 3000
            || input.group_gidnumber_start > 60000
            || input.group_gidnumber_max < 3000
            || input.group_gidnumber_max > 60000)
    {
        return Err(FieldError::new(
            "group_gidnumber must be between 3000 and 60000",
            juniper::Value::null(),
        ));
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

    handler.set_posix_settings(settings).await.map_err(|e| {
        FieldError::new(
            "Failed to save POSIX settings",
            graphql_value!({ "details": (e.to_string()) }),
        )
    })?;

    Ok(PosixSettingsResponse {
        success: true,
        message: "✅ POSIX settings saved (toggles and ranges updated)".to_string(),
    })
}

pub(super) async fn reassign_user_uid_numbers<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<PosixSettingsResponse> {
    let span = debug_span!("[GraphQL mutation] reassign_user_uid_numbers");
    span.in_scope(|| debug!("Reassigning all user uidNumbers"));

    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized uidNumber reassign",
        ))?;

    posix_reassign_response(
        handler.reassign_user_uid_numbers().await,
        "Failed to reassign user uidNumbers",
        "✅ All user uidNumbers have been reassigned",
    )
}

pub(super) async fn reassign_user_gid_numbers<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<PosixSettingsResponse> {
    let span = debug_span!("[GraphQL mutation] reassign_user_gid_numbers");
    span.in_scope(|| debug!("Reassigning all user gidNumbers"));

    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized gidNumber reassign",
        ))?;

    posix_reassign_response(
        handler.reassign_user_gid_numbers().await,
        "Failed to reassign user gidNumbers",
        "✅ All user gidNumbers have been reassigned",
    )
}

pub(super) async fn reassign_user_homedirectories<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<PosixSettingsResponse> {
    let span = debug_span!("[GraphQL mutation] reassign_user_homedirectories");
    span.in_scope(|| debug!("Reassigning all user homeDirectories"));

    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized homeDirectory reassign",
        ))?;

    posix_reassign_response(
        handler.reassign_user_homedirectories().await,
        "Failed to reassign user homeDirectories",
        "✅ All user homeDirectories have been reassigned",
    )
}

pub(super) async fn reassign_user_loginshells<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<PosixSettingsResponse> {
    let span = debug_span!("[GraphQL mutation] reassign_user_loginshells");
    span.in_scope(|| debug!("Reassigning all user loginShells"));

    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized loginShell reassign",
        ))?;

    posix_reassign_response(
        handler.reassign_user_loginshells().await,
        "Failed to reassign user loginShells",
        "✅ All user loginShells have been reassigned",
    )
}

pub(super) async fn reassign_gid_numbers<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
) -> FieldResult<PosixSettingsResponse> {
    let span = debug_span!("[GraphQL mutation] reassign_gid_numbers");
    span.in_scope(|| debug!("Reassigning all group gidNumbers"));

    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized gidNumber reassign",
        ))?;

    posix_reassign_response(
        handler.reassign_gid_numbers().await,
        "Failed to reassign gidNumbers",
        "✅ All group gidNumbers have been reassigned",
    )
}
