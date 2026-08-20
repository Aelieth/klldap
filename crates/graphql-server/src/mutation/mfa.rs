use crate::api::{Context, FullHandler, field_error_callback};
use crate::mutation::{MfaEnrollmentStart, Success};
use juniper::FieldResult;
use lldap_access_control::UserReadableBackendHandler;
use lldap_domain::types::UserId;
use lldap_domain_handlers::handler::MfaBackendHandler;
use lldap_domain_handlers::mfa::{MfaPolicy, MfaResetReason};
use lldap_opaque_handler::OpaqueHandler;
use tracing::{debug, debug_span};

pub(super) async fn reset_user_mfa<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    user_id: String,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] reset_user_mfa");
    span.in_scope(|| debug!(?user_id));
    let user_id = UserId::new(&user_id);
    if context.mfa_policy == MfaPolicy::Always && user_id == context.validation_result.user {
        return Err(
            "Cannot reset your own MFA when it is required by the server configuration".into(),
        );
    }
    let user_is_admin = context
        .get_readable_handler(user_id.clone())
        .ok_or_else(field_error_callback(&span, "Unauthorized MFA reset"))?
        .get_user_groups(&user_id)
        .await?
        .iter()
        .any(|g| g.display_name == "lldap_admin".into());
    context
        .get_mfa_reset_handler(&user_id, user_is_admin)
        .ok_or_else(field_error_callback(&span, "Unauthorized MFA reset"))?
        .reset_user_mfa(&user_id, MfaResetReason::Administrative)
        .await?;
    Ok(Success::new())
}

pub(super) async fn reset_own_mfa<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    code: String,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] reset_own_mfa");
    let user_id = &context.validation_result.user;
    span.in_scope(|| debug!(?user_id));
    context.reject_if_mfa_disabled(&span)?;
    if context.mfa_policy == MfaPolicy::Always {
        return Err("MFA is required by the server configuration".into());
    }
    context
        .get_mfa_self_handler()
        .reset_own_mfa(user_id, &code)
        .await?;
    Ok(Success::new())
}

pub(super) async fn start_mfa_enrollment<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    current_code: Option<String>,
) -> FieldResult<MfaEnrollmentStart> {
    let span = debug_span!("[GraphQL mutation] start_mfa_enrollment");
    let user_id = &context.validation_result.user;
    span.in_scope(|| debug!(?user_id));
    context.reject_if_mfa_disabled(&span)?;
    Ok(context
        .get_mfa_self_handler()
        .start_totp_enrollment(user_id, current_code)
        .await?
        .into())
}

pub(super) async fn finish_mfa_enrollment<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    state: String,
    code: String,
) -> FieldResult<Success> {
    let span = debug_span!("[GraphQL mutation] finish_mfa_enrollment");
    let user_id = &context.validation_result.user;
    span.in_scope(|| debug!(?user_id));
    context.reject_if_mfa_disabled(&span)?;
    context
        .get_mfa_self_handler()
        .finish_totp_enrollment(user_id, &state, &code)
        .await?;
    Ok(Success::new())
}
