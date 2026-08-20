use crate::{mutation::Mutation, query::Query};
use juniper::{EmptySubscription, FieldError, FieldResult, RootNode};
use lldap_access_control::{
    AccessControlledBackendHandler, AdminBackendHandler, ReadonlyBackendHandler,
    UserReadableBackendHandler, UserWriteableBackendHandler,
};
use lldap_auth::{access_control::ValidationResults, types::UserId};
use lldap_domain_handlers::handler::{BackendHandler, MfaBackendHandler};
use lldap_domain_handlers::logging::{self, LogKind};
use lldap_domain_handlers::mfa::MfaPolicy;
use lldap_opaque_handler::OpaqueHandler;
use tracing::debug;

pub trait FullHandler: BackendHandler + OpaqueHandler {}

impl<T: BackendHandler + OpaqueHandler> FullHandler for T {}

pub struct Context<Handler: FullHandler> {
    pub handler: AccessControlledBackendHandler<Handler>,
    pub validation_result: ValidationResults,
    pub mfa_policy: MfaPolicy,
    pub mfa_enrollment_pending: bool,
}

pub fn field_error_callback<'a>(
    span: &'a tracing::Span,
    error_message: &'a str,
) -> impl 'a + FnOnce() -> FieldError {
    move || {
        span.in_scope(|| debug!("Unauthorized"));
        logging::record_failure(LogKind::AccessDenied, None, error_message);
        FieldError::from(error_message)
    }
}

impl<Handler: FullHandler> Context<Handler> {
    #[cfg(test)]
    pub fn new_for_tests(handler: Handler, validation_result: ValidationResults) -> Self {
        Self::new_for_tests_with_policy(handler, validation_result, MfaPolicy::Disabled, false)
    }

    #[cfg(test)]
    pub fn new_for_tests_with_policy(
        handler: Handler,
        validation_result: ValidationResults,
        mfa_policy: MfaPolicy,
        mfa_enrollment_pending: bool,
    ) -> Self {
        Self {
            handler: AccessControlledBackendHandler::new(handler),
            validation_result,
            mfa_policy,
            mfa_enrollment_pending,
        }
    }

    // An unenrolled session under "always" may only read itself and enroll
    // (Query::get_schema's lister is schema-only).
    pub fn get_admin_handler(&self) -> Option<&(impl AdminBackendHandler + Send + Sync + '_)> {
        if self.mfa_enrollment_pending {
            return None;
        }
        self.handler.get_admin_handler(&self.validation_result)
    }

    pub fn get_readonly_handler(&self) -> Option<&(impl ReadonlyBackendHandler + '_)> {
        if self.mfa_enrollment_pending {
            return None;
        }
        self.handler.get_readonly_handler(&self.validation_result)
    }

    pub fn get_writeable_handler(
        &self,
        user_id: UserId,
    ) -> Option<&(impl UserWriteableBackendHandler + OpaqueHandler + '_)> {
        if self.mfa_enrollment_pending {
            return None;
        }
        self.handler
            .get_writeable_handler(&self.validation_result, user_id)
    }

    pub fn get_readable_handler(
        &self,
        user_id: UserId,
    ) -> Option<&(impl UserReadableBackendHandler + '_)> {
        if self.mfa_enrollment_pending && user_id != self.validation_result.user {
            return None;
        }
        self.handler
            .get_readable_handler(&self.validation_result, user_id)
    }

    pub fn get_mfa_self_handler(&self) -> &(impl MfaBackendHandler + '_) {
        self.handler.get_mfa_self_handler()
    }

    pub fn get_mfa_reset_handler(
        &self,
        user_id: &UserId,
        user_is_admin: bool,
    ) -> Option<&(impl MfaBackendHandler + '_)> {
        if self.mfa_enrollment_pending {
            return None;
        }
        self.handler
            .get_mfa_reset_handler(&self.validation_result, user_id, user_is_admin)
    }

    pub fn reject_if_mfa_disabled(&self, span: &tracing::Span) -> FieldResult<()> {
        if self.mfa_policy == MfaPolicy::Disabled {
            span.in_scope(|| debug!("MFA disabled"));
            return Err("MFA is disabled by the server configuration".into());
        }
        Ok(())
    }
}

impl<Handler: FullHandler> juniper::Context for Context<Handler> {}

type Schema<Handler> =
    RootNode<Query<Handler>, Mutation<Handler>, EmptySubscription<Context<Handler>>>;

pub fn schema<Handler: FullHandler>() -> Schema<Handler> {
    Schema::new(
        Query::<Handler>::new(),
        Mutation::<Handler>::default(),
        EmptySubscription::<Context<Handler>>::new(),
    )
}

pub fn export_schema(output_file: Option<String>) -> anyhow::Result<()> {
    use anyhow::Context;
    use lldap_sql_backend_handler::SqlBackendHandler;

    let output = schema::<SqlBackendHandler>().as_sdl();

    match output_file {
        None => println!("{output}"),
        Some(path) => {
            use std::fs::File;
            use std::io::prelude::*;
            use std::path::Path;
            let path = Path::new(&path);
            let mut file =
                File::create(path).context(format!("unable to open '{}'", path.display()))?;
            file.write_all(output.as_bytes())
                .context(format!("unable to write in '{}'", path.display()))?;
        }
    }
    Ok(())
}
