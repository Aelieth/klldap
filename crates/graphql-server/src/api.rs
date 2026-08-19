use crate::{mutation::Mutation, query::Query};
use juniper::{EmptySubscription, FieldError, RootNode};
use lldap_access_control::{
    AccessControlledBackendHandler, AdminBackendHandler, ReadonlyBackendHandler,
    UserReadableBackendHandler, UserWriteableBackendHandler,
};
use lldap_auth::{access_control::ValidationResults, types::UserId};
use lldap_domain_handlers::handler::BackendHandler;
use lldap_domain_handlers::logging::{self, LogKind};
use lldap_opaque_handler::OpaqueHandler;
use tracing::debug;

pub trait FullHandler: BackendHandler + OpaqueHandler {}

impl<T: BackendHandler + OpaqueHandler> FullHandler for T {}

pub struct Context<Handler: FullHandler> {
    pub handler: AccessControlledBackendHandler<Handler>,
    pub validation_result: ValidationResults,
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
        Self {
            handler: AccessControlledBackendHandler::new(handler),
            validation_result,
        }
    }

    pub fn get_admin_handler(&self) -> Option<&(impl AdminBackendHandler + Send + Sync + '_)> {
        self.handler.get_admin_handler(&self.validation_result)
    }

    pub fn get_readonly_handler(&self) -> Option<&(impl ReadonlyBackendHandler + '_)> {
        self.handler.get_readonly_handler(&self.validation_result)
    }

    pub fn get_writeable_handler(
        &self,
        user_id: UserId,
    ) -> Option<&(impl UserWriteableBackendHandler + OpaqueHandler + '_)> {
        self.handler
            .get_writeable_handler(&self.validation_result, user_id)
    }

    pub fn get_readable_handler(
        &self,
        user_id: UserId,
    ) -> Option<&(impl UserReadableBackendHandler + '_)> {
        self.handler
            .get_readable_handler(&self.validation_result, user_id)
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
