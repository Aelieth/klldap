use crate::configuration::Configuration;
use actix_web::{
    Error,
    dev::{ServiceRequest, ServiceResponse},
};
use std::env;
use tracing::{Span, debug, error};
use tracing_actix_web::RootSpanBuilder;
use tracing_subscriber::{filter::EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// We will define a custom root span builder to capture additional fields, specific
/// to our application, on top of the ones provided by `DefaultRootSpanBuilder` out of the box.
pub struct CustomRootSpanBuilder;

impl RootSpanBuilder for CustomRootSpanBuilder {
    fn on_request_start(request: &ServiceRequest) -> Span {
        tracing::debug_span!(
            "HTTP request",
            method = request.method().to_string(),
            uri = request.path()
        )
    }

    fn on_request_end<B>(_: Span, outcome: &Result<ServiceResponse<B>, Error>) {
        match &outcome {
            Ok(response) => {
                if let Some(error) = response.response().error() {
                    error!(?error);
                } else {
                    debug!(status_code = &response.response().status().as_u16());
                }
            }
            Err(error) => error!(?error),
        };
    }
}

pub fn init(config: &Configuration) -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(if config.verbose {
            "sqlx=warn,reqwest=warn,debug"
        } else {
            "sqlx=warn,reqwest=warn,krb5_kdc=warn,info"
        })
    });
    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_forest::ForestLayer::default());
    if env::var("LLDAP_RAW_LOG").is_ok() {
        registry.with(tracing_subscriber::fmt::layer()).init();
    } else {
        registry.init();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer};

    #[derive(Clone, Default)]
    struct Uris(Arc<Mutex<Vec<String>>>);

    impl Visit for Uris {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "uri" {
                self.0.lock().unwrap().push(format!("{value:?}"));
            }
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "uri" {
                self.0.lock().unwrap().push(value.to_owned());
            }
        }
    }

    impl<S: tracing::Subscriber> Layer<S> for Uris {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _: &tracing::span::Id,
            _: Context<'_, S>,
        ) {
            attrs.record(&mut self.clone());
        }
    }

    #[test]
    fn test_the_request_span_records_the_path_without_the_query_string() {
        let uris = Uris::default();
        let subscriber = tracing_subscriber::registry().with(uris.clone());
        let request = actix_web::test::TestRequest::post()
            .uri("/api/graphql?query=mutation%7BsetPassword%28password%3A%22hunter22%22%29%7D")
            .to_srv_request();
        tracing::subscriber::with_default(subscriber, || {
            let _span = CustomRootSpanBuilder::on_request_start(&request);
        });
        assert_eq!(*uris.0.lock().unwrap(), vec!["/api/graphql".to_owned()]);
    }
}
