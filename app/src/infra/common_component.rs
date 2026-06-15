//! Common logic for components that use the backend.

use std::future::Future;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use anyhow::{Error, Result};
use gloo_console::error;
use graphql_client::GraphQLQuery;
use yew::prelude::*;

use crate::infra::api::HostService;

/// Trait required for common components (CRTP pattern).
pub trait CommonComponent<C: Component>: Component {
    /// Handle the incoming message. If an error is returned here, any running task will be
    /// cancelled, the error will be written to the [`CommonComponentParts::error`] and the
    /// component will be refreshed.
    fn handle_msg(&mut self, ctx: &Context<C>, msg: C::Message) -> Result<bool>;
    /// Get a mutable reference to the inner component parts, necessary for the CRTP.
    fn mut_common(&mut self) -> &mut CommonComponentParts<C>;
}

/// Structure that contains the common parts needed by most components.
pub struct CommonComponentParts<C: Component> {
    pub error: Option<Error>,
    is_task_running: Arc<Mutex<u32>>,
    _phantom: PhantomData<C>,
}

impl<C: Component + CommonComponent<C>> CommonComponentParts<C> {
    pub fn create() -> Self {
        CommonComponentParts {
            error: None,
            is_task_running: Arc::new(Mutex::new(0)),
            _phantom: PhantomData,
        }
    }

    /// Whether there is a currently running task in the background.
    pub fn is_task_running(&self) -> bool {
        *self.is_task_running.lock().unwrap() > 0
    }

    /// This should be called from the [`yew::prelude::Component::update`]: it will in turn call
    /// [`CommonComponent::handle_msg`] and handle any resulting error.
    pub fn update(com: &mut C, ctx: &Context<C>, msg: C::Message) -> bool {
        com.mut_common().error = None;
        match com.handle_msg(ctx, msg) {
            Err(e) => {
                error!(&e.to_string());
                com.mut_common().error = Some(e);
                true
            }
            Ok(b) => b,
        }
    }

    /// Same as above, but the resulting error is instead passed to the reporting function.
    pub fn update_and_report_error(
        com: &mut C,
        ctx: &Context<C>,
        msg: C::Message,
        report_fn: Callback<Error>,
    ) -> bool {
        let should_render = Self::update(com, ctx, msg);
        com.mut_common()
            .error
            .take()
            .map(|e| {
                report_fn.emit(e);
                true
            })
            .unwrap_or(should_render)
    }

    /// Call `method` from the backend with the given `request`, and pass the `callback` for the
    /// result.
    ///
    /// NOTE: `Req` is removed entirely — we never use it. This eliminates all inference problems.
    pub fn call_backend<Resp, Fut, Cb>(&mut self, ctx: &Context<C>, fut: Fut, callback: Cb)
    where
        Fut: Future<Output = Result<Resp>> + 'static,
        Cb: FnOnce(Result<Resp>) -> C::Message + 'static,
    {
        {
            let mut running = self.is_task_running.lock().unwrap();
            *running += 1;
        }
        let is_task_running = self.is_task_running.clone();
        ctx.link().send_future(async move {
            let res = fut.await;
            {
                let mut running = is_task_running.lock().unwrap();
                *running -= 1;
            }
            callback(res)
        });
    }

    /// Call the backend with a GraphQL query.
    ///
    /// `EnumCallback` should usually be left as `_`.
    pub fn call_graphql<QueryType, EnumCallback>(
        &mut self,
        ctx: &Context<C>,
        variables: QueryType::Variables,
        enum_callback: EnumCallback,
        error_message: &'static str,
    ) where
        QueryType: GraphQLQuery + 'static,
        EnumCallback: Fn(Result<QueryType::ResponseData>) -> C::Message + 'static,
    {
        self.call_backend::<QueryType::ResponseData, _, _>(
            ctx,
            HostService::graphql_query::<QueryType>(variables, error_message),
            enum_callback,
        );
    }
}
