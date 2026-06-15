use crate::components::status_modal::StatusModal;
use crate::infra::{
    common_component::{CommonComponent, CommonComponentParts},
    modal::Modal,
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/delete_ou.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteOuQuery;

pub struct DeleteOu {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
    status_message: Option<(String, bool)>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct DeleteOuProps {
    pub ou: String,
    pub reassign_to: String, // "people" or "groups"
    pub on_ou_deleted: Callback<String>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedDeleteOu,
    ConfirmDeleteOu,
    DismissModal,
    DeleteOuResponse(Result<delete_ou_query::ResponseData>),
    ShowStatus(String, bool),
    DismissStatus,
}

impl CommonComponent<DeleteOu> for DeleteOu {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedDeleteOu => {
                if ctx.props().ou == "people"
                    || ctx.props().ou == "groups"
                    || ctx.props().ou == "All"
                {
                    ctx.link().send_message(Msg::ShowStatus(
                        "Cannot delete built-in OU 'people', 'groups', or 'All'".to_string(),
                        false,
                    ));
                    return Ok(true);
                }
                self.common.error = None;
                self.status_message = None;
                self.modal.as_ref().expect("modal not initialized").show();
                Ok(true)
            }
            Msg::ConfirmDeleteOu => {
                self.common.call_graphql::<DeleteOuQuery, _>(
                    ctx,
                    delete_ou_query::Variables {
                        name: ctx.props().ou.clone(),
                    },
                    Msg::DeleteOuResponse,
                    "Error trying to delete OU",
                );
                Ok(true)
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
                Ok(true)
            }
            Msg::DeleteOuResponse(response) => {
                match response {
                    Ok(_) => {
                        let msg = format!("Successfully deleted OU: {}", ctx.props().ou);
                        ctx.props().on_ou_deleted.emit(ctx.props().ou.clone());
                        ctx.link().send_message(Msg::ShowStatus(msg, true));
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        ctx.props().on_error.emit(e);
                        ctx.link().send_message(Msg::ShowStatus(msg, false));
                    }
                }
                self.modal.as_ref().expect("modal not initialized").hide();
                Ok(true)
            }
            Msg::ShowStatus(message, is_success) => {
                self.status_message = Some((message, is_success));
                Ok(true)
            }
            Msg::DismissStatus => {
                self.status_message = None;
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for DeleteOu {
    type Message = Msg;
    type Properties = DeleteOuProps;

    fn create(_: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            node_ref: NodeRef::default(),
            modal: None,
            status_message: None,
        }
    }

    fn rendered(&mut self, _: &Context<Self>, first_render: bool) {
        if first_render {
            self.modal = Some(Modal::new(
                self.node_ref
                    .cast::<web_sys::Element>()
                    .expect("Modal node is not an element"),
            ));
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update_and_report_error(
            self,
            ctx,
            msg,
            ctx.props().on_error.clone(),
        )
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();

        let status_html = if let Some((msg, is_success)) = &self.status_message {
            let on_dismiss = link.callback(|_| Msg::DismissStatus);
            html! { <StatusModal message={msg.clone()} is_success={*is_success} on_dismiss={on_dismiss} /> }
        } else {
            html! {}
        };

        html! {
          <>
          <button
            class="btn btn-danger"
            disabled={self.common.is_task_running()
                || ctx.props().ou == "people"
                || ctx.props().ou == "groups"
                || ctx.props().ou == "All"}
            onclick={link.callback(|_| Msg::ClickedDeleteOu)}>
            <i class="bi-x-circle-fill me-2" aria-label="Delete OU" />
            {"Delete OU"}
          </button>
          {self.show_modal(ctx)}
          {status_html}
          </>
        }
    }
}

impl DeleteOu {
    fn show_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        let reassign_text = if ctx.props().reassign_to == "people" {
            "people"
        } else {
            "groups"
        };

        html! {
          <div
            class="modal fade"
            id={format!("deleteOuModal{}", ctx.props().ou)}
            tabindex="-1"
            aria-labelledby="deleteOuModalLabel"
            aria-hidden="true"
            ref={self.node_ref.clone()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="deleteOuModalLabel">{"Delete Organizational Unit?"}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                  <span>
                    {"Are you sure you want to delete Organizational Unit "}
                    <b>{&ctx.props().ou}</b>{"?"}<br />
                    {format!("All items in this OU will be reassigned to '{}'. This cannot be undone.", reassign_text)}
                  </span>
                </div>
                <div class="modal-footer">
                  <button
                    type="button"
                    class="btn btn-secondary"
                    onclick={link.callback(|_| Msg::DismissModal)}>
                    <i class="bi-x-circle me-2"></i>
                    {"Cancel"}
                  </button>
                  <button
                    type="button"
                    onclick={link.callback(|_| Msg::ConfirmDeleteOu)}
                    class="btn btn-danger"
                    disabled={self.common.is_task_running()}>
                    <i class="bi-check-circle me-2"></i>
                    {"Yes, I'm sure"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
