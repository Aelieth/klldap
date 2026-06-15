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
    query_path = "queries/delete_user.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteUserQuery;

pub struct DeleteUser {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct DeleteUserProps {
    pub selected_users: Vec<String>,
    pub on_user_deleted: Callback<String>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedDeleteUser,
    ConfirmDeleteUser,
    DismissModal,
    DeleteUserResponse(Result<delete_user_query::ResponseData>, String),
}

impl CommonComponent<DeleteUser> for DeleteUser {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedDeleteUser => {
                if ctx.props().selected_users.is_empty() {
                    return Ok(true);
                }
                self.modal.as_ref().expect("modal not initialized").show();
                Ok(true)
            }
            Msg::ConfirmDeleteUser => {
                for user_id in ctx.props().selected_users.clone() {
                    self.common.call_graphql::<DeleteUserQuery, _>(
                        ctx,
                        delete_user_query::Variables {
                            user: user_id.clone(),
                        },
                        move |response| Msg::DeleteUserResponse(response, user_id.clone()),
                        "Error trying to delete user",
                    );
                }
                self.modal.as_ref().expect("modal not initialized").hide();
                Ok(true)
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
                Ok(true)
            }
            Msg::DeleteUserResponse(response, user_id) => {
                match response {
                    Ok(_) => {
                        ctx.props().on_user_deleted.emit(user_id.clone());
                    }
                    Err(e) => {
                        ctx.props().on_error.emit(e);
                    }
                }
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for DeleteUser {
    type Message = Msg;
    type Properties = DeleteUserProps;

    fn create(_: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            node_ref: NodeRef::default(),
            modal: None,
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
        let count = ctx.props().selected_users.len();

        let button_text = if count <= 1 {
            "Delete User".to_string()
        } else {
            format!("Delete {} Users", count)
        };

        html! {
          <>
          <button
            class="btn btn-danger"
            disabled={self.common.is_task_running() || count == 0}
            onclick={link.callback(|_| Msg::ClickedDeleteUser)}>
            <i class="bi-x-circle-fill me-2" aria-label="Delete selected users" />
            {button_text}
          </button>
          {self.show_modal(ctx)}
          </>
        }
    }
}

impl DeleteUser {
    fn show_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        let count = ctx.props().selected_users.len();

        html! {
          <div
            class="modal fade"
            id="deleteUsersModal"
            tabindex="-1"
            aria-labelledby="deleteUsersModalLabel"
            aria-hidden="true"
            ref={self.node_ref.clone()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="deleteUsersModalLabel">{format!("Delete {} users?", count)}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                  <span>
                    {"Are you sure you want to permanently delete "}
                    <b>{count}</b>{" selected users? This action cannot be undone."}
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
                    onclick={link.callback(|_| Msg::ConfirmDeleteUser)}
                    class="btn btn-danger"
                    disabled={self.common.is_task_running()}>
                    <i class="bi-check-circle me-2"></i>
                    {"Yes, delete them"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
