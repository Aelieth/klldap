use crate::infra::{
    common_component::{CommonComponent, CommonComponentParts},
    modal::ModalHandle,
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/delete_group.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteGroupQuery;

pub struct DeleteGroup {
    common: CommonComponentParts<Self>,
    modal: ModalHandle,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct DeleteGroupProps {
    pub selected_groups: Vec<i64>,
    pub on_group_deleted: Callback<i64>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedDeleteGroup,
    ConfirmDeleteGroup,
    DismissModal,
    DeleteGroupResponse(Result<delete_group_query::ResponseData>, i64),
}

impl CommonComponent<DeleteGroup> for DeleteGroup {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedDeleteGroup => {
                if ctx.props().selected_groups.is_empty() {
                    return Ok(true);
                }
                self.modal.show();
                Ok(true)
            }
            Msg::ConfirmDeleteGroup => {
                for group_id in ctx.props().selected_groups.clone() {
                    self.common.call_graphql::<DeleteGroupQuery, _>(
                        ctx,
                        delete_group_query::Variables { group_id },
                        move |response| Msg::DeleteGroupResponse(response, group_id),
                        "Error trying to delete group",
                    );
                }
                self.modal.hide();
                Ok(true)
            }
            Msg::DismissModal => {
                self.modal.hide();
                Ok(true)
            }
            Msg::DeleteGroupResponse(response, group_id) => {
                match response {
                    Ok(_) => {
                        ctx.props().on_group_deleted.emit(group_id);
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

impl Component for DeleteGroup {
    type Message = Msg;
    type Properties = DeleteGroupProps;

    fn create(_: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            modal: ModalHandle::new(),
        }
    }

    fn rendered(&mut self, _: &Context<Self>, first_render: bool) {
        self.modal.init_on_first_render(first_render);
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
        let count = ctx.props().selected_groups.len();

        let button_text = if count <= 1 {
            "Delete Group".to_string()
        } else {
            format!("Delete {} Groups", count)
        };

        html! {
          <>
          <button
            class="btn btn-danger"
            disabled={self.common.is_task_running() || count == 0}
            onclick={link.callback(|_| Msg::ClickedDeleteGroup)}>
            <i class="bi-x-circle-fill me-2" aria-label="Delete selected groups" />
            {button_text}
          </button>
          {self.show_modal(ctx)}
          </>
        }
    }
}

impl DeleteGroup {
    fn show_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        let count = ctx.props().selected_groups.len();

        html! {
          <div
            class="modal fade"
            id="deleteGroupsModal"
            tabindex="-1"
            aria-labelledby="deleteGroupsModalLabel"
            aria-hidden="true"
            ref={self.modal.node_ref()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="deleteGroupsModalLabel">{format!("Delete {} groups?", count)}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                  <span>
                    {"Are you sure you want to permanently delete "}
                    <b>{count}</b>{" selected groups? This action cannot be undone."}
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
                    onclick={link.callback(|_| Msg::ConfirmDeleteGroup)}
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
