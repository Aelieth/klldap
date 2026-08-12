use crate::components::{ou_selector::OuSelector, status_modal::StatusModal};
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
    query_path = "queries/change_user_ou.graphql",
    response_derives = "Debug, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ChangeUserOuQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/change_group_ou.graphql",
    response_derives = "Debug, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ChangeGroupOuQuery;

#[derive(Clone, PartialEq)]
pub enum OuChangeKind {
    Users(Vec<String>),
    Groups(Vec<i64>),
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct ChangeOuProps {
    pub kind: OuChangeKind,
    pub ous: Vec<String>,
    pub on_ou_changed: Callback<String>,
    pub on_error: Callback<Error>,
}

pub struct ChangeOu {
    common: CommonComponentParts<Self>,
    modal: ModalHandle,
    selected_ou: String,
    status_message: Option<(String, bool)>,
}

pub enum Msg {
    ClickedChangeOu,
    ConfirmChangeOu,
    DismissModal,
    NewOuSelected(String),
    ShowStatus(String, bool),
    DismissStatus,
    ChangeOuResponse(Result<()>),
}

impl CommonComponent<ChangeOu> for ChangeOu {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedChangeOu => {
                let empty = match &ctx.props().kind {
                    OuChangeKind::Users(ids) => ids.is_empty(),
                    OuChangeKind::Groups(ids) => ids.is_empty(),
                };
                if empty {
                    return Ok(true);
                }
                self.common.error = None;
                self.selected_ou = match &ctx.props().kind {
                    OuChangeKind::Users(_) => "people".to_string(),
                    OuChangeKind::Groups(_) => "groups".to_string(),
                };
                self.status_message = None;
                self.modal.show();
                Ok(true)
            }
            Msg::ConfirmChangeOu => {
                if self.selected_ou == "All" || self.selected_ou.is_empty() {
                    return Ok(true);
                }
                match &ctx.props().kind {
                    OuChangeKind::Users(ids) => {
                        self.common.call_graphql::<ChangeUserOuQuery, _>(
                            ctx,
                            change_user_ou_query::Variables {
                                user_ids: ids.clone(),
                                new_ou: self.selected_ou.clone(),
                            },
                            |r| Msg::ChangeOuResponse(r.map(|_| ())),
                            "Error changing OU",
                        );
                    }
                    OuChangeKind::Groups(ids) => {
                        self.common.call_graphql::<ChangeGroupOuQuery, _>(
                            ctx,
                            change_group_ou_query::Variables {
                                group_ids: ids.clone(),
                                new_ou: self.selected_ou.clone(),
                            },
                            |r| Msg::ChangeOuResponse(r.map(|_| ())),
                            "Error changing OU",
                        );
                    }
                }
                Ok(true)
            }
            Msg::DismissModal => {
                self.modal.hide();
                Ok(true)
            }
            Msg::NewOuSelected(ou) => {
                self.selected_ou = ou;
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
            Msg::ChangeOuResponse(res) => {
                match res {
                    Ok(_) => {
                        let count = match &ctx.props().kind {
                            OuChangeKind::Users(ids) => ids.len(),
                            OuChangeKind::Groups(ids) => ids.len(),
                        };
                        let entity = match &ctx.props().kind {
                            OuChangeKind::Users(_) => "user(s)",
                            OuChangeKind::Groups(_) => "group(s)",
                        };
                        let msg = format!(
                            "Successfully moved {} {} to OU: {}",
                            count, entity, self.selected_ou
                        );
                        ctx.link().send_message(Msg::ShowStatus(msg, true));
                        ctx.props().on_ou_changed.emit(self.selected_ou.clone());
                        self.selected_ou = match &ctx.props().kind {
                            OuChangeKind::Users(_) => "people".to_string(),
                            OuChangeKind::Groups(_) => "groups".to_string(),
                        };
                    }
                    Err(e) => {
                        let err_msg = e.to_string();
                        ctx.props().on_error.emit(e);
                        ctx.link().send_message(Msg::ShowStatus(err_msg, false));
                    }
                }
                self.modal.hide();
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for ChangeOu {
    type Message = Msg;
    type Properties = ChangeOuProps;

    fn create(_: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            modal: ModalHandle::new(),
            selected_ou: "people".to_string(), // default, overridden on click
            status_message: None,
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

        let status_html = if let Some((msg, is_success)) = &self.status_message {
            let on_dismiss = link.callback(|_| Msg::DismissStatus);
            html! { <StatusModal message={msg.clone()} is_success={*is_success} on_dismiss={on_dismiss} /> }
        } else {
            html! {}
        };

        let count = match &ctx.props().kind {
            OuChangeKind::Users(ids) => ids.len(),
            OuChangeKind::Groups(ids) => ids.len(),
        };

        let button_text = if count <= 1 {
            "Change OU".to_string()
        } else {
            format!("Change {} OUs", count)
        };

        html! {
          <>
          <button
            class="btn btn-warning"
            disabled={self.common.is_task_running() || count == 0}
            onclick={link.callback(|_| Msg::ClickedChangeOu)}>
            <i class="bi-arrow-left-right me-2" aria-label="Change OU" />
            {button_text}
          </button>
          {self.show_modal(ctx)}
          {status_html}
          </>
        }
    }
}

impl ChangeOu {
    fn show_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        let count = match &ctx.props().kind {
            OuChangeKind::Users(ids) => ids.len(),
            OuChangeKind::Groups(ids) => ids.len(),
        };
        let entity = match &ctx.props().kind {
            OuChangeKind::Users(_) => "users",
            OuChangeKind::Groups(_) => "groups",
        };

        html! {
          <div
            class="modal fade"
            id="changeOuModal"
            tabindex="-1"
            aria-labelledby="changeOuModalLabel"
            aria-hidden="true"
            ref={self.modal.node_ref()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="changeOuModalLabel">{format!("Change OU for {} selected {}", count, entity)}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                  <label class="form-label">{"New Organizational Unit"}</label>
                  <OuSelector
                    ous={ctx.props().ous.clone()}
                    current_ou={self.selected_ou.clone()}
                    on_ou_changed={link.callback(Msg::NewOuSelected)}
                    show_all={false} />
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
                    onclick={link.callback(|_| Msg::ConfirmChangeOu)}
                    class="btn btn-primary"
                    disabled={self.selected_ou.is_empty() || self.common.is_task_running()}>
                    <i class="bi-check-circle me-2"></i>
                    {"Change OU"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
