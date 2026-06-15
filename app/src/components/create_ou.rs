use crate::components::ou_selector::OuSelector;
use crate::components::status_modal::StatusModal;
use crate::infra::{
    common_component::{CommonComponent, CommonComponentParts},
    modal::Modal,
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use wasm_bindgen::JsCast;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_ou.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateOuQuery;

pub struct CreateOu {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
    is_primary: bool,
    selected_primary: String,
    secondary_name: String,
    status_message: Option<(String, bool)>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct CreateOuProps {
    pub on_ou_created: Callback<String>,
    pub on_error: Callback<Error>,
    pub ous: Vec<String>,
    pub default_primary: String, // "people" or "groups"
}

pub enum Msg {
    ClickedCreateOu,
    ConfirmCreateOu,
    DismissModal,
    CreateOuResponse(Result<create_ou_query::ResponseData>),
    ToggleMode(bool),
    PrimarySelected(String),
    SecondaryNameChanged(String),
    ShowStatus(String, bool),
    DismissStatus,
}

impl CommonComponent<CreateOu> for CreateOu {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedCreateOu => {
                self.common.error = None;
                self.is_primary = true;
                self.selected_primary = ctx.props().default_primary.clone();
                self.secondary_name = String::new();
                self.status_message = None;
                self.modal.as_ref().expect("modal not initialized").show();
                Ok(true)
            }
            Msg::ConfirmCreateOu => {
                let final_name = if self.is_primary {
                    self.selected_primary.clone()
                } else {
                    format!("{}\\{}", self.selected_primary, self.secondary_name)
                };
                if final_name.trim().is_empty() {
                    return Ok(true);
                }
                self.common.call_graphql::<CreateOuQuery, _>(
                    ctx,
                    create_ou_query::Variables {
                        name: final_name.clone(),
                    },
                    Msg::CreateOuResponse,
                    "Error trying to create OU",
                );
                Ok(true)
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
                Ok(true)
            }
            Msg::CreateOuResponse(response) => {
                match response {
                    Ok(_) => {
                        let final_name = if self.is_primary {
                            self.selected_primary.clone()
                        } else {
                            format!("{}\\{}", self.selected_primary, self.secondary_name)
                        };
                        let msg = format!("Successfully created OU: {}", final_name);
                        ctx.props().on_ou_created.emit(final_name);
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
            Msg::ToggleMode(is_primary) => {
                self.is_primary = is_primary;
                if !is_primary && self.selected_primary.is_empty() {
                    self.selected_primary = ctx.props().default_primary.clone();
                }
                Ok(true)
            }
            Msg::PrimarySelected(ou) => {
                self.selected_primary = ou;
                Ok(true)
            }
            Msg::SecondaryNameChanged(name) => {
                self.secondary_name = name;
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

impl Component for CreateOu {
    type Message = Msg;
    type Properties = CreateOuProps;

    fn create(ctx: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            node_ref: NodeRef::default(),
            modal: None,
            is_primary: true,
            selected_primary: ctx.props().default_primary.clone(),
            secondary_name: String::new(),
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
            class="btn btn-primary"
            disabled={self.common.is_task_running()}
            onclick={link.callback(|_| Msg::ClickedCreateOu)}>
            <i class="bi-plus-circle me-2" aria-label="Create OU" />
            {"Create OU"}
          </button>
          {self.show_create_modal(ctx)}
          {status_html}
          </>
        }
    }
}

impl CreateOu {
    fn show_create_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();

        let mode_selector = html! {
            <div class="mb-3">
                <div class="form-check form-check-inline">
                    <input
                        class="form-check-input"
                        type="radio"
                        id="primary-mode"
                        name="ou-mode"
                        checked={self.is_primary}
                        onchange={link.callback(|_| Msg::ToggleMode(true))} />
                    <label class="form-check-label" for="primary-mode">{"Primary OU"}</label>
                </div>
                <div class="form-check form-check-inline">
                    <input
                        class="form-check-input"
                        type="radio"
                        id="secondary-mode"
                        name="ou-mode"
                        checked={!self.is_primary}
                        onchange={link.callback(|_| Msg::ToggleMode(false))} />
                    <label class="form-check-label" for="secondary-mode">{"Secondary OU"}</label>
                </div>
            </div>
        };

        let primary_selector = if !self.is_primary {
            let primaries: Vec<String> = ctx
                .props()
                .ous
                .iter()
                .filter(|o| !o.contains('\\'))
                .cloned()
                .collect();

            html! {
                <div class="mb-3">
                    <label class="form-label">{"Primary OU"}</label>
                    <OuSelector
                        ous={primaries}
                        current_ou={self.selected_primary.clone()}
                        on_ou_changed={link.callback(Msg::PrimarySelected)}
                        label={None::<String>}
                        show_all={false} />
                </div>
            }
        } else {
            html! {}
        };

        let name_input = if self.is_primary {
            html! {
                <input
                    type="text"
                    class="form-control"
                    placeholder="Enter primary OU name (e.g. office)"
                    value={self.selected_primary.clone()}
                    oninput={link.callback(|e: InputEvent| {
                        let value = e.target()
                            .unwrap()
                            .dyn_into::<web_sys::HtmlInputElement>()
                            .unwrap()
                            .value();
                        Msg::PrimarySelected(value)
                    })} />
            }
        } else {
            html! {
                <input
                    type="text"
                    class="form-control"
                    placeholder="Enter secondary OU name (e.g. accounting)"
                    value={self.secondary_name.clone()}
                    oninput={link.callback(|e: InputEvent| {
                        let value = e.target()
                            .unwrap()
                            .dyn_into::<web_sys::HtmlInputElement>()
                            .unwrap()
                            .value();
                        Msg::SecondaryNameChanged(value)
                    })} />
            }
        };

        html! {
          <div
            class="modal fade"
            id="createOuModal"
            tabindex="-1"
            aria-labelledby="createOuModalLabel"
            aria-hidden="true"
            ref={self.node_ref.clone()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="createOuModalLabel">{"Create New Organizational Unit"}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                  {mode_selector}
                  {primary_selector}
                  <label class="form-label">
                    {if self.is_primary { "Primary OU name" } else { "Secondary OU name" }}
                  </label>
                  {name_input}
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
                    onclick={link.callback(|_| Msg::ConfirmCreateOu)}
                    class="btn btn-primary"
                    disabled={self.common.is_task_running() ||
                              (self.is_primary && self.selected_primary.trim().is_empty()) ||
                              (!self.is_primary && (self.selected_primary.trim().is_empty() || self.secondary_name.trim().is_empty()))}>
                    <i class="bi-check-circle me-2"></i>
                    {"Create OU"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
