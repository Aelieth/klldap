use crate::{
    components::create_user::{GetKerberosInfo, get_kerberos_info},
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        modal::ModalHandle,
    },
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use web_sys::{HtmlInputElement, InputEvent};
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/delete_user.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteUserQuery;

const PRINCIPAL_STAYS: &str = "The Kerberos realm is closed on this server: the user is deleted \
    now, and its Kerberos principal stays until the realm opens, which removes it.";

/// The users deleted at the first "yes", and those asked for by name one at a time after it: the
/// synced ones, on a directory-only server only.
fn split_for_confirmation(
    selected: &[String],
    synced: &[String],
    directory_only: bool,
) -> (Vec<String>, Vec<String>) {
    match directory_only {
        true => selected
            .iter()
            .cloned()
            .partition(|user| !synced.contains(user)),
        false => (selected.to_vec(), Vec::new()),
    }
}

/// The name typed confirms the user in any case, as user ids compare.
fn confirms(typed: &str, user: &str) -> bool {
    typed.trim().to_lowercase() == user.to_lowercase()
}

pub struct DeleteUser {
    common: CommonComponentParts<Self>,
    modal: ModalHandle,
    directory_only: bool,
    asking: Vec<String>,
    typed: String,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct DeleteUserProps {
    pub selected_users: Vec<String>,
    pub synced_users: Vec<String>,
    pub on_user_deleted: Callback<String>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedDeleteUser,
    ConfirmDeleteUser,
    TypedName(String),
    ConfirmSyncedUser,
    SkipSyncedUser,
    DismissModal,
    KerberosInfoResponse(Result<get_kerberos_info::ResponseData>),
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
                self.asking.clear();
                self.typed.clear();
                self.modal.show();
                Ok(true)
            }
            Msg::ConfirmDeleteUser => {
                let props = ctx.props();
                let (now, asking) = split_for_confirmation(
                    &props.selected_users,
                    &props.synced_users,
                    self.directory_only,
                );
                for user_id in now {
                    self.delete(ctx, user_id, None);
                }
                self.asking = asking;
                self.next_or_hide();
                Ok(true)
            }
            Msg::TypedName(typed) => {
                self.typed = typed;
                Ok(true)
            }
            Msg::ConfirmSyncedUser => {
                let Some(user_id) = self.asking.first().cloned() else {
                    return Ok(true);
                };
                if confirms(&self.typed, &user_id) {
                    let named = self.typed.trim().to_owned();
                    self.delete(ctx, user_id, Some(named));
                    self.asking.remove(0);
                    self.next_or_hide();
                }
                Ok(true)
            }
            Msg::SkipSyncedUser => {
                if !self.asking.is_empty() {
                    self.asking.remove(0);
                }
                self.next_or_hide();
                Ok(true)
            }
            Msg::DismissModal => {
                self.asking.clear();
                self.modal.hide();
                Ok(true)
            }
            Msg::KerberosInfoResponse(info) => {
                let state = info.map(|data| data.kerberos_info.state);
                self.directory_only = state.is_ok_and(|state| state == "directory-only");
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
            modal: ModalHandle::new(),
            directory_only: false,
            asking: Vec::new(),
            typed: String::new(),
        }
    }

    fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
        self.modal.init_on_first_render(first_render);
        if first_render {
            self.common.call_graphql::<GetKerberosInfo, _>(
                ctx,
                get_kerberos_info::Variables {},
                Msg::KerberosInfoResponse,
                "Error trying to fetch the Kerberos state",
            );
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
    fn delete(&mut self, ctx: &Context<Self>, user_id: String, confirm: Option<String>) {
        self.common.call_graphql::<DeleteUserQuery, _>(
            ctx,
            delete_user_query::Variables {
                user: user_id.clone(),
                confirm,
            },
            move |response| Msg::DeleteUserResponse(response, user_id.clone()),
            "Error trying to delete user",
        );
    }

    fn next_or_hide(&mut self) {
        self.typed.clear();
        if self.asking.is_empty() {
            self.modal.hide();
        }
    }

    fn show_modal(&self, ctx: &Context<Self>) -> Html {
        let (title, body, footer) = match self.asking.first() {
            Some(user_id) => (
                format!("Delete {user_id}?"),
                self.ask_by_name(ctx, user_id),
                self.footer_by_name(ctx, user_id),
            ),
            None => (
                format!("Delete {} users?", ctx.props().selected_users.len()),
                self.ask_all(ctx),
                self.footer_all(ctx),
            ),
        };
        html! {
          <div
            class="modal fade"
            id="deleteUsersModal"
            tabindex="-1"
            aria-labelledby="deleteUsersModalLabel"
            aria-hidden="true"
            ref={self.modal.node_ref()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="deleteUsersModalLabel">{title}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={ctx.link().callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">{body}</div>
                <div class="modal-footer">{footer}</div>
              </div>
            </div>
          </div>
        }
    }

    fn ask_all(&self, ctx: &Context<Self>) -> Html {
        let props = ctx.props();
        let (_, asking) = split_for_confirmation(
            &props.selected_users,
            &props.synced_users,
            self.directory_only,
        );
        html! {
          <>
            <span>
              {"Are you sure you want to permanently delete "}
              <b>{props.selected_users.len()}</b>{" selected users? This action cannot be undone."}
            </span>
            { if asking.is_empty() {
              html! {}
            } else {
              html! {
                <p class="mt-2 mb-0">
                  {format!("{} of them have Kerberos sync: each is asked for by name next.", asking.len())}
                </p>
              }
            }}
          </>
        }
    }

    fn ask_by_name(&self, ctx: &Context<Self>, user_id: &str) -> Html {
        html! {
          <>
            <p><b>{user_id}</b>{" has Kerberos sync. "}{PRINCIPAL_STAYS}</p>
            <label for="deleteUserName" class="form-label">{"Type the user's name to confirm"}</label>
            <input
              id="deleteUserName"
              class="form-control"
              type="text"
              autocomplete="off"
              value={self.typed.clone()}
              oninput={ctx.link().callback(|e: InputEvent| {
                let input: HtmlInputElement = e.target_unchecked_into();
                Msg::TypedName(input.value())
              })} />
          </>
        }
    }

    fn footer_all(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        html! {
          <>
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
          </>
        }
    }

    fn footer_by_name(&self, ctx: &Context<Self>, user_id: &str) -> Html {
        let link = ctx.link();
        html! {
          <>
            <button
              type="button"
              class="btn btn-secondary"
              onclick={link.callback(|_| Msg::SkipSyncedUser)}>
              {"Keep this user"}
            </button>
            <button
              type="button"
              onclick={link.callback(|_| Msg::ConfirmSyncedUser)}
              class="btn btn-danger"
              disabled={!confirms(&self.typed, user_id)}>
              <i class="bi-check-circle me-2"></i>
              {format!("Delete {user_id}")}
            </button>
          </>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_a_directory_only_server_asks_for_each_synced_user_by_name() {
        let names =
            |users: &[&str]| -> Vec<String> { users.iter().map(|u| (*u).to_owned()).collect() };
        let selected = names(&["ann", "bob", "carl"]);
        let synced = names(&["bob", "carl", "dora"]);
        let rows = [
            (false, (names(&["ann", "bob", "carl"]), names(&[]))),
            (true, (names(&["ann"]), names(&["bob", "carl"]))),
        ];
        for (directory_only, split) in rows {
            let got = split_for_confirmation(&selected, &synced, directory_only);
            assert_eq!(got, split, "directory-only {directory_only}");
        }
    }

    #[test]
    fn test_the_typed_name_confirms_in_any_case_and_nothing_else_does() {
        let rows = [
            ("bob", true),
            (" Bob ", true),
            ("BOB", true),
            ("", false),
            ("bo", false),
            ("bobby", false),
        ];
        for (typed, confirmed) in rows {
            assert_eq!(confirms(typed, "bob"), confirmed, "{typed:?}");
        }
    }
}
