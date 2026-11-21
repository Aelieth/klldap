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
    query_path = "queries/unlock_user.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct UnlockUser;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/reenable_user.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReenableUser;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_sign_in_state.graphql",
    response_derives = "Debug, Clone, PartialEq, Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetSignInState;

pub type SignInState = get_sign_in_state::GetSignInStateUserSignInState;

pub const REENABLE_CONFIRM: &str = "Re-enable sign-in for this user (resets the inactivity count)";
pub const UNLOCK_TITLE: &str = "Unlock sign-in for this user (clears the failed-login count)";

pub fn unlocked_line(user: &str) -> String {
    format!("Unlocked {user}")
}

pub fn reenabled_line(user: &str) -> String {
    format!("Re-enabled {user}")
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignInView {
    pub locked: Option<String>,
    pub inactive: Option<String>,
    pub unlock: bool,
    pub reenable: bool,
}

pub fn sign_in_view(read: Option<Option<&SignInState>>) -> SignInView {
    let Some(read) = read else {
        return SignInView::default();
    };
    let Some(state) = read else {
        return SignInView {
            unlock: true,
            reenable: true,
            ..SignInView::default()
        };
    };
    let locked = state.locked.then(|| match state.locked_until {
        Some(until) => format!("Locked until {}", until.format("%Y-%m-%d %H:%M:%S UTC")),
        None => "Locked until an admin unlocks".to_owned(),
    });
    let inactive = state.inactive.then(|| match state.inactive_since {
        Some(since) => format!("Inactive since {}", since.format("%Y-%m-%d")),
        None => "Inactive".to_owned(),
    });
    SignInView {
        locked,
        inactive,
        unlock: state.locked,
        reenable: state.inactive,
    }
}

pub struct SignInActions {
    common: CommonComponentParts<Self>,
    modal: ModalHandle,
    read: Option<Option<SignInState>>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct SignInActionsProps {
    pub username: String,
    pub on_start: Callback<()>,
    pub on_done: Callback<String>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    StateResponse(Result<get_sign_in_state::ResponseData>),
    ClickedUnlock,
    UnlockResponse(Result<unlock_user::ResponseData>),
    ClickedReenable,
    ConfirmReenable,
    DismissModal,
    ReenableResponse(Result<reenable_user::ResponseData>),
}

impl CommonComponent<SignInActions> for SignInActions {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        let user = ctx.props().username.clone();
        match msg {
            Msg::StateResponse(response) => {
                self.read = Some(response.ok().and_then(|data| data.user.sign_in_state));
            }
            Msg::ClickedUnlock => {
                ctx.props().on_start.emit(());
                self.common.call_graphql::<UnlockUser, _>(
                    ctx,
                    unlock_user::Variables { user },
                    Msg::UnlockResponse,
                    "Error trying to unlock the user",
                );
            }
            Msg::UnlockResponse(response) => {
                response?;
                ctx.props().on_done.emit(unlocked_line(&user));
                self.fetch_state(ctx);
            }
            Msg::ClickedReenable => {
                ctx.props().on_start.emit(());
                self.modal.show();
            }
            Msg::DismissModal => {
                self.modal.hide();
            }
            Msg::ConfirmReenable => {
                self.modal.hide();
                self.common.call_graphql::<ReenableUser, _>(
                    ctx,
                    reenable_user::Variables { user },
                    Msg::ReenableResponse,
                    "Error trying to re-enable the user",
                );
            }
            Msg::ReenableResponse(response) => {
                response?;
                ctx.props().on_done.emit(reenabled_line(&user));
                self.fetch_state(ctx);
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for SignInActions {
    type Message = Msg;
    type Properties = SignInActionsProps;

    fn create(ctx: &Context<Self>) -> Self {
        let mut component = Self {
            common: CommonComponentParts::<Self>::create(),
            modal: ModalHandle::new(),
            read: None,
        };
        component.fetch_state(ctx);
        component
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
        let task = self.common.is_task_running();
        let view = sign_in_view(self.read.as_ref().map(Option::as_ref));
        let badge = |id: &'static str, line: Option<String>| {
            line.map_or_else(|| html! {}, |line| html! {
              <span class="badge bg-warning text-dark align-self-center me-2" id={id}>{line}</span>
            })
        };
        html! {
          <>
          { if view.unlock { html! {
            <button
              class="btn btn-outline-secondary me-2"
              id="unlock-user"
              title={UNLOCK_TITLE}
              disabled={task}
              onclick={link.callback(|_| Msg::ClickedUnlock)}>
              <i class="bi-unlock me-2"></i>
              {"Unlock"}
            </button>
          } } else { html! {} } }
          {badge("sign-in-locked", view.locked)}
          { if view.reenable { html! {
            <button
              class="btn btn-outline-secondary me-2"
              id="reenable-user"
              title={REENABLE_CONFIRM}
              disabled={task}
              onclick={link.callback(|_| Msg::ClickedReenable)}>
              <i class="bi-person-check me-2"></i>
              {"Re-enable after inactivity"}
            </button>
          } } else { html! {} } }
          {badge("sign-in-inactive", view.inactive)}
          {self.view_modal(ctx)}
          </>
        }
    }
}

impl SignInActions {
    fn fetch_state(&mut self, ctx: &Context<Self>) {
        self.common.call_graphql::<GetSignInState, _>(
            ctx,
            get_sign_in_state::Variables {
                id: ctx.props().username.clone(),
            },
            Msg::StateResponse,
            "Error trying to read the user's sign-in state",
        );
    }

    fn view_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        let user = &ctx.props().username;
        html! {
          <div
            class="modal fade"
            id={"reenableModal".to_string() + user}
            tabindex="-1"
            aria-labelledby="reenableModalLabel"
            aria-hidden="true"
            ref={self.modal.node_ref()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="reenableModalLabel">{format!("Re-enable {user}?")}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                  <span>{REENABLE_CONFIRM}</span>
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
                    onclick={link.callback(|_| Msg::ConfirmReenable)}
                    class="btn btn-primary"
                    disabled={self.common.is_task_running()}>
                    <i class="bi-check-circle me-2"></i>
                    {"Yes, re-enable"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_sign_in_buttons_confirm_and_say_what_they_did() {
        assert_eq!(
            REENABLE_CONFIRM,
            "Re-enable sign-in for this user (resets the inactivity count)"
        );
        assert_eq!(unlocked_line("bob"), "Unlocked bob");
        assert_eq!(reenabled_line("bob"), "Re-enabled bob");
        let unlocked: unlock_user::ResponseData =
            serde_json::from_value(serde_json::json!({"unlockUser": {"ok": true}})).unwrap();
        assert!(unlocked.unlock_user.ok);
        let reenabled: reenable_user::ResponseData =
            serde_json::from_value(serde_json::json!({"reenableUser": {"ok": true}})).unwrap();
        assert!(reenabled.reenable_user.ok);
    }

    fn read(answer: serde_json::Value) -> get_sign_in_state::ResponseData {
        serde_json::from_value(answer).unwrap()
    }

    #[test]
    fn test_the_buttons_come_only_with_their_state() {
        let state = |locked: bool, until: Option<&str>, inactive: bool, since: Option<&str>| {
            serde_json::json!({"user": {"signInState": {
                "locked": locked, "lockedUntil": until, "inactive": inactive, "inactiveSince": since
            }}})
        };
        let locked_line = "Locked until 2027-01-15 08:10:00 UTC";
        let held_line = "Locked until an admin unlocks";
        let inactive_line = "Inactive since 2027-01-14";
        let view = |locked: Option<&str>, inactive: Option<&str>| SignInView {
            locked: locked.map(str::to_owned),
            inactive: inactive.map(str::to_owned),
            unlock: locked.is_some(),
            reenable: inactive.is_some(),
        };
        let rows = [
            (
                "locked with an end",
                state(true, Some("2027-01-15T08:10:00Z"), false, None),
                view(Some(locked_line), None),
            ),
            (
                "locked until an unlock",
                state(true, None, false, None),
                view(Some(held_line), None),
            ),
            (
                "inactive",
                state(false, None, true, Some("2027-01-14T08:00:00Z")),
                view(None, Some(inactive_line)),
            ),
            (
                "both",
                state(
                    true,
                    Some("2027-01-15T08:10:00Z"),
                    true,
                    Some("2027-01-14T08:00:00Z"),
                ),
                view(Some(locked_line), Some(inactive_line)),
            ),
            ("neither", state(false, None, false, None), view(None, None)),
        ];
        for (label, answer, expected) in rows {
            let data = read(answer);
            let shown = sign_in_view(Some(data.user.sign_in_state.as_ref()));
            assert_eq!(shown, expected, "{label}");
        }
    }

    #[test]
    fn test_a_failed_read_shows_both_buttons_and_an_unanswered_one_shows_nothing() {
        let fallback = SignInView {
            locked: None,
            inactive: None,
            unlock: true,
            reenable: true,
        };
        let null = read(serde_json::json!({"user": {"signInState": null}}));
        assert_eq!(
            (
                sign_in_view(Some(null.user.sign_in_state.as_ref())),
                sign_in_view(Some(None)),
                sign_in_view(None),
            ),
            (fallback.clone(), fallback, SignInView::default())
        );
    }
}
