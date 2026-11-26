use crate::infra::encrypt::SealTo;
use crate::infra::opaque::{
    begin_registration, finish_registration, new_password_at_the_floor, registration_started,
};
use crate::{
    components::{
        form::{field::Field, submit::Submit},
        router::{AppRoute, Link},
    },
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::{Result, anyhow, bail};
use lldap_auth::password_reset::ServerPasswordResetResponse;
use lldap_auth::{opaque, registration};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct FormModel {
    #[validate(custom(function = "new_password_at_the_floor"))]
    password: String,
    #[validate(must_match(other = "password", message = "Passwords must match"))]
    confirm_password: String,
}

pub struct ResetPasswordStep2Form {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    username: Option<String>,
    opaque_data: Option<opaque::client::registration::ClientRegistration>,
}

#[derive(Clone, PartialEq, Eq, Properties)]
pub struct Props {
    pub token: String,
    pub mfa_enabled: bool,
}

pub enum Msg {
    ValidateTokenResponse(Result<ServerPasswordResetResponse>),
    FormUpdate,
    Submit,
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStart>>),
    RegistrationFinishResponse(Result<()>),
}

impl CommonComponent<ResetPasswordStep2Form> for ResetPasswordStep2Form {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ValidateTokenResponse(response) => {
                self.username = Some(response?.user_id);
                Ok(true)
            }
            Msg::FormUpdate => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let new_password = self.form.model().password.clone();
                let Some(username) = self.username.clone() else {
                    bail!("Username not available");
                };
                let (state, req) = begin_registration(&username, &new_password)?;
                self.opaque_data = Some(state);
                self.common.call_backend(
                    ctx,
                    HostService::register_start(req),
                    Msg::RegistrationStartResponse,
                );
                Ok(false)
            }
            Msg::RegistrationStartResponse(res) => {
                let res = registration_started(res)?;
                let registration = match self.opaque_data.take() {
                    Some(r) => r,
                    None => bail!("Invalid state"),
                };
                let Some(username) = self.username.as_deref() else {
                    bail!("Username not available");
                };
                // No password exists to sign in with here: the key as the start answered it.
                let password = self.form.model().password;
                let req =
                    finish_registration(registration, username, &password, *res, SealTo::Answered)?;
                self.common.call_backend(
                    ctx,
                    HostService::register_finish(req),
                    Msg::RegistrationFinishResponse,
                );
                Ok(false)
            }
            Msg::RegistrationFinishResponse(response) => {
                response.map_err(|e| anyhow!("Failed to set new password: {e:#}"))?;
                ctx.link().history().unwrap().push(AppRoute::Login);
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for ResetPasswordStep2Form {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut form = ResetPasswordStep2Form {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::<FormModel>::new(FormModel::default()),
            username: None,
            opaque_data: None,
        };
        let token = ctx.props().token.clone();
        form.common.call_backend(
            ctx,
            HostService::reset_password_step2(token),
            Msg::ValidateTokenResponse,
        );
        form
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

        match (&self.username, &self.common.error) {
            (None, None) => html! { <div>{"Validating reset token..."}</div> },
            (None, Some(e)) => html! {
                <>
                <div class="alert alert-danger">{e.to_string()}</div>
                <Link classes="btn-link btn" to={AppRoute::Login}>{"Back to Login"}</Link>
                </>
            },
            _ => html! {
                <>
                <h2>{"Reset your password"}</h2>
                { if ctx.props().mfa_enabled {
                    html! {
                      <p class="text-muted">
                        {"Resetting your password also removes any two-factor authentication on this account; you can set it up again afterwards from your profile."}
                      </p>
                    }
                } else { html! {} }}
                <form class="form">
                <Field<FormModel>
                label="New password"
                required=true
                form={&self.form}
                field_name="password"
                autocomplete="new-password"
                input_type="password"
                oninput={link.callback(|_| Msg::FormUpdate)} />
                <Field<FormModel>
                label="Confirm password"
                required=true
                form={&self.form}
                field_name="confirm_password"
                autocomplete="new-password"
                input_type="password"
                oninput={link.callback(|_| Msg::FormUpdate)} />
                <Submit
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})} />
                </form>
                { if let Some(e) = &self.common.error {
                    html! { <div class="alert alert-danger">{e.to_string()}</div> }
                } else { html! {} }}
                </>
            },
        }
    }
}
