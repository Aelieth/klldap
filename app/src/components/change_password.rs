use crate::infra::encrypt::SealTo;
use crate::infra::opaque::{
    FinishFor, LoginState, begin_login, begin_registration, finish_login, finish_registration,
    new_password_at_the_floor, registration_started, signed_in_key,
};
use crate::{
    components::{
        form::{field::Field, submit::Submit},
        router::AppRoute,
    },
    infra::{
        api::{HostService, LoginOutcome},
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::{Result, anyhow, bail};
use lldap_auth::{login, opaque, registration};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(PartialEq, Eq, Default)]
enum OpaqueData {
    #[default]
    None,
    Login(Box<LoginState>, String),
    Registration(Box<opaque::client::registration::ClientRegistration>),
}

impl OpaqueData {
    fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct FormModel {
    #[validate(custom(
        function = "empty_or_long",
        message = "Password should be longer than 8 characters"
    ))]
    old_password: String,
    #[validate(custom(function = "new_password_at_the_floor"))]
    password: String,
    #[validate(must_match(other = "password", message = "Passwords must match"))]
    confirm_password: String,
}

fn empty_or_long(value: &str) -> Result<(), validator::ValidationError> {
    if value.is_empty() || value.len() >= 8 {
        Ok(())
    } else {
        Err(validator::ValidationError::new(""))
    }
}

pub struct ChangePasswordForm {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    opaque_data: OpaqueData,
    checked_key: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Properties)]
pub struct Props {
    pub username: String,
    pub is_admin: bool,
}

pub enum Msg {
    FormUpdate,
    Submit,
    LoginStartResponse(Result<Box<login::ServerLoginStart>>),
    LoginFinishResponse(Result<LoginOutcome>),
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStart>>),
    RegistrationFinishResponse(Result<()>),
    SubmitNewPassword,
}

impl CommonComponent<ChangePasswordForm> for ChangePasswordForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        use anyhow::Context;
        match msg {
            Msg::FormUpdate => Ok(true),
            Msg::Submit => {
                if self.common.is_task_running() || self.opaque_data != OpaqueData::None {
                    return Ok(false);
                }
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                if ctx.props().is_admin {
                    self.handle_msg(ctx, Msg::SubmitNewPassword)
                } else {
                    let old_password = self.form.model().old_password.clone();
                    if old_password.is_empty() {
                        bail!("Current password is required for non-admin users");
                    }
                    let (state, request) = begin_login(&ctx.props().username, &old_password)?;
                    self.opaque_data = OpaqueData::Login(Box::new(state), old_password);
                    self.common.call_backend(
                        ctx,
                        HostService::login_start(request),
                        Msg::LoginStartResponse,
                    );
                    Ok(true)
                }
            }
            Msg::LoginStartResponse(res) => {
                let held = self.opaque_data.take();
                let res = res.context("Old password verification failed")?;
                let OpaqueData::Login(state, password) = held else {
                    bail!("Invalid state");
                };
                let (request, checked_key) =
                    finish_login(*state, &password, *res, FinishFor::PasswordCheck)
                        .context("Old password verification failed")?;
                self.checked_key = checked_key;
                self.common.call_backend(
                    ctx,
                    HostService::login_finish(request),
                    Msg::LoginFinishResponse,
                );
                Ok(false)
            }
            Msg::LoginFinishResponse(res) => {
                // Verified, or verified with a code asked for: no session is made either way.
                let _ = res.context("Old password incorrect")?;
                self.handle_msg(ctx, Msg::SubmitNewPassword)
            }
            Msg::SubmitNewPassword => {
                let new_password = self.form.model().password.clone();
                let (state, req) = begin_registration(&ctx.props().username, &new_password)?;
                self.opaque_data = OpaqueData::Registration(Box::new(state));
                self.common.call_backend(
                    ctx,
                    HostService::register_start(req),
                    Msg::RegistrationStartResponse,
                );
                Ok(true)
            }
            Msg::RegistrationStartResponse(res) => {
                let held = self.opaque_data.take();
                let res = registration_started(res)?;
                let registration = match held {
                    OpaqueData::Registration(r) => *r,
                    _ => bail!("Invalid state"),
                };
                // An admin's page has no check of its own: the key its sign-in bound, if any.
                let bound = match ctx.props().is_admin {
                    true => signed_in_key(),
                    false => self.checked_key.take(),
                };
                let req = finish_registration(
                    registration,
                    &ctx.props().username,
                    &self.form.model().password,
                    *res,
                    SealTo::Bound(bound.as_deref()),
                )?;
                self.common.call_backend(
                    ctx,
                    HostService::register_finish(req),
                    Msg::RegistrationFinishResponse,
                );
                Ok(false)
            }
            Msg::RegistrationFinishResponse(response) => {
                response.map_err(|e| anyhow!("Failed to set new password: {e:#}"))?;
                self.navigate_to_user_details(ctx);
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl ChangePasswordForm {
    fn navigate_to_user_details(&self, ctx: &Context<Self>) {
        ctx.link().history().unwrap().push(AppRoute::UserDetails {
            user_id: ctx.props().username.clone(),
        });
    }
}

impl Component for ChangePasswordForm {
    type Message = Msg;
    type Properties = Props;

    fn create(_: &Context<Self>) -> Self {
        ChangePasswordForm {
            common: CommonComponentParts::<Self>::create(),
            form: Form::<FormModel>::new(FormModel::default()),
            opaque_data: OpaqueData::None,
            checked_key: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let is_admin = ctx.props().is_admin;
        html! {
            <>
            <div class="mb-2 mt-2">
            <h5 class="fw-bold">{"Change Password"}</h5>
            </div>

            { if let Some(e) = &self.common.error {
                html! { <div class="alert alert-danger">{e.to_string()}</div> }
            } else { html! {} }}

            <form class="form">
            { if !is_admin {
                html! {
                    <Field<FormModel>
                    form={&self.form}
                    required=true
                    label="Current Password"
                    field_name="old_password"
                    input_type="password"
                    autocomplete="current-password"
                    oninput={link.callback(|_| Msg::FormUpdate)} />
                }
            } else { html! {} }}

            <Field<FormModel>
            form={&self.form}
            required=true
            label="New Password"
            field_name="password"
            input_type="password"
            autocomplete="new-password"
            oninput={link.callback(|_| Msg::FormUpdate)} />

            <Field<FormModel>
            form={&self.form}
            required=true
            label="Confirm New Password"
            field_name="confirm_password"
            input_type="password"
            autocomplete="new-password"
            oninput={link.callback(|_| Msg::FormUpdate)} />

            <Submit
            disabled={self.common.is_task_running()}
            onclick={link.callback(|e: MouseEvent| { e.prevent_default(); Msg::Submit })}
            text="Change Password">
            </Submit>
            </form>
            </>
        }
    }
}
