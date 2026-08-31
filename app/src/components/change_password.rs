use crate::infra::opaque::{
    LoginState, begin_login, begin_registration, finish_login, finish_registration,
};
use crate::infra::queries::{
    GetKerberosInfo, SyncKerberosPassword, get_kerberos_info, sync_kerberos_password,
};
use crate::{
    components::{
        form::{field::Field, submit::Submit},
        router::AppRoute,
    },
    infra::{
        api::{HostService, LoginOutcome},
        common_component::{CommonComponent, CommonComponentParts},
        encrypt::encrypt_kerberos_password,
    },
};
use anyhow::{Result, bail};
use lldap_auth::{login, opaque, registration};
use lldap_mfa::split_totp_suffix;
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(PartialEq, Eq, Default)]
enum OpaqueData {
    #[default]
    None,
    Login(Box<LoginState>, String, Option<String>, Option<String>),
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
    #[validate(length(min = 8, message = "Invalid password. Min length: 8"))]
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
    kerberos_info: Option<get_kerberos_info::GetKerberosInfoKerberosInfo>,
    encrypted_password: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Properties)]
pub struct Props {
    pub username: String,
    pub is_admin: bool,
    pub mfa_enabled: bool,
}

pub enum Msg {
    FormUpdate,
    Submit,
    LoginStartResponse(Result<Box<login::ServerLoginStartResponse>>),
    LoginFinishResponse(Result<LoginOutcome>),
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStartResponse>>),
    RegistrationFinishResponse(Result<()>),
    KerberosInfoResponse(Result<get_kerberos_info::ResponseData>),
    SyncKerberosResponse(Result<sync_kerberos_password::ResponseData>),
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
            Msg::KerberosInfoResponse(res) => {
                self.kerberos_info = Some(res?.kerberos_info);
                Ok(true)
            }
            Msg::Submit => {
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
                    // An enrolled user may confirm with `password:code`, as at the login form.
                    let split = ctx
                        .props()
                        .mfa_enabled
                        .then(|| split_totp_suffix(&old_password))
                        .flatten();
                    let (password, totp_code, retry) = match split {
                        Some((p, c)) => (p.to_owned(), Some(c.to_owned()), Some(old_password)),
                        None => (old_password, None, None),
                    };
                    let (state, request) = begin_login(&ctx.props().username, &password)?;
                    self.opaque_data =
                        OpaqueData::Login(Box::new(state), password, totp_code, retry);
                    self.common.call_backend(
                        ctx,
                        HostService::login_start(request),
                        Msg::LoginStartResponse,
                    );
                    Ok(false)
                }
            }
            Msg::LoginStartResponse(res) => {
                let res = res.context("Old password verification failed")?;
                let OpaqueData::Login(state, password, totp_code, retry) = self.opaque_data.take()
                else {
                    bail!("Invalid state");
                };
                let request = match finish_login(*state, &password, *res, totp_code) {
                    Ok(request) => request,
                    Err(e) => {
                        // A password that itself ends in ':' and six digits was split: try it whole.
                        let Some(original) = retry else {
                            return Err(e).context("Old password verification failed");
                        };
                        let (state, request) = begin_login(&ctx.props().username, &original)?;
                        self.opaque_data = OpaqueData::Login(Box::new(state), original, None, None);
                        self.common.call_backend(
                            ctx,
                            HostService::login_start(request),
                            Msg::LoginStartResponse,
                        );
                        return Ok(false);
                    }
                };
                self.common.call_backend(
                    ctx,
                    HostService::login_finish(request),
                    Msg::LoginFinishResponse,
                );
                Ok(false)
            }
            Msg::LoginFinishResponse(res) => {
                // The server proved the password either way; a missing code is the login's concern.
                let _ = res.context("Old password incorrect")?;
                self.handle_msg(ctx, Msg::SubmitNewPassword)
            }
            Msg::SubmitNewPassword => {
                let new_password = self.form.model().password.clone();

                // Kerberos encryption (strict, same pattern as create_user.rs)
                self.encrypted_password = Some(encrypt_kerberos_password(
                    self.kerberos_info
                        .as_ref()
                        .and_then(|i| i.public_key_der_base64.as_deref()),
                    &new_password,
                )?);

                let (state, req) = begin_registration(&ctx.props().username, &new_password)?;
                self.opaque_data = OpaqueData::Registration(Box::new(state));
                self.common.call_backend(
                    ctx,
                    HostService::register_start(req),
                    Msg::RegistrationStartResponse,
                );
                Ok(false)
            }
            Msg::RegistrationStartResponse(res) => {
                let res = res.context("Could not initiate registration")?;
                let registration = match self.opaque_data.take() {
                    OpaqueData::Registration(r) => *r,
                    _ => bail!("Invalid state"),
                };
                let req = finish_registration(registration, &self.form.model().password, *res)?;
                self.common.call_backend(
                    ctx,
                    HostService::register_finish(req),
                    Msg::RegistrationFinishResponse,
                );
                Ok(false)
            }
            Msg::RegistrationFinishResponse(response) => {
                response.context("Failed to set new password")?;
                if let Some(enc_pw) = &self.encrypted_password {
                    let variables = sync_kerberos_password::Variables {
                        user_id: ctx.props().username.clone(),
                        encrypted_password: enc_pw.clone(),
                    };
                    self.common.call_graphql::<SyncKerberosPassword, _>(
                        ctx,
                        variables,
                        Msg::SyncKerberosResponse,
                        "Error syncing Kerberos password",
                    );
                    Ok(false)
                } else {
                    self.navigate_to_user_details(ctx);
                    Ok(true)
                }
            }
            Msg::SyncKerberosResponse(response) => {
                response?;
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
            kerberos_info: None,
            encrypted_password: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let is_admin = ctx.props().is_admin;

        if self.kerberos_info.is_none() {
            return html! {
              <>
              { if let Some(e) = &self.common.error {
                  html! { <div class="alert alert-danger">{e.to_string()}</div> }
              } else { html! {} }}
              <div>{"Loading Kerberos configuration..."}</div>
              </>
            };
        }

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

    fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
        if first_render {
            self.common.call_graphql::<GetKerberosInfo, _>(
                ctx,
                get_kerberos_info::Variables {},
                Msg::KerberosInfoResponse,
                "Failed to load Kerberos info",
            );
        }
    }
}
