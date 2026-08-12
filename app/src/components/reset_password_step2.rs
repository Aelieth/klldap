use crate::infra::opaque::{begin_registration, finish_registration};
use crate::infra::queries::{
    GetKerberosInfo, SyncKerberosPassword, get_kerberos_info, sync_kerberos_password,
};
use crate::{
    components::{
        form::{field::Field, submit::Submit},
        router::{AppRoute, Link},
    },
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
        encrypt::encrypt_kerberos_password,
    },
};
use anyhow::{Result, bail};
use lldap_auth::password_reset::ServerPasswordResetResponse;
use lldap_auth::{opaque, registration};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct FormModel {
    #[validate(length(min = 8, message = "Invalid password. Min length: 8"))]
    password: String,
    #[validate(must_match(other = "password", message = "Passwords must match"))]
    confirm_password: String,
}

pub struct ResetPasswordStep2Form {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    username: Option<String>,
    opaque_data: Option<opaque::client::registration::ClientRegistration>,
    kerberos_info: Option<get_kerberos_info::GetKerberosInfoKerberosInfo>,
    encrypted_password: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Properties)]
pub struct Props {
    pub token: String,
}

pub enum Msg {
    ValidateTokenResponse(Result<ServerPasswordResetResponse>),
    KerberosInfoResponse(Result<get_kerberos_info::ResponseData>),
    FormUpdate,
    Submit,
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStartResponse>>),
    RegistrationFinishResponse(Result<()>),
    SyncKerberosResponse(Result<sync_kerberos_password::ResponseData>),
}

impl CommonComponent<ResetPasswordStep2Form> for ResetPasswordStep2Form {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        use anyhow::Context;
        match msg {
            Msg::ValidateTokenResponse(response) => {
                self.username = Some(response?.user_id);
                Ok(true)
            }
            Msg::KerberosInfoResponse(res) => {
                self.kerberos_info = Some(res?.kerberos_info);
                Ok(true)
            }
            Msg::FormUpdate => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                if self.username.is_none() {
                    bail!("Username not available");
                }

                let new_password = self.form.model().password.clone();

                self.encrypted_password = Some(encrypt_kerberos_password(
                    self.kerberos_info
                        .as_ref()
                        .and_then(|i| i.public_key_der_base64.as_deref()),
                    &new_password,
                )?);

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
                let res = res.context("Could not initiate registration")?;
                let registration = match self.opaque_data.take() {
                    Some(r) => r,
                    None => bail!("Invalid state"),
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
                    let Some(user_id) = self.username.clone() else {
                        bail!("Username not available");
                    };
                    let variables = sync_kerberos_password::Variables {
                        user_id,
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
                    ctx.link().history().unwrap().push(AppRoute::Login);
                    Ok(true)
                }
            }
            Msg::SyncKerberosResponse(response) => {
                response?;
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
            kerberos_info: None,
            encrypted_password: None,
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
            _ => {
                if self.kerberos_info.is_none() {
                    html! {
                      <>
                      { if let Some(e) = &self.common.error {
                          html! { <div class="alert alert-danger">{e.to_string()}</div> }
                      } else { html! {} }}
                      <div>{"Loading Kerberos configuration..."}</div>
                      </>
                    }
                } else {
                    html! {
                        <>
                        <h2>{"Reset your password"}</h2>
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
                    }
                }
            }
        }
    }

    fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
        if first_render {
            self.common.call_graphql::<GetKerberosInfo, _>(
                ctx,
                get_kerberos_info::Variables {},
                Msg::KerberosInfoResponse,
                "Error fetching Kerberos info",
            );
        }
    }
}
