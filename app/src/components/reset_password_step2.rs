use crate::{
    components::{
        form::{field::Field, submit::Submit},
        router::{AppRoute, Link},
    },
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
        encrypt::encrypt_password,
    },
};
use anyhow::{Result, bail};
use graphql_client::GraphQLQuery;
use lldap_auth::password_reset::ServerPasswordResetResponse;
use lldap_auth::{opaque, registration};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_kerberos_info.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetKerberosInfo;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/sync_kerberos.graphql",
    response_derives = "Debug,Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct SyncKerberosPassword;

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
    fetched_kerberos: bool,
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

                // Kerberos encryption FIRST (strict, same as create_user.rs)
                self.encrypted_password = None;
                if let Some(info) = &self.kerberos_info {
                    if let Some(ref pub_key_der_base64) = info.public_key_der_base64 {
                        match encrypt_password(pub_key_der_base64, &new_password) {
                            Ok(encrypted) => self.encrypted_password = Some(encrypted),
                            Err(e) => bail!("Failed to encrypt password for Kerberos sync: {}", e),
                        }
                    } else {
                        bail!(
                            "Kerberos enabled but no public key available—check backend startup/logs"
                        );
                    }
                }

                if self.encrypted_password.is_none() {
                    bail!("Kerberos password encryption failed");
                }

                // OPAQUE registration
                let mut rng = rand::rngs::OsRng;
                let registration_start_request = opaque::client::registration::start_registration(
                    new_password.as_bytes(),
                    &mut rng,
                )?;
                let req = registration::ClientRegistrationStartRequest {
                    username: self.username.as_ref().unwrap().clone().into(),
                    registration_start_request: registration_start_request.message,
                };
                self.opaque_data = Some(registration_start_request.state);
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
                let registration_finish = opaque::client::registration::finish_registration(
                    registration,
                    self.form.model().password.as_bytes(),
                    res.registration_response,
                    &mut rand::rngs::OsRng,
                )?;
                let req = registration::ClientRegistrationFinishRequest {
                    server_data: res.server_data,
                    registration_upload: registration_finish.message,
                };
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
                        user_id: self.username.clone().unwrap(),
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
            fetched_kerberos: false,
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
                    html! { <div>{"Loading Kerberos configuration..."}</div> }
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
        if first_render && !self.fetched_kerberos {
            self.common.call_graphql::<GetKerberosInfo, _>(
                ctx,
                get_kerberos_info::Variables {},
                Msg::KerberosInfoResponse,
                "Error fetching Kerberos info",
            );
            self.fetched_kerberos = true;
        }
    }
}
