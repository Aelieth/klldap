use crate::{
    components::{
        form::submit::Submit,
        router::{AppRoute, Link},
    },
    infra::{
        api::{HostService, LoginOutcome},
        common_component::{CommonComponent, CommonComponentParts},
        opaque::{LoginState, begin_login, finish_login},
    },
};
use anyhow::{Result, anyhow, bail};
use gloo_console::error;
use lldap_auth::login;
use lldap_mfa::{TotpFailure, split_totp_suffix, totp_failure};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;

pub struct LoginForm {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    refreshing: bool,
    totp_code: Option<String>,
    retry_credentials: Option<(String, String)>,
    mfa_help: bool,
}

/// The fields of the form, with the constraints.
#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct FormModel {
    #[validate(length(min = 1, message = "Missing username"))]
    username: String,
    #[validate(length(min = 1, message = "Missing password"))]
    password: String,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub on_logged_in: Callback<(String, bool, bool)>,
    pub password_reset_enabled: bool,
    pub mfa_enabled: bool,
}

pub enum Msg {
    Update,
    Submit,
    AuthenticationRefreshResponse(Result<(String, bool, bool)>),
    AuthenticationStartResponse(
        (
            Box<LoginState>,
            String,
            Result<Box<login::ServerLoginStartResponse>>,
        ),
    ),
    AuthenticationFinishResponse(Result<LoginOutcome>),
}

impl LoginForm {
    fn start_login_attempt(
        &mut self,
        ctx: &Context<Self>,
        username: String,
        password: String,
    ) -> Result<bool> {
        let (state, request) = begin_login(&username, &password)?;
        self.common
            .call_backend(ctx, HostService::login_start(request), move |r| {
                Msg::AuthenticationStartResponse((Box::new(state), password, r))
            });
        Ok(true)
    }
}

impl CommonComponent<LoginForm> for LoginForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        use anyhow::Context;
        match msg {
            Msg::Update => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                self.mfa_help = false;
                let FormModel { username, password } = self.form.model();
                let split = ctx
                    .props()
                    .mfa_enabled
                    .then(|| split_totp_suffix(&password))
                    .flatten()
                    .map(|(p, c)| (p.to_owned(), c.to_owned()));
                let password = match split {
                    Some((stripped, code)) => {
                        self.totp_code = Some(code);
                        self.retry_credentials = Some((username.clone(), password));
                        stripped
                    }
                    None => {
                        self.totp_code = None;
                        self.retry_credentials = None;
                        password
                    }
                };
                self.start_login_attempt(ctx, username, password)
            }
            Msg::AuthenticationStartResponse((state, password, res)) => {
                let res = match res {
                    Ok(r) => r,
                    Err(e) => {
                        // Let authentication errors (including disabled account) show their real message
                        self.common.error = Some(e);
                        return Ok(true);
                    }
                };
                let request = match finish_login(*state, &password, *res, self.totp_code.clone()) {
                    Ok(request) => request,
                    Err(e) => {
                        // A password that itself ends in ':' and six digits was split: try it whole.
                        if let Some((username, password)) = self.retry_credentials.take() {
                            self.totp_code = None;
                            return self.start_login_attempt(ctx, username, password);
                        }
                        // Common error, we want to print a full error to the console but only a
                        // simple one to the user.
                        error!(&format!("Invalid username or password: {:#}", e));
                        self.common.error = Some(anyhow!("Invalid username or password"));
                        return Ok(true);
                    }
                };
                self.common.call_backend(
                    ctx,
                    HostService::login_finish(request),
                    Msg::AuthenticationFinishResponse,
                );
                Ok(false)
            }
            Msg::AuthenticationFinishResponse(res) => {
                self.retry_credentials = None;
                match res {
                    Err(e) => {
                        if self.totp_code.take().is_some() {
                            error!(&format!("Invalid credentials: {}", e));
                            self.common.error = Some(match totp_failure(&e.to_string()) {
                                TotpFailure::Replayed => {
                                    anyhow!("That code was already used. Wait for the next one.")
                                }
                                TotpFailure::TooManyAttempts => {
                                    anyhow!("Too many attempts. Wait for the next code.")
                                }
                                TotpFailure::CodeRequired
                                | TotpFailure::EnrollmentRequired
                                | TotpFailure::Other => anyhow!("Invalid username or password"),
                            });
                            Ok(true)
                        } else {
                            Err(e).context("Could not log in")
                        }
                    }
                    Ok(LoginOutcome::MfaRequired) => {
                        self.totp_code = None;
                        self.mfa_help = true;
                        Ok(true)
                    }
                    Ok(LoginOutcome::Success {
                        user_id,
                        is_admin,
                        mfa_enrollment_required,
                    }) => {
                        self.totp_code = None;
                        ctx.props()
                            .on_logged_in
                            .emit((user_id, is_admin, mfa_enrollment_required));
                        Ok(true)
                    }
                }
            }
            Msg::AuthenticationRefreshResponse(user_info) => {
                self.refreshing = false;
                if let Ok(user_info) = user_info {
                    ctx.props().on_logged_in.emit(user_info);
                }
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for LoginForm {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut app = LoginForm {
            common: CommonComponentParts::<Self>::create(),
            form: Form::<FormModel>::new(FormModel::default()),
            refreshing: true,
            totp_code: None,
            retry_credentials: None,
            mfa_help: false,
        };
        app.common.call_backend(
            ctx,
            HostService::refresh(),
            Msg::AuthenticationRefreshResponse,
        );
        app
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        type Field = yew_form::Field<FormModel>;
        let password_reset_enabled = ctx.props().password_reset_enabled;
        let link = &ctx.link();
        if self.refreshing {
            html! {
              <div>
                <img src={"/static/spinner.gif"} alt={"Loading"} />
              </div>
            }
        } else {
            html! {
              <form class="form center-block col-sm-4 col-offset-4">
                <div class="input-group">
                  <div class="input-group-prepend">
                    <span class="input-group-text">
                      <i class="bi-person-fill"/>
                    </span>
                  </div>
                  <Field
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    form={&self.form}
                    field_name="username"
                    placeholder="Username"
                    autocomplete="username"
                    oninput={link.callback(|_| Msg::Update)} />
                </div>
                <div class="input-group">
                  <div class="input-group-prepend">
                    <span class="input-group-text">
                      <i class="bi-lock-fill"/>
                    </span>
                  </div>
                  <Field
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    form={&self.form}
                    field_name="password"
                    input_type="password"
                    placeholder="Password"
                    autocomplete="current-password" />
                </div>
                <Submit
                  text="Login"
                  disabled={self.common.is_task_running()}
                  onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})}>
                  { if password_reset_enabled {
                    html! {
                      <Link
                        classes="btn-link btn"
                        disabled={self.common.is_task_running()}
                        to={AppRoute::StartResetPassword}>
                        {"Forgot your password?"}
                      </Link>
                    }
                  } else {
                    html!{}
                  }}
                </Submit>
                <div class="form-group">
                { if let Some(e) = &self.common.error {
                    html! { e.to_string() }
                  } else { html! {} }
                }
                </div>
                { if self.mfa_help {
                  html! {
                    <div class="alert alert-warning">
                      <h6 class="fw-bold">
                        <i class="bi-shield-lock me-2"></i>
                        {"This account uses two-factor authentication"}
                      </h6>
                      <p class="mb-2">
                        {"Enter your password, ':' and the current code: "}
                        <code>{"yourpassword:123456"}</code>
                      </p>
                    </div>
                  }
                } else {
                  html!{}
                }}
              </form>
            }
        }
    }
}
