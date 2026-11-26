use crate::{
    components::{
        form::submit::Submit,
        register_mfa::is_totp_code,
        router::{AppRoute, Link},
    },
    infra::{
        api::{HostService, LoginOutcome},
        common_component::{CommonComponent, CommonComponentParts},
        opaque::{FinishFor, LoginState, begin_login, finish_login, keep_signed_in_key},
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

const INVALID_CREDENTIALS: &str = "Invalid username or password";

struct Credentials {
    username: String,
    password: String,
    code: Option<String>,
    bound_key: Option<String>,
}

enum Step {
    Password,
    // The password stays in this component's memory for the code step only.
    Code { username: String, password: String },
}

pub struct LoginForm {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    code_form: Form<CodeModel>,
    refreshing: bool,
    step: Step,
    in_flight: Option<Credentials>,
    old_form_hint: bool,
}

/// The fields of the form, with the constraints.
#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct FormModel {
    #[validate(length(min = 1, message = "Missing username"))]
    username: String,
    #[validate(length(min = 1, message = "Missing password"))]
    password: String,
}

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct CodeModel {
    #[validate(custom(
        function = "is_totp_code",
        message = "Enter the 6-digit code from your authenticator"
    ))]
    totp_code: String,
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
    SubmitCode,
    BackToPassword,
    AuthenticationRefreshResponse(Result<(String, bool, bool)>),
    AuthenticationStartResponse((Box<LoginState>, Result<Box<login::ServerLoginStart>>)),
    AuthenticationFinishResponse(Result<LoginOutcome>),
}

fn shows_old_form_hint(mfa_enabled: bool, password: &str) -> bool {
    mfa_enabled && split_totp_suffix(password).is_some()
}

fn code_refusal(message: &str) -> &'static str {
    match totp_failure(message) {
        TotpFailure::Replayed => "That code was already used. Wait for the next one.",
        TotpFailure::TooManyAttempts => "Too many attempts. Wait for the next code.",
        _ => "Invalid code",
    }
}

impl LoginForm {
    fn start_login_attempt(
        &mut self,
        ctx: &Context<Self>,
        credentials: Credentials,
    ) -> Result<bool> {
        let (state, request) = begin_login(&credentials.username, &credentials.password)?;
        self.in_flight = Some(credentials);
        self.common
            .call_backend(ctx, HostService::login_start(request), move |r| {
                Msg::AuthenticationStartResponse((Box::new(state), r))
            });
        Ok(true)
    }

    fn back_to_password(&mut self, error: Option<anyhow::Error>) {
        self.step = Step::Password;
        self.code_form = Form::<CodeModel>::new(CodeModel::default());
        self.common.error = error;
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
                if self.in_flight.is_some() || self.common.is_task_running() {
                    return Ok(false);
                }
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                self.old_form_hint = false;
                let FormModel { username, password } = self.form.model();
                self.start_login_attempt(
                    ctx,
                    Credentials {
                        username,
                        password,
                        code: None,
                        bound_key: None,
                    },
                )
            }
            Msg::SubmitCode => {
                if self.in_flight.is_some() || self.common.is_task_running() {
                    return Ok(false);
                }
                if !self.code_form.validate() {
                    bail!("Check the form for errors");
                }
                let Step::Code { username, password } = &self.step else {
                    bail!("Invalid state");
                };
                let credentials = Credentials {
                    username: username.clone(),
                    password: password.clone(),
                    code: Some(self.code_form.field_value("totp_code")),
                    bound_key: None,
                };
                self.start_login_attempt(ctx, credentials)
            }
            Msg::BackToPassword => {
                self.back_to_password(None);
                Ok(true)
            }
            Msg::AuthenticationStartResponse((state, res)) => {
                let res = match res {
                    Ok(r) => r,
                    Err(e) => {
                        self.in_flight = None;
                        // Let authentication errors (including disabled account) show their real message
                        self.common.error = Some(e);
                        return Ok(true);
                    }
                };
                let Some(mut credentials) = self.in_flight.take() else {
                    bail!("Invalid state");
                };
                let finish_for = FinishFor::SignIn(credentials.code.clone());
                let request = match finish_login(*state, &credentials.password, *res, finish_for) {
                    Ok((request, bound_key)) => {
                        credentials.bound_key = bound_key;
                        request
                    }
                    Err(e) => {
                        // Common error, we want to print a full error to the console but only a
                        // simple one to the user.
                        error!(&format!("Invalid username or password: {:#}", e));
                        if credentials.code.is_some() {
                            self.back_to_password(Some(anyhow!(INVALID_CREDENTIALS)));
                            return Ok(true);
                        }
                        self.old_form_hint =
                            shows_old_form_hint(ctx.props().mfa_enabled, &credentials.password);
                        self.common.error = Some(anyhow!(INVALID_CREDENTIALS));
                        return Ok(true);
                    }
                };
                self.in_flight = Some(credentials);
                self.common.call_backend(
                    ctx,
                    HostService::login_finish(request),
                    Msg::AuthenticationFinishResponse,
                );
                Ok(false)
            }
            Msg::AuthenticationFinishResponse(res) => {
                let Some(credentials) = self.in_flight.take() else {
                    bail!("Invalid state");
                };
                let code_step = credentials.code.is_some();
                match res {
                    Ok(LoginOutcome::Success {
                        user_id,
                        is_admin,
                        mfa_enrollment_required,
                    }) => {
                        self.back_to_password(None);
                        keep_signed_in_key(credentials.bound_key);
                        ctx.props()
                            .on_logged_in
                            .emit((user_id, is_admin, mfa_enrollment_required));
                        Ok(true)
                    }
                    Ok(LoginOutcome::MfaRequired) if !code_step => {
                        let Credentials {
                            username, password, ..
                        } = credentials;
                        self.form.set_field_value("password", "");
                        self.step = Step::Code { username, password };
                        Ok(true)
                    }
                    Ok(_) => bail!("Invalid response to login finish"),
                    Err(e) if code_step => {
                        error!(&format!("Code refused: {}", e));
                        self.code_form.set_field_value("totp_code", "");
                        self.common.error = Some(anyhow!(code_refusal(&e.to_string())));
                        Ok(true)
                    }
                    Err(e) => Err(e).context("Could not log in"),
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
            code_form: Form::<CodeModel>::new(CodeModel::default()),
            refreshing: true,
            step: Step::Password,
            in_flight: None,
            old_form_hint: false,
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
        if self.refreshing {
            return html! {
              <div>
                <img src={"/static/spinner.gif"} alt={"Loading"} />
              </div>
            };
        }
        match self.step {
            Step::Password => self.view_password(ctx),
            Step::Code { .. } => self.view_code(ctx),
        }
    }
}

impl LoginForm {
    fn view_error(&self) -> Html {
        html! {
          <div class="form-group">
          { if let Some(e) = &self.common.error {
              html! { e.to_string() }
            } else { html! {} }
          }
          </div>
        }
    }

    fn view_password(&self, ctx: &Context<Self>) -> Html {
        type Field = yew_form::Field<FormModel>;
        let password_reset_enabled = ctx.props().password_reset_enabled;
        let link = &ctx.link();
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
            {self.view_error()}
            { if self.old_form_hint {
              html! {
                <div class="alert alert-info">
                  {"If you added ':' and a code to your password, enter the password alone: the code is asked in the next step."}
                </div>
              }
            } else {
              html!{}
            }}
          </form>
        }
    }

    fn view_code(&self, ctx: &Context<Self>) -> Html {
        type Field = yew_form::Field<CodeModel>;
        let link = &ctx.link();
        html! {
          <form class="form center-block col-sm-4 col-offset-4">
            <div class="alert alert-warning">
              <h6 class="fw-bold">
                <i class="bi-shield-lock me-2"></i>
                {"This account uses two-factor authentication"}
              </h6>
              <p class="mb-0">{"Enter the current code from your authenticator."}</p>
            </div>
            <div class="input-group">
              <div class="input-group-prepend">
                <span class="input-group-text">
                  <i class="bi-shield-lock"/>
                </span>
              </div>
              <Field
                class="form-control"
                class_invalid="is-invalid has-error"
                class_valid="has-success"
                form={&self.code_form}
                field_name="totp_code"
                placeholder="123456"
                autocomplete="one-time-code"
                oninput={link.callback(|_| Msg::Update)} />
              <div class="invalid-feedback">
                {self.code_form.field_message("totp_code")}
              </div>
            </div>
            <Submit
              text="Verify"
              disabled={self.common.is_task_running()}
              onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitCode})}>
              <button
                type="button"
                class="btn btn-secondary ms-2"
                disabled={self.common.is_task_running()}
                onclick={link.callback(|_| Msg::BackToPassword)}>
                {"Back"}
              </button>
            </Submit>
            {self.view_error()}
          </form>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lldap_mfa::{TOTP_CODE_ALREADY_USED, TOTP_TOO_MANY_ATTEMPTS};

    #[test]
    fn test_the_old_one_field_form_gets_a_hint_only_with_mfa_on() {
        let rows = [
            (true, "secret:123456", true),
            (true, "secret", false),
            (true, "secret:12345", false),
            (false, "secret:123456", false),
        ];
        for (mfa_enabled, password, hint) in rows {
            assert_eq!(
                shows_old_form_hint(mfa_enabled, password),
                hint,
                "{mfa_enabled} {password}"
            );
        }
    }

    #[test]
    fn test_a_refused_code_keeps_the_used_and_attempts_messages() {
        let rows = [
            (
                format!("Could not finish authentication: {TOTP_CODE_ALREADY_USED} for bob"),
                "That code was already used. Wait for the next one.",
            ),
            (
                format!("Could not finish authentication: {TOTP_TOO_MANY_ATTEMPTS} for bob"),
                "Too many attempts. Wait for the next code.",
            ),
            (
                "Could not finish authentication: Invalid TOTP code for bob".to_owned(),
                "Invalid code",
            ),
        ];
        for (message, shown) in rows {
            assert_eq!(code_refusal(&message), shown, "{message}");
        }
    }
}
