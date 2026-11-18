use crate::{
    components::{
        form::submit::Submit,
        router::{AppRoute, Link},
    },
    infra::{
        api::{HostService, LoginOutcome},
        common_component::{CommonComponent, CommonComponentParts},
        cookies::{delete_cookie, get_cookie},
        modal::ModalHandle,
        opaque::{FinishFor, LoginState, begin_login, finish_login},
    },
};
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use gloo_console::error;
use gloo_timers::callback::Timeout;
use graphql_client::GraphQLQuery;
use lldap_auth::login;
use lldap_mfa::{
    PASSWORD_PROOF_REQUIRED, TOTP_CURRENT_CODE_REQUIRED, TOTP_DIGITS, TOTP_ENROLLMENT_EXPIRED,
    TOTP_ENROLLMENT_TTL_SECS, split_totp_suffix,
};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/start_mfa_enrollment.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct StartMfaEnrollment;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/finish_mfa_enrollment.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct FinishMfaEnrollment;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/own_mfa.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct OwnMfa;

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct ConfirmationModel {
    #[validate(custom(
        function = "has_combined_shape",
        message = "Enter your password, a ':' and the current 6-digit code"
    ))]
    combined: String,
}

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct PasswordModel {
    #[validate(custom(function = "is_present", message = "Enter your current password"))]
    current_password: String,
}

fn is_present(value: &str) -> Result<(), validator::ValidationError> {
    match value.is_empty() {
        true => Err(validator::ValidationError::new("")),
        false => Ok(()),
    }
}

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct GateModel {
    #[validate(custom(
        function = "is_totp_code",
        message = "Enter the 6-digit code from your authenticator"
    ))]
    current_code: String,
}

pub fn has_combined_shape(value: &str) -> Result<(), validator::ValidationError> {
    match split_totp_suffix(value) {
        Some((password, _)) if !password.is_empty() => Ok(()),
        _ => Err(validator::ValidationError::new("")),
    }
}

pub fn is_totp_code(value: &str) -> Result<(), validator::ValidationError> {
    match value.len() == TOTP_DIGITS as usize && value.bytes().all(|b| b.is_ascii_digit()) {
        true => Ok(()),
        false => Err(validator::ValidationError::new("")),
    }
}

fn spaced_groups(secret: &str) -> String {
    secret
        .chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

struct EnrollmentData {
    secret_base32: String,
    state: String,
    qr_data_uri: String,
    seed: Vec<u8>,
}

enum Phase {
    Loading,
    Password,
    Gate,
    InProgress(EnrollmentData),
    Complete,
}

enum CodeHint {
    None,
    Valid,
    Invalid,
}

pub struct RegisterMfa {
    common: CommonComponentParts<Self>,
    form: Form<ConfirmationModel>,
    password: Form<PasswordModel>,
    gate: Form<GateModel>,
    ask_proof: bool,
    pending_code: Option<String>,
    opaque_data: Option<(Box<LoginState>, String, String)>,
    phase: Phase,
    hint: CodeHint,
    mfa_exempt: bool,
    expiry_timer: Option<Timeout>,
    modal: ModalHandle,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub username: String,
    pub enrollment_required: bool,
    pub on_enrolled: Callback<()>,
    pub on_logged_out: Callback<()>,
}

pub enum Msg {
    OwnMfaLoaded(Result<own_mfa::ResponseData>),
    EnrollmentStartResponse(Result<start_mfa_enrollment::ResponseData>),
    Update,
    SubmitPassword,
    SubmitGate,
    Submit,
    AuthenticationStartResponse(Result<Box<login::ServerLoginStartResponse>>),
    LoginFinishResponse(Result<LoginOutcome>),
    EnrollmentFinishResponse(Result<finish_mfa_enrollment::ResponseData>),
    EnrollmentExpired,
    ExpiredLogoutRequested,
    ExpiredLogoutCompleted(Result<()>),
}

impl CommonComponent<RegisterMfa> for RegisterMfa {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        use anyhow::Context;
        match msg {
            Msg::OwnMfaLoaded(res) => {
                let enrolled = res?.user.mfa_enrolled.unwrap_or(false);
                self.phase = if enrolled {
                    Phase::Gate
                } else {
                    Phase::Password
                };
                Ok(true)
            }
            Msg::EnrollmentStartResponse(res) => match res {
                Ok(res) => {
                    let start = res.start_mfa_enrollment;
                    // Not in create(): the gate's code entry would eat the server's TTL.
                    let link = ctx.link().clone();
                    self.expiry_timer = Some(Timeout::new(
                        (TOTP_ENROLLMENT_TTL_SECS * 1000) as u32,
                        move || link.send_message(Msg::EnrollmentExpired),
                    ));
                    let qr_svg = qrcode::QrCode::new(start.otpauth_uri.as_bytes())
                        .map_err(|e| anyhow!("Could not render the QR code: {}", e))?
                        .render::<qrcode::render::svg::Color>()
                        .min_dimensions(200, 200)
                        .build();
                    let qr_data_uri = format!(
                        "data:image/svg+xml;base64,{}",
                        base64::engine::general_purpose::STANDARD.encode(&qr_svg)
                    );
                    let seed = lldap_mfa::seed_from_base32(&start.secret_base32)
                        .map_err(|_| anyhow!("Invalid secret received from the server"))?;
                    self.phase = Phase::InProgress(EnrollmentData {
                        secret_base32: start.secret_base32,
                        state: start.state,
                        qr_data_uri,
                        seed,
                    });
                    Ok(true)
                }
                Err(e) if e.to_string().contains(PASSWORD_PROOF_REQUIRED) => {
                    self.phase = Phase::Password;
                    self.common.error = Some(anyhow!(
                        "The password check expired or was already used. Enter your password again."
                    ));
                    Ok(true)
                }
                Err(e) if e.to_string().contains(TOTP_CURRENT_CODE_REQUIRED) => {
                    self.phase = Phase::Gate;
                    Ok(true)
                }
                Err(e) => Err(e),
            },
            Msg::Update => {
                let combined = self.form.field_value("combined");
                self.hint = match (&self.phase, split_totp_suffix(&combined)) {
                    (Phase::InProgress(data), Some((_, code))) => {
                        let now_secs = chrono::Utc::now().timestamp() as u64;
                        match lldap_mfa::totp_verify(&data.seed, code, now_secs) {
                            Ok(true) => CodeHint::Valid,
                            _ => CodeHint::Invalid,
                        }
                    }
                    _ => CodeHint::None,
                };
                Ok(true)
            }
            Msg::SubmitPassword => {
                if self.opaque_data.is_some() || self.common.is_task_running() {
                    return Ok(false);
                }
                if !self.password.validate() {
                    bail!("Check the form for errors");
                }
                let password = self.password.field_value("current_password");
                self.password.set_field_value("current_password", "");
                let (state, request) = begin_login(&ctx.props().username, &password)?;
                self.ask_proof = true;
                self.opaque_data = Some((Box::new(state), password, String::new()));
                self.common.call_backend(
                    ctx,
                    HostService::login_start(request),
                    Msg::AuthenticationStartResponse,
                );
                Ok(true)
            }
            Msg::SubmitGate => {
                if !self.gate.validate() {
                    bail!("Check the form for errors");
                }
                self.start_enrollment(ctx, Some(self.gate.field_value("current_code")), None);
                Ok(true)
            }
            Msg::Submit => {
                if self.opaque_data.is_some() || self.common.is_task_running() {
                    return Ok(false);
                }
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                if !matches!(self.phase, Phase::InProgress(_)) {
                    bail!("No enrollment in progress");
                }
                let combined = self.form.field_value("combined");
                let Some((password, code)) = split_totp_suffix(&combined) else {
                    bail!("Check the form for errors");
                };
                self.ask_proof = false;
                let (state, request) = begin_login(&ctx.props().username, password)?;
                // Keep the submitted code: the field stays editable while the login is in flight.
                self.opaque_data = Some((Box::new(state), password.to_owned(), code.to_owned()));
                self.common.call_backend(
                    ctx,
                    HostService::login_start(request),
                    Msg::AuthenticationStartResponse,
                );
                Ok(true)
            }
            Msg::AuthenticationStartResponse(res) => {
                let held = self.opaque_data.take();
                let res = res.map_err(|e| anyhow!("Could not initiate login: {}", e))?;
                let Some((state, password, code)) = held else {
                    bail!("Invalid state");
                };
                let finish_for = match self.ask_proof {
                    true => FinishFor::EnrollmentProof,
                    false => FinishFor::PasswordCheck,
                };
                let request = finish_login(*state, &password, *res, finish_for).map_err(|e| {
                    error!(&format!("Invalid password: {:#}", e));
                    anyhow!("Invalid password")
                })?;
                self.pending_code = Some(code);
                self.common.call_backend(
                    ctx,
                    HostService::login_finish(request),
                    Msg::LoginFinishResponse,
                );
                Ok(true)
            }
            Msg::LoginFinishResponse(res) => {
                let pending_code = self.pending_code.take();
                let outcome = res.context("Password verification failed")?;
                if self.ask_proof {
                    self.ask_proof = false;
                    let LoginOutcome::Verified {
                        enrollment_proof: Some(proof),
                    } = outcome
                    else {
                        bail!("The server did not return an enrollment proof");
                    };
                    self.start_enrollment(ctx, None, Some(proof));
                    return Ok(true);
                }
                // The password verified. An enrolled user is told a code is still required.
                let Some(code) = pending_code else {
                    bail!("No enrollment in progress");
                };
                let Phase::InProgress(data) = &self.phase else {
                    bail!("No enrollment in progress");
                };
                self.common.call_graphql::<FinishMfaEnrollment, _>(
                    ctx,
                    finish_mfa_enrollment::Variables {
                        state: data.state.clone(),
                        code,
                    },
                    Msg::EnrollmentFinishResponse,
                    "Error enabling two-factor authentication",
                );
                Ok(true)
            }
            Msg::EnrollmentFinishResponse(res) => match res {
                Ok(_) => {
                    if let Some(timer) = self.expiry_timer.take() {
                        timer.cancel();
                    }
                    self.phase = Phase::Complete;
                    ctx.props().on_enrolled.emit(());
                    Ok(true)
                }
                Err(e) if e.to_string().contains(TOTP_ENROLLMENT_EXPIRED) => {
                    self.modal.show();
                    Ok(true)
                }
                Err(e) => Err(e),
            },
            Msg::EnrollmentExpired => {
                if matches!(self.phase, Phase::InProgress(_)) {
                    self.modal.show();
                }
                Ok(true)
            }
            Msg::ExpiredLogoutRequested => {
                self.common
                    .call_backend(ctx, HostService::logout(), Msg::ExpiredLogoutCompleted);
                Ok(true)
            }
            Msg::ExpiredLogoutCompleted(res) => {
                res?;
                self.modal.hide();
                delete_cookie("user_id")?;
                delete_cookie("is_admin")?;
                delete_cookie("mfa_exempt")?;
                ctx.props().on_logged_out.emit(());
                Ok(false)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for RegisterMfa {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut component = RegisterMfa {
            common: CommonComponentParts::<Self>::create(),
            form: Form::<ConfirmationModel>::new(ConfirmationModel::default()),
            password: Form::<PasswordModel>::new(PasswordModel::default()),
            gate: Form::<GateModel>::new(GateModel::default()),
            ask_proof: false,
            pending_code: None,
            opaque_data: None,
            phase: Phase::Loading,
            hint: CodeHint::None,
            mfa_exempt: get_cookie("mfa_exempt").ok().flatten().as_deref() == Some("true"),
            expiry_timer: None,
            modal: ModalHandle::new(),
        };
        component.common.call_graphql::<OwnMfa, _>(
            ctx,
            own_mfa::Variables {
                id: ctx.props().username.clone(),
            },
            Msg::OwnMfaLoaded,
            "Error reading two-factor status",
        );
        component
    }

    fn rendered(&mut self, _: &Context<Self>, first_render: bool) {
        self.modal.init_on_first_render(first_render);
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
          <>
            <div class="mb-2 mt-2">
              <h5 class="fw-bold text-center">
                {"Set up two-factor authentication"}
              </h5>
            </div>
            {
              if let Some(e) = &self.common.error {
                html! {
                  <div class="alert alert-danger mt-3 mb-3">
                    {e.to_string() }
                  </div>
                }
              } else { html! {} }
            }
            { match &self.phase {
                Phase::Password => self.view_password(ctx),
                Phase::Loading => html! {
                  <div>
                    <img src={"/static/spinner.gif"} alt={"Loading"} />
                  </div>
                },
                Phase::Gate => self.view_gate(ctx),
                Phase::InProgress(data) => self.view_enrollment(ctx, data),
                Phase::Complete => self.view_complete(ctx),
            }}
            {self.expiry_modal(ctx)}
          </>
        }
    }
}

impl RegisterMfa {
    fn start_enrollment(
        &mut self,
        ctx: &Context<Self>,
        current_code: Option<String>,
        enrollment_proof: Option<String>,
    ) {
        self.common.call_graphql::<StartMfaEnrollment, _>(
            ctx,
            start_mfa_enrollment::Variables {
                current_code,
                enrollment_proof,
            },
            Msg::EnrollmentStartResponse,
            "Error starting two-factor enrollment",
        );
    }

    fn view_password(&self, ctx: &Context<Self>) -> Html {
        type Field = yew_form::Field<PasswordModel>;
        let link = ctx.link();
        html! {
          <div class="mx-auto" style="max-width: 410px">
            <p>{"Enter your current password to set up two-factor authentication."}</p>
            <form class="form">
              <label for="current_password" class="form-label">
                {"Current password"}
                <span class="text-danger">{"*"}</span>
                {":"}
              </label>
              <Field
                class="form-control"
                class_invalid="is-invalid has-error"
                class_valid="has-success"
                form={&self.password}
                field_name="current_password"
                input_type="password"
                autocomplete="current-password" />
              <div class="invalid-feedback">
                {self.password.field_message("current_password")}
              </div>
              <Submit
                text="Continue"
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitPassword})}>
                {self.back_link(ctx)}
              </Submit>
            </form>
          </div>
        }
    }

    fn view_gate(&self, ctx: &Context<Self>) -> Html {
        type Field = yew_form::Field<GateModel>;
        let link = ctx.link();
        html! {
          <div class="mx-auto" style="max-width: 410px">
            <p>
              {"Please enter only your current two-factor code to proceed. Example: "}
              <code>{"123456"}</code>
            </p>
            <form class="form">
              <label for="current_code" class="form-label">
                {"Current two-factor code"}
                <span class="text-danger">{"*"}</span>
                {":"}
              </label>
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
                  form={&self.gate}
                  field_name="current_code"
                  input_type="password"
                  autocomplete="off" />
                <div class="invalid-feedback">
                  {self.gate.field_message("current_code")}
                </div>
              </div>
              <Submit
                text="Continue"
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitGate})}>
                {self.back_link(ctx)}
              </Submit>
            </form>
          </div>
        }
    }

    fn back_link(&self, ctx: &Context<Self>) -> Html {
        if ctx.props().enrollment_required {
            return html! {};
        }
        html! {
          <Link
            classes="btn btn-secondary ms-2 col-auto col-form-label"
            to={AppRoute::UserDetails{user_id: ctx.props().username.clone()}}>
            <i class="bi-arrow-return-left me-2"></i>
            {"Back"}
          </Link>
        }
    }

    fn view_enrollment(&self, ctx: &Context<Self>, data: &EnrollmentData) -> Html {
        type Field = yew_form::Field<ConfirmationModel>;
        let link = ctx.link();
        html! {
          <>
            <p class="text-center">
              {"Scan the QR code with an authenticator app (or enter the secret manually):"}
            </p>
            <p class="text-center">
              <img
                src={data.qr_data_uri.clone()}
                width="200"
                height="200"
                alt="TOTP QR code" />
            </p>
            <p class="text-center">
              <code>{spaced_groups(&data.secret_base32)}</code>
            </p>
            <div class="mx-auto" style="max-width: 720px">
            { if self.mfa_exempt {
                html! {
                  <div class="alert alert-warning">
                    {"You are in lldap_mfa_disabled, so you will not be asked for a code at login until you leave the group."}
                  </div>
                }
              } else {
                html! {
                  <p>
                    {"After enrolling, the web login asks for your two-factor code after your password. LDAP clients and scripts send your password, a colon, and the code."}
                  </p>
                }
              }}
            <p>
              {"Verify by confirming with your password, ':' and the current code: "}
              <code>{"yourpassword:123456"}</code>
            </p>
            <form class="form">
              <div class="mx-auto" style="max-width: 410px">
                <label for="combined" class="form-label">
                  {"Password and code"}
                  <span class="text-danger">{"*"}</span>
                  {":"}
                </label>
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
                    field_name="combined"
                    input_type="password"
                    autocomplete="off"
                    oninput={link.callback(|_| Msg::Update)} />
                  <div class="invalid-feedback">
                    {self.form.field_message("combined")}
                  </div>
                </div>
                <div class="mb-3 mt-1">
                  { match self.hint {
                      CodeHint::None => html! {},
                      CodeHint::Valid => html! {
                        <div class="text-success">
                          <i class="bi-check-circle me-2"></i>
                          {"The code matches."}
                        </div>
                      },
                      CodeHint::Invalid => html! {
                        <div class="text-danger">
                          <i class="bi-x-circle me-2"></i>
                          {"This code does not match yet."}
                        </div>
                      },
                  }}
                </div>
              </div>
              <Submit
                text="Enable two-factor"
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})}>
                {self.back_link(ctx)}
              </Submit>
            </form>
            </div>
          </>
        }
    }

    fn view_complete(&self, ctx: &Context<Self>) -> Html {
        html! {
          <>
            <div class="alert alert-success mt-4">
              {"Two-factor authentication is enabled."}
            </div>
            <Link
              classes="btn btn-primary"
              to={AppRoute::UserDetails{user_id: ctx.props().username.clone()}}>
              <i class="bi-arrow-return-left me-2"></i>
              {"Back to profile"}
            </Link>
          </>
        }
    }

    fn expiry_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        html! {
          <div
            class="modal fade"
            id="mfaEnrollmentExpiredModal"
            tabindex="-1"
            aria-labelledby="mfaEnrollmentExpiredModalLabel"
            aria-hidden="true"
            data-bs-backdrop="static"
            data-bs-keyboard="false"
            ref={self.modal.node_ref()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="mfaEnrollmentExpiredModalLabel">{"Enrollment session expired"}</h5>
                </div>
                <div class="modal-body">
                  <span>
                    {"This page has expired. Log in again to continue setting up two-factor authentication."}
                  </span>
                </div>
                <div class="modal-footer">
                  <button
                    type="button"
                    class="btn btn-primary"
                    disabled={self.common.is_task_running()}
                    onclick={link.callback(|_| Msg::ExpiredLogoutRequested)}>
                    <i class="bi-box-arrow-right me-2"></i>
                    {"Log in again"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
