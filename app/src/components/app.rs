use crate::{
    components::{
        banner::Banner,
        change_password::ChangePasswordForm,
        create_group::CreateGroupForm,
        create_group_attribute::CreateGroupAttributeForm,
        create_user::CreateUserForm,
        create_user_attribute::CreateUserAttributeForm,
        federation::Federation,
        group_details::GroupDetails,
        group_schema_table::ListGroupSchema,
        group_table::GroupTable,
        login::LoginForm,
        register_mfa::RegisterMfa,
        reset_own_mfa::ResetOwnMfaForm,
        reset_password_step1::ResetPasswordStep1Form,
        reset_password_step2::ResetPasswordStep2Form,
        router::{AppRoute, Redirect},
        user_details::UserDetails,
        user_schema_table::ListUserSchema,
        user_table::UserTable,
    },
    infra::{api::HostService, cookies::get_cookie},
};

use gloo_console::error;
use lldap_frontend_options::Options;
use yew::{
    Context, function_component,
    html::Scope,
    prelude::{Component, Html, html},
};
use yew_router::{
    BrowserRouter, Switch,
    prelude::{History, Location},
    scope_ext::RouterScopeExt,
};

#[function_component(AppContainer)]
pub fn app_container() -> Html {
    html! {
        <BrowserRouter>
            <App />
        </BrowserRouter>
    }
}

pub struct App {
    user_info: Option<(String, bool)>,
    redirect_to: Option<AppRoute>,
    password_reset_enabled: Option<bool>,
    mfa_enabled: Option<bool>,
    mfa_required: bool,
    mfa_enrollment_pending: bool,
}

// Session state the routes need, kept together so dispatch_route keeps a readable signature.
struct SessionRouting {
    user: Option<String>,
    mfa_enabled: Option<bool>,
    mfa_required: bool,
    mfa_enrollment_pending: bool,
}

pub enum Msg {
    Login((String, bool, bool)),
    Logout,
    SettingsReceived(anyhow::Result<Options>),
    SessionRefreshed(anyhow::Result<(String, bool, bool)>),
    MfaEnrolled,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let app = Self {
            user_info: get_cookie("user_id")
                .unwrap_or_else(|e| {
                    error!(&e.to_string());
                    None
                })
                .and_then(|u| {
                    get_cookie("is_admin")
                        .map(|so| so.map(|s| (u, s == "true")))
                        .unwrap_or_else(|e| {
                            error!(&e.to_string());
                            None
                        })
                }),
            redirect_to: Self::get_redirect_route(ctx),
            password_reset_enabled: None,
            mfa_enabled: None,
            mfa_required: false,
            mfa_enrollment_pending: false,
        };
        ctx.link()
            .send_future(async move { Msg::SettingsReceived(HostService::get_settings().await) });
        // The cookies do not carry the enrollment flag: a reload relearns it from the server.
        if app.user_info.is_some() {
            ctx.link()
                .send_future(async move { Msg::SessionRefreshed(HostService::refresh().await) });
        }
        app.apply_initial_redirections(ctx);
        app
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        let history = ctx.link().history().unwrap();
        match msg {
            Msg::Login((user_name, is_admin, mfa_enrollment_required)) => {
                self.user_info = Some((user_name.clone(), is_admin));
                self.mfa_enrollment_pending = mfa_enrollment_required;
                if mfa_enrollment_required {
                    self.redirect_to = None;
                    history.push(AppRoute::RegisterMfa { user_id: user_name });
                } else {
                    history.push(self.redirect_to.take().unwrap_or_else(|| {
                        if is_admin {
                            AppRoute::ListUsers
                        } else {
                            AppRoute::UserDetails {
                                user_id: user_name.clone(),
                            }
                        }
                    }));
                }
            }
            Msg::Logout => {
                self.user_info = None;
                self.redirect_to = None;
                self.mfa_enrollment_pending = false;
                history.push(AppRoute::Login);
            }
            Msg::SettingsReceived(Ok(settings)) => {
                self.password_reset_enabled = Some(settings.password_reset_enabled);
                self.mfa_enabled = Some(settings.mfa_enabled);
                self.mfa_required = settings.mfa_required;
            }
            Msg::SettingsReceived(Err(err)) => {
                error!(err.to_string());
            }
            Msg::SessionRefreshed(Ok((user_name, is_admin, mfa_enrollment_required))) => {
                self.user_info = Some((user_name, is_admin));
                self.mfa_enrollment_pending = mfa_enrollment_required;
            }
            Msg::SessionRefreshed(Err(err)) => {
                error!(err.to_string());
            }
            Msg::MfaEnrolled => {
                self.mfa_enrollment_pending = false;
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link().clone();
        let is_admin = self.is_admin();
        let username = self.user_info.clone().map(|(username, _)| username);
        let password_reset_enabled = self.password_reset_enabled;
        let session = SessionRouting {
            user: username.clone(),
            mfa_enabled: self.mfa_enabled,
            mfa_required: self.mfa_required,
            mfa_enrollment_pending: self.mfa_enrollment_pending,
        };
        html! {
          <div>
            <Banner is_admin={is_admin} username={username} on_logged_out={link.callback(|_| Msg::Logout)} />
            <div class="container py-3">
              <div class="row justify-content-center app-content">
                <main class="py-3">
                  <Switch<AppRoute>
                    render={Switch::render(move |routes| Self::dispatch_route(routes, &link, is_admin, password_reset_enabled, &session))}
                  />
                </main>
              </div>
              {self.view_footer()}
            </div>
          </div>
        }
    }
}

impl App {
    // Get the page to land on after logging in, defaulting to the index.
    fn get_redirect_route(ctx: &Context<Self>) -> Option<AppRoute> {
        let route = ctx.link().history().unwrap().location().route::<AppRoute>();
        route.filter(|route| {
            !matches!(
                route,
                AppRoute::Index
                    | AppRoute::Login
                    | AppRoute::StartResetPassword
                    | AppRoute::FinishResetPassword { token: _ }
            )
        })
    }

    fn apply_initial_redirections(&self, ctx: &Context<Self>) {
        let history = ctx.link().history().unwrap();
        let route = history.location().route::<AppRoute>();
        let redirection = match (route, &self.user_info, &self.redirect_to) {
            (
                Some(AppRoute::StartResetPassword | AppRoute::FinishResetPassword { token: _ }),
                _,
                _,
            ) => {
                if self.password_reset_enabled == Some(false) {
                    Some(AppRoute::Login)
                } else {
                    None
                }
            }
            (None, _, _) | (_, None, _) => Some(AppRoute::Login),
            // User is logged in, a URL was given, don't redirect.
            (_, Some(_), Some(_)) => None,
            (_, Some((user_name, is_admin)), None) => {
                if *is_admin {
                    Some(AppRoute::ListUsers)
                } else {
                    Some(AppRoute::UserDetails {
                        user_id: user_name.clone(),
                    })
                }
            }
        };
        if let Some(redirect_to) = redirection {
            history.push(redirect_to);
        }
    }

    fn dispatch_route(
        switch: &AppRoute,
        link: &Scope<Self>,
        is_admin: bool,
        password_reset_enabled: Option<bool>,
        session: &SessionRouting,
    ) -> Html {
        let logged_in_user = session.user.as_deref();
        let is_self =
            |user_id: &str| logged_in_user.is_some_and(|u| u.eq_ignore_ascii_case(user_id));
        let SessionRouting {
            mfa_enabled,
            mfa_required,
            mfa_enrollment_pending,
            ..
        } = *session;
        // Under "always" an unenrolled session may only enroll: every other page redirects
        // there until the server has affirmatively said two-factor is off.
        if mfa_enrollment_pending
            && mfa_enabled != Some(false)
            && let Some(user) = logged_in_user
            && !matches!(switch, AppRoute::RegisterMfa { user_id } if is_self(user_id))
        {
            return html! {
                <Redirect to={AppRoute::RegisterMfa { user_id: user.to_owned() }} />
            };
        }
        match switch {
            AppRoute::Login => html! {
                <LoginForm on_logged_in={link.callback(Msg::Login)} password_reset_enabled={password_reset_enabled.unwrap_or(false)} mfa_enabled={mfa_enabled != Some(false)}/>
            },
            AppRoute::CreateUser => html! {
                <CreateUserForm/>
            },
            AppRoute::Index | AppRoute::ListUsers => {
                html! {
                    <UserTable mfa_enabled={mfa_enabled.unwrap_or(false)} />
                }
            }
            AppRoute::CreateGroup => html! {
                <CreateGroupForm/>
            },
            AppRoute::CreateUserAttribute => html! {
                <CreateUserAttributeForm/>
            },
            AppRoute::CreateGroupAttribute => html! {
                <CreateGroupAttributeForm/>
            },
            AppRoute::ListGroups => {
                html! {
                    <GroupTable />
                }
            }
            AppRoute::ListUserSchema => html! {
                <ListUserSchema />
            },
            AppRoute::ListGroupSchema => html! {
                <ListGroupSchema />
            },
            AppRoute::Federation => html! {
                <Federation />
            },
            AppRoute::GroupDetails { group_id } => html! {
                <GroupDetails group_id={*group_id} is_admin={is_admin} />
            },
            AppRoute::UserDetails { user_id } => html! {
                <UserDetails
                    username={user_id.clone()}
                    is_admin={is_admin}
                    is_self={is_self(user_id)}
                    mfa_enabled={mfa_enabled.unwrap_or(false)}
                    mfa_required={mfa_required} />
            },
            AppRoute::ChangePassword { user_id } => html! {
                <ChangePasswordForm username={user_id.clone()} is_admin={is_admin} mfa_enabled={mfa_enabled != Some(false)} />
            },
            AppRoute::RegisterMfa { user_id } => match mfa_enabled {
                None => html! {},
                Some(true) if is_self(user_id) => html! {
                    <RegisterMfa
                        username={user_id.clone()}
                        enrollment_required={mfa_enrollment_pending}
                        on_enrolled={link.callback(|_| Msg::MfaEnrolled)}
                        on_logged_out={link.callback(|_| Msg::Logout)} />
                },
                // Enrollment is always the caller's own: another user's page goes back.
                Some(_) => html! {
                    <Redirect to={AppRoute::UserDetails { user_id: user_id.clone() }} />
                },
            },
            AppRoute::ResetOwnMfa { user_id } => match mfa_enabled {
                None => html! {},
                Some(true) if !mfa_required && is_self(user_id) => html! {
                    <ResetOwnMfaForm username={user_id.clone()} />
                },
                Some(_) => html! {
                    <Redirect to={AppRoute::UserDetails { user_id: user_id.clone() }} />
                },
            },
            AppRoute::StartResetPassword => match password_reset_enabled {
                Some(true) => html! { <ResetPasswordStep1Form /> },
                Some(false) => {
                    html! { <Redirect to={AppRoute::Login}/> }
                }

                None => html! {},
            },
            AppRoute::FinishResetPassword { token } => match password_reset_enabled {
                Some(true) => html! {
                    <ResetPasswordStep2Form
                        token={token.clone()}
                        mfa_enabled={mfa_enabled.unwrap_or(false)} />
                },
                Some(false) => {
                    html! { <Redirect to={AppRoute::Login}/> }
                }
                None => html! {},
            },
        }
    }

    fn view_footer(&self) -> Html {
        html! {
          <footer class="text-center fixed-bottom text-muted bg-light py-2">
            <div>
              <span>{format!("KLLDAP version {}", env!("CARGO_PKG_VERSION"))}</span>
            </div>
            <div>
              <a href="https://github.com/Aelieth/klldap" class="me-4 text-reset">
                <i class="bi-github"></i>
              </a>
            </div>
            <div>
              <span>{"License "}<a href="https://github.com/Aelieth/klldap/blob/main/LICENSE" class="link-secondary">{"AGPL-3.0"}</a></span>
            </div>
          </footer>
        }
    }

    fn is_admin(&self) -> bool {
        match &self.user_info {
            None => false,
            Some((_, is_admin)) => *is_admin,
        }
    }
}
