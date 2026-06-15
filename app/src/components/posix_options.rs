use crate::infra::common_component::{CommonComponent, CommonComponentParts};
use anyhow::Result;
use graphql_client::GraphQLQuery;
use wasm_bindgen::JsCast;
use yew::prelude::*;

// GraphQL derives
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_posix_config.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetPosixConfig;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/set_posix_config.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct SetPosixConfig;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/reassign_gid_numbers.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReassignGidNumbers;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/reassign_user_uid_numbers.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReassignUserUidNumbers;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/reassign_user_gid_numbers.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReassignUserGidNumbers;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/reassign_user_homedirectories.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReassignUserHomeDirectories;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/reassign_user_loginshells.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReassignUserLoginShells;

#[derive(Properties, PartialEq)]
pub struct PosixOptionsProps {
    pub on_status_update: Callback<String>,
}

pub struct PosixOptions {
    common: CommonComponentParts<Self>,
    user_uidnumber_assign: bool,
    user_uidnumber_start: String,
    user_uidnumber_max: String,
    user_gidnumber_assign: bool,
    user_gidnumber_start: String,
    user_loginshell_assign: bool,
    user_loginshell_default: String,
    user_homedirectory_assign: bool,
    user_homedirectory_prefix: String,
    group_gidnumber_assign: bool,
    group_gidnumber_start: String,
    group_gidnumber_max: String,

    // saved states for button logic and pending-save behavior
    saved_user_uidnumber_assign: bool,
    saved_user_gidnumber_assign: bool,
    saved_user_loginshell_assign: bool,
    saved_user_homedirectory_assign: bool,
    saved_group_gidnumber_assign: bool,

    config_changed: bool,
    loading: bool,
    // Confirmation modal
    pending_reassign: Option<ReassignAction>,
    // local status badge
    status: String,
    status_class: String,
}

#[derive(Clone, PartialEq)]
enum ReassignAction {
    UserUidNumbers,
    UserGidNumbers,
    UserLoginShells,
    UserHomeDirectories,
    GroupGidNumbers,
}

pub enum Msg {
    LoadConfig,
    ConfigResponse(Result<get_posix_config::ResponseData>),
    UpdateUserUidAssign(bool),
    UpdateUserUidStart(String),
    UpdateUserUidMax(String),
    UpdateUserGidAssign(bool),
    UpdateUserGidStart(String),
    UpdateUserLoginShellAssign(bool),
    UpdateUserLoginShellDefault(String),
    UpdateUserHomeAssign(bool),
    UpdateUserHomePrefix(String),
    UpdateGroupGidAssign(bool),
    UpdateGroupGidStart(String),
    UpdateGroupGidMax(String),
    SaveConfig,
    SaveResponse(Result<set_posix_config::ResponseData>),
    ReassignUserUidNumbers,
    ReassignUserGidNumbers,
    ReassignUserLoginShells,
    ReassignUserHomeDirectories,
    ReassignGroupGidNumbers,
    ConfirmReassign,
    CancelReassign,
    ReassignResponse(Result<()>),
}

impl CommonComponent<PosixOptions> for PosixOptions {
    fn handle_msg(&mut self, ctx: &Context<Self>, msg: Self::Message) -> Result<bool> {
        match msg {
            Msg::LoadConfig => {
                let vars = get_posix_config::Variables {};
                self.common.call_graphql::<GetPosixConfig, _>(
                    ctx,
                    vars,
                    Msg::ConfigResponse,
                    "Failed to load POSIX config",
                );
                self.loading = true;
                self.status = "Loading POSIX config...".to_string();
                self.status_class = "bg-info".to_string();
                Ok(false)
            }
            Msg::ConfigResponse(Ok(data)) => {
                let cfg = data.posix_settings;

                self.user_uidnumber_assign = cfg.user_uidnumber_assign;
                self.saved_user_uidnumber_assign = cfg.user_uidnumber_assign;
                self.user_uidnumber_start = if cfg.user_uidnumber_assign {
                    cfg.user_uidnumber_start.to_string()
                } else {
                    "".to_string()
                };
                self.user_uidnumber_max = if cfg.user_uidnumber_assign {
                    cfg.user_uidnumber_max.to_string()
                } else {
                    "".to_string()
                };

                self.user_gidnumber_assign = cfg.user_gidnumber_assign;
                self.saved_user_gidnumber_assign = cfg.user_gidnumber_assign;
                self.user_gidnumber_start = if cfg.user_gidnumber_assign {
                    cfg.user_gidnumber_start.to_string()
                } else {
                    "".to_string()
                };

                self.user_loginshell_assign = cfg.user_loginshell_assign;
                self.saved_user_loginshell_assign = cfg.user_loginshell_assign;
                self.user_loginshell_default = if cfg.user_loginshell_assign {
                    cfg.user_loginshell_default
                } else {
                    "".to_string()
                };

                self.user_homedirectory_assign = cfg.user_homedirectory_assign;
                self.saved_user_homedirectory_assign = cfg.user_homedirectory_assign;
                self.user_homedirectory_prefix = if cfg.user_homedirectory_assign {
                    cfg.user_homedirectory_prefix
                } else {
                    "".to_string()
                };

                self.group_gidnumber_assign = cfg.group_gidnumber_assign;
                self.saved_group_gidnumber_assign = cfg.group_gidnumber_assign;
                self.group_gidnumber_start = if cfg.group_gidnumber_assign {
                    cfg.group_gidnumber_start.to_string()
                } else {
                    "".to_string()
                };
                self.group_gidnumber_max = if cfg.group_gidnumber_assign {
                    cfg.group_gidnumber_max.to_string()
                } else {
                    "".to_string()
                };

                self.loading = false;
                self.config_changed = false;
                self.status = "POSIX config loaded".to_string();
                self.status_class = "bg-success".to_string();
                ctx.props().on_status_update.emit(self.status.clone());
                Ok(true)
            }
            Msg::ConfigResponse(Err(e)) => {
                self.loading = false;
                self.status = format!("POSIX config failure: {}", e);
                self.status_class = "bg-danger".to_string();
                ctx.props().on_status_update.emit(self.status.clone());
                Ok(true)
            }

            // Update handlers
            Msg::UpdateUserUidAssign(v) => {
                self.user_uidnumber_assign = v;
                if !v {
                    self.user_uidnumber_start = "".to_string();
                    self.user_uidnumber_max = "".to_string();
                }
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateUserUidStart(s) => {
                self.user_uidnumber_start = s;
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateUserUidMax(s) => {
                self.user_uidnumber_max = s;
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateUserGidAssign(v) => {
                self.user_gidnumber_assign = v;
                if !v {
                    self.user_gidnumber_start = "".to_string();
                }
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateUserGidStart(s) => {
                self.user_gidnumber_start = s;
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateUserLoginShellAssign(v) => {
                self.user_loginshell_assign = v;
                if !v {
                    self.user_loginshell_default = "".to_string();
                }
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateUserLoginShellDefault(s) => {
                self.user_loginshell_default = s;
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateUserHomeAssign(v) => {
                self.user_homedirectory_assign = v;
                if !v {
                    self.user_homedirectory_prefix = "".to_string();
                }
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateUserHomePrefix(s) => {
                self.user_homedirectory_prefix = s;
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateGroupGidAssign(v) => {
                self.group_gidnumber_assign = v;
                if !v {
                    self.group_gidnumber_start = "".to_string();
                    self.group_gidnumber_max = "".to_string();
                }
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateGroupGidStart(s) => {
                self.group_gidnumber_start = s;
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateGroupGidMax(s) => {
                self.group_gidnumber_max = s;
                self.config_changed = true;
                Ok(true)
            }

            Msg::SaveConfig => {
                let input = set_posix_config::PosixSettingsInput {
                    user_uidnumber_assign: self.user_uidnumber_assign,
                    user_uidnumber_start: self.user_uidnumber_start.parse().unwrap_or(3000),
                    user_uidnumber_max: self.user_uidnumber_max.parse().unwrap_or(60000),
                    user_gidnumber_assign: self.user_gidnumber_assign,
                    user_gidnumber_start: self.user_gidnumber_start.parse().unwrap_or(3000),
                    user_loginshell_assign: self.user_loginshell_assign,
                    user_loginshell_default: self.user_loginshell_default.clone(),
                    user_homedirectory_assign: self.user_homedirectory_assign,
                    user_homedirectory_prefix: self.user_homedirectory_prefix.clone(),
                    group_gidnumber_assign: self.group_gidnumber_assign,
                    group_gidnumber_start: self.group_gidnumber_start.parse().unwrap_or(3000),
                    group_gidnumber_max: self.group_gidnumber_max.parse().unwrap_or(60000),
                };
                let vars = set_posix_config::Variables { input };
                self.common.call_graphql::<SetPosixConfig, _>(
                    ctx,
                    vars,
                    Msg::SaveResponse,
                    "Save POSIX config failure",
                );
                self.status = "Saving...".to_string();
                self.status_class = "bg-info".to_string();
                Ok(false)
            }
            Msg::SaveResponse(Ok(_)) => {
                // sync saved states to current after successful save
                self.saved_user_uidnumber_assign = self.user_uidnumber_assign;
                self.saved_user_gidnumber_assign = self.user_gidnumber_assign;
                self.saved_user_loginshell_assign = self.user_loginshell_assign;
                self.saved_user_homedirectory_assign = self.user_homedirectory_assign;
                self.saved_group_gidnumber_assign = self.group_gidnumber_assign;

                self.config_changed = false;
                self.status = "POSIX config saved".to_string();
                self.status_class = "bg-success".to_string();
                ctx.props().on_status_update.emit(self.status.clone());
                Ok(true)
            }
            Msg::SaveResponse(Err(e)) => {
                self.status = format!("Failed: {}", e);
                self.status_class = "bg-danger".to_string();
                ctx.props().on_status_update.emit(self.status.clone());
                Ok(true)
            }

            // Reassign buttons open the confirmation modal
            Msg::ReassignUserUidNumbers => {
                self.pending_reassign = Some(ReassignAction::UserUidNumbers);
                Ok(true)
            }
            Msg::ReassignUserGidNumbers => {
                self.pending_reassign = Some(ReassignAction::UserGidNumbers);
                Ok(true)
            }
            Msg::ReassignUserLoginShells => {
                self.pending_reassign = Some(ReassignAction::UserLoginShells);
                Ok(true)
            }
            Msg::ReassignUserHomeDirectories => {
                self.pending_reassign = Some(ReassignAction::UserHomeDirectories);
                Ok(true)
            }
            Msg::ReassignGroupGidNumbers => {
                self.pending_reassign = Some(ReassignAction::GroupGidNumbers);
                Ok(true)
            }

            Msg::ConfirmReassign => {
                if let Some(action) = self.pending_reassign.take() {
                    match action {
                        ReassignAction::UserUidNumbers => {
                            let vars = reassign_user_uid_numbers::Variables {};
                            self.common.call_graphql::<ReassignUserUidNumbers, _>(
                                ctx,
                                vars,
                                |r| Msg::ReassignResponse(r.map(|_| ())),
                                "Reassign user uidNumbers failure",
                            );
                        }
                        ReassignAction::UserGidNumbers => {
                            let vars = reassign_user_gid_numbers::Variables {};
                            self.common.call_graphql::<ReassignUserGidNumbers, _>(
                                ctx,
                                vars,
                                |r| Msg::ReassignResponse(r.map(|_| ())),
                                "Reassign user gidNumbers failure",
                            );
                        }
                        ReassignAction::UserLoginShells => {
                            let vars = reassign_user_login_shells::Variables {};
                            self.common.call_graphql::<ReassignUserLoginShells, _>(
                                ctx,
                                vars,
                                |r| Msg::ReassignResponse(r.map(|_| ())),
                                "Reassign user loginShells failure",
                            );
                        }
                        ReassignAction::UserHomeDirectories => {
                            let vars = reassign_user_home_directories::Variables {};
                            self.common.call_graphql::<ReassignUserHomeDirectories, _>(
                                ctx,
                                vars,
                                |r| Msg::ReassignResponse(r.map(|_| ())),
                                "Reassign user homeDirectories failure",
                            );
                        }
                        ReassignAction::GroupGidNumbers => {
                            let vars = reassign_gid_numbers::Variables {};
                            self.common.call_graphql::<ReassignGidNumbers, _>(
                                ctx,
                                vars,
                                |r| Msg::ReassignResponse(r.map(|_| ())),
                                "Reassign group gidNumbers failure",
                            );
                        }
                    }
                    self.status = "Reassigning...".to_string();
                    self.status_class = "bg-info".to_string();
                }
                Ok(false)
            }
            Msg::CancelReassign => {
                self.pending_reassign = None;
                Ok(true)
            }

            Msg::ReassignResponse(Ok(_)) => {
                self.status = "Reassign completed".to_string();
                self.status_class = "bg-success".to_string();
                ctx.props().on_status_update.emit(self.status.clone());
                Ok(true)
            }
            Msg::ReassignResponse(Err(e)) => {
                self.status = format!("Reassign failed: {}", e);
                self.status_class = "bg-danger".to_string();
                ctx.props().on_status_update.emit(self.status.clone());
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for PosixOptions {
    type Message = Msg;
    type Properties = PosixOptionsProps;

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Msg::LoadConfig);
        Self {
            common: CommonComponentParts::<Self>::create(),
            user_uidnumber_assign: false,
            user_uidnumber_start: "3000".to_string(),
            user_uidnumber_max: "60000".to_string(),
            user_gidnumber_assign: false,
            user_gidnumber_start: "3000".to_string(),
            user_loginshell_assign: false,
            user_loginshell_default: "/bin/bash".to_string(),
            user_homedirectory_assign: false,
            user_homedirectory_prefix: "/home".to_string(),
            group_gidnumber_assign: false,
            group_gidnumber_start: "3000".to_string(),
            group_gidnumber_max: "60000".to_string(),

            saved_user_uidnumber_assign: false,
            saved_user_gidnumber_assign: false,
            saved_user_loginshell_assign: false,
            saved_user_homedirectory_assign: false,
            saved_group_gidnumber_assign: false,

            config_changed: false,
            loading: true,
            pending_reassign: None,
            status: "Loading POSIX config...".to_string(),
            status_class: "bg-info".to_string(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.handle_msg(ctx, msg).unwrap_or(false)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

        // Callbacks
        let on_user_uid_assign = link.callback(|e: Event| {
            let checked = e
                .target()
                .unwrap()
                .dyn_into::<web_sys::HtmlInputElement>()
                .unwrap()
                .checked();
            Msg::UpdateUserUidAssign(checked)
        });
        let on_user_uid_start = link.callback(|e: InputEvent| {
            Msg::UpdateUserUidStart(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_user_uid_max = link.callback(|e: InputEvent| {
            Msg::UpdateUserUidMax(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_user_gid_assign = link.callback(|e: Event| {
            let checked = e
                .target()
                .unwrap()
                .dyn_into::<web_sys::HtmlInputElement>()
                .unwrap()
                .checked();
            Msg::UpdateUserGidAssign(checked)
        });
        let on_user_gid_start = link.callback(|e: InputEvent| {
            Msg::UpdateUserGidStart(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_user_loginshell_assign = link.callback(|e: Event| {
            let checked = e
                .target()
                .unwrap()
                .dyn_into::<web_sys::HtmlInputElement>()
                .unwrap()
                .checked();
            Msg::UpdateUserLoginShellAssign(checked)
        });
        let on_user_loginshell_default = link.callback(|e: InputEvent| {
            Msg::UpdateUserLoginShellDefault(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_user_home_assign = link.callback(|e: Event| {
            let checked = e
                .target()
                .unwrap()
                .dyn_into::<web_sys::HtmlInputElement>()
                .unwrap()
                .checked();
            Msg::UpdateUserHomeAssign(checked)
        });
        let on_user_home_prefix = link.callback(|e: InputEvent| {
            Msg::UpdateUserHomePrefix(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_group_gid_assign = link.callback(|e: Event| {
            let checked = e
                .target()
                .unwrap()
                .dyn_into::<web_sys::HtmlInputElement>()
                .unwrap()
                .checked();
            Msg::UpdateGroupGidAssign(checked)
        });
        let on_group_gid_start = link.callback(|e: InputEvent| {
            Msg::UpdateGroupGidStart(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_group_gid_max = link.callback(|e: InputEvent| {
            Msg::UpdateGroupGidMax(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });

        let on_reassign_user_uid = link.callback(|_| Msg::ReassignUserUidNumbers);
        let on_reassign_user_gid = link.callback(|_| Msg::ReassignUserGidNumbers);
        let on_reassign_user_loginshell = link.callback(|_| Msg::ReassignUserLoginShells);
        let on_reassign_user_home = link.callback(|_| Msg::ReassignUserHomeDirectories);
        let on_reassign_group_gid = link.callback(|_| Msg::ReassignGroupGidNumbers);

        let on_save = link.callback(|_| Msg::SaveConfig);

        let save_disabled = self.loading || !self.config_changed;

        // per-button logic (label + enabled after save)
        let uid_button_text = if self.user_uidnumber_assign {
            "Reassign"
        } else {
            "Remove"
        };
        let uid_button_disabled =
            self.loading || (self.user_uidnumber_assign != self.saved_user_uidnumber_assign);

        let gid_user_button_text = if self.user_gidnumber_assign {
            "Reassign"
        } else {
            "Remove"
        };
        let gid_user_button_disabled =
            self.loading || (self.user_gidnumber_assign != self.saved_user_gidnumber_assign);

        let loginshell_button_text = if self.user_loginshell_assign {
            "Reassign"
        } else {
            "Remove"
        };
        let loginshell_button_disabled =
            self.loading || (self.user_loginshell_assign != self.saved_user_loginshell_assign);

        let home_button_text = if self.user_homedirectory_assign {
            "Reassign"
        } else {
            "Remove"
        };
        let home_button_disabled = self.loading
            || (self.user_homedirectory_assign != self.saved_user_homedirectory_assign);

        let gid_group_button_text = if self.group_gidnumber_assign {
            "Reassign"
        } else {
            "Remove"
        };
        let gid_group_button_disabled =
            self.loading || (self.group_gidnumber_assign != self.saved_group_gidnumber_assign);

        html! {
            <div class="row">
                <div class="col-12">
                    <div class="card mb-4">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5>{ "POSIX Attributes" }</h5>
                            <span class={format!("badge {}", self.status_class)}>{ &self.status }</span>
                        </div>
                        <div class="card-body">

                            <h6 class="text-muted mb-3 text-decoration-underline">{ "Users Section" }</h6>
                            <div class="mb-4">
                                <div class="d-flex align-items-center mb-3">
                                    <div class="form-check flex-grow-1">
                                        <input type="checkbox" class="form-check-input" checked={self.user_uidnumber_assign} onchange={on_user_uid_assign} disabled={self.loading} />
                                        <label class="form-check-label">{ "Auto-assign uidNumber range" }</label>
                                    </div>
                                    <input type="number" class="form-control form-control-sm mx-2" style="width: 90px;" value={self.user_uidnumber_start.clone()} oninput={on_user_uid_start} min="3000" max="60000" disabled={self.loading || !self.user_uidnumber_assign} />
                                    <span class="mx-1 text-muted small">{ "to" }</span>
                                    <input type="number" class="form-control form-control-sm mx-2" style="width: 90px;" value={self.user_uidnumber_max.clone()} oninput={on_user_uid_max} min="3000" max="60000" disabled={self.loading || !self.user_uidnumber_assign} />
                                    <button onclick={on_reassign_user_uid} class="btn btn-warning btn-sm ms-2" disabled={uid_button_disabled}>{ uid_button_text }</button>
                                </div>

                                <div class="d-flex align-items-center mb-3">
                                    <div class="form-check flex-grow-1">
                                        <input type="checkbox" class="form-check-input" checked={self.user_gidnumber_assign} onchange={on_user_gid_assign} disabled={self.loading} />
                                        <label class="form-check-label">{ "Auto-assign gidNumber" }</label>
                                    </div>
                                    <input type="number" class="form-control form-control-sm mx-2" style="width: 90px;" value={self.user_gidnumber_start.clone()} oninput={on_user_gid_start} min="3000" max="60000" disabled={self.loading || !self.user_gidnumber_assign} />
                                    <button onclick={on_reassign_user_gid} class="btn btn-warning btn-sm ms-2" disabled={gid_user_button_disabled}>{ gid_user_button_text }</button>
                                </div>

                                <div class="d-flex align-items-center mb-3">
                                    <div class="form-check flex-grow-1">
                                        <input type="checkbox" class="form-check-input" checked={self.user_loginshell_assign} onchange={on_user_loginshell_assign} disabled={self.loading} />
                                        <label class="form-check-label">{ "Auto-assign loginShell" }</label>
                                    </div>
                                    <input type="text" class="form-control form-control-sm mx-2" style="width: 160px;" value={self.user_loginshell_default.clone()} oninput={on_user_loginshell_default} disabled={self.loading || !self.user_loginshell_assign} />
                                    <button onclick={on_reassign_user_loginshell} class="btn btn-warning btn-sm ms-2" disabled={loginshell_button_disabled}>{ loginshell_button_text }</button>
                                </div>

                                <div class="d-flex align-items-center mb-3">
                                    <div class="form-check flex-grow-1">
                                        <input type="checkbox" class="form-check-input" checked={self.user_homedirectory_assign} onchange={on_user_home_assign} disabled={self.loading} />
                                        <label class="form-check-label">{ "Auto-assign homeDirectory" }</label>
                                    </div>
                                    <input type="text" class="form-control form-control-sm mx-2" style="width: 160px;" value={self.user_homedirectory_prefix.clone()} oninput={on_user_home_prefix} disabled={self.loading || !self.user_homedirectory_assign} />
                                    <button onclick={on_reassign_user_home} class="btn btn-warning btn-sm ms-2" disabled={home_button_disabled}>{ home_button_text }</button>
                                </div>
                            </div>

                            <h6 class="text-muted mb-3 text-decoration-underline">{ "Groups Section" }</h6>
                            <div class="mb-4">
                                <div class="d-flex align-items-center">
                                    <div class="form-check flex-grow-1">
                                        <input type="checkbox" class="form-check-input" checked={self.group_gidnumber_assign} onchange={on_group_gid_assign} disabled={self.loading} />
                                        <label class="form-check-label">{ "Auto-assign gidNumber range" }</label>
                                    </div>
                                    <input type="number" class="form-control form-control-sm mx-2" style="width: 90px;" value={self.group_gidnumber_start.clone()} oninput={on_group_gid_start} min="3000" max="60000" disabled={self.loading || !self.group_gidnumber_assign} />
                                    <span class="mx-1 text-muted small">{ "to" }</span>
                                    <input type="number" class="form-control form-control-sm mx-2" style="width: 90px;" value={self.group_gidnumber_max.clone()} oninput={on_group_gid_max} min="3000" max="60000" disabled={self.loading || !self.group_gidnumber_assign} />
                                    <button onclick={on_reassign_group_gid} class="btn btn-warning btn-sm ms-2" disabled={gid_group_button_disabled}>{ gid_group_button_text }</button>
                                </div>
                            </div>

                        </div>

                        <div class="card-footer text-end pe-3">
                            <button onclick={on_save} class="btn btn-success px-4" disabled={save_disabled}>
                                { "Save POSIX Config" }
                            </button>
                        </div>

                        // Confirmation modal
                        { if let Some(action) = &self.pending_reassign {
                            let message = match action {
                                ReassignAction::UserUidNumbers => "This will reassign all user uidNumbers using the configured range.".to_string(),
                                ReassignAction::UserGidNumbers => "This will reassign all user gidNumbers using the configured value.".to_string(),
                                ReassignAction::UserLoginShells => "This will reassign the loginShell to every user.".to_string(),
                                ReassignAction::UserHomeDirectories => "This will reassign the homeDirectory to every user.".to_string(),
                                ReassignAction::GroupGidNumbers => "This will reassign all group gidNumbers using the configured range.".to_string(),
                            };
                            html! {
                                <div class="modal fade show" style="display: block; background: rgba(0,0,0,0.5);" tabindex="-1">
                                    <div class="modal-dialog">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title">{ "Confirm Reassign" }</h5>
                                                <button type="button" class="btn-close" onclick={link.callback(|_| Msg::CancelReassign)}></button>
                                            </div>
                                            <div class="modal-body">
                                                <p>{ message }</p>
                                                <p class="text-danger fw-bold">{ "This action affects the entire database and cannot be undone." }</p>
                                            </div>
                                            <div class="modal-footer">
                                                <button type="button" class="btn btn-secondary" onclick={link.callback(|_| Msg::CancelReassign)}>{ "Cancel" }</button>
                                                <button type="button" class="btn btn-warning" onclick={link.callback(|_| Msg::ConfirmReassign)}>{ "Confirm Reassign" }</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            }
                        } else { html! {} }}
                    </div>
                </div>
            </div>
        }
    }
}
