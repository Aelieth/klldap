use crate::infra::common_component::{CommonComponent, CommonComponentParts};
use anyhow::Result;
use graphql_client::GraphQLQuery;
use wasm_bindgen::JsCast;
use yew::events::InputEvent;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/export_keytab.graphql",
    response_derives = "Debug"
)]
pub struct ExportKeytabForKeycloak;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/keycloak_suggested_config.graphql",
    response_derives = "Debug"
)]
pub struct KeycloakSuggestedConfig;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/keycloak_config.graphql",
    response_derives = "Debug"
)]
pub struct KeycloakConfig;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/test_keycloak_connection.graphql",
    response_derives = "Debug"
)]
pub struct TestKeycloakConnection;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/save_keycloak_config.graphql",
    response_derives = "Debug"
)]
pub struct SaveKeycloakConfig;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/push_realm_to_keycloak.graphql",
    response_derives = "Debug"
)]
pub struct PushRealmToKeycloak;

pub struct KeycloakSettings {
    common: CommonComponentParts<Self>,
    keycloak_url: String,
    realm: String,
    admin_username: String,
    admin_password: String,
    suggested_url: String,
    suggested_realm: String,
    suggested_admin_username: String,
    connection_status: String,
    status_class: String,
    loaded_from_toml: bool,
    connection_tested_successfully: bool,

    new_realm_name: String,
    lldap_url: String,
    sync_username: String,
    sync_password: String,
    enable_hsts: bool,
    enable_brute_force: bool,
}

pub enum Msg {
    LoadConfigs,
    TestConnection,
    SaveSettings,
    UpdateKeycloakUrl(String),
    UpdateRealm(String),
    UpdateAdminUsername(String),
    UpdateAdminPassword(String),
    UpdateNewRealmName(String),
    UpdateLldapUrl(String),
    UpdateSyncUsername(String),
    UpdateSyncPassword(String),
    ToggleHsts,
    ToggleBruteForce,
    ExportKeytab,
    PushRealmToKeycloak,
    ConfigResponse(Result<keycloak_config::ResponseData>),
    SuggestedResponse(Result<keycloak_suggested_config::ResponseData>),
    TestResponse(Result<test_keycloak_connection::ResponseData>),
    SaveResponse(Result<save_keycloak_config::ResponseData>),
    ExportResponse(Result<export_keytab_for_keycloak::ResponseData>),
    PushResponse(Result<push_realm_to_keycloak::ResponseData>),
}

impl CommonComponent<KeycloakSettings> for KeycloakSettings {
    fn handle_msg(&mut self, ctx: &Context<Self>, msg: Self::Message) -> Result<bool> {
        match msg {
            Msg::LoadConfigs => {
                let vars = keycloak_config::Variables {};
                self.common.call_graphql::<KeycloakConfig, _>(
                    ctx,
                    vars,
                    Msg::ConfigResponse,
                    "Failed to load saved config",
                );
                let vars2 = keycloak_suggested_config::Variables {};
                self.common.call_graphql::<KeycloakSuggestedConfig, _>(
                    ctx,
                    vars2,
                    Msg::SuggestedResponse,
                    "Failed to load suggested config",
                );
                self.connection_status = "Standby: Test to Enable New Realm Settings".to_string();
                self.status_class = "bg-info".to_string();
                Ok(true)
            }
            Msg::TestConnection => {
                let variables = test_keycloak_connection::Variables {
                    input: test_keycloak_connection::TestKeycloakConnectionInput {
                        url: self.keycloak_url.clone(),
                        realm: self.realm.clone(),
                        admin_user: self.admin_username.clone(),
                        admin_pass: self.admin_password.clone(),
                    },
                };
                self.common.call_graphql::<TestKeycloakConnection, _>(
                    ctx,
                    variables,
                    Msg::TestResponse,
                    "Error testing connection",
                );
                self.connection_status = "Testing...".to_string();
                self.status_class = "bg-info".to_string();
                Ok(true)
            }
            Msg::SaveSettings => {
                let variables = save_keycloak_config::Variables {
                    input: save_keycloak_config::SaveKeycloakConfigInput {
                        url: self.keycloak_url.clone(),
                        realm: self.realm.clone(),
                        admin_user: self.admin_username.clone(),
                    },
                };
                self.common.call_graphql::<SaveKeycloakConfig, _>(
                    ctx,
                    variables,
                    Msg::SaveResponse,
                    "Error saving config",
                );
                self.connection_status = "Saving...".to_string();
                self.status_class = "bg-info".to_string();
                Ok(true)
            }
            Msg::UpdateKeycloakUrl(s) => {
                self.keycloak_url = s;
                self.loaded_from_toml = true;
                Ok(true)
            }
            Msg::UpdateRealm(s) => {
                self.realm = s;
                self.loaded_from_toml = true;
                Ok(true)
            }
            Msg::UpdateAdminUsername(s) => {
                self.admin_username = s;
                self.loaded_from_toml = true;
                Ok(true)
            }
            Msg::UpdateAdminPassword(s) => {
                self.admin_password = s;
                Ok(true)
            }
            Msg::UpdateNewRealmName(s) => {
                self.new_realm_name = s;
                Ok(true)
            }
            Msg::UpdateLldapUrl(s) => {
                self.lldap_url = s;
                Ok(true)
            }
            Msg::UpdateSyncUsername(s) => {
                self.sync_username = s;
                Ok(true)
            }
            Msg::UpdateSyncPassword(s) => {
                self.sync_password = s;
                Ok(true)
            }
            Msg::ToggleHsts => {
                self.enable_hsts = !self.enable_hsts;
                Ok(true)
            }
            Msg::ToggleBruteForce => {
                self.enable_brute_force = !self.enable_brute_force;
                Ok(true)
            }
            Msg::ExportKeytab => {
                let variables = export_keytab_for_keycloak::Variables {
                    hostname: "keycloak".to_string(),
                };
                self.common.call_graphql::<ExportKeytabForKeycloak, _>(
                    ctx,
                    variables,
                    Msg::ExportResponse,
                    "Error exporting keytab",
                );
                self.connection_status = "Exporting keytab...".to_string();
                self.status_class = "bg-info".to_string();
                Ok(true)
            }
            Msg::PushRealmToKeycloak => {
                let variables = push_realm_to_keycloak::Variables {
                    input: push_realm_to_keycloak::PushRealmToKeycloakInput {
                        url: self.keycloak_url.clone(),
                        realm: self.new_realm_name.clone(),
                        admin_user: self.admin_username.clone(),
                        admin_pass: self.admin_password.clone(),
                        lldap_url: self.lldap_url.clone(),
                        sync_username: self.sync_username.clone(),
                        sync_password: self.sync_password.clone(),
                        enable_hsts: self.enable_hsts,
                        enable_brute_force: self.enable_brute_force,
                    },
                };
                self.common.call_graphql::<PushRealmToKeycloak, _>(
                    ctx,
                    variables,
                    Msg::PushResponse,
                    "Error pushing realm",
                );
                self.connection_status = "Pushing realm to Keycloak...".to_string();
                self.status_class = "bg-info".to_string();
                Ok(true)
            }
            Msg::ConfigResponse(Ok(data)) => {
                let cfg = data.keycloak_config;
                if !self.loaded_from_toml {
                    self.keycloak_url = cfg.url;
                    self.realm = cfg.realm;
                    self.admin_username = cfg.admin_user;
                    self.loaded_from_toml = true;
                }
                Ok(true)
            }
            Msg::SuggestedResponse(Ok(data)) => {
                let s = data.keycloak_suggested_config;
                self.suggested_url = s.url;
                self.suggested_realm = s.realm.clone();
                self.suggested_admin_username = s.admin_username;
                if self.new_realm_name.is_empty() {
                    self.new_realm_name = s.realm.clone();
                }
                if self.lldap_url.is_empty() {
                    self.lldap_url = "ldap://lldap:3890".to_string();
                }
                if self.sync_username.is_empty() {
                    self.sync_username = "keycloak".to_string();
                }
                Ok(true)
            }
            Msg::TestResponse(Ok(data)) => {
                self.connection_status = data.test_keycloak_connection.message.clone();
                self.connection_tested_successfully = data.test_keycloak_connection.ok;
                self.status_class = if data.test_keycloak_connection.ok {
                    "bg-success".to_string()
                } else {
                    "bg-danger".to_string()
                };
                Ok(true)
            }
            Msg::SaveResponse(Ok(data)) => {
                self.connection_status = data.save_keycloak_config.message;
                self.status_class = "bg-success".to_string();
                Ok(true)
            }
            Msg::TestResponse(Err(e))
            | Msg::SaveResponse(Err(e))
            | Msg::SuggestedResponse(Err(e))
            | Msg::ConfigResponse(Err(e)) => {
                self.connection_status = format!("❌ {}", e);
                self.status_class = "bg-danger".to_string();
                Ok(true)
            }
            Msg::PushResponse(Ok(data)) => {
                self.connection_status = data.push_realm_to_keycloak.message;
                self.status_class = "bg-success".to_string();
                Ok(true)
            }
            Msg::PushResponse(Err(e)) => {
                self.connection_status = format!("❌ {}", e);
                self.status_class = "bg-danger".to_string();
                Ok(true)
            }
            Msg::ExportResponse(Ok(data)) => {
                let resp = data.export_keytab_for_keycloak;
                self.connection_status = if resp.ok {
                    format!("Keytab saved to {}", resp.path)
                } else {
                    format!("❌ {}", resp.error_msg)
                };
                self.status_class = if resp.ok {
                    "bg-success".to_string()
                } else {
                    "bg-danger".to_string()
                };
                Ok(true)
            }
            Msg::ExportResponse(Err(e)) => {
                self.connection_status = format!("❌ {}", e);
                self.status_class = "bg-danger".to_string();
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for KeycloakSettings {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Msg::LoadConfigs);
        Self {
            common: CommonComponentParts::<Self>::create(),
            keycloak_url: "".to_string(),
            realm: "".to_string(),
            admin_username: "admin".to_string(),
            admin_password: "".to_string(),
            suggested_url: "".to_string(),
            suggested_realm: "".to_string(),
            suggested_admin_username: "".to_string(),
            connection_status: "Loading...".to_string(),
            status_class: "bg-info".to_string(),
            loaded_from_toml: false,
            connection_tested_successfully: false,

            new_realm_name: "".to_string(),
            lldap_url: "ldap://lldap:3890".to_string(),
            sync_username: "keycloak".to_string(),
            sync_password: "".to_string(),
            enable_hsts: false,
            enable_brute_force: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.handle_msg(ctx, msg).unwrap_or(false)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let on_test = ctx.link().callback(|_| Msg::TestConnection);
        let on_save = ctx.link().callback(|_| Msg::SaveSettings);
        let on_export = ctx.link().callback(|_| Msg::ExportKeytab);
        let on_push = ctx.link().callback(|_| Msg::PushRealmToKeycloak);

        let on_keycloak_url = ctx.link().callback(|e: InputEvent| {
            Msg::UpdateKeycloakUrl(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_realm = ctx.link().callback(|e: InputEvent| {
            Msg::UpdateRealm(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_admin_username = ctx.link().callback(|e: InputEvent| {
            Msg::UpdateAdminUsername(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_admin_password = ctx.link().callback(|e: InputEvent| {
            Msg::UpdateAdminPassword(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });

        let on_new_realm_name = ctx.link().callback(|e: InputEvent| {
            Msg::UpdateNewRealmName(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_lldap_url = ctx.link().callback(|e: InputEvent| {
            Msg::UpdateLldapUrl(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_sync_username = ctx.link().callback(|e: InputEvent| {
            Msg::UpdateSyncUsername(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });
        let on_sync_password = ctx.link().callback(|e: InputEvent| {
            Msg::UpdateSyncPassword(
                e.target()
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value(),
            )
        });

        let on_hsts = ctx.link().callback(|_| Msg::ToggleHsts);
        let on_brute = ctx.link().callback(|_| Msg::ToggleBruteForce);

        let push_enabled = self.connection_tested_successfully && !self.sync_password.is_empty();

        html! {
            <div class="row">
                <div class="col-12">
                    <div class="card mb-4">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5>{ "Keycloak Federation" }</h5>
                            <span class={format!("badge {}", self.status_class)}>{ &self.connection_status }</span>
                        </div>
                        <form class="card-body" onsubmit={Callback::from(|e: web_sys::FocusEvent| {
                            e.prevent_default();
                        })}>
                            <div class="row">
                                // LEFT COLUMN — Connection Settings
                                <div class="col-md-6 border-end border-secondary pe-4">
                                    <h6 class="text-muted mb-3 text-decoration-underline">{ "Keycloak Connection Settings" }</h6>

                                    <div class="d-flex align-items-center mb-3">
                                        <label class="form-label me-3" style="min-width: 140px;">{ "Keycloak URL" }</label>
                                        <input type="url" class="form-control flex-grow-1" value={self.keycloak_url.clone()} oninput={on_keycloak_url} />
                                    </div>

                                    <div class="d-flex align-items-center mb-3">
                                        <label class="form-label me-3" style="min-width: 140px;">{ "Realm" }</label>
                                        <input type="text" class="form-control flex-grow-1" value={self.realm.clone()} oninput={on_realm} />
                                    </div>

                                    <div class="d-flex align-items-center mb-3">
                                        <label class="form-label me-3" style="min-width: 140px;">{ "Admin Username" }</label>
                                        <input type="text" class="form-control flex-grow-1" value={self.admin_username.clone()} oninput={on_admin_username} />
                                    </div>

                                    <div class="d-flex align-items-center mb-3">
                                        <label class="form-label me-3" style="min-width: 140px;">{ "Admin Password" }</label>
                                        <input type="password" class="form-control flex-grow-1" value={self.admin_password.clone()} oninput={on_admin_password} placeholder="LLDAP_KEYCLOAK_ADMIN_PASS" />
                                    </div>

                                    <div class="text-end">
                                        <button onclick={on_test} class="btn btn-primary me-2">{ "Test Settings" }</button>
                                        <button onclick={on_save} class="btn btn-success">{ "Save Changes" }</button>
                                    </div>
                                </div>

                                // RIGHT COLUMN — New Realm Settings
                                <div class="col-md-6 ps-4">
                                    <h6 class="text-muted mb-3 text-decoration-underline">{ "New Realm Settings" }</h6>

                                    <div class={if self.connection_tested_successfully { "" } else { "opacity-50 pe-none" }}>
                                        <div class="d-flex align-items-center mb-3">
                                            <label class="form-label me-3" style="min-width: 140px;">{ "Realm Name" }</label>
                                            <input type="text" class="form-control flex-grow-1" value={self.new_realm_name.clone()} oninput={on_new_realm_name} />
                                        </div>

                                        <div class="d-flex align-items-center mb-3">
                                            <label class="form-label me-3" style="min-width: 140px;">{ "LLDAP URL" }</label>
                                            <input type="text" class="form-control flex-grow-1" value={self.lldap_url.clone()} oninput={on_lldap_url} />
                                        </div>

                                        <div class="d-flex align-items-center mb-3">
                                            <label class="form-label me-3" style="min-width: 140px;">{ "Sync Username" }</label>
                                            <input type="text" class="form-control flex-grow-1" value={self.sync_username.clone()} oninput={on_sync_username} />
                                        </div>

                                        <div class="d-flex align-items-center mb-3">
                                            <label class="form-label me-3" style="min-width: 140px;">{ "Sync Password" } <span class="text-danger">{ "*" }</span></label>
                                            <input type="password" class="form-control flex-grow-1" value={self.sync_password.clone()} oninput={on_sync_password} placeholder="REQUIRED - used for bind DN" />
                                        </div>

                                        // === Buttons now share the same line as Enable HSTS ===
                                        <div class="d-flex justify-content-between align-items-center mb-2">
                                            <div class="form-check">
                                                <input type="checkbox" class="form-check-input" checked={self.enable_hsts} onchange={on_hsts} />
                                                <label class="form-check-label">{ "Enable HSTS" }</label>
                                            </div>

                                            <div>
                                                <button onclick={on_export} class="btn btn-primary me-2">{ "Export keytab" }</button>
                                                <button onclick={on_push} class={if push_enabled { "btn btn-danger" } else { "btn btn-secondary disabled" }} disabled={!push_enabled}>
                                                    { "Push To Keycloak" }
                                                </button>
                                            </div>
                                        </div>

                                        // Brute Force stays on its own line below
                                        <div class="form-check mb-3">
                                            <input type="checkbox" class="form-check-input" checked={self.enable_brute_force} onchange={on_brute} />
                                            <label class="form-check-label">{ "Enable Brute Force Protection" }</label>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        }
    }
}
