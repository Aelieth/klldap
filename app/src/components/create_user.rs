use crate::{
    components::{
        form::{
            attribute_input::{ListAttributeInput, SingleAttributeInput},
            field::Field,
            submit::Submit,
        },
        kerberos_switch::KerberosSwitch,
        ou_selector::OuSelector,
        router::AppRoute,
    },
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
        encrypt::encrypt_password,
        form_utils::{EmailIsRequired, GraphQlAttributeSchema, IsAdmin, read_all_form_attributes},
        schema::AttributeType,
    },
};
use anyhow::{Result, bail};
use gloo_console::log;
use graphql_client::GraphQLQuery;
use lldap_auth::{opaque, registration};
use validator_derive::Validate;
use yew::Context as YewContext;
use yew::prelude::*;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

fn attribute_priority(name: &str) -> (i32, String) {
    let priorities = vec![
        "firstname",
        "lastname",
        "displayname",
        "mail",
        "avatar",
        "uidnumber",
        "gidnumber",
        "homedirectory",
        "loginshell",
    ];
    let index = priorities
        .iter()
        .position(|&p| p == name)
        .map(|i| i as i32)
        .unwrap_or(100);
    (index, name.to_lowercase())
}

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

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_user.graphql",
    response_derives = "Debug,Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateUser;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_posix_config.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetPosixConfig;

use create_user::AttributeValueInput as GraphQLAttributeValue;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_attributes_schema.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql",
    extern_enums("AttributeType")
)]
pub struct GetUserAttributesSchema;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_ous.graphql",
    response_derives = "Debug, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListOusQuery;

pub type Attribute = get_user_attributes_schema::GetUserAttributesSchemaSchemaUserSchemaAttributes;

impl From<&Attribute> for GraphQlAttributeSchema {
    fn from(attr: &Attribute) -> Self {
        Self {
            name: attr.name.clone(),
            is_list: attr.is_list,
            is_readonly: attr.is_readonly,
            is_editable: attr.is_editable,
        }
    }
}

pub struct CreateUserForm {
    common: CommonComponentParts<Self>,
    form: yew_form::Form<CreateUserModel>,
    attributes_schema: Option<Vec<Attribute>>,
    form_ref: NodeRef,
    fetched_schema: bool,
    encrypted_password: Option<String>,
    user_id: Option<String>,
    opaque_data: Option<opaque::client::registration::ClientRegistration>,
    kerberos_info: Option<get_kerberos_info::GetKerberosInfoKerberosInfo>,
    kerberossync_enabled: bool,
    selected_ou: String,
    ous: Vec<String>,
    // POSIX auto-assign flags
    posix_config_loaded: bool,
    user_uidnumber_assign: bool,
    user_gidnumber_assign: bool,
    user_loginshell_assign: bool,
    user_homedirectory_assign: bool,
    group_gidnumber_assign: bool,
}

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct CreateUserModel {
    #[validate(length(min = 1, message = "Username is required"))]
    username: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    password: String,
    #[validate(must_match(other = "password", message = "Passwords must match"))]
    confirm_password: String,
}

pub enum Msg {
    Update,
    ListAttributesResponse(Result<get_user_attributes_schema::ResponseData>),
    ListUserOusResponse(Result<list_ous_query::ResponseData>),
    KerberosInfoResponse(Result<get_kerberos_info::ResponseData>),
    PosixConfigResponse(Result<get_posix_config::ResponseData>),
    SubmitForm,
    CreateUserResponse(Result<create_user::ResponseData>),
    SuccessfulCreation,
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStartResponse>>),
    RegistrationFinishResponse(Result<()>),
    SyncKerberosResponse(Result<sync_kerberos_password::ResponseData>),
    ToggleKerberosSync(bool),
    OuChanged(String),
}

impl CommonComponent<CreateUserForm> for CreateUserForm {
    fn handle_msg(
        &mut self,
        ctx: &YewContext<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        use anyhow::Context;
        match msg {
            Msg::Update => Ok(true),
            Msg::ListAttributesResponse(schema) => {
                self.attributes_schema = Some(schema?.schema.user_schema.attributes);
                self.common.call_graphql::<GetKerberosInfo, _>(
                    ctx,
                    get_kerberos_info::Variables {},
                    Msg::KerberosInfoResponse,
                    "Error trying to fetch Kerberos info",
                );
                self.common.call_graphql::<GetPosixConfig, _>(
                    ctx,
                    get_posix_config::Variables {},
                    Msg::PosixConfigResponse,
                    "Error trying to fetch POSIX config",
                );
                Ok(true)
            }
            Msg::ListUserOusResponse(ous) => {
                self.ous = ous?.list_ous;
                Ok(true)
            }
            Msg::KerberosInfoResponse(res) => {
                self.kerberos_info = Some(res?.kerberos_info);
                Ok(true)
            }
            Msg::PosixConfigResponse(Ok(data)) => {
                let cfg = data.posix_settings;
                self.user_uidnumber_assign = cfg.user_uidnumber_assign;
                self.user_gidnumber_assign = cfg.user_gidnumber_assign;
                self.user_loginshell_assign = cfg.user_loginshell_assign;
                self.user_homedirectory_assign = cfg.user_homedirectory_assign;
                self.group_gidnumber_assign = cfg.group_gidnumber_assign;
                self.posix_config_loaded = true;
                Ok(true)
            }
            Msg::PosixConfigResponse(Err(_)) => {
                // Default to no auto-assign on error
                self.posix_config_loaded = true;
                Ok(true)
            }
            Msg::ToggleKerberosSync(enabled) => {
                self.kerberossync_enabled = enabled;
                Ok(true)
            }
            Msg::OuChanged(ou) => {
                self.selected_ou = ou;
                Ok(true)
            }
            Msg::SubmitForm => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }

                self.encrypted_password = None;
                let model = self.form.model();
                let new_password = model.password.clone();

                if let Some(info) = &self.kerberos_info {
                    if let Some(ref pub_key_der_base64) = info.public_key_der_base64 {
                        match encrypt_password(pub_key_der_base64, &new_password) {
                            Ok(encrypted) => {
                                self.encrypted_password = Some(encrypted);
                            }
                            Err(e) => {
                                bail!("Failed to encrypt password for Kerberos sync: {}", e);
                            }
                        }
                    } else {
                        bail!(
                            "Kerberos enabled but no public key available—check backend startup/logs"
                        );
                    }
                }

                let all_values = read_all_form_attributes(
                    self.attributes_schema.iter().flatten(),
                    &self.form_ref,
                    IsAdmin(true),
                    EmailIsRequired(true),
                )?;

                if let Some(avatar_attr) = all_values.iter().find(|a| a.name == "avatar") {
                    let avatar_val = avatar_attr.values.first().cloned().unwrap_or_default();
                    log!(
                        "CREATE_FORM_READER: avatar (bytes) length = {}",
                        avatar_val.len()
                    );
                    if avatar_val.len() > 100 {
                        log!(
                            "CREATE_FORM_READER: avatar base64 starts with: {}",
                            &avatar_val[0..100.min(avatar_val.len())]
                        );
                    } else if !avatar_val.is_empty() {
                        log!(
                            "CREATE_FORM_READER: avatar base64 is short (len={})",
                            avatar_val.len()
                        );
                    }
                }

                let mut attributes = vec![];
                let mut email = None;
                let mut display_name = None;
                let mut first_name = None;
                let mut last_name = None;
                let mut avatar = None;

                for attr in all_values {
                    match attr.name.as_str() {
                        "mail" => {
                            if let Some(v) = attr.values.first() {
                                email = Some(v.clone());
                            }
                        }
                        "displayname" => {
                            if let Some(v) = attr.values.first() {
                                display_name = Some(v.clone());
                            }
                        }
                        "firstname" => {
                            if let Some(v) = attr.values.first() {
                                first_name = Some(v.clone());
                            }
                        }
                        "lastname" => {
                            if let Some(v) = attr.values.first() {
                                last_name = Some(v.clone());
                            }
                        }
                        "avatar" => {
                            if let Some(v) = attr.values.first() {
                                avatar = Some(v.clone());
                            }
                        }
                        _ => {
                            if !attr.values.is_empty() && attr.name != "kerberossync" {
                                attributes.push(GraphQLAttributeValue {
                                    name: attr.name,
                                    value: attr.values,
                                });
                            }
                        }
                    }
                }

                attributes.push(GraphQLAttributeValue {
                    name: "ou".to_string(),
                    value: vec![self.selected_ou.clone()],
                });

                let kerb_value = if self.kerberossync_enabled { "1" } else { "0" };
                attributes.push(GraphQLAttributeValue {
                    name: "kerberossync".to_string(),
                    value: vec![kerb_value.to_string()],
                });

                let user = create_user::CreateUserInput {
                    id: model.username,
                    display_name: display_name,
                    first_name: first_name,
                    last_name: last_name,
                    avatar,
                    email,
                    attributes: Some(attributes),
                };
                let variables = create_user::Variables { user };
                self.common.call_graphql::<CreateUser, _>(
                    ctx,
                    variables,
                    Msg::CreateUserResponse,
                    "Error trying to create user",
                );
                Ok(true)
            }
            Msg::CreateUserResponse(res) => {
                self.user_id = Some(res?.create_user.id);
                let mut rng = rand::rngs::OsRng;
                let registration_start_request = opaque::client::registration::start_registration(
                    self.form.model().password.as_bytes(),
                    &mut rng,
                )
                .context("Could not initiate registration")?;
                let req = registration::ClientRegistrationStartRequest {
                    username: self.user_id.clone().unwrap().into(),
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
                let registration = self.opaque_data.take().expect("Missing registration data");
                let mut rng = rand::rngs::OsRng;
                let registration_finish = opaque::client::registration::finish_registration(
                    registration,
                    self.form.model().password.as_bytes(), // ← added password
                    res.registration_response,
                    &mut rng,
                )
                .context("Error during registration")?;
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
                response?;
                if self.kerberossync_enabled {
                    if let Some(enc_pw) = &self.encrypted_password {
                        let variables = sync_kerberos_password::Variables {
                            user_id: self.user_id.clone().unwrap(),
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
                        self.handle_msg(ctx, Msg::SuccessfulCreation)
                    }
                } else {
                    self.handle_msg(ctx, Msg::SuccessfulCreation)
                }
            }
            Msg::SyncKerberosResponse(response) => {
                response?.sync_kerberos_password;
                self.handle_msg(ctx, Msg::SuccessfulCreation)
            }
            Msg::SuccessfulCreation => {
                ctx.link().history().unwrap().push(AppRoute::ListUsers);
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for CreateUserForm {
    type Message = Msg;
    type Properties = ();

    fn create(_: &YewContext<Self>) -> Self {
        CreateUserForm {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::<CreateUserModel>::new(CreateUserModel::default()),
            attributes_schema: None,
            form_ref: NodeRef::default(),
            fetched_schema: false,
            encrypted_password: None,
            user_id: None,
            opaque_data: None,
            kerberos_info: None,
            kerberossync_enabled: true,
            selected_ou: "people".to_string(),
            ous: vec!["people".to_string()],
            posix_config_loaded: false,
            user_uidnumber_assign: false,
            user_gidnumber_assign: false,
            user_loginshell_assign: false,
            user_homedirectory_assign: false,
            group_gidnumber_assign: false,
        }
    }

    fn update(&mut self, ctx: &YewContext<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &YewContext<Self>) -> Html {
        let link = ctx.link();
        if self.attributes_schema.is_none()
            || self.kerberos_info.is_none()
            || !self.posix_config_loaded
        {
            html! { <div>{"Loading schema, Kerberos info and POSIX config..."}</div> }
        } else {
            let attrs = self.attributes_schema.as_ref().unwrap();

            let should_show = |a: &Attribute| !a.is_readonly && a.name != "kerberossync";

            let mut visible_attrs: Vec<&Attribute> =
                attrs.iter().filter(|a| should_show(a)).collect();
            visible_attrs.sort_by_key(|a| attribute_priority(&a.name));

            html! {
                <div class="row justify-content-center">
                <form class="form py-3" ref={self.form_ref.clone()}>
                <Field<CreateUserModel>
                form={&self.form}
                required=true
                label="User name"
                field_name="username"
                oninput={link.callback(|_| Msg::Update)} />

                { visible_attrs.iter()
                    .map(|&a| get_custom_attribute_input(
                        a,
                        self.user_uidnumber_assign,
                        self.user_gidnumber_assign,
                        self.user_loginshell_assign,
                        self.user_homedirectory_assign
                    ))
                    .collect::<Vec<Html>>() }

                    <KerberosSwitch
                    enabled={self.kerberossync_enabled}
                    on_toggle={link.callback(Msg::ToggleKerberosSync)}
                    show_banner={false}
                    />

                    <div class="mb-3 row">
                    <label class="form-label col-4 col-form-label">{"Organizational Unit :"}
                    <button data-bs-placement="right" title="user_ou" type="button" class="btn btn-sm btn-link" aria-label="User OU Info">
                    <i aria-label="Info" class="bi bi-info-circle"></i>
                    </button>
                    </label>
                    <div class="col-8">
                    <OuSelector
                    ous={self.ous.clone()}
                    current_ou={self.selected_ou.clone()}
                    on_ou_changed={link.callback(Msg::OuChanged)}
                    show_all={false} />
                    </div>
                    </div>

                    <Field<CreateUserModel>
                    form={&self.form}
                    label="Password"
                    field_name="password"
                    input_type="password"
                    autocomplete="new-password"
                    oninput={link.callback(|_| Msg::Update)} />
                    <Field<CreateUserModel>
                    form={&self.form}
                    label="Confirm password"
                    field_name="confirm_password"
                    input_type="password"
                    autocomplete="new-password"
                    oninput={link.callback(|_| Msg::Update)} />

                    <Submit
                    disabled={self.common.is_task_running()}
                    onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitForm})} />
                    </form>

                    { if let Some(e) = &self.common.error {
                        html! { <div class="alert alert-danger">{e.to_string()}</div> }
                    } else { html! {} }}
                    </div>
            }
        }
    }

    fn rendered(&mut self, ctx: &YewContext<Self>, first_render: bool) {
        if first_render && !self.fetched_schema {
            self.common.call_graphql::<GetUserAttributesSchema, _>(
                ctx,
                get_user_attributes_schema::Variables {},
                Msg::ListAttributesResponse,
                "Error trying to fetch user schema",
            );
            self.fetched_schema = true;

            self.common.call_graphql::<ListOusQuery, _>(
                ctx,
                list_ous_query::Variables {},
                Msg::ListUserOusResponse,
                "Error trying to fetch OUs",
            );
        }
    }
}

fn get_custom_attribute_input(
    attribute_schema: &Attribute,
    user_uidnumber_assign: bool,
    user_gidnumber_assign: bool,
    user_loginshell_assign: bool,
    user_homedirectory_assign: bool,
) -> Html {
    let mail_is_required = attribute_schema.name.as_str() == "mail";

    let name_lower = attribute_schema.name.to_lowercase();
    let auto_assign = match name_lower.as_str() {
        "uidnumber" | "uid_number" => user_uidnumber_assign,
        "gidnumber" | "gid_number" => user_gidnumber_assign,
        "loginshell" | "login_shell" => user_loginshell_assign,
        "homedirectory" | "home_directory" => user_homedirectory_assign,
        _ => false,
    };

    if attribute_schema.is_list {
        html! {
            <ListAttributeInput
            name={attribute_schema.name.clone()}
            attribute_type={attribute_schema.attribute_type}
            required={mail_is_required}
            auto_assign={auto_assign}
            />
        }
    } else {
        html! {
            <SingleAttributeInput
            name={attribute_schema.name.clone()}
            attribute_type={attribute_schema.attribute_type}
            required={mail_is_required}
            auto_assign={auto_assign}
            />
        }
    }
}
