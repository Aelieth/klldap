use crate::components::fragments::attribute_order::attribute_priority;
use crate::infra::opaque::{begin_registration, finish_registration};
use crate::infra::queries::{
    GetKerberosInfo, GetPosixConfig, GetUserAttributesSchema, ListOusQuery, SyncKerberosPassword,
    get_kerberos_info, get_posix_config, get_user_attributes_schema, list_ous_query,
    sync_kerberos_password,
};
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
        encrypt::encrypt_kerberos_password,
        form_utils::{EmailIsRequired, GraphQlAttributeSchema, IsAdmin, read_all_form_attributes},
    },
};
use anyhow::{Result, bail};
use graphql_client::GraphQLQuery;
use lldap_auth::{opaque, registration};
use validator_derive::Validate;
use yew::Context as YewContext;
use yew::prelude::*;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_user.graphql",
    response_derives = "Debug,Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateUser;

use create_user::AttributeValueInput as GraphQLAttributeValue;

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
    ListOusResponse(Result<list_ous_query::ResponseData>),
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
            Msg::ListOusResponse(ous) => {
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

                if self.kerberos_info.is_some() {
                    self.encrypted_password = Some(encrypt_kerberos_password(
                        self.kerberos_info
                            .as_ref()
                            .and_then(|i| i.public_key_der_base64.as_deref()),
                        &new_password,
                    )?);
                }

                let all_values = read_all_form_attributes(
                    self.attributes_schema.iter().flatten(),
                    &self.form_ref,
                    IsAdmin(true),
                    EmailIsRequired(true),
                )?;

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
                    display_name,
                    first_name,
                    last_name,
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
                let user_id = res?.create_user.id;
                self.user_id = Some(user_id.clone());
                let (state, req) = begin_registration(&user_id, &self.form.model().password)?;
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
                let state = self
                    .opaque_data
                    .take()
                    .context("Missing registration data")?;
                let req = finish_registration(state, &self.form.model().password, *res)?;
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
        }
    }

    fn update(&mut self, ctx: &YewContext<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &YewContext<Self>) -> Html {
        let link = ctx.link();
        let Some(attrs) = self
            .attributes_schema
            .as_ref()
            .filter(|_| self.kerberos_info.is_some() && self.posix_config_loaded)
        else {
            return html! { <div>{"Loading schema, Kerberos info and POSIX config..."}</div> };
        };

        let should_show = |a: &Attribute| !a.is_readonly && a.name != "kerberossync";

        let mut visible_attrs: Vec<&Attribute> = attrs.iter().filter(|a| should_show(a)).collect();
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

    fn rendered(&mut self, ctx: &YewContext<Self>, first_render: bool) {
        if first_render {
            self.common.call_graphql::<GetUserAttributesSchema, _>(
                ctx,
                get_user_attributes_schema::Variables {},
                Msg::ListAttributesResponse,
                "Error trying to fetch user schema",
            );

            self.common.call_graphql::<ListOusQuery, _>(
                ctx,
                list_ous_query::Variables {},
                Msg::ListOusResponse,
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
