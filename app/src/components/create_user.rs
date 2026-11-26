use crate::components::fragments::attribute_order::attribute_priority;
use crate::infra::opaque::{
    begin_registration, finish_registration, new_user_password_at_the_floor, registration_started,
    signed_in_key,
};
use crate::infra::queries::{
    GetPosixConfig, GetUserAttributesSchema, ListOusQuery, get_posix_config,
    get_user_attributes_schema, list_ous_query,
};
use crate::{
    components::{
        form::{
            attribute_input::{ListAttributeInput, SingleAttributeInput},
            field::Field,
            submit::Submit,
        },
        kerberos_switch::{KerberosSwitch, sync_locked},
        ou_selector::OuSelector,
        router::AppRoute,
    },
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
        encrypt::{KeyNotBound, SealTo, check_kerberos_envelope},
        form_utils::{EmailIsRequired, GraphQlAttributeSchema, IsAdmin, read_all_form_attributes},
    },
};
use anyhow::{Result, anyhow, bail};
use graphql_client::GraphQLQuery;
use lldap_auth::{opaque, registration, zeroize::Zeroizing};
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

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_kerberos_info.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetKerberosInfo;

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
    user_id: Option<String>,
    opaque_data: Option<opaque::client::registration::ClientRegistration>,
    kerberossync_enabled: bool,
    kerberos_enabled: Option<bool>,
    sync_locked: bool,
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
    #[validate(custom(function = "new_user_password_at_the_floor"))]
    password: String,
    #[validate(must_match(other = "password", message = "Passwords must match"))]
    confirm_password: String,
}

pub enum Msg {
    Update,
    ListAttributesResponse(Result<get_user_attributes_schema::ResponseData>),
    ListOusResponse(Result<list_ous_query::ResponseData>),
    PosixConfigResponse(Result<get_posix_config::ResponseData>),
    KerberosInfoResponse(Result<get_kerberos_info::ResponseData>),
    SubmitForm,
    CreateUserResponse(Result<create_user::ResponseData>),
    SuccessfulCreation,
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStart>>),
    RegistrationFinishResponse(Result<()>),
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
            Msg::KerberosInfoResponse(info) => {
                let info = info.map(|data| data.kerberos_info);
                self.sync_locked = info.as_ref().is_ok_and(|info| sync_locked(&info.state));
                let enabled = info.map(|info| info.enabled);
                self.kerberos_enabled = Some(enabled.unwrap_or(true));
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

                let model = self.form.model();
                let sync = sent_sync(
                    self.kerberos_enabled,
                    self.sync_locked,
                    self.kerberossync_enabled,
                );
                if sync == Some(true) {
                    check_kerberos_envelope(&model.password)?;
                    // Before createUser: a page that holds no bound key could not set the password.
                    if signed_in_key().is_none() {
                        return Err(KeyNotBound.into());
                    }
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
                        _ => attributes.push(GraphQLAttributeValue {
                            name: attr.name,
                            value: attr.values,
                        }),
                    }
                }
                let attributes = create_attributes(attributes, &self.selected_ou, sync);

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
                let password = Zeroizing::new(self.form.model().password);
                let (state, req) = begin_registration(&user_id, &password)
                    .map_err(|e| created_without_password(&user_id, &e.to_string()))?;
                self.opaque_data = Some(state);
                self.common.call_backend(
                    ctx,
                    HostService::register_start(req),
                    Msg::RegistrationStartResponse,
                );
                Ok(false)
            }
            Msg::RegistrationStartResponse(res) => {
                let user_id = self
                    .user_id
                    .as_deref()
                    .context("Missing registration data")?;
                let res = registration_started(res)
                    .map_err(|e| created_without_password(user_id, &e.to_string()))?;
                let state = self
                    .opaque_data
                    .take()
                    .context("Missing registration data")?;
                let (password, bound) =
                    (Zeroizing::new(self.form.model().password), signed_in_key());
                let seal_to = SealTo::Bound(bound.as_deref());
                let req = finish_registration(state, user_id, &password, *res, seal_to)
                    .map_err(|e| created_without_password(user_id, &format!("{e:#}")))?;
                self.common.call_backend(
                    ctx,
                    HostService::register_finish(req),
                    Msg::RegistrationFinishResponse,
                );
                Ok(false)
            }
            Msg::RegistrationFinishResponse(response) => {
                let user_id = self
                    .user_id
                    .as_deref()
                    .context("Missing registration data")?;
                response.map_err(|e| password_may_be_unset(user_id, &format!("{e:#}")))?;
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
            user_id: None,
            opaque_data: None,
            kerberossync_enabled: true,
            kerberos_enabled: None,
            sync_locked: false,
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
            .filter(|_| self.posix_config_loaded && self.kerberos_enabled.is_some())
        else {
            return html! { <div>{"Loading schema and POSIX config..."}</div> };
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

                { if self.kerberos_enabled == Some(true) {
                    html! {
                        <KerberosSwitch
                        enabled={self.kerberossync_enabled && !self.sync_locked}
                        on_toggle={link.callback(Msg::ToggleKerberosSync)}
                        show_banner={false}
                        locked={self.sync_locked}
                        />
                    }
                } else { html! {} }}

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

            self.common.call_graphql::<GetKerberosInfo, _>(
                ctx,
                get_kerberos_info::Variables {},
                Msg::KerberosInfoResponse,
                "Error trying to fetch the Kerberos configuration",
            );
        }
    }
}

fn created_without_password(user_id: &str, cause: &str) -> anyhow::Error {
    anyhow!("{cause}. User {user_id} was created without a password; set one from the user's page")
}

fn password_may_be_unset(user_id: &str, cause: &str) -> anyhow::Error {
    anyhow!(
        "Failed to set new password: {cause}. User {user_id} was created, and its password may \
         not have been set; set one from the user's page"
    )
}

/// A locked switch shows Off, and a user is created without sync.
fn sent_sync(kerberos_enabled: Option<bool>, locked: bool, switch: bool) -> Option<bool> {
    (kerberos_enabled != Some(false)).then_some(switch && !locked)
}

fn create_attributes(
    form: Vec<GraphQLAttributeValue>,
    ou: &str,
    sync: Option<bool>,
) -> Vec<GraphQLAttributeValue> {
    let mut attributes: Vec<_> = form
        .into_iter()
        .filter(|attr| !attr.value.is_empty() && attr.name != "kerberossync")
        .collect();
    attributes.push(GraphQLAttributeValue {
        name: "ou".to_string(),
        value: vec![ou.to_owned()],
    });
    attributes.extend(sync.map(|on| GraphQLAttributeValue {
        name: "kerberossync".to_string(),
        value: vec![if on { "1" } else { "0" }.to_string()],
    }));
    attributes
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::opaque::finish_refusal;

    #[test]
    fn test_the_page_says_a_user_was_created_without_a_password_and_names_n_only_for_the_minimum() {
        const WITHOUT: &str =
            "User bob was created without a password; set one from the user's page";
        let refused_start = |failure: &str| {
            let refused = registration_started::<()>(Err(anyhow!("{failure}")));
            refused.unwrap_err().to_string()
        };
        let rows = [
            (
                refused_start(
                    "Could not start registration: [400 Bad Request]: Bad request: `the password \
                     policy could not be read; try again`",
                ),
                "the password policy could not be read; try again",
            ),
            (
                refused_start("Could not start registration: [500 Internal Server Error]: down"),
                "Could not initiate registration",
            ),
            (
                finish_refusal("Eleven-11ch", Some(12)).unwrap(),
                "Invalid password. Min length: 12",
            ),
            (
                finish_refusal("Eleven-11ch\0", Some(12)).unwrap(),
                "the password must not contain a NUL character (U+0000)",
            ),
        ];
        for (cause, shown) in rows {
            assert_eq!(
                created_without_password("bob", &cause).to_string(),
                format!("{shown}. {WITHOUT}"),
                "{cause}"
            );
        }
    }

    #[test]
    fn test_a_refused_finish_says_the_user_was_created_and_its_password_may_not_be_set() {
        let cause = "Could not finish registration: [400 Bad Request]: Bad request: `refused`";
        assert_eq!(
            password_may_be_unset("bob", cause).to_string(),
            "Failed to set new password: Could not finish registration: [400 Bad Request]: Bad \
             request: `refused`. User bob was created, and its password may not have been set; \
             set one from the user's page"
        );
    }

    #[test]
    fn test_the_request_carries_kerberossync_only_where_kerberos_runs() {
        let form = || {
            let attribute = |name: &str, value: &[&str]| GraphQLAttributeValue {
                name: name.to_owned(),
                value: value.iter().map(|v| (*v).to_owned()).collect(),
            };
            vec![
                attribute("uidnumber", &["1001"]),
                attribute("kerberossync", &["1"]),
                attribute("empty", &[]),
            ]
        };
        let rows = [
            (Some(true), false, true, Some("1")),
            (Some(true), false, false, Some("0")),
            (Some(false), false, true, None),
            (Some(false), false, false, None),
            (None, false, true, Some("1")),
            (Some(true), true, true, Some("0")),
        ];
        for (kerberos, locked, switch, sent) in rows {
            let sync = sent_sync(kerberos, locked, switch);
            let attributes = create_attributes(form(), "people", sync);
            let got: Vec<_> = attributes
                .iter()
                .map(|a| (a.name.as_str(), a.value.join(",")))
                .collect();
            let mut want = vec![
                ("uidnumber", "1001".to_owned()),
                ("ou", "people".to_owned()),
            ];
            want.extend(sent.map(|value| ("kerberossync", value.to_owned())));
            assert_eq!(
                got, want,
                "Kerberos {kerberos:?}, locked {locked}, switch {switch}"
            );
        }
    }
}
