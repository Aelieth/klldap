use crate::{
    components::{
        avatar::Avatar,
        form::{
            attribute_input::{ListAttributeInput, SingleAttributeInput},
            static_value::StaticValue,
            submit::Submit,
        },
        kerberos_switch::{KerberosSwitch, prepare_kerberos_update},
        user_details::{Attribute, AttributeSchema, User},
    },
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        form_utils::{AttributeValue, EmailIsRequired, IsAdmin, read_all_form_attributes},
        schema::AttributeType,
    },
};
use anyhow::Result;
use chrono::NaiveDateTime;
use gloo_console::log;
use graphql_client::GraphQLQuery;
use yew::Callback;
use yew::prelude::*;
use yew::virtual_dom::AttrValue;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/update_user.graphql",
    response_derives = "Debug",
    variables_derives = "Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct UpdateUser;

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

pub struct UserDetailsForm {
    common: CommonComponentParts<Self>,
    just_updated: bool,
    user: User,
    form_ref: NodeRef,
    kerberossync_enabled: bool,
    original_kerberossync_enabled: bool,
    show_kerberos_banner: bool,
}

pub enum Msg {
    Update,
    SubmitClicked,
    UserUpdated(Result<update_user::ResponseData>),
    ToggleKerberosSync(bool),
}

#[derive(yew::Properties, Clone, PartialEq)] // Eq removed – Callback<()> does not implement Eq
pub struct Props {
    pub user: User,
    pub user_attributes_schema: Vec<AttributeSchema>,
    pub is_admin: bool,
    pub is_edited_user_admin: bool,
    #[prop_or_default]
    pub on_updated: Option<Callback<()>>,
}

impl CommonComponent<UserDetailsForm> for UserDetailsForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        // All real logic is in the Component impl below.
        // This just satisfies the trait bounds.
        match msg {
            Msg::Update => Ok(true),
            Msg::SubmitClicked => Ok(self.submit_user_update_form(ctx)),
            Msg::UserUpdated(response) => {
                if response.is_ok() {
                    self.show_kerberos_banner = false;
                    self.just_updated = true;
                    self.original_kerberossync_enabled = self.kerberossync_enabled;
                }
                Ok(true)
            }
            Msg::ToggleKerberosSync(value) => {
                self.kerberossync_enabled = value;
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for UserDetailsForm {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let kerberossync_enabled = ctx.props().user.attributes.iter().any(|attr| {
            attr.schema.name.to_lowercase() == "kerberossync" && attr.value == vec!["1"]
        });
        Self {
            common: CommonComponentParts::<Self>::create(),
            just_updated: false,
            user: ctx.props().user.clone(),
            form_ref: NodeRef::default(),
            kerberossync_enabled,
            original_kerberossync_enabled: kerberossync_enabled,
            show_kerberos_banner: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.just_updated = false;
        match msg {
            Msg::Update => true,
            Msg::SubmitClicked => self.submit_user_update_form(ctx),
            Msg::UserUpdated(response) => {
                match response {
                    Ok(_) => {
                        self.just_updated = true;
                        self.show_kerberos_banner = false;
                        self.original_kerberossync_enabled = self.kerberossync_enabled;

                        // OPTIMIZED AVATAR REFRESH:
                        // Immediately notify parent to re-fetch fresh data
                        // This guarantees the new avatar base64 is loaded
                        // and displayed without stale data
                        if let Some(cb) = &ctx.props().on_updated {
                            cb.emit(());
                        }
                    }
                    Err(e) => {
                        self.common.error = Some(e);
                    }
                }
                true
            }
            Msg::ToggleKerberosSync(value) => {
                self.kerberossync_enabled = value;
                self.show_kerberos_banner = value;
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let is_admin = ctx.props().is_admin;

        let can_edit = |a: &AttributeSchema| !a.is_readonly && (is_admin || a.is_editable);

        let is_edited_user_admin = ctx.props().is_edited_user_admin;

        let display_field = |a: &AttributeSchema| {
            if can_edit(a) {
                get_custom_attribute_input(a, &self.user.attributes, is_edited_user_admin)
            } else {
                get_custom_attribute_static(a, &self.user.attributes, &self.user.id)
            }
        };

        let mut all_attrs: Vec<&AttributeSchema> = ctx
            .props()
            .user_attributes_schema
            .iter()
            .filter(|a| a.name != "userid" && a.name != "kerberossync")
            .collect();
        all_attrs.sort_by_key(|a| attribute_priority(&a.name));

        html! {
            <div class="py-3">
            <form class="form" ref={self.form_ref.clone()}>
            <StaticValue label="User ID" id="userId">
            <i>{&self.user.id}</i>
            </StaticValue>

            { all_attrs.iter().map(|&a| display_field(a)).collect::<Vec<_>>() }

            { if is_admin {
                html! {
                    <KerberosSwitch
                    enabled={self.kerberossync_enabled}
                    on_toggle={link.callback(Msg::ToggleKerberosSync)}
                    show_banner={self.show_kerberos_banner}
                    username={Some(self.user.id.clone())}
                    />
                }
            } else { html! {} }}

            <Submit
            text="Save changes"
            disabled={self.common.is_task_running()}
            onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitClicked})} />
            </form>

            { if let Some(e) = &self.common.error {
                html! { <div class="alert alert-danger">{e.to_string()}</div> }
            } else { html! {} }}

            <div hidden={!self.just_updated}>
            <div class="alert alert-success mt-4">{"User successfully updated!"}</div>
            </div>
            </div>
        }
    }
}

impl UserDetailsForm {
    fn submit_user_update_form(&mut self, ctx: &Context<Self>) -> bool {
        let form_values = match read_all_form_attributes(
            ctx.props().user_attributes_schema.iter(),
            &self.form_ref,
            IsAdmin(ctx.props().is_admin),
            EmailIsRequired(!ctx.props().is_edited_user_admin),
        ) {
            Ok(values) => values,
            Err(e) => {
                self.common.error = Some(e);
                return true;
            }
        };

        let base_attributes = &self.user.attributes;
        let empty: Vec<String> = vec![];

        let mut to_insert: Vec<AttributeValue> = vec![];
        let mut to_remove: Vec<String> = vec![];

        for attr in form_values {
            let name_lower = attr.name.to_lowercase();

            // === SKIP kerberossync — we handle it specially below ===
            if name_lower == "kerberossync" {
                continue;
            }

            let old_val = base_attributes
                .iter()
                .find(|b| b.schema.name.to_lowercase() == name_lower);
            let old_values = old_val.map_or(&empty, |v| &v.value);

            let has_changed = old_values != &attr.values;

            if !has_changed {
                continue;
            }

            if name_lower == "avatar"
                && (attr.values.is_empty()
                    || attr.values.first().is_none_or(|s| s.trim().is_empty()))
            {
                to_remove.push(attr.name.clone());
                continue;
            }

            if attr.values.is_empty() {
                to_remove.push(attr.name.clone());
            } else {
                to_insert.push(attr);
            }
        }

        // === KERBEROS LOGIC (centralized in kerberos_switch.rs) ===
        let (kerberos_insert, kerberos_remove) = prepare_kerberos_update(
            self.kerberossync_enabled,
            self.original_kerberossync_enabled,
        );
        to_insert.extend(kerberos_insert);
        to_remove.extend(kerberos_remove);

        let remove_attributes = if to_remove.is_empty() {
            None
        } else {
            Some(to_remove)
        };

        let insert_attributes: Option<Vec<update_user::AttributeValueInput>> =
            if to_insert.is_empty() {
                None
            } else {
                Some(
                    to_insert
                        .into_iter()
                        .map(
                            |AttributeValue { name, values }| update_user::AttributeValueInput {
                                name,
                                value: values,
                            },
                        )
                        .collect(),
                )
            };

        // === Extract displayname (and other special fields) to top-level like create_user does ===
        let mut display_name = None;
        if let Some(dn_attr) = insert_attributes.as_ref().and_then(|attrs| {
            attrs
                .iter()
                .find(|a| a.name.to_lowercase() == "displayname")
        }) {
            display_name = dn_attr.value.first().cloned();
        }

        // === Extract avatar to top-level (special field, like displayName) so backend persists it ===
        // This ensures GetUserDetails returns it in response.user.avatar (for banner) and attributes (for form)
        let mut avatar = None;
        if let Some(av_attr) = insert_attributes.as_ref().and_then(|attrs| {
            attrs
                .iter()
                .find(|a| a.name.to_lowercase() == "avatar" || a.name.to_lowercase() == "jpegphoto")
        }) {
            avatar = av_attr.value.first().cloned();
        }
        // If removing avatar, avatar stays None (clears it); removeAttributes also sent for cleanup

        let user_input = update_user::UpdateUserInput {
            id: self.user.id.clone(),
            email: None,
            display_name,
            first_name: None,
            last_name: None,
            avatar,
            remove_attributes,
            insert_attributes,
        };

        let req = update_user::Variables { user: user_input };
        self.common.call_graphql::<UpdateUser, _>(
            ctx,
            req,
            Msg::UserUpdated,
            "Error trying to update user",
        );
        false
    }
}

fn get_custom_attribute_input(
    attribute_schema: &AttributeSchema,
    user_attributes: &[Attribute],
    is_edited_user_admin: bool,
) -> Html {
    let values = user_attributes
        .iter()
        .find(|a| a.schema.name.to_lowercase() == attribute_schema.name.to_lowercase())
        .map(|attribute| attribute.value.clone())
        .unwrap_or_default();

    let name_lower = attribute_schema.name.to_lowercase();
    let mail_is_required = name_lower == "mail" && !is_edited_user_admin;

    if attribute_schema.is_list {
        html! {
            <ListAttributeInput
            name={attribute_schema.name.clone()}
            attribute_type={attribute_schema.attribute_type}
            values={values}
            required={mail_is_required}
            />
        }
    } else {
        html! {
            <SingleAttributeInput
            name={attribute_schema.name.clone()}
            attribute_type={attribute_schema.attribute_type}
            value={values.first().cloned().unwrap_or_default()}
            required={mail_is_required}
            />
        }
    }
}

fn get_custom_attribute_static(
    attribute_schema: &AttributeSchema,
    user_attributes: &[Attribute],
    user_id: &str,
) -> Html {
    let values = user_attributes
        .iter()
        .find(|a| a.schema.name.to_lowercase() == attribute_schema.name.to_lowercase())
        .map(|attribute| attribute.value.clone())
        .unwrap_or_default();

    if attribute_schema.attribute_type == AttributeType::Avatar {
        let avatar_b64 = values.first().cloned().unwrap_or_default();
        let preview = avatar_b64.chars().take(30).collect::<String>();
        log!(format!(
            "[FORM DEBUG] STATIC Avatar | b64_len={} | preview='{}...' | using GraphQL user={} path",
            avatar_b64.len(),
            preview,
            user_id
        ));

        // Use GraphQL path (same as banner) — reliable
        return html! {
            <StaticValue label={attribute_schema.name.clone()} id={attribute_schema.name.clone()}>
                <Avatar
                    user={Some(AttrValue::from(user_id.to_string()))}
                    width={128}
                    height={128}
                />
            </StaticValue>
        };
    }

    let value_to_str = match attribute_schema.attribute_type {
        AttributeType::String | AttributeType::Integer => |v: String| v,
        AttributeType::DateTime => |v: String| {
            if let Ok(dt) = NaiveDateTime::parse_from_str(&v, "%Y-%m-%d %H:%M:%S%.f") {
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&v) {
                dt.naive_utc().format("%Y-%m-%d %H:%M:%S").to_string()
            } else {
                v
            }
        },
        AttributeType::Avatar => unreachable!("Avatar handled above"),
    };

    html! {
        <StaticValue label={attribute_schema.name.clone()} id={attribute_schema.name.clone()}>
        {values.into_iter().map(|x| html!{<div>{value_to_str(x)}</div>}).collect::<Vec<_>>()}
        </StaticValue>
    }
}
