use crate::{
    components::{
        form::{
            attribute_input::{ListAttributeInput, SingleAttributeInput},
            field::Field,
            submit::Submit,
        },
        ou_selector::OuSelector,
        router::AppRoute,
    },
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        form_utils::{
            AttributeValue, EmailIsRequired, GraphQlAttributeSchema, IsAdmin,
            read_all_form_attributes,
        },
        schema::AttributeType,
    },
};
use anyhow::{Result, ensure};
use gloo_console::log;
use graphql_client::GraphQLQuery;
use list_ous_query::ResponseData as OusResponseData;
use validator_derive::Validate;
use yew::prelude::*;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_group_attributes_schema.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql",
    extern_enums("AttributeType")
)]
pub struct GetGroupAttributesSchema;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_ous.graphql",
    response_derives = "Debug, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListOusQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_posix_config.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetPosixConfig;

pub type Attribute =
    get_group_attributes_schema::GetGroupAttributesSchemaSchemaGroupSchemaAttributes;

impl From<&Attribute> for GraphQlAttributeSchema {
    fn from(attr: &Attribute) -> Self {
        Self {
            name: attr.name.clone(),
            is_list: attr.is_list,
            is_readonly: attr.is_readonly,
            is_editable: false,
        }
    }
}

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_group.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateGroup;

pub struct CreateGroupForm {
    common: CommonComponentParts<Self>,
    form: yew_form::Form<CreateGroupModel>,
    attributes_schema: Option<Vec<Attribute>>,
    form_ref: NodeRef,
    ous: Vec<String>,
    selected_ou: String,
    // POSIX auto-assign flags
    posix_config_loaded: bool,
    group_gidnumber_assign: bool,
}

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct CreateGroupModel {
    #[validate(length(min = 1, message = "Display name is required"))]
    display_name: String,
}

pub enum Msg {
    Update,
    ListAttributesResponse(Result<get_group_attributes_schema::ResponseData>),
    ListUserOusResponse(Result<OusResponseData>),
    PosixConfigResponse(Result<get_posix_config::ResponseData>),
    SubmitForm,
    CreateGroupResponse(Result<create_group::ResponseData>),
    OuChanged(String),
}

impl CommonComponent<CreateGroupForm> for CreateGroupForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::ListAttributesResponse(schema) => {
                self.attributes_schema = Some(schema?.schema.group_schema.attributes);
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
            Msg::PosixConfigResponse(Ok(data)) => {
                let cfg = data.posix_settings;
                self.group_gidnumber_assign = cfg.group_gidnumber_assign;
                self.posix_config_loaded = true;
                Ok(true)
            }
            Msg::PosixConfigResponse(Err(_)) => {
                self.posix_config_loaded = true;
                Ok(true)
            }
            Msg::SubmitForm => {
                ensure!(self.form.validate(), "Check the form for errors");

                let all_values = read_all_form_attributes(
                    self.attributes_schema.iter().flatten(),
                    &self.form_ref,
                    IsAdmin(true),
                    EmailIsRequired(false),
                )?;

                let mut attributes: Vec<create_group::AttributeValueInput> = all_values
                    .into_iter()
                    .filter(|a| !a.values.is_empty())
                    .map(
                        |AttributeValue { name, values }| create_group::AttributeValueInput {
                            name,
                            value: values,
                        },
                    )
                    .collect();

                // Always inject selected OU
                attributes.push(create_group::AttributeValueInput {
                    name: "ou".to_string(),
                    value: vec![self.selected_ou.clone()],
                });

                let model = self.form.model();
                let req = create_group::Variables {
                    group: create_group::CreateGroupInput {
                        display_name: model.display_name,
                        attributes: Some(attributes),
                    },
                };
                self.common.call_graphql::<CreateGroup, _>(
                    ctx,
                    req,
                    Msg::CreateGroupResponse,
                    "Error trying to create group",
                );
                Ok(true)
            }
            Msg::CreateGroupResponse(response) => {
                let data = response?;
                log!(format!(
                    "Created group '{}'",
                    data.create_group.display_name
                ));
                ctx.link().history().unwrap().push(AppRoute::ListGroups);
                Ok(true)
            }
            Msg::OuChanged(ou) => {
                self.selected_ou = ou;
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for CreateGroupForm {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let mut component = Self {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::<CreateGroupModel>::new(CreateGroupModel::default()),
            attributes_schema: None,
            form_ref: NodeRef::default(),
            ous: vec![],
            selected_ou: "groups".to_string(),
            posix_config_loaded: false,
            group_gidnumber_assign: false,
        };

        component
            .common
            .call_graphql::<GetGroupAttributesSchema, _>(
                ctx,
                get_group_attributes_schema::Variables {},
                Msg::ListAttributesResponse,
                "Error trying to fetch group schema",
            );

        component.common.call_graphql::<ListOusQuery, _>(
            ctx,
            list_ous_query::Variables {},
            Msg::ListUserOusResponse,
            "Error trying to fetch OUs",
        );

        component
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        if self.attributes_schema.is_none() || !self.posix_config_loaded {
            html! { <div>{"Loading schema and POSIX config..."}</div> }
        } else {
            html! {
                <div class="row justify-content-center">
                <form class="form py-3" style="max-width: 636px" ref={self.form_ref.clone()}>
                <div class="row mb-3">
                <h5 class="fw-bold">{"Create a group"}</h5>
                </div>

                <Field<CreateGroupModel>
                form={&self.form}
                required=true
                label="Display name"
                field_name="display_name"
                oninput={link.callback(|_| Msg::Update)} />

                <div class="mb-3 row">
                <label class="form-label col-4 col-form-label">{"Organizational Unit :"}</label>
                <div class="col-8">
                <OuSelector
                ous={self.ous.clone()}
                current_ou={self.selected_ou.clone()}
                on_ou_changed={link.callback(Msg::OuChanged)}
                show_all={false} />
                </div>
                </div>

                {
                    self.attributes_schema
                    .iter()
                    .flatten()
                    .filter(|a| !a.is_readonly && a.name != "displayname" && a.name != "display_name" && a.name != "ou")
                    .map(|a| get_custom_attribute_input(a, self.group_gidnumber_assign))
                    .collect::<Vec<_>>()
                }

                <Submit
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitForm})} />
                </form>

                { if let Some(e) = &self.common.error {
                    html! {
                        <div class="alert alert-danger">
                        {e.to_string() }
                        </div>
                    }
                } else { html! {} }}
                </div>
            }
        }
    }
}

fn get_custom_attribute_input(attribute_schema: &Attribute, group_gidnumber_assign: bool) -> Html {
    let name_lower = attribute_schema.name.to_lowercase();
    let auto_assign = if name_lower == "gidnumber" || name_lower == "gid_number" {
        group_gidnumber_assign
    } else {
        false
    };

    if attribute_schema.is_list {
        html! {
            <ListAttributeInput
            name={attribute_schema.name.clone()}
            attribute_type={attribute_schema.attribute_type}
            auto_assign={auto_assign}
            />
        }
    } else {
        html! {
            <SingleAttributeInput
            name={attribute_schema.name.clone()}
            attribute_type={attribute_schema.attribute_type}
            auto_assign={auto_assign}
            />
        }
    }
}
