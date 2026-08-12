use crate::components::fragments::icons::checkmark;
use crate::infra::queries::{GetGroupAttributesSchema, get_group_attributes_schema};
use crate::{
    components::{
        delete_group_attribute::DeleteGroupAttribute,
        fragments::attribute_schema::render_attribute_name,
        router::{AppRoute, Link},
    },
    infra::{
        attributes::resolve_attribute_description,
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::{Error, Result};
use yew::prelude::*;

pub type Attribute =
    get_group_attributes_schema::GetGroupAttributesSchemaSchemaGroupSchemaAttributes;

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub hardcoded: bool,
}

pub struct GroupSchemaTable {
    common: CommonComponentParts<Self>,
    attributes: Option<Vec<Attribute>>,
}

pub enum Msg {
    ListAttributesResponse(Result<get_group_attributes_schema::ResponseData>),
    OnAttributeDeleted(String),
    OnError(Error),
}

impl CommonComponent<GroupSchemaTable> for GroupSchemaTable {
    fn handle_msg(&mut self, _: &Context<Self>, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::ListAttributesResponse(schema) => {
                self.attributes = Some(schema?.schema.group_schema.attributes);
                Ok(true)
            }
            Msg::OnError(e) => Err(e),
            Msg::OnAttributeDeleted(attribute_name) => {
                if let Some(attrs) = &mut self.attributes {
                    attrs.retain(|a| a.name != attribute_name);
                }
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for GroupSchemaTable {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = GroupSchemaTable {
            common: CommonComponentParts::<Self>::create(),
            attributes: None,
        };
        table.common.call_graphql::<GetGroupAttributesSchema, _>(
            ctx,
            get_group_attributes_schema::Variables {},
            Msg::ListAttributesResponse,
            "Error trying to fetch group schema",
        );
        table
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div>
            {self.view_attributes(ctx)}
            {self.view_errors()}
            </div>
        }
    }
}

impl GroupSchemaTable {
    fn view_attributes(&self, ctx: &Context<Self>) -> Html {
        let hardcoded = ctx.props().hardcoded;
        let make_table = |attributes: &Vec<Attribute>| {
            html! {
                <div class="table-responsive">
                <h3>{if hardcoded {"Hardcoded"} else {"User-defined"}}{" attributes"}</h3>
                <table class="table table-hover">
                <thead>
                <tr>
                <th>{"Attribute name"}</th>
                <th>{"Type"}</th>
                <th>{"Visible"}</th>
                {if hardcoded {html!{}} else {html!{<th>{"Delete"}</th>}}}
                </tr>
                </thead>
                <tbody>
                {attributes.iter().map(|u| self.view_attribute(ctx, u)).collect::<Vec<_>>()}
                </tbody>
                </table>
                </div>
            }
        };
        match &self.attributes {
            None => html! {{"Loading..."}},
            Some(attributes) => {
                let mut attributes = attributes.clone();
                attributes.retain(|attribute| attribute.is_hardcoded == ctx.props().hardcoded);
                make_table(&attributes)
            }
        }
    }

    fn view_attribute(&self, ctx: &Context<Self>, attribute: &Attribute) -> Html {
        let desc = resolve_attribute_description(&attribute.name, &attribute.aliases);

        html! {
            <tr key={attribute.name.clone()}>
            <td>
            {render_attribute_name(
                ctx.props().hardcoded,
                                   &desc
            )}
            </td>
            <td>
            {if attribute.is_list {
                format!("List<{}>", attribute.attribute_type)
            } else {
                attribute.attribute_type.to_string()
            }}
            </td>
            <td>{if attribute.is_visible { checkmark() } else {html!{}}}</td>
            {
                if !attribute.is_hardcoded {
                    html!{
                        <td>
                        <DeleteGroupAttribute
                        attribute_name={attribute.name.clone()}
                        on_attribute_deleted={ctx.link().callback(Msg::OnAttributeDeleted)}
                        on_error={ctx.link().callback(Msg::OnError)}/>
                        </td>
                    }
                } else {
                    html!{}
                }
            }
            </tr>
        }
    }

    fn view_errors(&self) -> Html {
        match &self.common.error {
            None => html! {},
            Some(e) => html! {<div>{"Error: "}{e.to_string()}</div>},
        }
    }
}

#[function_component(ListGroupSchema)]
pub fn list_group_schema() -> Html {
    html! {
        <div>
        <GroupSchemaTable hardcoded={true} />
        <GroupSchemaTable hardcoded={false} />
        <Link classes="btn btn-primary" to={AppRoute::CreateGroupAttribute}>
        <i class="bi-plus-circle me-2"></i>
        {"Create an attribute"}
        </Link>
        </div>
    }
}
