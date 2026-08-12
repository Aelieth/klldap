use crate::{
    components::form::{date_input::DateTimeInput, file_input::AvatarFileInput},
    infra::{schema::AttributeType, tooltip::Tooltip},
};
use web_sys::{Element, FocusEvent, HtmlInputElement};
use yew::{
    Callback, Component, Context, Event, Html, Properties, TargetCast, function_component, html,
    use_effect_with_deps, use_node_ref, use_state, virtual_dom::AttrValue,
};

#[derive(Properties, PartialEq)]
struct AttributeInputProps {
    name: AttrValue,
    attribute_type: AttributeType,
    #[prop_or(None)]
    value: Option<String>,
    #[prop_or(false)]
    auto_assign: bool,
}

#[function_component(AttributeInput)]
fn attribute_input(props: &AttributeInputProps) -> Html {
    let current_value = use_state(|| {
        if props.auto_assign
            && props
                .value
                .as_ref()
                .is_none_or(|v| v.is_empty() || *v == "Auto-assign")
        {
            "Auto-assign".to_string()
        } else {
            props.value.clone().unwrap_or_default()
        }
    });

    // ROBUST AVATAR GUARD (Improved)
    // Force AvatarFileInput for any avatar field.
    // Matches on both type and common field names (case-insensitive).
    // Survives EAV + Kerberos schema changes.
    let name_lower = props.name.to_lowercase();
    if props.attribute_type == AttributeType::Avatar
        || name_lower == "avatar"
        || name_lower == "jpegphoto"
    {
        return html! {
            <AvatarFileInput name={props.name.clone()} value={props.value.clone()} />
        };
    }

    let is_auto_assign = *current_value == "Auto-assign";
    let input_type = if is_auto_assign {
        "text"
    } else {
        match props.attribute_type {
            AttributeType::String => "text",
            AttributeType::Integer => "number",
            AttributeType::DateTime => {
                return html! {
                    <DateTimeInput name={props.name.clone()} value={props.value.clone()} />
                };
            }
            // This arm is unreachable because of the if-guard above, but Rust requires it for exhaustiveness
            AttributeType::Avatar => unreachable!("Avatar already handled by guard above"),
        }
    };

    let onchange = {
        let current_value = current_value.clone();
        Callback::from(move |e: Event| {
            let input: HtmlInputElement = e.target_unchecked_into();
            current_value.set(input.value());
        })
    };

    let onfocus = {
        let current_value = current_value.clone();
        Callback::from(move |_: FocusEvent| {
            if *current_value == "Auto-assign" {
                current_value.set("".to_string());
            }
        })
    };

    let input_class = if is_auto_assign {
        "form-control text-muted fst-italic"
    } else {
        "form-control"
    };

    html! {
        <input
            type={input_type}
            name={props.name.clone()}
            class={input_class}
            value={(*current_value).clone()}
            onchange={onchange}
            onfocus={onfocus}
            title={if is_auto_assign { "Auto-assigned by POSIX config if left unchanged" } else { "" }} />
    }
}

#[derive(Properties, PartialEq)]
struct AttributeLabelProps {
    pub name: String,
    #[prop_or(false)]
    pub required: bool,
}
#[function_component(AttributeLabel)]
fn attribute_label(props: &AttributeLabelProps) -> Html {
    let tooltip_ref = use_node_ref();

    use_effect_with_deps(
        move |tooltip_ref| {
            Tooltip::new(
                tooltip_ref
                    .cast::<Element>()
                    .expect("Tooltip element should exist"),
            );
            || {}
        },
        tooltip_ref.clone(),
    );

    html! {
        <label for={props.name.clone()}
            class="form-label col-4 col-form-label"
            >
            {format!("{}{}", props.name[0..1].to_uppercase(), props.name[1..].replace('_', " "))}
            {if props.required { html!{<span class="text-danger">{"*"}</span>} } else { html!{} }}
            {":"}
            <button
                class="btn btn-sm btn-link"
                type="button"
                data-bs-placement="right"
                title={props.name.clone()}
                ref={tooltip_ref}>
                <i class="bi bi-info-circle" aria-label="Info" />
            </button>
        </label>
    }
}

#[derive(Properties, PartialEq)]
pub struct SingleAttributeInputProps {
    pub name: String,
    pub(crate) attribute_type: AttributeType,
    #[prop_or(None)]
    pub value: Option<String>,
    #[prop_or(false)]
    pub required: bool,
    #[prop_or(false)]
    pub auto_assign: bool,
}

#[function_component(SingleAttributeInput)]
pub fn single_attribute_input(props: &SingleAttributeInputProps) -> Html {
    html! {
        <div class="row mb-3">
            <AttributeLabel name={props.name.clone()} required={props.required} />
            <div class="col-8">
            <AttributeInput
                attribute_type={props.attribute_type}
                name={props.name.clone()}
                value={props.value.clone()}
                auto_assign={props.auto_assign} />
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct ListAttributeInputProps {
    pub name: String,
    pub(crate) attribute_type: AttributeType,
    #[prop_or(vec!())]
    pub values: Vec<String>,
    #[prop_or(false)]
    pub required: bool,
    #[prop_or(false)]
    pub auto_assign: bool,
}

pub enum ListAttributeInputMsg {
    Remove(usize),
    Append,
}

pub struct ListAttributeInput {
    indices: Vec<usize>,
    next_index: usize,
    values: Vec<String>,
}
impl Component for ListAttributeInput {
    type Message = ListAttributeInputMsg;
    type Properties = ListAttributeInputProps;

    fn create(ctx: &Context<Self>) -> Self {
        let values = ctx.props().values.clone();
        Self {
            indices: (0..values.len()).collect(),
            next_index: values.len(),
            values,
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            ListAttributeInputMsg::Remove(removed) => {
                self.indices.retain_mut(|x| *x != removed);
            }
            ListAttributeInputMsg::Append => {
                self.indices.push(self.next_index);
                self.next_index += 1;
            }
        };
        true
    }

    fn changed(&mut self, ctx: &Context<Self>) -> bool {
        if ctx.props().values != self.values {
            self.values.clone_from(&ctx.props().values);
            self.indices = (0..self.values.len()).collect();
            self.next_index = self.values.len();
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let props = &ctx.props();
        let link = &ctx.link();
        html! {
            <div class="row mb-3">
                <AttributeLabel name={props.name.clone()} required={props.required} />
                <div class="col-8">
                {self.indices.iter().map(|&i| html! {
                    <div class="input-group mb-2" key={i}>
                    <AttributeInput
                        attribute_type={props.attribute_type}
                        name={props.name.clone()}
                        value={props.values.get(i).cloned().unwrap_or_default()}
                        auto_assign={props.auto_assign} />
                    <button
                        class="btn btn-danger"
                        type="button"
                        onclick={link.callback(move |_| ListAttributeInputMsg::Remove(i))}>
                        <i class="bi-x-circle-fill" aria-label="Remove value" />
                    </button>
                    </div>
                }).collect::<Html>()}
                <button
                    class="btn btn-secondary"
                    type="button"
                    onclick={link.callback(|_| ListAttributeInputMsg::Append)}>
                    <i class="bi-plus-circle me-2"></i>
                    {"Add value"}
                </button>
                </div>
            </div>
        }
    }
}
