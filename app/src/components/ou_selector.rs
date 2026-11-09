use crate::infra::{
    form_utils::select_value,
    ou_policy::{ROOT_OU, flatten_ou_rows, ou_display_name},
};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct OuSelectorProps {
    pub ous: Vec<String>,
    pub current_ou: String,
    pub on_ou_changed: Callback<String>,
    #[prop_or(true)]
    pub show_all: bool,
    #[prop_or_default]
    pub domain: Option<String>,
}

#[function_component(OuSelector)]
pub fn ou_selector(props: &OuSelectorProps) -> Html {
    let mut display_ous = vec![];

    if props.show_all {
        display_ous.push((
            ou_display_name(ROOT_OU, props.domain.as_deref()),
            ROOT_OU.to_string(),
        ));
    }

    // The filter sentinel stays "All": drop the shared helper's root row and
    // keep the one pushed above, whose value the tables compare against.
    for row in flatten_ou_rows(&props.ous).into_iter().skip(1) {
        display_ous.push((format!("{}{}", row.prefix, row.leaf), row.key));
    }

    html! {
        <select
            class="form-select"
            onchange={props.on_ou_changed.reform(|e: Event| {

                select_value(&e)
            })}>
            { for display_ous.iter().map(|(display, value)| html! {
                <option value={value.clone()} selected={value == &props.current_ou}>
                    {display}
                </option>
            }) }
        </select>
    }
}
