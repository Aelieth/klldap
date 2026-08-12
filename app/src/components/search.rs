use crate::infra::form_utils::{input_value, select_value};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct Props {
    pub search_field: String,
    pub search_term: String,
    pub on_search_field_changed: Callback<String>,
    pub on_search_term_changed: Callback<String>,
    pub search_fields: Vec<String>,
}

#[function_component(SearchControls)]
pub fn search_controls(props: &Props) -> Html {
    html! {
        <>
            <div class="col-md-2 ms-auto">
                <select class="form-select" onchange={props.on_search_field_changed.reform(|e: Event| {
                    select_value(&e)
                })}>
                    { for props.search_fields.iter().map(|f| html! {
                        <option value={f.clone()} selected={f == &props.search_field}>{f}</option>
                    }) }
                </select>
            </div>
            <div class="col-md-4">
                <input type="text" class="form-control" placeholder="Type to search..." value={props.search_term.clone()}
                oninput={props.on_search_term_changed.reform(|e: InputEvent| {
                    input_value(&e)
                })} />
            </div>
        </>
    }
}
