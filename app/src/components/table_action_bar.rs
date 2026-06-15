use crate::components::{
    change_ou::{ChangeOu, OuChangeKind},
    router::{AppRoute, Link},
    search::SearchControls,
};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct TableActionBarProps {
    pub create_route: AppRoute,
    pub create_label: String,
    pub create_icon: String,
    pub kind: OuChangeKind,
    pub ous: Vec<String>,
    pub on_ou_changed: Callback<String>,
    pub on_error: Callback<anyhow::Error>,
    pub search_field: String,
    pub search_term: String,
    pub search_fields: Vec<String>,
    pub on_search_field_changed: Callback<String>,
    pub on_search_term_changed: Callback<String>,
}

#[function_component(TableActionBar)]
pub fn table_action_bar(props: &TableActionBarProps) -> Html {
    let change_ou_html = html! {
        <ChangeOu
            kind={props.kind.clone()}
            ous={props.ous.clone()}
            on_ou_changed={props.on_ou_changed.clone()}
            on_error={props.on_error.clone()} />
    };

    html! {
        <div class="row g-3 align-items-end mb-3">
            <div class="col-auto">
                <Link classes="btn btn-primary" to={props.create_route.clone()}>
                    <i class={props.create_icon.clone()}></i>
                    { " " }
                    { &props.create_label }
                </Link>
            </div>
            <div class="col-auto">
                { change_ou_html }
            </div>
            <SearchControls
                search_field={props.search_field.clone()}
                search_term={props.search_term.clone()}
                on_search_field_changed={props.on_search_field_changed.clone()}
                on_search_term_changed={props.on_search_term_changed.clone()}
                search_fields={props.search_fields.clone()}
            />
        </div>
    }
}
