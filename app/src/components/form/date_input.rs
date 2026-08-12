use crate::infra::form_utils::input_value;
use chrono::{DateTime, NaiveDateTime, Utc};
use std::str::FromStr;
use yew::{Event, Properties, function_component, html, use_state, virtual_dom::AttrValue};

#[derive(Properties, PartialEq)]
pub struct DateTimeInputProps {
    pub name: AttrValue,
    pub value: Option<String>,
}

#[function_component(DateTimeInput)]
pub fn date_time_input(props: &DateTimeInputProps) -> Html {
    let value = use_state(|| {
        props
            .value
            .as_ref()
            .and_then(|x| DateTime::<Utc>::from_str(x).ok())
    });

    html! {
        <div class="input-group">
            <input
                type="hidden"
                name={props.name.clone()}
                value={value.as_ref().map(|v: &DateTime<Utc>| v.to_rfc3339())} />
            <input
                type="datetime-local"
                step="1"
                class="form-control"
                value={value.as_ref().map(|v: &DateTime<Utc>| v.naive_utc().to_string())}
                onchange={move |e: Event| {
                    let string_val = input_value(&e);
                    value.set(
                        NaiveDateTime::from_str(&string_val)
                            .ok()
                            .map(|x| DateTime::from_naive_utc_and_offset(x, Utc))
                    )
                }} />
            <span class="input-group-text">{"UTC"}</span>
        </div>
    }
}
