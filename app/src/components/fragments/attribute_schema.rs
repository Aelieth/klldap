use crate::infra::attributes::AttributeDescription;
use lldap_validation::attributes::{ALLOWED_CHARACTERS_DESCRIPTION, validate_attribute_name};
use yew::{Html, html};

fn get_friendly_name(name: &str) -> String {
    match name {
        "uidnumber" => "uidnumber - POSIX UID".to_string(),
        "gidnumber" => "gidnumber - POSIX GID".to_string(),
        _ => name.to_string(),
    }
}

fn render_attribute_aliases(attribute_description: &AttributeDescription) -> Html {
    if attribute_description.aliases.is_empty() {
        html! {}
    } else {
        html! {
          <>
          <br/>
          <small class="text-muted">
          {"Aliases: "}
          {attribute_description.aliases.join(", ")}
          </small>
          </>
        }
    }
}

fn render_attribute_validation_warnings(attribute_name: &str) -> Html {
    match validate_attribute_name(attribute_name) {
        Ok(()) => html! {},
        Err(_) => {
            html! {
              <>
              <br/>
              <small class="text-warning">
              {"Warning: This attribute uses one or more invalid characters "}
              {"("}{ALLOWED_CHARACTERS_DESCRIPTION}{"). "}
              {"Some clients may not support it."}
              </small>
              </>
            }
        }
    }
}

pub fn render_attribute_name(
    hardcoded: bool,
    attribute_description: &AttributeDescription,
) -> Html {
    let friendly = get_friendly_name(attribute_description.attribute_name);
    html! {
      <>
      {friendly}
      {if hardcoded { render_attribute_aliases(attribute_description) } else { html!{} }}
      {render_attribute_validation_warnings(attribute_description.attribute_name)}
      </>
    }
}
