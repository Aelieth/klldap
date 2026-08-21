use anyhow::{Result, anyhow, ensure};
use validator::validate_email;
use wasm_bindgen::JsCast;
use web_sys::{FormData, HtmlFormElement, HtmlInputElement, HtmlSelectElement};
use yew::NodeRef;

/// Reads the `.value()` of the `<input>` that fired `event`.
pub fn input_value(event: &web_sys::Event) -> String {
    event
        .target()
        .and_then(|t| t.dyn_into::<HtmlInputElement>().ok())
        .map(|el| el.value())
        .unwrap_or_default()
}

/// Reads the `.checked()` state of the checkbox `<input>` that fired `event`.
pub fn input_checked(event: &web_sys::Event) -> bool {
    event
        .target()
        .and_then(|t| t.dyn_into::<HtmlInputElement>().ok())
        .map(|el| el.checked())
        .unwrap_or(false)
}

/// Reads the `.value()` of the `<select>` that fired `event`.
pub fn select_value(event: &web_sys::Event) -> String {
    event
        .target()
        .and_then(|t| t.dyn_into::<HtmlSelectElement>().ok())
        .map(|el| el.value())
        .unwrap_or_default()
}

#[derive(Clone, Debug)]
pub struct AttributeValue {
    pub name: String,
    pub values: Vec<String>,
}

pub struct GraphQlAttributeSchema {
    pub name: String,
    pub is_list: bool,
    pub is_readonly: bool,
    pub is_editable: bool,
}

fn validate_email_attributes(all_values: &[AttributeValue]) -> Result<()> {
    let maybe_email_values = all_values.iter().find(|a| a.name == "mail");
    let email_values = &maybe_email_values
        .ok_or_else(|| anyhow!("Email is required"))?
        .values;
    ensure!(!email_values.is_empty(), "Email is required");
    ensure!(email_values.len() == 1, "Multiple emails are not supported");
    ensure!(validate_email(&email_values[0]), "Email is not valid");
    Ok(())
}

pub struct IsAdmin(pub bool);
pub struct EmailIsRequired(pub bool);

pub fn read_all_form_attributes(
    schema: impl IntoIterator<Item = impl Into<GraphQlAttributeSchema>>,
    form_ref: &NodeRef,
    is_admin: IsAdmin,
    email_is_required: EmailIsRequired,
) -> Result<Vec<AttributeValue>> {
    let form = form_ref.cast::<HtmlFormElement>().unwrap();
    let form_data = FormData::new_with_form(&form)
        .map_err(|e| anyhow!("Failed to get FormData: {:#?}", e.as_string()))?;
    let all_values = schema
        .into_iter()
        .map(Into::<GraphQlAttributeSchema>::into)
        .filter(|attr| !attr.is_readonly && (is_admin.0 || attr.is_editable))
        .map(|attr| -> Result<AttributeValue> {
            let val = form_data
                .get_all(attr.name.as_str())
                .iter()
                .map(|js_val| js_val.as_string().unwrap_or_default())
                .filter(|val| !val.is_empty() && val != "Auto-assign")
                .collect::<Vec<String>>();
            ensure!(
                val.len() <= 1 || attr.is_list,
                "Multiple values supplied for non-list attribute {}",
                attr.name
            );
            Ok(AttributeValue {
                name: attr.name.clone(),
                values: val,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if email_is_required.0 {
        validate_email_attributes(&all_values)?;
    }
    Ok(all_values)
}
#[cfg(test)]
mod tests {
    use super::{AttributeValue, validate_email_attributes};

    fn attr(name: &str, values: &[&str]) -> AttributeValue {
        AttributeValue {
            name: name.to_string(),
            values: values.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_validate_email_attributes() {
        assert!(validate_email_attributes(&[attr("mail", &["a@b.com"])]).is_ok());
        for (label, attrs) in [
            ("missing", vec![attr("other", &["x"])]),
            ("empty", vec![attr("mail", &[])]),
            ("multiple", vec![attr("mail", &["a@b.com", "c@d.com"])]),
            ("invalid", vec![attr("mail", &["not-an-email"])]),
        ] {
            assert!(validate_email_attributes(&attrs).is_err(), "{label}");
        }
    }
}
