use crate::images;
use crate::types::{AttributeType, AttributeValue, Avatar};
use anyhow::{Context as AnyhowContext, Result, bail};
use base64::Engine;
use base64::engine::general_purpose;

pub fn deserialize_attribute_value(
    value: &[String],
    typ: AttributeType,
    is_list: bool,
) -> Result<AttributeValue> {
    if !is_list && value.len() != 1 {
        bail!("Attribute is not a list, but multiple values were provided");
    }
    let parse_int = |value: &String| -> Result<i64> {
        value
            .parse::<i64>()
            .with_context(|| format!("Invalid integer value {value}"))
    };
    let parse_date = |value: &String| -> Result<chrono::NaiveDateTime> {
        Ok(chrono::DateTime::parse_from_rfc3339(value)
            .with_context(|| format!("Invalid date value {value}"))?
            .naive_utc())
    };
    let parse_avatar = |value: &String| -> Result<Avatar> {
        if value.is_empty() {
            return Ok(Avatar::null());
        }

        let raw_bytes = general_purpose::STANDARD
            .decode(value)
            .context("Invalid base64 data for avatar")?;

        let jpeg_bytes =
            images::process_avatar_input(&raw_bytes).context("Failed to process avatar")?;
        Ok(Avatar::new(jpeg_bytes))
    };
    Ok(match (typ, is_list) {
        (AttributeType::String, false) => value[0].clone().into(),
        (AttributeType::String, true) => value.to_vec().into(),
        (AttributeType::Integer, false) => (parse_int(&value[0])?).into(),
        (AttributeType::Integer, true) => {
            (value.iter().map(parse_int).collect::<Result<Vec<_>>>()?).into()
        }
        (AttributeType::DateTime, false) => (parse_date(&value[0])?).into(),
        (AttributeType::DateTime, true) => {
            (value.iter().map(parse_date).collect::<Result<Vec<_>>>()?).into()
        }
        (AttributeType::Avatar, false) => (parse_avatar(&value[0])?).into(),
        (AttributeType::Avatar, true) => {
            (value.iter().map(parse_avatar).collect::<Result<Vec<_>>>()?).into()
        }
    })
}
