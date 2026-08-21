use crate::error::DomainError;
use base64::{Engine as _, engine::general_purpose};
use lldap_domain::types::{
    Attribute, AttributeName, AttributeType, AttributeValue, Avatar, Cardinality, Serialized,
};
use lldap_schema::AttributeList;

// Canonical DB byte encoding: String → UTF-8, Integer → ASCII decimal, Avatar → raw JPEG,
// DateTime → ASCII epoch seconds; lists → JSON. DateTime decode also accepts RFC3339,
// naive ISO, and LLDAP bincode-of-ISO-string. Integer/String/Avatar bincode is left as-is
// until the v13 re-encode.
pub fn encode_attribute_value(value: &AttributeValue) -> Vec<u8> {
    match value {
        AttributeValue::String(Cardinality::Singleton(s)) => s.as_bytes().to_vec(),
        AttributeValue::String(Cardinality::Unbounded(l)) => {
            serde_json::to_vec(l).unwrap_or_else(|_| b"[]".to_vec())
        }
        AttributeValue::Integer(Cardinality::Singleton(i)) => i.to_string().into_bytes(),
        AttributeValue::Integer(Cardinality::Unbounded(l)) => {
            serde_json::to_vec(l).unwrap_or_else(|_| b"[]".to_vec())
        }
        AttributeValue::Avatar(Cardinality::Singleton(p)) => p.0.clone(),
        AttributeValue::Avatar(Cardinality::Unbounded(l)) => {
            let encoded: Vec<String> = l
                .iter()
                .map(|p| general_purpose::STANDARD.encode(&p.0))
                .collect();
            serde_json::to_vec(&encoded).unwrap_or_else(|_| b"[]".to_vec())
        }
        AttributeValue::DateTime(Cardinality::Singleton(dt)) => {
            dt.and_utc().timestamp().to_string().into_bytes()
        }
        AttributeValue::DateTime(Cardinality::Unbounded(l)) => {
            let epochs: Vec<i64> = l.iter().map(|dt| dt.and_utc().timestamp()).collect();
            serde_json::to_vec(&epochs).unwrap_or_else(|_| b"[]".to_vec())
        }
    }
}

fn datetime_from_epoch(epoch: i64) -> Option<chrono::NaiveDateTime> {
    chrono::DateTime::from_timestamp(epoch, 0).map(|dt| dt.naive_utc())
}

fn datetime_from_text(s: &str) -> Option<chrono::NaiveDateTime> {
    s.parse::<i64>()
        .ok()
        .and_then(datetime_from_epoch)
        .or_else(|| {
            chrono::DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.naive_utc())
                .ok()
        })
        .or_else(|| s.parse::<chrono::NaiveDateTime>().ok())
}

fn decode_datetime(bytes: &[u8]) -> chrono::NaiveDateTime {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(datetime_from_text)
        .or_else(|| {
            bincode::deserialize::<String>(bytes)
                .ok()
                .and_then(|s| datetime_from_text(&s))
        })
        .unwrap_or_default()
}

pub fn decode_attribute_value(
    value: &Serialized,
    typ: AttributeType,
    is_list: bool,
) -> AttributeValue {
    let bytes = &value.0;
    if is_list && bytes.is_empty() {
        return match typ {
            AttributeType::String => AttributeValue::String(Cardinality::Unbounded(vec![])),
            AttributeType::Integer => AttributeValue::Integer(Cardinality::Unbounded(vec![])),
            AttributeType::Avatar => AttributeValue::Avatar(Cardinality::Unbounded(vec![])),
            AttributeType::DateTime => AttributeValue::DateTime(Cardinality::Unbounded(vec![])),
        };
    }
    match (typ, is_list) {
        (AttributeType::String, false) => {
            let s = std::str::from_utf8(bytes).unwrap_or("");
            AttributeValue::String(Cardinality::Singleton(s.to_string()))
        }
        (AttributeType::String, true) => {
            if let Ok(list) = serde_json::from_slice::<Vec<String>>(bytes) {
                AttributeValue::String(Cardinality::Unbounded(list))
            } else {
                let s = std::str::from_utf8(bytes).unwrap_or("");
                AttributeValue::String(Cardinality::Unbounded(vec![s.to_string()]))
            }
        }
        (AttributeType::Integer, false) => {
            let s = std::str::from_utf8(bytes).unwrap_or("0");
            let i: i64 = s.parse().unwrap_or(0);
            AttributeValue::Integer(Cardinality::Singleton(i))
        }
        (AttributeType::Integer, true) => {
            let list = serde_json::from_slice::<Vec<i64>>(bytes).unwrap_or_else(|_| {
                std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .map(|i| vec![i])
                    .unwrap_or_default()
            });
            AttributeValue::Integer(Cardinality::Unbounded(list))
        }
        (AttributeType::DateTime, false) => {
            AttributeValue::DateTime(Cardinality::Singleton(decode_datetime(bytes)))
        }
        (AttributeType::DateTime, true) => {
            let list = if let Ok(epochs) = serde_json::from_slice::<Vec<i64>>(bytes) {
                epochs.into_iter().filter_map(datetime_from_epoch).collect()
            } else if let Ok(texts) = bincode::deserialize::<Vec<String>>(bytes) {
                texts.iter().filter_map(|s| datetime_from_text(s)).collect()
            } else {
                vec![]
            };
            AttributeValue::DateTime(Cardinality::Unbounded(list))
        }
        // Stored avatar bytes were processed to JPEG at write time; decode returns them as-is.
        (AttributeType::Avatar, false) => {
            AttributeValue::Avatar(Cardinality::Singleton(Avatar(bytes.clone())))
        }
        (AttributeType::Avatar, true) => {
            let list = if let Ok(encoded) = serde_json::from_slice::<Vec<String>>(bytes) {
                encoded
                    .iter()
                    .filter_map(|s| general_purpose::STANDARD.decode(s).ok())
                    .map(Avatar)
                    .collect()
            } else if bytes.starts_with(&[0xFF, 0xD8]) {
                vec![Avatar(bytes.clone())]
            } else {
                vec![]
            };
            AttributeValue::Avatar(Cardinality::Unbounded(list))
        }
    }
}

pub fn decode_attribute(
    name: AttributeName,
    value: &Serialized,
    schema: &AttributeList,
) -> Result<Attribute, DomainError> {
    match schema.get_attribute_type(name.as_str()) {
        Some((typ, is_list)) => Ok(Attribute {
            name,
            value: decode_attribute_value(value, typ, is_list),
        }),
        None => Err(DomainError::InternalError(format!(
            "Unable to find schema for attribute named '{}'",
            name.into_string()
        ))),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use pretty_assertions::assert_eq;

    fn dt(s: &str) -> chrono::NaiveDateTime {
        s.parse().unwrap()
    }

    fn roundtrip(value: AttributeValue, typ: AttributeType, is_list: bool) {
        let bytes = Serialized(encode_attribute_value(&value));
        assert_eq!(decode_attribute_value(&bytes, typ, is_list), value);
    }

    #[test]
    fn test_roundtrip_all_type_cardinality_combos() {
        let jpeg = Avatar::new(lldap_domain::images::make_test_jpeg_bytes()).0;
        roundtrip(
            AttributeValue::String(Cardinality::Singleton("Bob".to_string())),
            AttributeType::String,
            false,
        );
        roundtrip(
            AttributeValue::String(Cardinality::Unbounded(vec![
                "a".to_string(),
                "b".to_string(),
            ])),
            AttributeType::String,
            true,
        );
        roundtrip(
            AttributeValue::Integer(Cardinality::Singleton(10042)),
            AttributeType::Integer,
            false,
        );
        roundtrip(
            AttributeValue::Integer(Cardinality::Unbounded(vec![1, -2, 3])),
            AttributeType::Integer,
            true,
        );
        roundtrip(
            AttributeValue::Avatar(Cardinality::Singleton(Avatar(jpeg.clone()))),
            AttributeType::Avatar,
            false,
        );
        roundtrip(
            AttributeValue::Avatar(Cardinality::Unbounded(vec![Avatar(jpeg)])),
            AttributeType::Avatar,
            true,
        );
        roundtrip(
            AttributeValue::DateTime(Cardinality::Singleton(dt("2024-05-01T12:00:00"))),
            AttributeType::DateTime,
            false,
        );
        roundtrip(
            AttributeValue::DateTime(Cardinality::Unbounded(vec![
                dt("2024-05-01T12:00:00"),
                dt("1970-01-01T00:00:01"),
            ])),
            AttributeType::DateTime,
            true,
        );
    }

    #[test]
    fn test_decode_tolerates_legacy_and_empty_forms() {
        let expected = dt("2024-05-01T12:00:00");
        let epoch = Serialized(b"1714564800".to_vec());
        assert_eq!(
            decode_attribute_value(&epoch, AttributeType::DateTime, false),
            AttributeValue::DateTime(Cardinality::Singleton(expected))
        );
        let rfc3339 = Serialized(b"2024-05-01T12:00:00Z".to_vec());
        assert_eq!(
            decode_attribute_value(&rfc3339, AttributeType::DateTime, false),
            AttributeValue::DateTime(Cardinality::Singleton(expected))
        );
        let iso_naive = Serialized(b"2024-05-01T12:00:00".to_vec());
        assert_eq!(
            decode_attribute_value(&iso_naive, AttributeType::DateTime, false),
            AttributeValue::DateTime(Cardinality::Singleton(expected))
        );
        let bincode_string =
            Serialized(bincode::serialize(&"2024-05-01T12:00:00".to_string()).unwrap());
        assert_eq!(
            decode_attribute_value(&bincode_string, AttributeType::DateTime, false),
            AttributeValue::DateTime(Cardinality::Singleton(expected))
        );
        let bincode_list =
            Serialized(bincode::serialize(&vec!["2024-05-01T12:00:00".to_string()]).unwrap());
        assert_eq!(
            decode_attribute_value(&bincode_list, AttributeType::DateTime, true),
            AttributeValue::DateTime(Cardinality::Unbounded(vec![expected]))
        );
        let garbage = Serialized(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            decode_attribute_value(&garbage, AttributeType::DateTime, false),
            AttributeValue::DateTime(Cardinality::Singleton(chrono::NaiveDateTime::default()))
        );
        let default = NaiveDate::from_ymd_opt(1970, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        assert_eq!(chrono::NaiveDateTime::default(), default);

        let empty = Serialized(vec![]);
        for (typ, expected) in [
            (
                AttributeType::String,
                AttributeValue::String(Cardinality::Unbounded(vec![])),
            ),
            (
                AttributeType::Integer,
                AttributeValue::Integer(Cardinality::Unbounded(vec![])),
            ),
            (
                AttributeType::Avatar,
                AttributeValue::Avatar(Cardinality::Unbounded(vec![])),
            ),
            (
                AttributeType::DateTime,
                AttributeValue::DateTime(Cardinality::Unbounded(vec![])),
            ),
        ] {
            let label = format!("empty {typ:?} list");
            assert_eq!(
                decode_attribute_value(&empty, typ, true),
                expected,
                "{label}"
            );
        }
        let legacy = Serialized(b"42".to_vec());
        assert_eq!(
            decode_attribute_value(&legacy, AttributeType::Integer, true),
            AttributeValue::Integer(Cardinality::Unbounded(vec![42])),
            "a legacy single ascii integer reads as a one-element list"
        );
    }
}
