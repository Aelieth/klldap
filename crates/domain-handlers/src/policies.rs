use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const ROOT_OU_KEY: &str = "";

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum PolicyScope {
    User,
    Group,
    Computer,
    Server,
}

#[derive(Clone, Copy, Debug)]
pub enum PolicyValueType {
    Bool,
    Int {
        min: i64,
        max: i64,
    },
    Enum {
        allowed: &'static [&'static str],
    },
    String {
        validate: fn(&str) -> Result<(), String>,
    },
    StringList {
        validate_element: fn(&str) -> Result<(), String>,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct PolicyItemSpec {
    pub key: &'static str,
    pub scope: PolicyScope,
    pub value_type: PolicyValueType,
    pub default_value: &'static str,
    pub enforced: bool,
    pub description: &'static str,
}

pub static POLICY_ITEM_CATALOG: &[PolicyItemSpec] = &[
    PolicyItemSpec {
        key: "require-mfa",
        scope: PolicyScope::User,
        value_type: PolicyValueType::Enum {
            allowed: &["off", "enrolled", "always"],
        },
        default_value: "off",
        enforced: false,
        description: "Whether users in this OU must present TOTP (off / enrolled / always). Not yet enforced.",
    },
    PolicyItemSpec {
        key: "lockout-threshold",
        scope: PolicyScope::User,
        value_type: PolicyValueType::Int { min: 0, max: 100 },
        default_value: "0",
        enforced: false,
        description: "Failed logins before lockout; 0 disables. Not yet enforced.",
    },
    PolicyItemSpec {
        key: "lockout-duration-seconds",
        scope: PolicyScope::User,
        value_type: PolicyValueType::Int {
            min: 0,
            max: 604800,
        },
        default_value: "900",
        enforced: false,
        description: "How long a lockout lasts, in seconds. Not yet enforced.",
    },
    PolicyItemSpec {
        key: "login-hours",
        scope: PolicyScope::User,
        value_type: PolicyValueType::String {
            validate: validate_login_hours,
        },
        default_value: "",
        enforced: false,
        description: "When logins are allowed; empty means always. Not yet enforced.",
    },
    PolicyItemSpec {
        key: "allowed-networks",
        scope: PolicyScope::User,
        value_type: PolicyValueType::StringList {
            validate_element: validate_cidr,
        },
        default_value: "",
        enforced: false,
        description: "Source CIDRs that may authenticate; empty means any. Not yet enforced.",
    },
    PolicyItemSpec {
        key: "inactivity-days",
        scope: PolicyScope::User,
        value_type: PolicyValueType::Int { min: 0, max: 3650 },
        default_value: "0",
        enforced: false,
        description: "Days without a login before the account is disabled; 0 disables. Not yet enforced.",
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PolicyId(pub i32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub id: PolicyId,
    pub name: String,
    pub description: String,
    pub items: BTreeMap<String, String>,
    pub linked_ous: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub description: String,
    pub items: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePolicyRequest {
    pub id: PolicyId,
    pub name: Option<String>,
    pub description: Option<String>,
    pub items: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OuPolicyState {
    pub ou_key: String,
    pub policy_id: Option<PolicyId>,
    pub policy_name: Option<String>,
    pub block_inheritance: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachedPolicy {
    pub id: PolicyId,
    pub name: String,
    pub items: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyLevel {
    pub ou_key: String,
    pub blocked: bool,
    pub policy: Option<AttachedPolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemSource {
    pub policy_id: PolicyId,
    pub policy_name: String,
    pub ou_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveItem {
    pub key: String,
    pub scope: PolicyScope,
    pub value: String,
    pub enforced: bool,
    pub source: Option<ItemSource>,
}

pub fn canonical_ou_key(ou: &str) -> String {
    ou.trim().to_lowercase()
}

pub fn ou_display(ou_key: &str) -> &str {
    if ou_key == ROOT_OU_KEY {
        "(root)"
    } else {
        ou_key
    }
}

pub fn ou_chain(ou: &str) -> Vec<String> {
    let key = canonical_ou_key(ou);
    if key.is_empty() {
        return vec![ROOT_OU_KEY.to_owned()];
    }
    let mut chain = vec![ROOT_OU_KEY.to_owned()];
    let mut acc = String::new();
    for part in key.split('\\') {
        if acc.is_empty() {
            acc = part.to_owned();
        } else {
            acc = format!("{acc}\\{part}");
        }
        chain.push(acc.clone());
    }
    chain
}

pub fn catalog_item(key: &str) -> Option<&'static PolicyItemSpec> {
    POLICY_ITEM_CATALOG.iter().find(|spec| spec.key == key)
}

pub fn validate_policy_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err("Policy name must be 1 to 64 characters".to_owned());
    }
    if trimmed.chars().any(char::is_control) {
        return Err("Policy name cannot contain control characters".to_owned());
    }
    Ok(trimmed.to_owned())
}

pub fn validate_items(items: &BTreeMap<String, String>) -> Result<(), String> {
    for (key, value) in items {
        let spec = catalog_item(key).ok_or_else(|| format!("Unknown policy item '{key}'"))?;
        validate_value(&spec.value_type, value).map_err(|e| format!("{key}: {e}"))?;
    }
    Ok(())
}

pub fn resolve_effective_items(
    specs: &[PolicyItemSpec],
    levels: &[PolicyLevel],
) -> Vec<EffectiveItem> {
    let start = levels
        .iter()
        .enumerate()
        .rev()
        .find(|(i, level)| level.blocked && *i != 0)
        .map(|(i, _)| i)
        .unwrap_or(0);
    specs
        .iter()
        .map(|spec| {
            let search: &[PolicyLevel] = if spec.scope == PolicyScope::Server {
                levels.get(..1.min(levels.len())).unwrap_or(&[])
            } else {
                levels.get(start..).unwrap_or(&[])
            };
            let found = search.iter().rev().find_map(|level| {
                let policy = level.policy.as_ref()?;
                let value = policy.items.get(spec.key)?;
                Some((
                    value.clone(),
                    ItemSource {
                        policy_id: policy.id,
                        policy_name: policy.name.clone(),
                        ou_key: level.ou_key.clone(),
                    },
                ))
            });
            match found {
                Some((value, source)) => EffectiveItem {
                    key: spec.key.to_owned(),
                    scope: spec.scope,
                    value,
                    enforced: spec.enforced,
                    source: Some(source),
                },
                None => EffectiveItem {
                    key: spec.key.to_owned(),
                    scope: spec.scope,
                    value: spec.default_value.to_owned(),
                    enforced: spec.enforced,
                    source: None,
                },
            }
        })
        .collect()
}

fn validate_value(value_type: &PolicyValueType, value: &str) -> Result<(), String> {
    match value_type {
        PolicyValueType::Bool => {
            if value == "true" || value == "false" {
                Ok(())
            } else {
                Err("must be exactly true or false".to_owned())
            }
        }
        PolicyValueType::Int { min, max } => {
            let parsed: i64 = value
                .parse()
                .map_err(|_| "must be a base-10 integer".to_owned())?;
            if parsed < *min || parsed > *max {
                Err(format!("must be between {min} and {max}"))
            } else {
                Ok(())
            }
        }
        PolicyValueType::Enum { allowed } => {
            if allowed.contains(&value) {
                Ok(())
            } else {
                Err(format!("must be one of {}", allowed.join(", ")))
            }
        }
        PolicyValueType::String { validate } => validate(value),
        PolicyValueType::StringList { validate_element } => {
            if value.is_empty() {
                return Ok(());
            }
            for element in value.split(',') {
                let element = element.trim();
                if element.is_empty() {
                    return Err("list elements cannot be empty".to_owned());
                }
                validate_element(element)?;
            }
            Ok(())
        }
    }
}

pub fn validate_cidr(value: &str) -> Result<(), String> {
    let (addr, prefix) = value
        .split_once('/')
        .ok_or_else(|| "CIDR must include an explicit prefix".to_owned())?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| "CIDR prefix must be a number".to_owned())?;
    if addr.parse::<Ipv4Addr>().is_ok() {
        if prefix > 32 {
            return Err("IPv4 prefix must be 0-32".to_owned());
        }
        Ok(())
    } else if addr.parse::<Ipv6Addr>().is_ok() {
        if prefix > 128 {
            return Err("IPv6 prefix must be 0-128".to_owned());
        }
        Ok(())
    } else {
        Err("CIDR address is not a valid IP".to_owned())
    }
}

const DAYS: &[&str] = &["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

pub fn validate_login_hours(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Ok(());
    }
    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            return Err("login-hours entries cannot be empty".to_owned());
        }
        let Some((days, times)) = part.rsplit_once(' ') else {
            return Err("login-hours entries must be DAY[-DAY] HH:MM-HH:MM".to_owned());
        };
        for day in days.split('-') {
            if !DAYS.iter().any(|d| d.eq_ignore_ascii_case(day)) {
                return Err(format!("unknown day '{day}'"));
            }
        }
        if days.split('-').count() > 2 {
            return Err("day range must be DAY or DAY-DAY".to_owned());
        }
        let Some((start, end)) = times.split_once('-') else {
            return Err("time range must be HH:MM-HH:MM".to_owned());
        };
        let start_mins = parse_hhmm(start)?;
        let end_mins = parse_hhmm(end)?;
        if start_mins >= end_mins {
            return Err("time range start must be before end".to_owned());
        }
    }
    Ok(())
}

fn parse_hhmm(value: &str) -> Result<u16, String> {
    let (hour, minute) = value
        .split_once(':')
        .ok_or_else(|| "time must be HH:MM".to_owned())?;
    if hour.len() != 2 || minute.len() != 2 {
        return Err("time must be HH:MM".to_owned());
    }
    let hour: u16 = hour.parse().map_err(|_| "invalid hour".to_owned())?;
    let minute: u16 = minute.parse().map_err(|_| "invalid minute".to_owned())?;
    if hour > 23 || minute > 59 {
        return Err("hour must be 00-23 and minute 00-59".to_owned());
    }
    Ok(hour * 60 + minute)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn items(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn attached(id: i32, name: &str, pairs: &[(&str, &str)]) -> AttachedPolicy {
        AttachedPolicy {
            id: PolicyId(id),
            name: name.to_owned(),
            items: items(pairs),
        }
    }

    fn level(ou: &str, blocked: bool, policy: Option<AttachedPolicy>) -> PolicyLevel {
        PolicyLevel {
            ou_key: ou.to_owned(),
            blocked,
            policy,
        }
    }

    #[test]
    fn test_ou_chain_table() {
        for (input, expected) in [
            ("", vec![""]),
            ("a", vec!["", "a"]),
            ("A\\B", vec!["", "a", "a\\b"]),
            (" a\\B ", vec!["", "a", "a\\b"]),
            ("a\\b\\c", vec!["", "a", "a\\b", "a\\b\\c"]),
        ] {
            assert_eq!(ou_chain(input), expected, "{input:?}");
        }
        assert_eq!(ou_display(""), "(root)");
        assert_eq!(ou_display("people"), "people");
        assert_eq!(canonical_ou_key(" People\\Labs "), "people\\labs");
    }

    #[test]
    fn test_validate_items_table() {
        let ok = |pairs: &[(&str, &str)]| {
            assert!(
                validate_items(&items(pairs)).is_ok(),
                "{pairs:?} should be valid"
            );
        };
        let err = |pairs: &[(&str, &str)], needle: &str| {
            let message = validate_items(&items(pairs)).expect_err(needle);
            assert!(
                message.contains(needle),
                "{pairs:?}: expected {needle:?} in {message}"
            );
        };
        err(&[("nope", "1")], "Unknown policy item");
        err(&[("require-mfa", "TRUE")], "must be one of");
        err(&[("lockout-threshold", "x")], "base-10");
        err(&[("lockout-threshold", "101")], "between");
        err(&[("lockout-threshold", "-1")], "between");
        err(&[("allowed-networks", "10.0.0.0")], "explicit prefix");
        err(&[("allowed-networks", "10.0.0.0/33")], "IPv4 prefix");
        err(&[("allowed-networks", "not-an-ip/24")], "valid IP");
        err(&[("login-hours", "funday 08:00-09:00")], "unknown day");
        err(&[("login-hours", "mon 8:00-09:00")], "HH:MM");
        err(
            &[("login-hours", "mon 18:00-08:00")],
            "start must be before",
        );
        ok(&[("require-mfa", "always")]);
        ok(&[("lockout-threshold", "0")]);
        ok(&[("lockout-duration-seconds", "604800")]);
        ok(&[("inactivity-days", "3650")]);
        ok(&[("login-hours", "")]);
        ok(&[("login-hours", "mon-fri 08:00-18:00;sat 09:00-12:00")]);
        ok(&[("allowed-networks", "")]);
        ok(&[("allowed-networks", "10.0.0.0/8,2001:db8::/32")]);
        assert!(validate_policy_name("").is_err());
        assert!(validate_policy_name("  ").is_err());
        assert!(validate_policy_name(&"x".repeat(65)).is_err());
        assert!(validate_policy_name("ok name").is_ok());
    }

    #[test]
    fn test_resolution_table() {
        let user = |key: &'static str, default: &'static str| PolicyItemSpec {
            key,
            scope: PolicyScope::User,
            value_type: PolicyValueType::String {
                validate: |_| Ok(()),
            },
            default_value: default,
            enforced: false,
            description: "",
        };
        let server = |key: &'static str, default: &'static str| PolicyItemSpec {
            key,
            scope: PolicyScope::Server,
            value_type: PolicyValueType::String {
                validate: |_| Ok(()),
            },
            default_value: default,
            enforced: false,
            description: "",
        };
        let catalog = [
            user("color", "red"),
            user("size", "m"),
            server("banner", "none"),
        ];
        fn source(item: &EffectiveItem) -> Option<(&str, &str)> {
            item.source
                .as_ref()
                .map(|s| (s.policy_name.as_str(), s.ou_key.as_str()))
        }
        fn value<'a>(items: &'a [EffectiveItem], key: &str) -> &'a str {
            items
                .iter()
                .find(|i| i.key == key)
                .map(|i| i.value.as_str())
                .unwrap()
        }

        let defaults = resolve_effective_items(&catalog, &[]);
        assert_eq!(value(&defaults, "color"), "red", "all-defaults");
        assert!(defaults.iter().all(|i| i.source.is_none()), "all-defaults");

        let root_only = resolve_effective_items(
            &catalog,
            &[
                level("", false, Some(attached(1, "base", &[("color", "blue")]))),
                level("a", false, None),
                level("a\\b", false, None),
            ],
        );
        assert_eq!(value(&root_only, "color"), "blue", "root-only at depth");
        assert_eq!(
            source(&root_only[0]),
            Some(("base", "")),
            "root-only source"
        );

        let deepest = resolve_effective_items(
            &catalog,
            &[
                level("", false, Some(attached(1, "base", &[("color", "blue")]))),
                level("a", false, None),
                level(
                    "a\\b",
                    false,
                    Some(attached(2, "leaf", &[("color", "green")])),
                ),
            ],
        );
        assert_eq!(value(&deepest, "color"), "green", "deepest-override");
        assert_eq!(source(&deepest[0]), Some(("leaf", "a\\b")));

        let merged = resolve_effective_items(
            &catalog,
            &[
                level("", false, Some(attached(1, "base", &[("color", "blue")]))),
                level("a", false, Some(attached(2, "mid", &[("size", "l")]))),
                level("a\\b", false, None),
            ],
        );
        assert_eq!(value(&merged, "color"), "blue", "merge color");
        assert_eq!(source(&merged[0]), Some(("base", "")), "merge color source");
        assert_eq!(value(&merged, "size"), "l", "merge size");
        assert_eq!(source(&merged[1]), Some(("mid", "a")), "merge size source");

        let block_primary = resolve_effective_items(
            &catalog,
            &[
                level("", false, Some(attached(1, "base", &[("color", "blue")]))),
                level("a", true, Some(attached(2, "mid", &[("size", "l")]))),
                level(
                    "a\\b",
                    false,
                    Some(attached(3, "leaf", &[("color", "green")])),
                ),
            ],
        );
        assert_eq!(
            value(&block_primary, "color"),
            "green",
            "block-at-primary color"
        );
        assert_eq!(value(&block_primary, "size"), "l", "block-at-primary size");
        assert!(
            source(&block_primary[0]) != Some(("base", "")),
            "root cut by primary block"
        );

        let block_secondary = resolve_effective_items(
            &catalog,
            &[
                level("", false, Some(attached(1, "base", &[("color", "blue")]))),
                level("a", false, Some(attached(2, "mid", &[("size", "l")]))),
                level(
                    "a\\b",
                    true,
                    Some(attached(3, "leaf", &[("color", "green")])),
                ),
            ],
        );
        assert_eq!(
            value(&block_secondary, "color"),
            "green",
            "block-at-secondary"
        );
        assert_eq!(
            value(&block_secondary, "size"),
            "m",
            "block-at-secondary default size"
        );

        let blocked_empty = resolve_effective_items(
            &catalog,
            &[
                level("", false, Some(attached(1, "base", &[("color", "blue")]))),
                level("a", true, None),
            ],
        );
        assert_eq!(value(&blocked_empty, "color"), "red", "blocked-empty");
        assert!(blocked_empty.iter().all(|i| i.source.is_none()));

        let orphan = resolve_effective_items(
            &catalog,
            &[
                level("", false, Some(attached(1, "base", &[("color", "blue")]))),
                level("a", false, Some(attached(2, "mid", &[("color", "teal")]))),
                level("a\\b", false, None),
                level("a\\b\\c", false, None),
            ],
        );
        assert_eq!(
            value(&orphan, "color"),
            "teal",
            "orphan deepest inherits middle"
        );

        let server_at_secondary = resolve_effective_items(
            &catalog,
            &[
                level("", false, Some(attached(1, "base", &[("banner", "root")]))),
                level("a", false, Some(attached(2, "mid", &[("banner", "child")]))),
            ],
        );
        assert_eq!(
            value(&server_at_secondary, "banner"),
            "root",
            "server-from-root-only"
        );
        assert_eq!(
            source(
                server_at_secondary
                    .iter()
                    .find(|i| i.key == "banner")
                    .unwrap()
            ),
            Some(("base", ""))
        );

        let root_block_noop = resolve_effective_items(
            &catalog,
            &[
                level("", true, Some(attached(1, "base", &[("color", "blue")]))),
                level("a", false, None),
            ],
        );
        assert_eq!(
            value(&root_block_noop, "color"),
            "blue",
            "defensive root block no-op"
        );
    }

    #[test]
    fn test_catalog_v1_shape() {
        assert_eq!(POLICY_ITEM_CATALOG.len(), 6);
        assert!(
            POLICY_ITEM_CATALOG
                .iter()
                .all(|s| s.scope == PolicyScope::User && !s.enforced)
        );
    }
}
