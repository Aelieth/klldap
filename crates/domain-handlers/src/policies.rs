use std::collections::BTreeMap;
use std::time::Duration;

pub const ROOT_OU_KEY: &str = "";
/// A policy read with no answer within this is refused as unreadable.
pub const POLICY_READ_WAIT: Duration = Duration::from_secs(2);

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
        key: "enable-mfa",
        scope: PolicyScope::User,
        value_type: PolicyValueType::Enum {
            allowed: &["off", "enabled", "always"],
        },
        default_value: "off",
        enforced: true,
        description: "Whether users in this OU present TOTP (off / enabled / always); an explicit server-wide enable_mfa overrides it.",
    },
    PolicyItemSpec {
        key: "lockout-threshold",
        scope: PolicyScope::User,
        value_type: PolicyValueType::Int { min: 0, max: 100 },
        default_value: "0",
        enforced: true,
        description: "Failed logins in a row before the account locks, at every door; 0 disables.",
    },
    PolicyItemSpec {
        key: "lockout-duration-seconds",
        scope: PolicyScope::User,
        value_type: PolicyValueType::Int {
            min: 0,
            max: 604800,
        },
        default_value: "900",
        enforced: true,
        description: "How long a lockout lasts, in seconds; 0 holds it until an admin unlocks.",
    },
    PolicyItemSpec {
        key: "password-min-length",
        scope: PolicyScope::User,
        value_type: PolicyValueType::Int { min: 8, max: 128 },
        default_value: "8",
        enforced: true,
        description: "The fewest characters a new password may have, at every door that sees it; 8 to 128.",
    },
    PolicyItemSpec {
        key: "login-hours",
        scope: PolicyScope::User,
        value_type: PolicyValueType::String {
            validate: validate_login_hours,
        },
        default_value: "",
        enforced: true,
        description: "When logins are allowed, in the server's login_hours_timezone; empty means always.",
    },
    PolicyItemSpec {
        key: "allowed-networks",
        scope: PolicyScope::User,
        value_type: PolicyValueType::StringList {
            validate_element: validate_cidr,
        },
        default_value: "",
        enforced: true,
        description: "Source CIDRs that may authenticate; empty means any.",
    },
    PolicyItemSpec {
        key: "inactivity-days",
        scope: PolicyScope::User,
        value_type: PolicyValueType::Int { min: 0, max: 3650 },
        default_value: "0",
        enforced: true,
        description: "Refuses sign-in to a user with no successful sign-in for this many days; 0 turns it off. An admin re-enables the user.",
    },
];

/// An item stored under an older name: carried over by the migration, refused at input.
pub struct RenamedItem {
    pub old: &'static str,
    pub new: &'static str,
    pub values: &'static [(&'static str, &'static str)],
}

pub static RENAMED_ITEMS: &[RenamedItem] = &[RenamedItem {
    old: "require-mfa",
    new: "enable-mfa",
    values: &[("enrolled", "enabled")],
}];

pub fn rename_items(items: &mut BTreeMap<String, String>) -> bool {
    let mut changed = false;
    for renamed in RENAMED_ITEMS {
        let Some(value) = items.remove(renamed.old) else {
            continue;
        };
        changed = true;
        let value = match renamed.values.iter().find(|(old, _)| *old == value) {
            Some((_, new)) => (*new).to_owned(),
            None => value,
        };
        items.entry(renamed.new.to_owned()).or_insert(value);
    }
    changed
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingSource {
    Server,
    Ou,
    Default,
}

/// A setting both the server and an OU's policy can set: a new one needs its catalog entry,
/// its server-wide key and this.
pub trait Setting {
    type Value;
    const KEY: &'static str;
    fn parse(value: &str) -> Self::Value;
}

/// The explicit server-wide value overrides the OUs; else the user's OU decides by the
/// inheritance above; else the catalog's default.
pub fn resolve<S: Setting>(
    server: Option<S::Value>,
    items: &[EffectiveItem],
) -> (S::Value, SettingSource) {
    if let Some(value) = server {
        return (value, SettingSource::Server);
    }
    match items.iter().find(|item| item.key == S::KEY) {
        Some(item) if item.source.is_some() => (S::parse(&item.value), SettingSource::Ou),
        _ => {
            let default = catalog_item(S::KEY).map_or("", |spec| spec.default_value);
            (S::parse(default), SettingSource::Default)
        }
    }
}

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
    if trimmed.is_empty() || trimmed.chars().count() > 64 {
        return Err("Policy name must be 1 to 64 characters".to_owned());
    }
    if trimmed.chars().any(char::is_control) {
        return Err("Policy name cannot contain control characters".to_owned());
    }
    Ok(trimmed.to_owned())
}

pub fn validate_items(items: &BTreeMap<String, String>) -> Result<(), String> {
    for (key, value) in items {
        if let Some(renamed) = RENAMED_ITEMS.iter().find(|renamed| renamed.old == key) {
            return Err(format!("Policy item '{key}' is now '{}'", renamed.new));
        }
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
    crate::networks::Net::parse(value).map(drop)
}

pub fn validate_login_hours(value: &str) -> Result<(), String> {
    crate::login_hours::parse(value).map(drop)
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
        err(&[("enable-mfa", "TRUE")], "must be one of");
        err(&[("enable-mfa", "enrolled")], "must be one of");
        err(
            &[("require-mfa", "always")],
            "'require-mfa' is now 'enable-mfa'",
        );
        err(&[("lockout-threshold", "x")], "base-10");
        err(&[("lockout-threshold", "101")], "between");
        err(&[("lockout-threshold", "-1")], "between");
        err(&[("allowed-networks", "10.0.0.0")], "explicit prefix");
        err(&[("allowed-networks", "10.0.0.0/+24")], "must be a number");
        err(&[("allowed-networks", "10.0.0.0/33")], "IPv4 prefix");
        err(&[("allowed-networks", "not-an-ip/24")], "valid IP");
        err(&[("login-hours", "funday 08:00-09:00")], "unknown day");
        err(&[("login-hours", "mon 8:00-09:00")], "HH:MM");
        err(
            &[("login-hours", "mon 18:00-08:00")],
            "start must be before",
        );
        ok(&[("enable-mfa", "always")]);
        ok(&[("enable-mfa", "enabled")]);
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
    fn test_an_old_item_is_carried_over_once_and_the_new_name_wins() {
        let rows = [
            (
                vec![("require-mfa", "enrolled")],
                vec![("enable-mfa", "enabled")],
                true,
            ),
            (
                vec![("require-mfa", "always")],
                vec![("enable-mfa", "always")],
                true,
            ),
            (
                vec![("require-mfa", "off")],
                vec![("enable-mfa", "off")],
                true,
            ),
            (
                vec![("require-mfa", "always"), ("enable-mfa", "off")],
                vec![("enable-mfa", "off")],
                true,
            ),
            (
                vec![("enable-mfa", "enabled"), ("lockout-threshold", "3")],
                vec![("enable-mfa", "enabled"), ("lockout-threshold", "3")],
                false,
            ),
            (vec![], vec![], false),
        ];
        for (before, after, changed) in rows {
            let mut stored = items(&before);
            assert_eq!(rename_items(&mut stored), changed, "{before:?}");
            assert_eq!(stored, items(&after), "{before:?}");
            assert!(
                !rename_items(&mut stored),
                "{before:?}: a second run changes nothing"
            );
        }
    }

    struct Threshold;

    impl Setting for Threshold {
        type Value = String;
        const KEY: &'static str = "lockout-threshold";
        fn parse(value: &str) -> String {
            value.to_owned()
        }
    }

    #[test]
    fn test_the_explicit_server_value_then_the_ou_then_the_default() {
        let levels = |set: Option<&str>| {
            let policy = set.map(|value| attached(1, "p", &[("lockout-threshold", value)]));
            vec![level("", false, None), level("labs", false, policy)]
        };
        let rows = [
            (Some("9"), Some("3"), ("9", SettingSource::Server)),
            (Some("0"), Some("3"), ("0", SettingSource::Server)),
            (Some("9"), None, ("9", SettingSource::Server)),
            (None, Some("3"), ("3", SettingSource::Ou)),
            (None, Some("0"), ("0", SettingSource::Ou)),
            (None, None, ("0", SettingSource::Default)),
        ];
        for (server, ou, (value, source)) in rows {
            let items = resolve_effective_items(POLICY_ITEM_CATALOG, &levels(ou));
            let got = resolve::<Threshold>(server.map(str::to_owned), &items);
            assert_eq!(got, (value.to_owned(), source), "{server:?} {ou:?}");
        }
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
    fn test_the_minimum_length_takes_8_to_128_whole_numbers() {
        let rows = [
            ("7", Err("password-min-length: must be between 8 and 128")),
            ("129", Err("password-min-length: must be between 8 and 128")),
            ("0", Err("password-min-length: must be between 8 and 128")),
            ("x", Err("password-min-length: must be a base-10 integer")),
            (
                "12.5",
                Err("password-min-length: must be a base-10 integer"),
            ),
            ("8", Ok(())),
            ("12", Ok(())),
            ("128", Ok(())),
        ];
        for (value, expected) in rows {
            let got = validate_items(&items(&[("password-min-length", value)]));
            assert_eq!(got, expected.map_err(str::to_owned), "{value:?}");
        }
        let spec = catalog_item("password-min-length").unwrap();
        assert_eq!(
            (spec.scope, spec.default_value, spec.enforced),
            (PolicyScope::User, "8", true)
        );
    }

    #[test]
    fn test_catalog_v1_shape() {
        assert_eq!(POLICY_ITEM_CATALOG.len(), 7);
        assert!(
            POLICY_ITEM_CATALOG
                .iter()
                .all(|s| s.scope == PolicyScope::User)
        );
        let enforced: Vec<&str> = POLICY_ITEM_CATALOG
            .iter()
            .filter(|s| s.enforced)
            .map(|s| s.key)
            .collect();
        assert_eq!(
            enforced,
            [
                "enable-mfa",
                "lockout-threshold",
                "lockout-duration-seconds",
                "password-min-length",
                "login-hours",
                "allowed-networks",
                "inactivity-days"
            ]
        );
        for spec in POLICY_ITEM_CATALOG {
            let says_not_yet = spec.description.contains("Not yet enforced");
            assert_eq!(says_not_yet, !spec.enforced, "{}", spec.key);
        }
        assert_eq!(
            catalog_item("login-hours").map(|spec| spec.description),
            Some(
                "When logins are allowed, in the server's login_hours_timezone; empty means always."
            )
        );
        assert_eq!(
            catalog_item("inactivity-days").map(|spec| spec.description),
            Some(
                "Refuses sign-in to a user with no successful sign-in for this many days; 0 turns \
                 it off. An admin re-enables the user."
            )
        );
    }
}
