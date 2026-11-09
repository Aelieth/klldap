use std::collections::{HashMap, HashSet};

pub const ROOT_OU: &str = "All";
pub const ROOT_OU_WIRE: &str = "";

pub fn ou_display_name(ou: &str, domain: Option<&str>) -> String {
    if ou == ROOT_OU || ou == ROOT_OU_WIRE {
        match domain {
            Some(d) if !d.is_empty() => d.to_uppercase(),
            _ => ROOT_OU.to_owned(),
        }
    } else {
        ou.to_owned()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OuNode {
    key: String,
    name: String,
    children: Vec<OuNode>,
}

fn build_ou_tree(ous: &[String]) -> Vec<OuNode> {
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut primaries: Vec<String> = Vec::new();
    for ou in ous {
        let ou = ou.trim();
        if ou.is_empty() {
            continue;
        }
        match ou.split_once('\\') {
            Some((primary, secondary)) => {
                children
                    .entry(primary.to_owned())
                    .or_default()
                    .push(secondary.to_owned());
                if !primaries.iter().any(|p| p == primary) {
                    primaries.push(primary.to_owned());
                }
            }
            None => {
                if !primaries.iter().any(|p| p == ou) {
                    primaries.push(ou.to_owned());
                }
            }
        }
    }
    primaries.sort();
    primaries
        .into_iter()
        .map(|primary| {
            let mut secondaries = children.remove(&primary).unwrap_or_default();
            secondaries.sort();
            let kids = secondaries
                .into_iter()
                .map(|name| OuNode {
                    key: format!("{primary}\\{name}"),
                    name,
                    children: Vec::new(),
                })
                .collect();
            OuNode {
                name: primary.clone(),
                key: primary,
                children: kids,
            }
        })
        .collect()
}

fn ancestor_keys(ou: &str) -> Vec<String> {
    if ou.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<&str> = ou.split('\\').collect();
    let mut ancestors = Vec::new();
    while !parts.is_empty() {
        parts.pop();
        if parts.is_empty() {
            ancestors.push(String::new());
        } else {
            ancestors.push(parts.join("\\"));
        }
    }
    ancestors
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OuRow {
    pub key: String,
    pub prefix: String,
    pub leaf: String,
}

/// Root first, then the glyph scheme shared with `OuSelector`: primaries bare,
/// secondaries prefixed `├── `/`└── ` — one source so the pages cannot drift.
pub fn flatten_ou_rows(ous: &[String]) -> Vec<OuRow> {
    let mut rows = vec![OuRow {
        key: ROOT_OU_WIRE.to_owned(),
        prefix: String::new(),
        leaf: ROOT_OU.to_owned(),
    }];
    for node in build_ou_tree(ous) {
        rows.push(OuRow {
            key: node.key,
            prefix: String::new(),
            leaf: node.name,
        });
        let last = node.children.len().saturating_sub(1);
        for (i, child) in node.children.into_iter().enumerate() {
            rows.push(OuRow {
                key: child.key,
                prefix: if i == last {
                    "└── "
                } else {
                    "├── "
                }
                .to_owned(),
                leaf: child.name,
            });
        }
    }
    rows
}

/// The nearest ancestor policy respecting inheritance blocks, as
/// (policy id, policy name, origin wire key). Consulted only for OUs without
/// their own policy: self-blocked → None; a blocked ancestor's own policy still
/// governs, nothing above it does.
pub fn governing_policy(
    ou_wire_key: &str,
    direct: &HashMap<String, (i64, String)>,
    blocked: &HashSet<String>,
) -> Option<(i64, String, String)> {
    if blocked.contains(ou_wire_key) {
        return None;
    }
    for ancestor in ancestor_keys(ou_wire_key) {
        if let Some((id, name)) = direct.get(&ancestor) {
            return Some((*id, name.clone(), ancestor));
        }
        if blocked.contains(&ancestor) {
            return None;
        }
    }
    None
}

pub struct CatalogText {
    pub label: &'static str,
    pub help: &'static str,
    pub placeholder: &'static str,
}

/// Human text for the v1 catalog keys; None → the page falls back to the raw
/// key and the server-supplied description.
pub fn catalog_text(key: &str) -> Option<CatalogText> {
    let (label, help, placeholder) = match key {
        "require-mfa" => ("Require MFA", "Must users show a TOTP code to log in?", ""),
        "lockout-threshold" => ("Failed logins before lockout", "0 turns lockout off", ""),
        "lockout-duration-seconds" => (
            "Lockout duration (seconds)",
            "How long a locked account stays locked",
            "",
        ),
        "login-hours" => (
            "Login hours",
            "DAY[-DAY] HH:MM-HH:MM, ; separated · empty = always",
            "mon-fri 08:00-18:00",
        ),
        "allowed-networks" => (
            "Allowed networks",
            "CIDRs with explicit prefix, comma-separated · empty = any",
            "10.0.0.0/8, 2001:db8::/32",
        ),
        "inactivity-days" => ("Disable after inactivity (days)", "0 = never disable", ""),
        _ => return None,
    };
    Some(CatalogText {
        label,
        help,
        placeholder,
    })
}

pub fn format_item_value(key: &str, value: &str) -> String {
    match key {
        "login-hours" if value.is_empty() => "always".to_owned(),
        "allowed-networks" if value.is_empty() => "any network".to_owned(),
        "inactivity-days" if value == "0" => "never".to_owned(),
        "inactivity-days" => format!("{value} days"),
        "lockout-threshold" if value == "0" => "off".to_owned(),
        "lockout-threshold" => format!("{value} tries"),
        "lockout-duration-seconds" => format!("{value} s"),
        _ => value.to_owned(),
    }
}

pub const POLICY_COLORS: [&str; 6] = [
    "#3b82c4", "#e07a2f", "#4a9d5f", "#8e5bb8", "#c94f7c", "#3aa6a6",
];

pub fn policy_color(id: i64) -> &'static str {
    POLICY_COLORS[(id - 1).rem_euclid(POLICY_COLORS.len() as i64) as usize]
}

pub struct DraftEntry {
    pub key: String,
    pub label: String,
    pub enabled: bool,
    pub value: String,
    pub int_range: Option<(i64, i64)>,
}

/// Editor gate before submit: the trimmed name is 1..=64 characters, every
/// ticked int is whole and in its catalog range (normalized to `n.to_string()`,
/// matching the server), and at least one rule is ticked. Ok = the (key, value)
/// items to submit; Err = the inline error line. Unticked rows are ignored.
pub fn validate_draft_items(
    name: &str,
    entries: &[DraftEntry],
) -> Result<Vec<(String, String)>, String> {
    let name_chars = name.trim().chars().count();
    if name_chars == 0 || name_chars > 64 {
        return Err("Policy name must be 1 to 64 characters".to_owned());
    }
    let mut items = Vec::new();
    for entry in entries.iter().filter(|e| e.enabled) {
        let value = entry.value.trim();
        if let Some((min, max)) = entry.int_range {
            let n: i64 = value
                .parse()
                .map_err(|_| format!("{}: must be a whole number", entry.label))?;
            if n < min || n > max {
                return Err(format!("{}: must be between {min} and {max}", entry.label));
            }
            items.push((entry.key.clone(), n.to_string()));
        } else {
            items.push((entry.key.clone(), value.to_owned()));
        }
    }
    if items.is_empty() {
        return Err("Tick at least one rule for this policy to set".to_owned());
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ou_display_name() {
        for (row, ou, domain, expected) in [
            ("root All", ROOT_OU, Some("example.com"), "EXAMPLE.COM"),
            (
                "root empty key",
                ROOT_OU_WIRE,
                Some("example.com"),
                "EXAMPLE.COM",
            ),
            ("empty domain", ROOT_OU, None, "All"),
            ("blank domain", ROOT_OU, Some(""), "All"),
            ("ordinary OU", "people", Some("example.com"), "people"),
            (
                "secondary OU",
                "people\\labs",
                Some("example.com"),
                "people\\labs",
            ),
        ] {
            assert_eq!(ou_display_name(ou, domain), expected, "{row}");
        }
    }

    fn row(key: &str, prefix: &str, leaf: &str) -> OuRow {
        OuRow {
            key: key.to_owned(),
            prefix: prefix.to_owned(),
            leaf: leaf.to_owned(),
        }
    }

    #[test]
    fn test_flatten_ou_rows() {
        let ous = |names: &[&str]| names.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for (name, input, expected) in [
            (
                "empty input keeps the root",
                ous(&[]),
                vec![row("", "", "All")],
            ),
            (
                "primary alone has no prefix",
                ous(&["people"]),
                vec![row("", "", "All"), row("people", "", "people")],
            ),
            (
                "two secondaries get branch then corner",
                ous(&["people", "people\\labs", "people\\admin"]),
                vec![
                    row("", "", "All"),
                    row("people", "", "people"),
                    row("people\\admin", "├── ", "admin"),
                    row("people\\labs", "└── ", "labs"),
                ],
            ),
            (
                "single secondary gets the corner",
                ous(&["people\\labs"]),
                vec![
                    row("", "", "All"),
                    row("people", "", "people"),
                    row("people\\labs", "└── ", "labs"),
                ],
            ),
            (
                "primaries sort and blanks are skipped",
                ous(&["zoo", "  ", "alpha"]),
                vec![
                    row("", "", "All"),
                    row("alpha", "", "alpha"),
                    row("zoo", "", "zoo"),
                ],
            ),
        ] {
            assert_eq!(flatten_ou_rows(&input), expected, "{name}");
        }
    }

    #[test]
    fn test_governing_policy() {
        let mut direct = HashMap::new();
        direct.insert(String::new(), (1, "Base".to_owned()));
        direct.insert("people".to_owned(), (2, "Hours".to_owned()));
        let empty = HashSet::new();
        let block = |k: &str| HashSet::from([k.to_owned()]);

        for (name, ou, direct_map, blocked, expected) in [
            (
                "nearest ancestor wins",
                "people\\labs",
                &direct,
                &empty,
                Some((2, "Hours".to_owned(), "people".to_owned())),
            ),
            (
                "block on self → none",
                "people\\labs",
                &direct,
                &block("people\\labs"),
                None,
            ),
            (
                "blocked primary still governs with its own policy",
                "people\\labs",
                &direct,
                &block("people"),
                Some((2, "Hours".to_owned(), "people".to_owned())),
            ),
            ("root has no ancestors", ROOT_OU_WIRE, &direct, &empty, None),
        ] {
            assert_eq!(
                governing_policy(ou, direct_map, blocked),
                expected,
                "{name}"
            );
        }
        let mut root_only = HashMap::new();
        root_only.insert(String::new(), (1, "Base".to_owned()));
        assert_eq!(
            governing_policy("people\\labs", &root_only, &block("people")),
            None,
            "block on a bare primary cuts the root off"
        );
    }

    #[test]
    fn test_catalog_text() {
        assert_eq!(catalog_text("require-mfa").unwrap().label, "Require MFA");
        assert_eq!(
            catalog_text("login-hours").unwrap().placeholder,
            "mon-fri 08:00-18:00"
        );
        assert!(catalog_text("future-key").is_none(), "unknown key → None");
    }

    #[test]
    fn test_format_item_value() {
        for (name, key, value, expected) in [
            ("mfa token verbatim", "require-mfa", "always", "always"),
            ("empty hours mean always", "login-hours", "", "always"),
            (
                "set hours verbatim",
                "login-hours",
                "mon 08:00-18:00",
                "mon 08:00-18:00",
            ),
            (
                "empty networks mean any",
                "allowed-networks",
                "",
                "any network",
            ),
            (
                "set networks verbatim",
                "allowed-networks",
                "10.0.0.0/8",
                "10.0.0.0/8",
            ),
            ("zero inactivity is never", "inactivity-days", "0", "never"),
            ("inactivity gets a unit", "inactivity-days", "90", "90 days"),
            ("zero threshold is off", "lockout-threshold", "0", "off"),
            ("threshold gets tries", "lockout-threshold", "5", "5 tries"),
            (
                "duration gets seconds",
                "lockout-duration-seconds",
                "900",
                "900 s",
            ),
            ("unknown key verbatim", "future-key", "x", "x"),
        ] {
            assert_eq!(format_item_value(key, value), expected, "{name}");
        }
    }

    #[test]
    fn test_policy_color() {
        let first_six: HashSet<_> = (1..=6).map(policy_color).collect();
        assert_eq!(first_six.len(), 6, "ids 1-6 get distinct colors");
        assert_eq!(policy_color(7), policy_color(1), "palette wraps at seven");
    }

    #[test]
    fn test_validate_draft_items() {
        let entry = |key: &str, enabled, value: &str, int_range| DraftEntry {
            key: key.to_owned(),
            label: format!("Label {key}"),
            enabled,
            value: value.to_owned(),
            int_range,
        };
        let ok = validate_draft_items(
            "  Front Desk  ",
            &[
                entry("require-mfa", true, "always", None),
                entry("lockout-threshold", true, " 7 ", Some((0, 100))),
                entry("login-hours", false, "garbage everywhere", None),
            ],
        )
        .unwrap();
        assert_eq!(
            ok,
            vec![
                ("require-mfa".to_owned(), "always".to_owned()),
                ("lockout-threshold".to_owned(), "7".to_owned()),
            ],
            "ints normalize, disabled garbage is ignored"
        );

        let one = [entry("require-mfa", true, "off", None)];
        for (name, policy_name, entries, expected_err) in [
            ("empty name", "   ", &one[..], "1 to 64 characters"),
            (
                "sixty-five chars refused",
                &"é".repeat(65) as &str,
                &one[..],
                "1 to 64 characters",
            ),
            (
                "fractional int",
                "P",
                &[entry("lockout-threshold", true, "1.5", Some((0, 100)))][..],
                "whole number",
            ),
            (
                "out of range names the range",
                "P",
                &[entry("lockout-threshold", true, "101", Some((0, 100)))][..],
                "between 0 and 100",
            ),
            (
                "nothing ticked",
                "P",
                &[entry("require-mfa", false, "off", None)][..],
                "at least one rule",
            ),
        ] {
            let err = validate_draft_items(policy_name, entries).unwrap_err();
            assert!(err.contains(expected_err), "{name}: {err}");
        }
        assert!(
            validate_draft_items(&"é".repeat(64), &one).is_ok(),
            "sixty-four multibyte chars pass"
        );
    }
}
