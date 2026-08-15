use crate::core::error::{LdapError, LdapResult};
use ldap3_proto::LdapResultCode;
use lldap_domain::types::{GroupName, UserId};
use tracing::{debug, warn};

pub const DEFAULT_PRIMARY_USER_OU: &str = "people";
pub const DEFAULT_PRIMARY_GROUP_OU: &str = "groups";

/// The internal OU string ("people\\home") from a DN's `ou=` RDNs, in order.
pub fn get_internal_ou_from_dn_parts(dn_parts: &[(String, String)]) -> String {
    let ou_chain: Vec<(String, String)> = dn_parts
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("ou"))
        .cloned()
        .collect();
    ldap_rdn_chain_to_internal_ou(&ou_chain)
}

/// The OUs exactly one level below `parent_internal_ou`.
pub fn get_direct_child_ous(parent_internal_ou: &str, allowed_ous: &[String]) -> Vec<String> {
    let parent_l = parent_internal_ou.to_ascii_lowercase();
    allowed_ous
        .iter()
        .filter(|ou| {
            let ou_l = ou.to_ascii_lowercase();
            if parent_l.is_empty() {
                !ou_l.contains('\\')
            } else if ou_l.starts_with(&format!("{}\\", parent_l)) {
                let suffix = &ou_l[parent_l.len() + 1..];
                !suffix.contains('\\')
            } else {
                false
            }
        })
        .cloned()
        .collect()
}

pub fn internal_ou_to_ldap_rdn_chain(ou: &str) -> Vec<(String, String)> {
    if ou.trim().is_empty() {
        return vec![];
    }
    let parts: Vec<&str> = ou.split('\\').collect();
    let mut chain = Vec::with_capacity(parts.len());
    for part in parts.iter().rev() {
        let trimmed = part.trim();
        if !trimmed.is_empty() {
            chain.push(("ou".to_string(), trimmed.to_string()));
        }
    }
    chain
}

pub fn ldap_rdn_chain_to_internal_ou(rdn_chain: &[(String, String)]) -> String {
    let ous: Vec<String> = rdn_chain
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("ou"))
        .map(|(_, v)| v.clone())
        .rev()
        .collect();
    if ous.is_empty() {
        String::new()
    } else {
        ous.join("\\")
    }
}

pub fn is_container_dn(
    dn_parts: &[(String, String)],
    base_dn: &[(String, String)],
    allowed_ous: &[String],
) -> bool {
    let ou_chain: Vec<(String, String)> = dn_parts
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("ou"))
        .cloned()
        .collect();
    let internal_ou = ldap_rdn_chain_to_internal_ou(&ou_chain);
    let is_allowed = allowed_ous
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&internal_ou));
    is_allowed && dn_parts.len() == base_dn.len() + ou_chain.len()
}

pub fn is_subtree(subtree: &[(String, String)], base_tree: &[(String, String)]) -> bool {
    if base_tree.is_empty() {
        return true;
    }
    if subtree.len() < base_tree.len() {
        return false;
    }

    let offset = subtree.len() - base_tree.len();
    for i in 0..base_tree.len() {
        if !subtree[offset + i].0.eq_ignore_ascii_case(&base_tree[i].0)
            || !subtree[offset + i].1.eq_ignore_ascii_case(&base_tree[i].1)
        {
            return false;
        }
    }
    true
}

fn make_dn_pair<I>(mut iter: I) -> LdapResult<(String, String)>
where
    I: Iterator<Item = String>,
{
    (|| {
        let pair = (
            iter.next().ok_or_else(|| "Empty DN element".to_string())?,
            iter.next().ok_or_else(|| "Missing DN value".to_string())?,
        );
        if let Some(e) = iter.next() {
            Err(format!(
                r#"Too many elements in distinguished name: "{}", "{}", "{}""#,
                pair.0, pair.1, e
            ))
        } else {
            Ok(pair)
        }
    })()
    .map_err(|e| LdapError {
        code: LdapResultCode::InvalidDNSyntax,
        message: e,
    })
}

pub fn parse_distinguished_name(dn: &str) -> LdapResult<Vec<(String, String)>> {
    let lower_dn = dn.to_ascii_lowercase();
    debug!(?dn, "Parsing client DN");
    let result: LdapResult<Vec<_>> = lower_dn
        .split(',')
        .map(|s| make_dn_pair(s.split('=').map(str::trim).map(String::from)))
        .collect();

    if let Err(e) = &result {
        warn!(?dn, error = ?e, "Invalid DN syntax received from client");
    }
    result
}

pub enum UserOrGroupName {
    User(UserId),
    Group(GroupName),
    BadSubStree,
    UnexpectedFormat,
    InvalidSyntax(LdapError),
}

impl UserOrGroupName {
    pub fn into_ldap_error(self, input: &str, expected_format: String) -> LdapError {
        LdapError {
            code: LdapResultCode::InvalidDNSyntax,
            message: match self {
                UserOrGroupName::BadSubStree => "Not a subtree of the base tree".to_string(),
                UserOrGroupName::InvalidSyntax(err) => return err,
                UserOrGroupName::UnexpectedFormat
                | UserOrGroupName::User(_)
                | UserOrGroupName::Group(_) => {
                    format!(r#"Unexpected DN format. Got "{input}", expected: {expected_format}"#)
                }
            },
        }
    }
}

/// `uid=` or `cn=` under `people` (or no OU) is a user; `cn=` under any other OU is a
/// group, so groups may live under custom and nested OUs.
pub fn get_user_or_group_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
) -> UserOrGroupName {
    let parts = match parse_distinguished_name(dn) {
        Ok(p) => p,
        Err(e) => return UserOrGroupName::InvalidSyntax(e),
    };
    if !is_subtree(&parts, base_tree) {
        return UserOrGroupName::BadSubStree;
    }

    let ou_chain: Vec<(String, String)> = parts
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("ou"))
        .cloned()
        .collect();

    let primary_ou = ou_chain
        .last()
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();

    if parts.len() == base_tree.len() + ou_chain.len() + 1 {
        let rdn = &parts[0];
        let rdn_type = rdn.0.to_ascii_lowercase();

        let is_user_ou = primary_ou == DEFAULT_PRIMARY_USER_OU || primary_ou.is_empty();

        if rdn_type == "uid" || (rdn_type == "cn" && is_user_ou) {
            return UserOrGroupName::User(UserId::from(rdn.1.clone()));
        } else if rdn_type == "cn" && !is_user_ou {
            return UserOrGroupName::Group(GroupName::from(rdn.1.clone()));
        }
    }

    UserOrGroupName::UnexpectedFormat
}

pub fn get_user_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<UserId> {
    match get_user_or_group_id_from_distinguished_name(dn, base_tree) {
        UserOrGroupName::User(user_id) => Ok(user_id),
        err => Err(err.into_ldap_error(dn, format!(r#""uid=id,ou=...,{}""#, base_dn_str))),
    }
}

pub fn get_group_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<GroupName> {
    match get_user_or_group_id_from_distinguished_name(dn, base_tree) {
        UserOrGroupName::Group(group_name) => Ok(group_name),
        err => Err(err.into_ldap_error(
            dn,
            format!(r#""cn=id,ou=any-allowed-ou,...{}""#, base_dn_str),
        )),
    }
}

fn looks_like_distinguished_name(dn: &str) -> bool {
    dn.contains('=') || dn.contains(',')
}

pub fn get_user_id_from_distinguished_name_or_plain_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<UserId> {
    if !looks_like_distinguished_name(dn) {
        Ok(UserId::from(dn))
    } else {
        get_user_id_from_distinguished_name(dn, base_tree, base_dn_str)
    }
}

pub fn get_group_id_from_distinguished_name_or_plain_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<GroupName> {
    if !looks_like_distinguished_name(dn) {
        Ok(GroupName::from(dn))
    } else {
        get_group_id_from_distinguished_name(dn, base_tree, base_dn_str)
    }
}

pub fn build_user_dn(user_id: &UserId, internal_ou: &str, base_dn_str: &str) -> String {
    let rdn_chain = internal_ou_to_ldap_rdn_chain(internal_ou);
    let ou_part = rdn_chain
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(",");
    if ou_part.is_empty() {
        format!("uid={},{}", user_id, base_dn_str)
    } else {
        format!("uid={},{}", user_id, ou_part + "," + base_dn_str)
    }
}

pub fn build_group_dn(group_name: &GroupName, internal_ou: &str, base_dn_str: &str) -> String {
    let rdn_chain = internal_ou_to_ldap_rdn_chain(internal_ou);
    let ou_part = rdn_chain
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(",");
    if ou_part.is_empty() {
        format!("cn={},{}", group_name, base_dn_str)
    } else {
        format!("cn={},{}", group_name, ou_part + "," + base_dn_str)
    }
}
