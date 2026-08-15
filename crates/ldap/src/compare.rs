use crate::core::error::LdapResult;
use ldap3_proto::proto::{LdapCompareRequest, LdapOp, LdapResult as LdapResultOp, LdapResultCode};
use lldap_domain::types::AttributeName;

/// Compares against the entry whose DN matches the request exactly, so the OUs the search
/// layer returns alongside the target do not affect the result.
pub fn compare(
    request: LdapCompareRequest,
    search_results: Vec<LdapOp>,
    base_dn: &str,
) -> LdapResult<Vec<LdapOp>> {
    let attr_name = AttributeName::from(&request.atype);

    let entries: Vec<_> = search_results
        .into_iter()
        .filter_map(|op| match op {
            LdapOp::SearchResultEntry(e) => Some(e),
            _ => None,
        })
        .collect();

    // Exact DN match, case-insensitive per LDAP rules.
    let matching_entry = entries
        .iter()
        .find(|e| e.dn.eq_ignore_ascii_case(&request.dn));

    match matching_entry {
        Some(entry) => {
            let attribute_exists = entry.attributes.iter().any(|attr| {
                AttributeName::from(&attr.atype) == attr_name && attr.vals.contains(&request.val)
            });

            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: if attribute_exists {
                    LdapResultCode::CompareTrue
                } else {
                    LdapResultCode::CompareFalse
                },
                matcheddn: request.dn,
                message: "".to_string(),
                referral: vec![],
            })])
        }
        None => Ok(vec![LdapOp::CompareResult(LdapResultOp {
            code: LdapResultCode::NoSuchObject,
            matcheddn: base_dn.to_string(),
            message: "".to_string(),
            referral: vec![],
        })]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::tests::setup_bound_admin_handler;
    use chrono::TimeZone;
    use lldap_domain::types::{Group, GroupId, GroupMember, User, UserAndGroups, UserId, Uuid};
    use lldap_test_utils::{MockTestBackendHandler, setup_default_ldap_mock};
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_compare_user() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_list_users().returning(|_, _| {
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("bob"),
                    email: "bob@bobmail.bob".into(),
                    display_name: Some("Bob".into()),
                    ..Default::default()
                },
                groups: None,
            }])
        });
        mock.expect_list_groups().returning(|_| Ok(vec![]));

        let ldap_handler = setup_bound_admin_handler(mock).await;

        let dn = "uid=bob,ou=people,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "uid".to_owned(),
            val: b"bob".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareTrue,
                matcheddn: dn.to_string(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_group() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_list_users().returning(|_, _| Ok(vec![]));
        mock.expect_list_groups().returning(|_| {
            Ok(vec![Group {
                id: GroupId(1),
                display_name: "group".into(),
                creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                users: vec![],
                uuid: Uuid::from_name_and_date(
                    "group",
                    &chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                ),
                attributes: Vec::new(),
                modified_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
            }])
        });

        let ldap_handler = setup_bound_admin_handler(mock).await;

        let dn = "cn=group,ou=groups,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "cn".to_owned(),
            val: b"group".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareTrue,
                matcheddn: dn.to_string(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_not_found() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_list_users().returning(|_, _| Ok(vec![]));
        mock.expect_list_groups().returning(|_| Ok(vec![]));

        let ldap_handler = setup_bound_admin_handler(mock).await;

        let dn = "uid=bob,ou=people,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "uid".to_owned(),
            val: b"bob".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::NoSuchObject,
                matcheddn: "dc=example,dc=com".to_owned(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_no_match() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_list_users().returning(|_, _| {
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("bob"),
                    email: "bob@bobmail.bob".into(),
                    ..Default::default()
                },
                groups: None,
            }])
        });
        mock.expect_list_groups().returning(|_| Ok(vec![]));

        let ldap_handler = setup_bound_admin_handler(mock).await;

        let dn = "uid=bob,ou=people,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "mail".to_owned(),
            val: b"completely-wrong-value".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareFalse,
                matcheddn: dn.to_string(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_group_member() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_list_users().returning(|_, _| Ok(vec![]));
        mock.expect_list_groups().returning(|_| {
            Ok(vec![Group {
                id: GroupId(1),
                display_name: "group".into(),
                creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                users: vec![GroupMember {
                    user_id: UserId::new("bob"),
                    ou: "people".to_string(),
                }],
                uuid: Uuid::from_name_and_date(
                    "group",
                    &chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                ),
                attributes: Vec::new(),
                modified_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
            }])
        });

        let ldap_handler = setup_bound_admin_handler(mock).await;

        let dn = "cn=group,ou=groups,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "uniqueMember".to_owned(),
            val: b"uid=bob,ou=people,dc=example,dc=com".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareTrue,
                matcheddn: dn.to_owned(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }
}
