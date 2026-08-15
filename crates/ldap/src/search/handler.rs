//! Main LDAP search handler.

use crate::core::{
    error::{LdapError, LdapResult},
    utils::LdapInfo,
};
use crate::dn::parse_distinguished_name;
use crate::search::filters::{convert_group_filter, convert_user_filter};
use crate::search::scope::ou_matches_filter;
use crate::search::{
    build_ou_entries, convert_groups_to_ldap_op, convert_users_to_ldap_op, get_search_scope,
    make_ou_entry, make_search_success,
};
use ldap3_proto::proto::{LdapOp, LdapSearchRequest, LdapSearchScope};
use ldap3_proto::{LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry};
use lldap_access_control::UserAndGroupListerBackendHandler;
use lldap_domain::types::{Group, UserAndGroups};
use lldap_domain_handlers::handler::{GroupListerBackendHandler, UserListerBackendHandler};
use lldap_schema::PublicSchema;
use tracing::{debug, instrument};

#[instrument(skip_all, level = "debug", fields(ldap_filter, request_groups))]
pub(crate) async fn get_user_list<Backend: UserListerBackendHandler>(
    ldap_info: &LdapInfo,
    ldap_filter: &LdapFilter,
    request_groups: bool,
    base: &str,
    backend: &Backend,
    schema: &PublicSchema,
) -> LdapResult<Vec<UserAndGroups>> {
    let filters = convert_user_filter(ldap_info, ldap_filter, schema)?;
    debug!(?filters);
    backend
        .list_users(Some(filters), request_groups)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::Other,
            message: format!(r#"Error while searching user "{base}": {e:#}"#),
        })
}

#[instrument(skip_all, level = "debug", fields(ldap_filter))]
pub(crate) async fn get_groups_list<Backend: GroupListerBackendHandler>(
    ldap_info: &LdapInfo,
    ldap_filter: &LdapFilter,
    base: &str,
    backend: &Backend,
    schema: &PublicSchema,
) -> LdapResult<Vec<Group>> {
    let filters = convert_group_filter(ldap_info, ldap_filter, schema)?;
    debug!(?filters);
    backend
        .list_groups(Some(filters))
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::Other,
            message: format!(r#"Error while listing groups "{base}": {e:#}"#),
        })
}

fn no_such_object() -> LdapError {
    LdapError {
        code: LdapResultCode::NoSuchObject,
        message: String::new(),
    }
}

// Keeps entries under `base`; with `child_rdn_count` (one-level searches) only entries with
// exactly that many RDNs, i.e. direct children.
fn retain_under_base(ops: &mut Vec<LdapOp>, base: &str, child_rdn_count: Option<usize>) {
    let base_lower = base.to_ascii_lowercase();
    ops.retain(|op| match op {
        LdapOp::SearchResultEntry(entry) => match parse_distinguished_name(&entry.dn) {
            Ok(parts) => {
                entry.dn.to_ascii_lowercase().ends_with(&base_lower)
                    && child_rdn_count.is_none_or(|count| parts.len() == count)
            }
            Err(_) => false,
        },
        _ => true,
    });
}

fn retain_exact_dn(ops: &mut Vec<LdapOp>, base: &str) {
    let base_lower = base.to_ascii_lowercase();
    ops.retain(|op| match op {
        LdapOp::SearchResultEntry(entry) => entry.dn.to_ascii_lowercase() == base_lower,
        _ => true,
    });
}

pub(crate) fn include_operational(attrs: &[String]) -> bool {
    // "+" or any requested attribute that is operational (== always_operational), from the table.
    attrs
        .iter()
        .any(|a| a == "+" || crate::schema::operational::is_operational(a))
}

pub(crate) fn root_base_entry(
    base_dn: &[(String, String)],
    base_dn_str: &str,
) -> LdapSearchResultEntry {
    let dc_val = base_dn
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("dc"))
        .map(|(_, v)| v.as_bytes().to_vec())
        .unwrap_or_else(|| b"lldap".to_vec());
    let o_val = base_dn
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("o"))
        .map(|(_, v)| v.as_bytes().to_vec())
        .unwrap_or_else(|| b"lldap Directory".to_vec());
    LdapSearchResultEntry {
        dn: base_dn_str.to_string(),
        attributes: vec![
            LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec![
                    b"top".to_vec(),
                    b"dcObject".to_vec(),
                    b"organization".to_vec(),
                ],
            },
            LdapPartialAttribute {
                atype: "dc".to_string(),
                vals: vec![dc_val],
            },
            LdapPartialAttribute {
                atype: "o".to_string(),
                vals: vec![o_val],
            },
            LdapPartialAttribute {
                atype: "hasSubordinates".to_string(),
                vals: vec![b"TRUE".to_vec()],
            },
            LdapPartialAttribute {
                atype: "structuralObjectClass".to_string(),
                vals: vec![b"organization".to_vec()],
            },
            LdapPartialAttribute {
                atype: "subschemaSubentry".to_string(),
                vals: vec![format!("cn=Subschema,{}", base_dn_str).into_bytes()],
            },
        ],
    }
}

pub async fn do_search<Backend>(
    backend: &Backend,
    ldap_info: &LdapInfo,
    request: &LdapSearchRequest,
    allowed_ous: &[String],
) -> LdapResult<Vec<LdapOp>>
where
    Backend: UserAndGroupListerBackendHandler,
{
    let base_dn = &ldap_info.base_dn;
    let dn_parts = match parse_distinguished_name(&request.base) {
        Ok(p) => p,
        Err(_) => return Ok(vec![make_search_success()]),
    };

    let scope = get_search_scope(base_dn, &dn_parts, &request.scope, allowed_ous);
    let schema = PublicSchema::shared();
    let include_op = include_operational(&request.attrs);

    match scope {
        crate::search::scope::SearchScope::Root => {
            if request.scope == LdapSearchScope::Base {
                return Ok(vec![
                    LdapOp::SearchResultEntry(root_base_entry(base_dn, &ldap_info.base_dn_str)),
                    make_search_success(),
                ]);
            }
            let top_level_ous = crate::dn::get_direct_child_ous("", allowed_ous);
            let ous_to_add = if request.scope == LdapSearchScope::Subtree {
                allowed_ous.to_vec()
            } else {
                top_level_ous.clone()
            };
            let ous_to_add: Vec<String> = ous_to_add
                .into_iter()
                .filter(|ou| ou_matches_filter(ou, &request.filter))
                .collect();
            let mut results = build_ou_entries(&ous_to_add, &ldap_info.base_dn_str, include_op);

            if request.scope == LdapSearchScope::Subtree {
                let user_results = get_user_list(
                    ldap_info,
                    &request.filter,
                    true,
                    &request.base,
                    backend,
                    schema,
                )
                .await?;
                results.extend(convert_users_to_ldap_op(
                    user_results,
                    &request.attrs,
                    ldap_info,
                    schema,
                ));

                let group_results =
                    get_groups_list(ldap_info, &request.filter, &request.base, backend, schema)
                        .await?;
                results.extend(convert_groups_to_ldap_op(
                    group_results,
                    &request.attrs,
                    ldap_info,
                    &None,
                    schema,
                ));
            }

            results.push(make_search_success());
            Ok(results)
        }
        crate::search::scope::SearchScope::Container => {
            let mut results = vec![];
            let internal_ou = crate::dn::get_internal_ou_from_dn_parts(&dn_parts);

            if request.scope == LdapSearchScope::Base {
                if ou_matches_filter(&internal_ou, &request.filter) {
                    let ou_entry = make_ou_entry(&internal_ou, &ldap_info.base_dn_str, include_op);
                    results.push(LdapOp::SearchResultEntry(ou_entry));
                }
            } else {
                let child_ous: Vec<String> = if request.scope == LdapSearchScope::OneLevel {
                    crate::dn::get_direct_child_ous(&internal_ou, allowed_ous)
                } else {
                    let curr_l = internal_ou.to_ascii_lowercase();
                    allowed_ous
                        .iter()
                        .filter(|ou| {
                            let ou_l = ou.to_ascii_lowercase();
                            !curr_l.is_empty() && ou_l.starts_with(&format!("{}\\", curr_l))
                        })
                        .cloned()
                        .collect()
                };
                let child_ous: Vec<String> = child_ous
                    .into_iter()
                    .filter(|ou| ou_matches_filter(ou, &request.filter))
                    .collect();
                if !child_ous.is_empty() {
                    results.extend(build_ou_entries(
                        &child_ous,
                        &ldap_info.base_dn_str,
                        include_op,
                    ));
                }

                let user_results = get_user_list(
                    ldap_info,
                    &request.filter,
                    true,
                    &request.base,
                    backend,
                    schema,
                )
                .await?;
                let mut user_ops: Vec<LdapOp> =
                    convert_users_to_ldap_op(user_results, &request.attrs, ldap_info, schema)
                        .collect();

                let group_results =
                    get_groups_list(ldap_info, &request.filter, &request.base, backend, schema)
                        .await?;
                let mut group_ops: Vec<LdapOp> = convert_groups_to_ldap_op(
                    group_results,
                    &request.attrs,
                    ldap_info,
                    &None,
                    schema,
                )
                .collect();

                let child_rdn_count =
                    (request.scope == LdapSearchScope::OneLevel).then_some(dn_parts.len() + 1);
                retain_under_base(&mut user_ops, &request.base, child_rdn_count);
                retain_under_base(&mut group_ops, &request.base, child_rdn_count);

                results.extend(user_ops);
                results.extend(group_ops);
            }
            results.push(make_search_success());
            Ok(results)
        }
        // Leaf lookups probe by RDN first so a missing entry is NoSuchObject while an entry
        // the client filter rejects is a plain success with no entries.
        crate::search::scope::SearchScope::LeafUser => {
            let Ok(user_id) = crate::dn::get_user_id_from_distinguished_name(
                &request.base,
                base_dn,
                &ldap_info.base_dn_str,
            ) else {
                return Ok(vec![make_search_success()]);
            };
            let probe = LdapFilter::Equality("uid".to_string(), user_id.to_string());
            if get_user_list(ldap_info, &probe, false, &request.base, backend, schema)
                .await?
                .is_empty()
            {
                return Err(no_such_object());
            }
            let filter = LdapFilter::And(vec![probe, request.filter.clone()]);
            let users =
                get_user_list(ldap_info, &filter, true, &request.base, backend, schema).await?;
            let mut results: Vec<LdapOp> =
                convert_users_to_ldap_op(users, &request.attrs, ldap_info, schema).collect();
            retain_exact_dn(&mut results, &request.base);
            results.push(make_search_success());
            Ok(results)
        }
        crate::search::scope::SearchScope::LeafGroup => {
            let Ok(group_name) = crate::dn::get_group_id_from_distinguished_name(
                &request.base,
                base_dn,
                &ldap_info.base_dn_str,
            ) else {
                return Ok(vec![make_search_success()]);
            };
            let probe = LdapFilter::Equality("cn".to_string(), group_name.to_string());
            if get_groups_list(ldap_info, &probe, &request.base, backend, schema)
                .await?
                .is_empty()
            {
                return Err(no_such_object());
            }
            let filter = LdapFilter::And(vec![probe, request.filter.clone()]);
            let groups =
                get_groups_list(ldap_info, &filter, &request.base, backend, schema).await?;
            let mut results: Vec<LdapOp> =
                convert_groups_to_ldap_op(groups, &request.attrs, ldap_info, &None, schema)
                    .collect();
            retain_exact_dn(&mut results, &request.base);
            results.push(make_search_success());
            Ok(results)
        }
        crate::search::scope::SearchScope::Invalid | crate::search::scope::SearchScope::Unknown => {
            Ok(vec![make_search_success()])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::tests::setup_bound_admin_handler;
    use crate::search::make_search_request;
    use lldap_domain::types::{Attribute, GroupId, User, UserAndGroups, UserId, Uuid};
    use lldap_test_utils::{MockTestBackendHandler, setup_default_ldap_mock};

    fn user_in(uid: &str, ou: &str) -> UserAndGroups {
        UserAndGroups {
            user: User {
                user_id: UserId::new(uid),
                attributes: vec![Attribute {
                    name: "ou".into(),
                    value: ou.to_string().into(),
                }],
                ..Default::default()
            },
            groups: Some(vec![]),
        }
    }

    fn group_in(name: &str, ou: &str) -> Group {
        let epoch = chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc();
        Group {
            id: GroupId(7),
            display_name: name.into(),
            creation_date: epoch,
            uuid: Uuid::from_name_and_date(name, &epoch),
            users: vec![],
            attributes: vec![Attribute {
                name: "ou".into(),
                value: ou.to_string().into(),
            }],
            modified_date: epoch,
        }
    }

    fn base_request(base: &str, filter: LdapFilter) -> LdapSearchRequest {
        let mut request = make_search_request(base, filter, vec!["objectClass"]);
        request.scope = LdapSearchScope::Base;
        request
    }

    fn entry_dns(ops: &[LdapOp]) -> Vec<String> {
        ops.iter()
            .filter_map(|op| match op {
                LdapOp::SearchResultEntry(e) => Some(e.dn.clone()),
                _ => None,
            })
            .collect()
    }

    fn person_filter() -> LdapFilter {
        LdapFilter::Equality("objectClass".to_string(), "person".to_string())
    }

    #[tokio::test]
    async fn base_search_on_a_user_returns_the_entry_and_success() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        mock.expect_list_users()
            .returning(|_, _| Ok(vec![user_in("bob", "people")]));
        let handler = setup_bound_admin_handler(mock).await;
        let ops = handler
            .do_search_or_dse(&base_request(
                "uid=bob,ou=people,dc=example,dc=com",
                person_filter(),
            ))
            .await
            .unwrap();
        assert_eq!(entry_dns(&ops), vec!["uid=bob,ou=people,dc=example,dc=com"]);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops.last(), Some(&make_search_success()));
    }

    #[tokio::test]
    async fn base_search_on_a_user_the_filter_rejects_is_success_only() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        mock.expect_list_users()
            .times(1)
            .return_once(|_, _| Ok(vec![user_in("bob", "people")]));
        mock.expect_list_users().return_once(|_, _| Ok(vec![]));
        let handler = setup_bound_admin_handler(mock).await;
        let ops = handler
            .do_search_or_dse(&base_request(
                "uid=bob,ou=people,dc=example,dc=com",
                LdapFilter::Equality("uid".to_string(), "alice".to_string()),
            ))
            .await
            .unwrap();
        assert_eq!(ops, vec![make_search_success()]);
    }

    #[tokio::test]
    async fn base_search_on_a_missing_user_is_no_such_object() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        mock.expect_list_users().returning(|_, _| Ok(vec![]));
        let handler = setup_bound_admin_handler(mock).await;
        let err = handler
            .do_search_or_dse(&base_request(
                "uid=nobody,ou=people,dc=example,dc=com",
                person_filter(),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code, LdapResultCode::NoSuchObject);
    }

    #[tokio::test]
    async fn base_search_on_a_group_returns_the_entry_and_success() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        mock.expect_list_groups()
            .returning(|_| Ok(vec![group_in("admins", "groups")]));
        let handler = setup_bound_admin_handler(mock).await;
        let ops = handler
            .do_search_or_dse(&base_request(
                "cn=admins,ou=groups,dc=example,dc=com",
                LdapFilter::Present("objectClass".to_string()),
            ))
            .await
            .unwrap();
        assert_eq!(
            entry_dns(&ops),
            vec!["cn=admins,ou=groups,dc=example,dc=com"]
        );
        assert_eq!(ops.last(), Some(&make_search_success()));
    }

    #[tokio::test]
    async fn base_search_on_a_missing_group_is_no_such_object() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        mock.expect_list_groups().returning(|_| Ok(vec![]));
        let handler = setup_bound_admin_handler(mock).await;
        let err = handler
            .do_search_or_dse(&base_request(
                "cn=nobody,ou=groups,dc=example,dc=com",
                LdapFilter::Present("objectClass".to_string()),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code, LdapResultCode::NoSuchObject);
    }

    #[tokio::test]
    async fn one_level_search_keeps_only_direct_children() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        mock.expect_list_users().returning(|_, _| {
            Ok(vec![
                user_in("bob", "people"),
                user_in("alice", "people\\lab"),
            ])
        });
        mock.expect_list_groups().returning(|_| Ok(vec![]));
        let handler = setup_bound_admin_handler(mock).await;
        let mut request = make_search_request(
            "ou=people,dc=example,dc=com",
            person_filter(),
            vec!["objectClass"],
        );
        request.scope = LdapSearchScope::OneLevel;
        let ops = handler.do_search_or_dse(&request).await.unwrap();
        let dns = entry_dns(&ops);
        assert!(
            dns.contains(&"uid=bob,ou=people,dc=example,dc=com".to_string()),
            "{dns:?}"
        );
        assert!(
            !dns.iter().any(|dn| dn.starts_with("uid=alice,")),
            "one-level must hide the nested user: {dns:?}"
        );
        request.scope = LdapSearchScope::Subtree;
        let dns = entry_dns(&handler.do_search_or_dse(&request).await.unwrap());
        assert!(dns.iter().any(|dn| dn.starts_with("uid=alice,")), "{dns:?}");
    }

    #[test]
    fn include_operational_is_plus_or_any_always_operational() {
        assert!(!include_operational(&[]));
        assert!(!include_operational(&["*".into()]));
        assert!(!include_operational(&["uid".into()]));
        // loginDisabled/sudoHost are explicit-only virtuals — not operational for gating.
        assert!(!include_operational(&["loginDisabled".into()]));
        assert!(!include_operational(&["sudoHost".into()]));
        assert!(include_operational(&["+".into()]));
        for name in [
            "hasSubordinates",
            "structuralObjectClass",
            "subschemaSubentry",
            "createTimestamp",
            "modifyTimestamp",
            "pwdChangedTime",
            "entryUUID",
            "memberOf",
            "entryDN",
            "creatorsName",
            "modifiersName",
        ] {
            assert!(include_operational(&[name.into()]), "{name}");
        }
    }

    #[test]
    fn root_base_entry_always_emits_three_operational_attrs() {
        let base_dn = vec![("dc".into(), "example".into()), ("dc".into(), "com".into())];
        let entry = root_base_entry(&base_dn, "dc=example,dc=com");
        assert_eq!(entry.dn, "dc=example,dc=com");
        let names: Vec<&str> = entry.attributes.iter().map(|a| a.atype.as_str()).collect();
        assert_eq!(
            names,
            [
                "objectClass",
                "dc",
                "o",
                "hasSubordinates",
                "structuralObjectClass",
                "subschemaSubentry",
            ]
        );
        assert!(!names.contains(&"entryDN"));
        assert!(!names.contains(&"entryUUID"));
        assert!(!names.contains(&"creatorsName"));
        let dc = entry.attributes.iter().find(|a| a.atype == "dc").unwrap();
        assert_eq!(dc.vals, vec![b"example".to_vec()]);
        let subschema = entry
            .attributes
            .iter()
            .find(|a| a.atype == "subschemaSubentry")
            .unwrap();
        assert_eq!(
            subschema.vals,
            vec![b"cn=Subschema,dc=example,dc=com".to_vec()]
        );
    }
}
