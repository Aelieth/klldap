//! Main LDAP search handler (now uses SchemaManager as primary).

use crate::core::{
    error::{LdapError, LdapResult},
    utils::LdapInfo,
};
use crate::dn::parse_distinguished_name;
use crate::search::scope::ou_matches_filter;
use crate::search::{
    build_ou_entries, convert_groups_to_ldap_op, convert_users_to_ldap_op, get_search_scope,
    make_ou_entry, make_search_success,
};
use ldap3_proto::LdapResultCode;
use ldap3_proto::proto::{LdapOp, LdapSearchRequest, LdapSearchScope};
use lldap_access_control::UserAndGroupListerBackendHandler;
use lldap_domain::public_schema::PublicSchema;

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
    let schema = PublicSchema::get();
    let include_op = request.attrs.iter().any(|a| {
        a == "+"
            || a.eq_ignore_ascii_case("hassubordinates")
            || a.eq_ignore_ascii_case("structuralobjectclass")
            || a.eq_ignore_ascii_case("subschemasubentry")
            || a.eq_ignore_ascii_case("createtimestamp")
            || a.eq_ignore_ascii_case("modifytimestamp")
            || a.eq_ignore_ascii_case("pwdchangedtime")
            || a.eq_ignore_ascii_case("entryuuid")
            || a.eq_ignore_ascii_case("memberof")
    });

    match scope {
        crate::search::scope::SearchScope::Root => {
            if request.scope == LdapSearchScope::Base {
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
                let root_entry = ldap3_proto::LdapSearchResultEntry {
                    dn: ldap_info.base_dn_str.clone(),
                    attributes: vec![
                        ldap3_proto::LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![
                                b"top".to_vec(),
                                b"dcObject".to_vec(),
                                b"organization".to_vec(),
                            ],
                        },
                        ldap3_proto::LdapPartialAttribute {
                            atype: "dc".to_string(),
                            vals: vec![dc_val],
                        },
                        ldap3_proto::LdapPartialAttribute {
                            atype: "o".to_string(),
                            vals: vec![o_val],
                        },
                        ldap3_proto::LdapPartialAttribute {
                            atype: "hasSubordinates".to_string(),
                            vals: vec![b"TRUE".to_vec()],
                        },
                        ldap3_proto::LdapPartialAttribute {
                            atype: "structuralObjectClass".to_string(),
                            vals: vec![b"organization".to_vec()],
                        },
                        ldap3_proto::LdapPartialAttribute {
                            atype: "subschemaSubentry".to_string(),
                            vals: vec![
                                format!("cn=Subschema,{}", ldap_info.base_dn_str).into_bytes(),
                            ],
                        },
                    ],
                };
                return Ok(vec![
                    LdapOp::SearchResultEntry(root_entry),
                    make_search_success(),
                ]);
            }
            let top_level_ous = crate::dn::get_direct_child_ous("", allowed_ous);
            let ous_to_add = if request.scope == LdapSearchScope::Subtree {
                allowed_ous.to_vec()
            } else {
                top_level_ous.clone()
            };
            // FIX: apply OU filter so (ou=office) returns only office, not all (Problem 2)
            let ous_to_add: Vec<String> = ous_to_add
                .into_iter()
                .filter(|ou| ou_matches_filter(ou, &request.filter))
                .collect();
            let mut results = build_ou_entries(&ous_to_add, &ldap_info.base_dn_str, include_op);

            if request.scope == LdapSearchScope::Subtree {
                let user_results = crate::core::user::get_user_list(
                    ldap_info,
                    &request.filter,
                    true,
                    &request.base,
                    backend,
                    &schema,
                )
                .await?;
                results.extend(convert_users_to_ldap_op(
                    user_results,
                    &request.attrs,
                    ldap_info,
                    &schema,
                ));

                let group_results = crate::core::group::get_groups_list(
                    ldap_info,
                    &request.filter,
                    &request.base,
                    backend,
                    &schema,
                )
                .await?;
                results.extend(convert_groups_to_ldap_op(
                    group_results,
                    &request.attrs,
                    ldap_info,
                    &None,
                    &schema,
                ));
            }

            results.push(make_search_success());
            Ok(results)
        }
        crate::search::scope::SearchScope::Container => {
            let mut results = vec![];
            let internal_ou = crate::dn::get_internal_ou_from_dn_parts(&dn_parts);

            if request.scope == LdapSearchScope::Base {
                // FIX: only include the OU entry if it matches the filter (Problem 2)
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
                // FIX: filter child OUs by the client filter (Problem 2)
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

                let user_results = crate::core::user::get_user_list(
                    ldap_info,
                    &request.filter,
                    true,
                    &request.base,
                    backend,
                    &schema,
                )
                .await?;
                let mut user_ops: Vec<LdapOp> =
                    convert_users_to_ldap_op(user_results, &request.attrs, ldap_info, &schema)
                        .collect();

                let group_results = crate::core::group::get_groups_list(
                    ldap_info,
                    &request.filter,
                    &request.base,
                    backend,
                    &schema,
                )
                .await?;
                let mut group_ops: Vec<LdapOp> = convert_groups_to_ldap_op(
                    group_results,
                    &request.attrs,
                    ldap_info,
                    &None,
                    &schema,
                )
                .collect();

                // ADS-compatible filtering (unchanged, stable)
                {
                    let base_lower = request.base.to_ascii_lowercase();
                    let expected_rdn_count = dn_parts.len() + 1;
                    let is_one_level = request.scope == LdapSearchScope::OneLevel;

                    user_ops.retain(|op| {
                        if let LdapOp::SearchResultEntry(e) = op {
                            if let Ok(parts) = parse_distinguished_name(&e.dn) {
                                let under = e.dn.to_ascii_lowercase().ends_with(&base_lower);
                                if is_one_level {
                                    under && parts.len() == expected_rdn_count
                                } else {
                                    under
                                }
                            } else {
                                false
                            }
                        } else {
                            true
                        }
                    });

                    group_ops.retain(|op| {
                        if let LdapOp::SearchResultEntry(e) = op {
                            if let Ok(parts) = parse_distinguished_name(&e.dn) {
                                let under = e.dn.to_ascii_lowercase().ends_with(&base_lower);
                                if is_one_level {
                                    under && parts.len() == expected_rdn_count
                                } else {
                                    under
                                }
                            } else {
                                false
                            }
                        } else {
                            true
                        }
                    });
                }

                results.extend(user_ops);
                results.extend(group_ops);
            }
            results.push(make_search_success());
            Ok(results)
        }
        crate::search::scope::SearchScope::LeafUser => {
            let user_id = match crate::dn::get_user_id_from_distinguished_name(
                &request.base,
                base_dn,
                &ldap_info.base_dn_str,
            ) {
                Ok(id) => id,
                Err(_) => return Ok(vec![make_search_success()]),
            };
            // FIX: existence check with specific filter (preserves NoSuchObject behavior)
            let specific_filter =
                ldap3_proto::LdapFilter::Equality("uid".to_string(), user_id.to_string());
            let exists_users = crate::core::user::get_user_list(
                ldap_info,
                &specific_filter,
                true,
                &request.base,
                backend,
                &schema,
            )
            .await?;
            if exists_users.is_empty() {
                return Err(LdapError {
                    code: LdapResultCode::NoSuchObject,
                    message: "".to_string(),
                });
            }
            // Now apply the REAL client filter (Problem 3)
            let users = crate::core::user::get_user_list(
                ldap_info,
                &request.filter,
                true,
                &request.base,
                backend,
                &schema,
            )
            .await?;
            let mut results: Vec<LdapOp> =
                convert_users_to_ldap_op(users, &request.attrs, ldap_info, &schema).collect();
            // Post-filter to exact base DN (consistent with Container pattern, reusable)
            let base_lower = request.base.to_ascii_lowercase();
            results.retain(|op| {
                if let LdapOp::SearchResultEntry(e) = op {
                    e.dn.to_ascii_lowercase() == base_lower
                } else {
                    true
                }
            });
            if results.is_empty() {
                // Entry exists but filter did not match → success, 0 entries (correct LDAP behavior)
                return Ok(vec![make_search_success()]);
            }
            results.push(make_search_success());
            Ok(results)
        }
        crate::search::scope::SearchScope::LeafGroup => {
            let group_name = match crate::dn::get_group_id_from_distinguished_name(
                &request.base,
                base_dn,
                &ldap_info.base_dn_str,
            ) {
                Ok(name) => name,
                Err(_) => return Ok(vec![make_search_success()]),
            };

            // Existence check using the canonical attribute name for the group RDN.
            // We use SchemaManager so we stay consistent with the dynamic alias mapping
            // (displayname <-> cn) that was standardized in this release.
            let schema_manager = crate::schema::get_schema_manager();
            let group_rdn_attr = schema_manager.get_canonical_name("cn");
            let specific_filter =
                ldap3_proto::LdapFilter::Equality(group_rdn_attr, group_name.to_string());

            let exists_groups = crate::core::group::get_groups_list(
                ldap_info,
                &specific_filter,
                &request.base,
                backend,
                &schema,
            )
            .await?;
            if exists_groups.is_empty() {
                return Err(LdapError {
                    code: LdapResultCode::NoSuchObject,
                    message: "".to_string(),
                });
            }

            // Apply the REAL client filter after confirming the entry exists.
            // This two-step pattern (existence check + real filter) is required to
            // correctly return NoSuchObject vs Success+0 entries per LDAP semantics.
            let groups = crate::core::group::get_groups_list(
                ldap_info,
                &request.filter,
                &request.base,
                backend,
                &schema,
            )
            .await?;
            let mut results: Vec<LdapOp> =
                convert_groups_to_ldap_op(groups, &request.attrs, ldap_info, &None, &schema)
                    .collect();

            let base_lower = request.base.to_ascii_lowercase();
            results.retain(|op| {
                if let LdapOp::SearchResultEntry(e) = op {
                    e.dn.to_ascii_lowercase() == base_lower
                } else {
                    true
                }
            });
            if results.is_empty() {
                return Ok(vec![make_search_success()]);
            }
            results.push(make_search_success());
            Ok(results)
        }
        crate::search::scope::SearchScope::Invalid | crate::search::scope::SearchScope::Unknown => {
            Ok(vec![make_search_success()])
        }
    }
}
