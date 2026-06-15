//! Root DSE and subschema request handling.

use ldap3_proto::proto::{
    LdapOp, LdapSearchRequest, LdapSearchScope, OID_PASSWORD_MODIFY, OID_WHOAMI,
};

pub fn root_dse_response(base_dn: &str) -> LdapOp {
    let realm = {
        let domain = base_dn
            .split(',')
            .filter_map(|part| part.strip_prefix("dc="))
            .collect::<Vec<_>>()
            .join(".")
            .to_lowercase();
        std::env::var("LLDAP_KERB_REALM_NAME")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| domain.to_uppercase())
            .to_uppercase()
    };

    let realm_bytes = realm.into_bytes();
    let full_subschema_dn = format!("cn=Subschema,{}", base_dn);

    LdapOp::SearchResultEntry(ldap3_proto::LdapSearchResultEntry {
        dn: "".to_string(),
        attributes: vec![
            ldap3_proto::LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec![b"top".to_vec()],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "vendorName".to_string(),
                vals: vec![b"LLDAP".to_vec()],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "vendorVersion".to_string(),
                vals: vec![
                    concat!("lldap_", env!("CARGO_PKG_VERSION"))
                        .to_string()
                        .into_bytes(),
                ],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "supportedLDAPVersion".to_string(),
                vals: vec![b"3".to_vec()],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "supportedExtension".to_string(),
                vals: vec![
                    OID_PASSWORD_MODIFY.as_bytes().to_vec(),
                    OID_WHOAMI.as_bytes().to_vec(),
                ],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "supportedControl".to_string(),
                vals: vec![
                    b"1.2.840.113556.1.4.319".to_vec(),
                    b"1.3.6.1.4.1.4203.1.9.1".to_vec(),
                ],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "defaultNamingContext".to_string(),
                vals: vec![base_dn.to_string().into_bytes()],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "namingContexts".to_string(),
                vals: vec![base_dn.to_string().into_bytes()],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "schemaNamingContext".to_string(),
                vals: vec![full_subschema_dn.clone().into_bytes()],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "configurationNamingContext".to_string(),
                vals: vec![base_dn.to_string().into_bytes()],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "isGlobalCatalogReady".to_string(),
                vals: vec![b"false".to_vec()],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "subschemaSubentry".to_string(),
                vals: vec![full_subschema_dn.into_bytes()],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "krb5RealmName".to_string(),
                vals: vec![realm_bytes.clone()],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "supportedSASLMechanisms".to_string(),
                vals: vec![
                    b"GSSAPI".to_vec(),
                    b"GSS-SPNEGO".to_vec(),
                    b"DIGEST-MD5".to_vec(),
                ],
            },
            ldap3_proto::LdapPartialAttribute {
                atype: "defaultRealm".to_string(),
                vals: vec![realm_bytes],
            },
        ],
    })
}

pub fn is_root_dse_request(request: &LdapSearchRequest) -> bool {
    request.base.is_empty()
        && request.scope == LdapSearchScope::Base
        && matches!(&request.filter, ldap3_proto::LdapFilter::Present(attr) if attr.eq_ignore_ascii_case("objectclass"))
}

pub fn is_subschema_entry_request(request: &LdapSearchRequest) -> bool {
    let base_lower = request.base.to_ascii_lowercase();
    let base_matches = base_lower.contains("cn=subschema");
    let scope_ok = matches!(
        request.scope,
        LdapSearchScope::Base | LdapSearchScope::Subtree
    );
    let filter_ok = match &request.filter {
        ldap3_proto::LdapFilter::Present(attr) => attr.eq_ignore_ascii_case("objectclass"),
        ldap3_proto::LdapFilter::Equality(attr, val) => {
            attr.eq_ignore_ascii_case("objectclass")
                && (val == "*"
                    || val.eq_ignore_ascii_case("top")
                    || val.eq_ignore_ascii_case("subschema"))
        }
        ldap3_proto::LdapFilter::And(filters) | ldap3_proto::LdapFilter::Or(filters) => {
            filters.iter().any(|f| {
                if let ldap3_proto::LdapFilter::Equality(a, _v) = f {
                    a.eq_ignore_ascii_case("objectclass")
                } else {
                    false
                }
            })
        }
        _ => true,
    };
    base_matches && scope_ok && filter_ok
}
