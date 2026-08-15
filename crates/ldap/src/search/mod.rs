//! Search module

pub mod filters;
pub mod handler;
pub mod results;
pub mod root_dse;
pub mod scope;
pub mod subschema;

pub use handler::do_search;
pub(crate) use handler::get_user_list;
pub use results::{convert_groups_to_ldap_op, convert_users_to_ldap_op};
pub use root_dse::{is_root_dse_request, is_subschema_entry_request, root_dse_response};
pub use scope::{build_ou_entries, get_search_scope, make_ou_entry};
pub use subschema::make_ldap_subschema_entry;

pub fn make_search_request<S: Into<String>>(
    base: &str,
    filter: ldap3_proto::LdapFilter,
    attrs: Vec<S>,
) -> ldap3_proto::proto::LdapSearchRequest {
    ldap3_proto::proto::LdapSearchRequest {
        base: base.to_string(),
        scope: ldap3_proto::LdapSearchScope::Subtree,
        aliases: ldap3_proto::proto::LdapDerefAliases::Never,
        sizelimit: 0,
        timelimit: 0,
        typesonly: false,
        filter,
        attrs: attrs.into_iter().map(Into::into).collect(),
    }
}

pub fn make_search_success() -> ldap3_proto::proto::LdapOp {
    make_search_error(ldap3_proto::LdapResultCode::Success, "".to_string())
}

pub fn make_search_error(
    code: ldap3_proto::LdapResultCode,
    message: String,
) -> ldap3_proto::proto::LdapOp {
    ldap3_proto::proto::LdapOp::SearchResultDone(ldap3_proto::proto::LdapResult {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}
