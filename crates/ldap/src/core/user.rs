use crate::core::{
    error::{LdapError, LdapResult},
    utils::LdapInfo,
};
use lldap_domain::public_schema::PublicSchema;
use lldap_domain::types::UserAndGroups;
use lldap_domain_handlers::handler::UserListerBackendHandler;
use tracing::{debug, instrument};

/// Returns the default object classes for users.
pub fn get_default_user_object_classes() -> Vec<lldap_domain::types::LdapObjectClass> {
    crate::attributes::get_default_user_object_classes()
}

/// List users (thin entry point).
#[instrument(skip_all, level = "debug", fields(ldap_filter, request_groups))]
pub(crate) async fn get_user_list<Backend: UserListerBackendHandler>(
    ldap_info: &LdapInfo,
    ldap_filter: &ldap3_proto::LdapFilter,
    request_groups: bool,
    base: &str,
    backend: &Backend,
    schema: &PublicSchema,
) -> LdapResult<Vec<UserAndGroups>> {
    let filters = crate::search::filters::convert_user_filter(ldap_info, ldap_filter, schema)?;
    debug!(?filters);
    backend
        .list_users(Some(filters), request_groups)
        .await
        .map_err(|e| LdapError {
            code: ldap3_proto::LdapResultCode::Other,
            message: format!(r#"Error while searching user "{base}": {e:#}"#),
        })
}

#[cfg(test)]
mod object_classes_tests {
    use super::super::user::get_default_user_object_classes;

    #[test]
    fn default_user_object_classes_includes_kldap_extras() {
        let classes: Vec<String> = get_default_user_object_classes()
            .into_iter()
            .map(|c| c.to_string())
            .collect();

        // From attributes.rs + public_schema.rs extras (KLLDAP 7.1)
        assert!(classes.contains(&"top".to_string()));
        assert!(classes.contains(&"person".to_string()));
        assert!(classes.contains(&"inetOrgPerson".to_string()));
        assert!(classes.contains(&"posixAccount".to_string()));
        assert!(classes.contains(&"ldapPublicKey".to_string()));

        // Should be stable order (top, person, then extras)
        assert!(classes.len() >= 5);
    }

    #[test]
    fn default_object_classes_are_not_empty() {
        assert!(!get_default_user_object_classes().is_empty());
    }
}
