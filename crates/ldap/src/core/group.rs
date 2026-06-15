use crate::core::{
    error::{LdapError, LdapResult},
    utils::LdapInfo,
};
use lldap_domain::public_schema::PublicSchema;
use lldap_domain::types::Group;
use lldap_domain_handlers::handler::GroupListerBackendHandler;
use tracing::{debug, instrument};

/// Returns the default object classes for groups.
pub fn get_default_group_object_classes() -> Vec<lldap_domain::types::LdapObjectClass> {
    crate::attributes::get_default_group_object_classes()
}

/// List groups (thin entry point).
#[instrument(skip_all, level = "debug", fields(ldap_filter))]
pub(crate) async fn get_groups_list<Backend: GroupListerBackendHandler>(
    ldap_info: &LdapInfo,
    ldap_filter: &ldap3_proto::LdapFilter,
    base: &str,
    backend: &Backend,
    schema: &PublicSchema,
) -> LdapResult<Vec<Group>> {
    let filters = crate::search::filters::convert_group_filter(ldap_info, ldap_filter, schema)?;
    debug!(?filters);
    backend
        .list_groups(Some(filters))
        .await
        .map_err(|e| LdapError {
            code: ldap3_proto::LdapResultCode::Other,
            message: format!(r#"Error while listing groups "{base}": {e:#}"#),
        })
}

#[cfg(test)]
mod object_classes_tests {
    use super::super::group::get_default_group_object_classes;

    #[test]
    fn default_group_object_classes_includes_posix() {
        let classes: Vec<String> = get_default_group_object_classes()
            .into_iter()
            .map(|c| c.to_string())
            .collect();

        assert!(classes.contains(&"groupOfUniqueNames".to_string()));
        assert!(classes.contains(&"groupOfNames".to_string()));
        assert!(classes.contains(&"posixGroup".to_string()));
    }

    #[test]
    fn default_object_classes_are_not_empty() {
        assert!(!get_default_group_object_classes().is_empty());
    }
}
