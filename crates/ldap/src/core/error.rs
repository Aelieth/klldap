use ldap3_proto::LdapResultCode;
use lldap_domain_handlers::kerberos::kerberos_backend;
use lldap_domain_model::error::DomainError;

#[derive(Debug, PartialEq)]
pub struct LdapError {
    pub code: LdapResultCode,
    pub message: String,
}

impl std::fmt::Display for LdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LdapError {}

pub type LdapResult<T> = std::result::Result<T, LdapError>;

/// In directory-only a change that needs a principal is answered as unavailable at every door.
pub(crate) fn unavailable_in_directory_only(e: &DomainError) -> Option<LdapError> {
    let refused = matches!(e, DomainError::KdcUnavailable(_))
        && kerberos_backend().directory_only().is_some();
    refused.then(|| LdapError {
        code: LdapResultCode::Unavailable,
        message: e.to_string(),
    })
}
