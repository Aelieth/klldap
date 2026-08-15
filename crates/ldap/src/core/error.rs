use ldap3_proto::LdapResultCode;

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

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3_proto::LdapResultCode;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_ldap_error_displays_message() {
        let err = LdapError {
            code: LdapResultCode::Other,
            message: "something went wrong".to_string(),
        };
        assert_eq!(err.to_string(), "something went wrong");
    }

    #[test]
    fn test_ldap_error_is_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(LdapError {
            code: LdapResultCode::NoSuchObject,
            message: "not found".into(),
        });
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_ldap_result_type_works() {
        let ok: LdapResult<i32> = Ok(42);
        assert!(matches!(ok, Ok(42)));

        let err: LdapResult<()> = Err(LdapError {
            code: LdapResultCode::Other,
            message: "boom".into(),
        });
        assert!(err.is_err());
    }
}
