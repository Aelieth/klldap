use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Serialize, Deserialize, derive_more::Display)]
#[display("{_0}")]
pub struct DatabaseUrl(Url);

impl From<Url> for DatabaseUrl {
    fn from(url: Url) -> Self {
        Self(url)
    }
}

impl From<&str> for DatabaseUrl {
    fn from(url: &str) -> Self {
        Self(Url::parse(url).expect("Invalid database URL"))
    }
}

impl DatabaseUrl {
    pub fn db_type(&self) -> &str {
        self.0.scheme()
    }

    /// sqlx needs `?mode=rwc` to create a missing sqlite file, and docker
    /// absolute paths need four slashes (`sqlite:////data/foo.db`).
    pub fn to_connect_string(&self) -> String {
        normalize_sqlite_connect_url(&self.to_string())
    }
}

pub(crate) fn normalize_sqlite_connect_url(url: &str) -> String {
    if !url.starts_with("sqlite:") || url.contains(":memory:") {
        return url.to_string();
    }
    let mut normalized = url.to_string();
    if let Some(rest) = normalized.strip_prefix("sqlite://")
        && rest.starts_with('/')
        && !rest.starts_with("//")
    {
        normalized = format!("sqlite:///{rest}");
    }
    if !normalized.contains("mode=") {
        if normalized.contains('?') {
            normalized.push_str("&mode=rwc");
        } else {
            normalized.push_str("?mode=rwc");
        }
    }
    normalized
}

impl std::fmt::Debug for DatabaseUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.password().is_some() {
            let mut url = self.0.clone();
            // It can fail for URLs that cannot have a password, like "mailto:bob@example".
            let _ = url.set_password(Some("***PASSWORD***"));
            f.write_fmt(format_args!(r#""{url}""#))
        } else {
            f.write_fmt(format_args!(r#""{}""#, self.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_url_debug() {
        let url = DatabaseUrl::from("postgres://user:pass@localhost:5432/dbname");
        assert_eq!(
            format!("{url:?}"),
            r#""postgres://user:***PASSWORD***@localhost:5432/dbname""#
        );
        assert_eq!(
            url.to_string(),
            "postgres://user:pass@localhost:5432/dbname"
        );
    }

    #[test]
    fn sqlite_three_slash_data_path_gets_four_slashes_and_mode() {
        assert_eq!(
            normalize_sqlite_connect_url("sqlite:///data/custom.db"),
            "sqlite:////data/custom.db?mode=rwc"
        );
        assert_eq!(
            DatabaseUrl::from("sqlite:///data/custom.db").to_connect_string(),
            "sqlite:////data/custom.db?mode=rwc"
        );
    }

    #[test]
    fn sqlite_already_correct_is_unchanged() {
        assert_eq!(
            normalize_sqlite_connect_url("sqlite:////data/users.db?mode=rwc"),
            "sqlite:////data/users.db?mode=rwc"
        );
    }

    #[test]
    fn sqlite_memory_is_unchanged() {
        assert_eq!(
            normalize_sqlite_connect_url("sqlite::memory:"),
            "sqlite::memory:"
        );
    }

    #[test]
    fn sqlite_relative_gets_mode_only() {
        assert_eq!(
            normalize_sqlite_connect_url("sqlite://users.db"),
            "sqlite://users.db?mode=rwc"
        );
    }

    #[test]
    fn postgres_is_unchanged() {
        assert_eq!(
            normalize_sqlite_connect_url("postgres://u:p@h/db"),
            "postgres://u:p@h/db"
        );
    }
}
