use std::str::FromStr;

use clap::{Parser, builder::EnumValueParser};
use lettre::message::Mailbox;
use serde::{Deserialize, Serialize};
use strum::{EnumString, IntoStaticStr};
use url::Url;

use crate::database_string::DatabaseUrl;

// Can be deserialized from either a boolean or a string, to facilitate migration.
#[derive(Copy, Clone, Debug, Serialize, Default, EnumString, IntoStaticStr)]
#[strum(ascii_case_insensitive)]
pub enum TrueFalseAlways {
    #[default]
    False,
    True,
    Always,
}

impl TrueFalseAlways {
    pub fn is_positive(&self) -> bool {
        matches!(self, TrueFalseAlways::True | TrueFalseAlways::Always)
    }

    pub fn is_yes(&self) -> bool {
        matches!(self, TrueFalseAlways::True)
    }
}

impl<'de> Deserialize<'de> for TrueFalseAlways {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self};

        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = TrueFalseAlways;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("true, false or always")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value {
                    Ok(TrueFalseAlways::True)
                } else {
                    Ok(TrueFalseAlways::False)
                }
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match TrueFalseAlways::from_str(value) {
                    Ok(v) => Ok(v),
                    Err(_) => Err(de::Error::unknown_variant(
                        value,
                        &["true", "false", "always"],
                    )),
                }
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Debug, Parser, Clone)]
#[clap(version, author, about = "lldap is a lightweight LDAP server")]
pub struct CLIOpts {
    #[clap(subcommand)]
    pub command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Parser, Clone)]
pub enum Command {
    #[clap(
        name = "export_graphql_schema",
        about = "Export the GraphQL schema to *.graphql"
    )]
    ExportGraphQLSchema(ExportGraphQLSchemaOpts),
    #[clap(name = "run", about = "Run the LDAP and GraphQL server")]
    Run(RunOpts),
    #[clap(
        name = "healthcheck",
        about = "Test whether the LDAP and GraphQL server are responsive"
    )]
    HealthCheck(RunOpts),
    #[clap(name = "send_test_email", about = "Send a test email")]
    SendTestEmail(TestEmailOpts),
    #[clap(name = "create_schema", about = "Create database schema")]
    CreateSchema(RunOpts),
}

#[derive(Debug, Parser, Clone)]
pub struct GeneralConfigOpts {
    #[clap(
        short,
        long,
        default_value = "lldap_config.toml",
        env = "LLDAP_CONFIG_FILE",
        help = "Change config file name"
    )]
    pub config_file: String,

    #[clap(short, long, help = "Set verbose logging")]
    pub verbose: bool,
}

#[derive(Debug, Parser, Clone)]
pub struct RunOpts {
    #[clap(flatten)]
    pub general_config: GeneralConfigOpts,

    #[clap(
        long,
        env = "LLDAP_SERVER_KEY_FILE",
        help = "Path to the file that contains the private server key. It will be created if it doesn't exist. Alternatively, you can set `server_key_seed`. If `server_key_seed` is given, `server_key_file` will be ignored"
    )]
    pub server_key_file: Option<String>,

    #[clap(
        long,
        env = "LLDAP_SERVER_KEY_SEED",
        help = "Seed used to generate the private server key. Takes precedence over `server_key_file`"
    )]
    pub server_key_seed: Option<String>,

    #[clap(
        long,
        env = "LLDAP_LDAP_HOST",
        help = "Change ldap host. Default: \"0.0.0.0\""
    )]
    pub ldap_host: Option<String>,

    #[clap(
        long,
        env = "LLDAP_LDAP_PORT",
        help = "Change ldap port. Default: 3890"
    )]
    pub ldap_port: Option<u16>,

    #[clap(
        long,
        env = "LLDAP_HTTP_HOST",
        help = "Change HTTP API host. Default: \"0.0.0.0\""
    )]
    pub http_host: Option<String>,

    #[clap(
        long,
        env = "LLDAP_HTTP_PORT",
        help = "Change HTTP API port. Default: 17170"
    )]
    pub http_port: Option<u16>,

    #[clap(
        long,
        env = "LLDAP_HTTP_URL",
        help = "URL of the server, for password reset links"
    )]
    pub http_url: Option<Url>,

    #[clap(
        short,
        long,
        env = "LLDAP_DATABASE_URL",
        help = "Database connection URL"
    )]
    pub database_url: Option<DatabaseUrl>,

    #[clap(
        long,
        env = "LLDAP_FORCE_LDAP_USER_PASS_RESET",
        help = "Force admin password reset to the config value. If set to true, it will be a one-time reset that doesn't start the server. You can set it to \"always\" to force a reset every time the server starts"
    )]
    pub force_ldap_user_pass_reset: Option<TrueFalseAlways>,

    #[clap(
        long,
        env = "LLDAP_FORCE_UPDATE_PRIVATE_KEY",
        help = "Force update of the private key after a key change"
    )]
    pub force_update_private_key: Option<bool>,

    #[clap(
        long,
        env = "LLDAP_ENABLE_MFA",
        help = "Second factor (TOTP): false = off, true = only users who enrolled present a code, \"always\" = every user must enroll. Members of lldap_mfa_disabled are exempt"
    )]
    pub enable_mfa: Option<TrueFalseAlways>,

    #[clap(flatten)]
    pub smtp_opts: SmtpOpts,

    #[clap(flatten)]
    pub ldaps_opts: LdapsOpts,

    #[clap(flatten)]
    pub healthcheck_opts: HealthcheckOpts,

    #[clap(flatten)]
    pub log_opts: LogOpts,
}

#[derive(Debug, Parser, Clone)]
pub struct TestEmailOpts {
    #[clap(flatten)]
    pub general_config: GeneralConfigOpts,

    #[clap(
        long,
        env = "LLDAP_TEST_EMAIL_TO",
        help = "Email address to send an email to"
    )]
    pub to: String,

    #[clap(flatten)]
    pub smtp_opts: SmtpOpts,
}

#[derive(Debug, Parser, Clone)]
#[clap(next_help_heading = Some("LDAPS"))]
pub struct LdapsOpts {
    #[clap(
        long,
        env = "LLDAP_LDAPS_OPTIONS__ENABLED",
        help = "Enable LDAPS. Default: false"
    )]
    pub ldaps_enabled: Option<bool>,

    #[clap(
        long,
        env = "LLDAP_LDAPS_OPTIONS__PORT",
        help = "Change ldap ssl port. Default: 6360"
    )]
    pub ldaps_port: Option<u16>,

    #[clap(
        long,
        env = "LLDAP_LDAPS_OPTIONS__CERT_FILE",
        help = "Ldaps certificate file. Default: cert.pem"
    )]
    pub ldaps_cert_file: Option<String>,

    #[clap(
        long,
        env = "LLDAP_LDAPS_OPTIONS__KEY_FILE",
        help = "Ldaps certificate key file. Default: key.pem"
    )]
    pub ldaps_key_file: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "UPPERCASE")]
#[clap(rename_all = "UPPERCASE")]
pub enum SmtpEncryption {
    None,
    Tls,
    StartTls,
}

#[derive(Debug, Parser, Clone)]
#[clap(next_help_heading = Some("SMTP"))]
pub struct SmtpOpts {
    #[clap(
        long,
        env = "LLDAP_SMTP_OPTIONS__ENABLE_PASSWORD_RESET",
        help = "Enable password reset"
    )]
    pub smtp_enable_password_reset: Option<bool>,

    #[clap(long, env = "LLDAP_SMTP_OPTIONS__FROM", help = "Sender email address")]
    pub smtp_from: Option<Mailbox>,

    #[clap(long, env = "LLDAP_SMTP_OPTIONS__TO", help = "Reply-to email address")]
    pub smtp_reply_to: Option<Mailbox>,

    #[clap(long, env = "LLDAP_SMTP_OPTIONS__SERVER", help = "SMTP server")]
    pub smtp_server: Option<String>,

    #[clap(
        long,
        env = "LLDAP_SMTP_OPTIONS__PORT",
        help = "SMTP port, 587 by default"
    )]
    pub smtp_port: Option<u16>,

    #[clap(long, env = "LLDAP_SMTP_OPTIONS__USER", help = "SMTP user")]
    pub smtp_user: Option<String>,

    #[clap(
        long,
        env = "LLDAP_SMTP_OPTIONS__PASSWORD",
        hide_env_values = true,
        help = "SMTP password"
    )]
    pub smtp_password: Option<String>,

    #[clap(
        long,
        env = "LLDAP_SMTP_OPTIONS__TLS_REQUIRED",
        hide = true,
        help = "Whether TLS should be used to connect to SMTP"
    )]
    pub smtp_tls_required: Option<bool>,

    #[clap(long, env = "LLDAP_SMTP_OPTIONS__SMTP_ENCRYPTION", value_parser = EnumValueParser::<SmtpEncryption>::new(), ignore_case = true)]
    pub smtp_encryption: Option<SmtpEncryption>,
}

#[derive(Debug, Parser, Clone)]
pub struct ExportGraphQLSchemaOpts {
    #[clap(
        short,
        long,
        help = "Output to a file. If not specified, the config is printed to the standard output"
    )]
    pub output_file: Option<String>,
}

#[derive(Debug, Parser, Clone)]
#[clap(next_help_heading = Some("HEALTHCHECK"))]
pub struct HealthcheckOpts {
    #[clap(
        long,
        env = "LLDAP_HEALTHCHECK_OPTIONS__HTTP_HOST",
        help = "Change the HTTP Host to test the health of.  Default: \"localhost\""
    )]
    pub healthcheck_http_host: Option<String>,

    #[clap(
        long,
        env = "LLDAP_HEALTHCHECK_OPTIONS__LDAP_HOST",
        help = "Change the LDAP Host to test the health of.  Default: \"localhost\""
    )]
    pub healthcheck_ldap_host: Option<String>,
}

#[derive(Debug, Parser, Clone)]
#[clap(next_help_heading = Some("LOGGING"))]
pub struct LogOpts {
    #[clap(
        long,
        env = "LLDAP_LOG_OPTIONS__PERSIST",
        help = "Persist the event log (logins, binds, directory changes, denials) to the database. Default: true"
    )]
    pub log_persist: Option<bool>,

    #[clap(
        long,
        env = "LLDAP_LOG_OPTIONS__RETENTION_DAYS",
        help = "Delete log events older than this many days; 0 keeps them forever. Default: 30"
    )]
    pub log_retention_days: Option<u32>,

    #[clap(
        long,
        env = "LLDAP_LOG_OPTIONS__MAX_ENTRIES",
        help = "Keep at most this many log events, oldest first; 0 means unlimited. Default: 50000"
    )]
    pub log_max_entries: Option<u64>,

    #[clap(
        long,
        env = "LLDAP_LOG_OPTIONS__BIND_COALESCE_SECONDS",
        help = "Store one successful bind per user, protocol and address within this many seconds; 0 stores every bind. Default: 300"
    )]
    pub log_bind_coalesce_seconds: Option<u32>,
}

pub fn init() -> CLIOpts {
    CLIOpts::parse()
}
